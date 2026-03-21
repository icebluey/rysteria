use std::collections::HashMap;
use std::error::Error;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::RwLock;
use tokio_util::task::TaskTracker;
use tokio_util::sync::CancellationToken;

use crate::app::internal::utils::copy_two_way;
use crate::core::client::{HyUdpConn, ReconnectableClient};
use crate::core::internal::utils::AtomicTime;

const UDP_BUFFER_SIZE: usize = 4096;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);
const IDLE_CLEANUP_INTERVAL: Duration = Duration::from_secs(1);

pub trait TCPEventLogger: Send + Sync {
    fn connect(&self, addr: SocketAddr);
    fn error(&self, addr: SocketAddr, err: Option<&(dyn Error + Send + Sync)>);
}

pub trait UDPEventLogger: Send + Sync {
    fn connect(&self, addr: SocketAddr);
    fn error(&self, addr: SocketAddr, err: Option<&(dyn Error + Send + Sync)>);
}

pub struct TCPTunnel {
    pub hy_client: Arc<ReconnectableClient>,
    pub remote: String,
    pub event_logger: Option<Arc<dyn TCPEventLogger>>,
}

impl TCPTunnel {
    pub async fn serve(self: Arc<Self>, listener: TcpListener, tracker: TaskTracker) -> io::Result<()> {
        loop {
            let (conn, _) = listener.accept().await?;
            let tunnel = Arc::clone(&self);
            tracker.spawn(async move {
                tunnel.handle(conn).await;
            });
        }
    }

    async fn handle(self: Arc<Self>, conn: TcpStream) {
        let remote_addr = conn
            .peer_addr()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
        if let Some(logger) = &self.event_logger {
            logger.connect(remote_addr);
        }

        let mut close_error: Option<Box<dyn Error + Send + Sync>> = None;

        let relay = async {
            let hy_conn = self.hy_client.tcp(&self.remote).await?;
            copy_two_way(conn, hy_conn).await?;
            Ok::<(), Box<dyn Error + Send + Sync>>(())
        }
        .await;

        if let Err(err) = relay {
            close_error = Some(err);
        }

        if let Some(logger) = &self.event_logger {
            logger.error(remote_addr, close_error.as_deref());
        }
    }
}

struct UdpSessionEntry {
    hy_conn: Arc<HyUdpConn>,
    last: AtomicTime,
    timeout: AtomicBool,
}

impl UdpSessionEntry {
    async fn feed(&self, data: &[u8], addr: &str) -> io::Result<()> {
        self.last.update();
        self.hy_conn.send(data, addr).await
    }
}

pub struct UDPTunnel {
    pub hy_client: Arc<ReconnectableClient>,
    pub remote: String,
    pub timeout: Duration,
    pub event_logger: Option<Arc<dyn UDPEventLogger>>,
    sessions: Arc<RwLock<HashMap<SocketAddr, Arc<UdpSessionEntry>>>>,
}

impl UDPTunnel {
    pub fn new(
        hy_client: Arc<ReconnectableClient>,
        remote: String,
        timeout: Duration,
        event_logger: Option<Arc<dyn UDPEventLogger>>,
    ) -> Self {
        Self {
            hy_client,
            remote,
            timeout,
            event_logger,
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn serve(self: Arc<Self>, socket: UdpSocket, tracker: TaskTracker) -> io::Result<()> {
        let socket = Arc::new(socket);
        let cancel = CancellationToken::new();

        let cleanup_tunnel = Arc::clone(&self);
        let cleanup_cancel = cancel.clone();
        tokio::spawn(async move {
            cleanup_tunnel.idle_cleanup_loop(cleanup_cancel).await;
        });

        let mut buf = vec![0u8; UDP_BUFFER_SIZE];
        let result = async {
            loop {
                let (n, addr) = socket.recv_from(&mut buf).await?;
                let data = buf[..n].to_vec();
                self.feed(Arc::clone(&socket), addr, data, &tracker).await;
            }
            #[allow(unreachable_code)]
            Ok::<(), io::Error>(())
        }
        .await;
        cancel.cancel();
        self.cleanup(false).await;
        result
    }

    async fn idle_cleanup_loop(self: Arc<Self>, cancel: CancellationToken) {
        let mut ticker = tokio::time::interval(IDLE_CLEANUP_INTERVAL);
        loop {
            tokio::select! {
                _ = ticker.tick() => self.cleanup(true).await,
                _ = cancel.cancelled() => return,
            }
        }
    }

    async fn cleanup(&self, idle_only: bool) {
        let timeout = if self.timeout.is_zero() {
            DEFAULT_TIMEOUT
        } else {
            self.timeout
        };

        let timeout_secs = timeout.as_secs();
        let mut to_remove = Vec::new();
        {
            let sessions = self.sessions.read().await;
            for (addr, entry) in sessions.iter() {
                if !idle_only || entry.last.is_idle(timeout_secs) {
                    entry.timeout.store(true, Ordering::Relaxed);
                    entry.hy_conn.close();
                    to_remove.push(*addr);
                }
            }
        }
        if to_remove.is_empty() {
            return;
        }
        let mut sessions = self.sessions.write().await;
        for addr in to_remove {
            sessions.remove(&addr);
        }
    }

    async fn feed(self: &Arc<Self>, socket: Arc<UdpSocket>, addr: SocketAddr, data: Vec<u8>, tracker: &TaskTracker) {
        let mut created = false;
        let entry = if let Some(existing) = self.sessions.read().await.get(&addr).cloned() {
            existing
        } else {
            if let Some(logger) = &self.event_logger {
                logger.connect(addr);
            }
            let hy_conn = match self.hy_client.udp().await {
                Ok(c) => c,
                Err(err) => {
                    if let Some(logger) = &self.event_logger {
                        logger.error(addr, Some(err.as_ref()));
                    }
                    return;
                }
            };
            let candidate = Arc::new(UdpSessionEntry {
                hy_conn: Arc::new(hy_conn),
                last: AtomicTime::new(),
                timeout: AtomicBool::new(false),
            });

            let mut sessions = self.sessions.write().await;
            if let Some(existing) = sessions.get(&addr).cloned() {
                existing
            } else {
                sessions.insert(addr, Arc::clone(&candidate));
                created = true;
                candidate
            }
        };

        if created {
            let tunnel = Arc::clone(self);
            let socket = Arc::clone(&socket);
            let entry_for_loop = Arc::clone(&entry);
            tracker.spawn(async move {
                tunnel
                    .session_receive_loop(socket, addr, entry_for_loop)
                    .await;
            });
        }

        if let Err(err) = entry.feed(&data, &self.remote).await {
            if let Some(logger) = &self.event_logger {
                logger.error(addr, Some(&err));
            }
            entry.hy_conn.close();
            self.sessions.write().await.remove(&addr);
        }
    }

    async fn session_receive_loop(
        self: Arc<Self>,
        socket: Arc<UdpSocket>,
        addr: SocketAddr,
        entry: Arc<UdpSessionEntry>,
    ) {
        let mut close_error: Option<Box<dyn Error + Send + Sync>> = None;
        loop {
            match entry.hy_conn.receive().await {
                Ok((data, _)) => {
                    if let Err(err) = socket.send_to(&data, addr).await {
                        close_error = Some(Box::new(err));
                        break;
                    }
                    entry.last.update();
                }
                Err(err) => {
                    if !entry.timeout.load(Ordering::Relaxed) {
                        close_error = Some(Box::new(err));
                    }
                    break;
                }
            }
        }

        if !entry.timeout.load(Ordering::Relaxed) {
            entry.hy_conn.close();
        }

        self.sessions.write().await.remove(&addr);
        if let Some(logger) = &self.event_logger {
            logger.error(addr, close_error.as_deref());
        }
    }
}
