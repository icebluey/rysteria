use std::collections::HashMap;
use std::error::Error;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use netstack_smoltcp::{StackBuilder, UdpSocket};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Mutex, mpsc};
use tun_rs::DeviceBuilder;

use crate::app::internal::utils::copy_two_way;
use crate::core::client::{HyUdpConn, ReconnectableClient};

const TUN_PACKET_BUFFER_SIZE: usize = 65_535;
const TUN_UDP_CHAN_SIZE: usize = 1024;

#[derive(Debug, Clone)]
pub struct TunConfig {
    pub name: String,
    pub mtu: u32,
    pub timeout: Duration,
    pub inet4_address: Vec<String>,
    pub inet6_address: Vec<String>,
    pub auto_route: bool,
    pub strict_route: bool,
    pub inet4_route_address: Vec<String>,
    pub inet6_route_address: Vec<String>,
    pub inet4_route_exclude_address: Vec<String>,
    pub inet6_route_exclude_address: Vec<String>,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: "hytun".to_string(),
            mtu: 1500,
            timeout: Duration::from_secs(300),
            inet4_address: Vec::new(),
            inet6_address: Vec::new(),
            auto_route: false,
            strict_route: false,
            inet4_route_address: Vec::new(),
            inet6_route_address: Vec::new(),
            inet4_route_exclude_address: Vec::new(),
            inet6_route_exclude_address: Vec::new(),
        }
    }
}

pub trait EventLogger: Send + Sync {
    fn tcp_request(&self, addr: &str, req_addr: &str);
    fn tcp_error(&self, addr: &str, req_addr: &str, err: Option<&(dyn Error + Send + Sync)>);
    fn udp_request(&self, addr: &str);
    fn udp_error(&self, addr: &str, err: Option<&(dyn Error + Send + Sync)>);
}

#[async_trait::async_trait]
pub trait TunBackend: Send + Sync {
    async fn run(self: Arc<Self>, server: Arc<TunServer>) -> io::Result<()>;
}

#[derive(Default)]
struct NetstackTunBackend;

#[async_trait::async_trait]
impl TunBackend for NetstackTunBackend {
    async fn run(self: Arc<Self>, server: Arc<TunServer>) -> io::Result<()> {
        let tun_device = build_tun_device(&server.config)?;
        let (stack, runner, udp_socket, tcp_listener) = StackBuilder::default()
            .enable_tcp(true)
            .enable_udp(true)
            .enable_icmp(true)
            .build()?;

        if let Some(runner) = runner {
            tokio::spawn(async move {
                let _ = runner.await;
            });
        }

        let udp_socket = udp_socket.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "UDP stack is not enabled")
        })?;
        let mut tcp_listener = tcp_listener.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "TCP stack is not enabled")
        })?;

        let (mut stack_sink, mut stack_stream) = stack.split();
        let tun_device = Arc::new(tun_device);

        let tun_to_stack = {
            let tun_device = Arc::clone(&tun_device);
            tokio::spawn(async move {
                let mut buf = vec![0u8; TUN_PACKET_BUFFER_SIZE];
                loop {
                    let n = tun_device.recv(&mut buf).await?;
                    if n == 0 {
                        continue;
                    }
                    stack_sink.send(buf[..n].to_vec()).await?;
                }
            })
        };

        let stack_to_tun = {
            let tun_device = Arc::clone(&tun_device);
            tokio::spawn(async move {
                while let Some(pkt) = stack_stream.next().await {
                    let pkt = pkt?;
                    let _ = tun_device.send(pkt.as_slice()).await?;
                }
                Ok::<(), io::Error>(())
            })
        };

        let tcp_loop = {
            let server = Arc::clone(&server);
            tokio::spawn(async move {
                while let Some((stream, src, dst)) = tcp_listener.next().await {
                    let server = Arc::clone(&server);
                    tokio::spawn(async move {
                        let _ = server
                            .handle_tun_tcp(stream, src.to_string(), dst.to_string())
                            .await;
                    });
                }
                Ok::<(), io::Error>(())
            })
        };

        let udp_loop = {
            let server = Arc::clone(&server);
            tokio::spawn(async move { run_udp_loop(server, udp_socket).await })
        };

        tokio::pin!(tun_to_stack);
        tokio::pin!(stack_to_tun);
        tokio::pin!(tcp_loop);
        tokio::pin!(udp_loop);

        let result = tokio::select! {
            r = &mut tun_to_stack => r.map_err(|e| io::Error::other(format!("tun->stack task join error: {e}")))?,
            r = &mut stack_to_tun => r.map_err(|e| io::Error::other(format!("stack->tun task join error: {e}")))?,
            r = &mut tcp_loop => r.map_err(|e| io::Error::other(format!("tun tcp loop join error: {e}")))?,
            r = &mut udp_loop => r.map_err(|e| io::Error::other(format!("tun udp loop join error: {e}")))?,
        };

        if !tun_to_stack.is_finished() {
            tun_to_stack.as_mut().abort();
            let _ = tun_to_stack.await;
        }
        if !stack_to_tun.is_finished() {
            stack_to_tun.as_mut().abort();
            let _ = stack_to_tun.await;
        }
        if !tcp_loop.is_finished() {
            tcp_loop.as_mut().abort();
            let _ = tcp_loop.await;
        }
        if !udp_loop.is_finished() {
            udp_loop.as_mut().abort();
            let _ = udp_loop.await;
        }

        result
    }
}

pub struct TunServer {
    pub hy_client: Arc<ReconnectableClient>,
    pub event_logger: Option<Arc<dyn EventLogger>>,
    pub config: TunConfig,
    pub backend: Option<Arc<dyn TunBackend>>,
}

impl TunServer {
    pub async fn serve(self: Arc<Self>) -> io::Result<()> {
        if let Some(backend) = &self.backend {
            return Arc::clone(backend).run(Arc::clone(&self)).await;
        }

        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TUN backend is not configured",
        ))
    }

    pub fn validate(&self) -> io::Result<()> {
        if self.config.name.trim().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tun.name is empty",
            ));
        }
        if self.config.mtu < 576 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tun.mtu must be >= 576",
            ));
        }
        for cidr in self
            .config
            .inet4_address
            .iter()
            .chain(self.config.inet6_address.iter())
        {
            let ip = cidr.split('/').next().unwrap_or("").trim();
            if ip.parse::<IpAddr>().is_err() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid TUN address: {cidr}"),
                ));
            }
        }
        Ok(())
    }

    pub async fn handle_tun_tcp<S>(&self, stream: S, src: String, dst: String) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        if let Some(logger) = &self.event_logger {
            logger.tcp_request(&src, &dst);
        }

        let mut close_err: Option<Box<dyn Error + Send + Sync>> = None;
        let result = async {
            let hy_stream = self.hy_client.tcp(&dst).await?;
            copy_two_way(stream, hy_stream).await?;
            Ok::<(), Box<dyn Error + Send + Sync>>(())
        }
        .await;

        if let Err(err) = result {
            close_err = Some(err);
        }

        if let Some(logger) = &self.event_logger {
            logger.tcp_error(&src, &dst, close_err.as_deref());
        }

        Ok(())
    }

    pub async fn handle_tun_udp(
        &self,
        mut local_recv: tokio::sync::mpsc::Receiver<(Vec<u8>, String)>,
        local_send: tokio::sync::mpsc::Sender<(Vec<u8>, String)>,
        src: String,
    ) -> io::Result<()> {
        if let Some(logger) = &self.event_logger {
            logger.udp_request(&src);
        }

        let hy_udp = self
            .hy_client
            .udp()
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;
        let hy_udp = Arc::new(hy_udp);
        let idle_timeout = if self.config.timeout.is_zero() {
            Duration::from_secs(300)
        } else {
            self.config.timeout
        };

        let a_hy = Arc::clone(&hy_udp);
        let a_send = local_send.clone();
        let a = tokio::spawn(async move {
            loop {
                let recv = tokio::time::timeout(idle_timeout, a_hy.receive()).await;
                let (data, from) = match recv {
                    Ok(Ok(v)) => v,
                    Ok(Err(e)) => return Err(io::Error::other(e.to_string())),
                    Err(_) => return Ok(()),
                };
                if a_send.send((data, from)).await.is_err() {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "local UDP sender closed",
                    ));
                }
            }
        });

        let b_hy = Arc::clone(&hy_udp);
        let b = tokio::spawn(async move {
            loop {
                match tokio::time::timeout(idle_timeout, local_recv.recv()).await {
                    Ok(Some((data, dst))) => b_hy.send(&data, &dst).await?,
                    Ok(None) => return Ok(()),
                    Err(_) => return Ok(()),
                }
            }
        });

        tokio::pin!(a);
        tokio::pin!(b);
        let err = tokio::select! {
            r = &mut a => r.map_err(|e| io::Error::other(format!("task join error: {e}")))?,
            r = &mut b => r.map_err(|e| io::Error::other(format!("task join error: {e}")))?,
        };

        if !a.is_finished() {
            a.as_mut().abort();
            let _ = a.await;
        }
        if !b.is_finished() {
            b.as_mut().abort();
            let _ = b.await;
        }

        hy_udp.close();

        if let Some(logger) = &self.event_logger {
            if let Err(ref e) = err {
                logger.udp_error(&src, Some(e));
            } else {
                logger.udp_error(&src, None);
            }
        }

        err
    }
}

async fn run_udp_loop(server: Arc<TunServer>, udp_socket: UdpSocket) -> io::Result<()> {
    let (mut udp_read, udp_write) = udp_socket.split();
    let udp_write = Arc::new(Mutex::new(udp_write));
    let sessions: Arc<Mutex<HashMap<(SocketAddr, SocketAddr), mpsc::Sender<Vec<u8>>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    while let Some((data, local_addr, remote_addr)) = udp_read.next().await {
        let key = (local_addr, remote_addr);
        let tx = {
            let mut guard = sessions.lock().await;
            if let Some(existing) = guard.get(&key) {
                existing.clone()
            } else {
                let (tx, rx) = mpsc::channel::<Vec<u8>>(TUN_UDP_CHAN_SIZE);
                guard.insert(key, tx.clone());
                spawn_tun_udp_pair(
                    Arc::clone(&server),
                    Arc::clone(&sessions),
                    Arc::clone(&udp_write),
                    key,
                    rx,
                );
                tx
            }
        };
        if tx.send(data).await.is_err() {
            sessions.lock().await.remove(&key);
        }
    }

    Ok(())
}

fn spawn_tun_udp_pair(
    server: Arc<TunServer>,
    sessions: Arc<Mutex<HashMap<(SocketAddr, SocketAddr), mpsc::Sender<Vec<u8>>>>>,
    udp_write: Arc<Mutex<netstack_smoltcp::udp::WriteHalf>>,
    key: (SocketAddr, SocketAddr),
    mut local_rx: mpsc::Receiver<Vec<u8>>,
) {
    tokio::spawn(async move {
        let (local_addr, remote_addr) = key;
        let local_addr_text = local_addr.to_string();

        if let Some(logger) = &server.event_logger {
            logger.udp_request(&local_addr_text);
        }

        let hy_udp = match server.hy_client.udp().await {
            Ok(conn) => Arc::new(conn),
            Err(err) => {
                if let Some(logger) = &server.event_logger {
                    let err = io::Error::other(err.to_string());
                    logger.udp_error(&local_addr_text, Some(&err));
                }
                sessions.lock().await.remove(&key);
                return;
            }
        };

        let send_hy = Arc::clone(&hy_udp);
        let idle_timeout = if server.config.timeout.is_zero() {
            Duration::from_secs(300)
        } else {
            server.config.timeout
        };
        let send_task = tokio::spawn(async move {
            loop {
                match tokio::time::timeout(idle_timeout, local_rx.recv()).await {
                    Ok(Some(data)) => send_hy.send(&data, &remote_addr.to_string()).await?,
                    Ok(None) => return Ok(()),
                    Err(_) => return Ok(()),
                }
            }
        });

        let recv_hy = Arc::clone(&hy_udp);
        let recv_write = Arc::clone(&udp_write);
        let recv_task = tokio::spawn(async move {
            loop {
                let recv = tokio::time::timeout(idle_timeout, recv_hy.receive()).await;
                let (data, from) = match recv {
                    Ok(Ok(v)) => v,
                    Ok(Err(e)) => return Err(io::Error::other(e.to_string())),
                    Err(_) => return Ok(()),
                };
                let src_addr = from.parse::<SocketAddr>().unwrap_or(remote_addr);
                let mut write_half = recv_write.lock().await;
                write_half.send((data, src_addr, local_addr)).await?;
            }
        });

        tokio::pin!(send_task);
        tokio::pin!(recv_task);
        let result: io::Result<()> = tokio::select! {
            r = &mut send_task => match r {
                Ok(v) => v,
                Err(e) => Err(io::Error::other(format!("tun udp send task join error: {e}"))),
            },
            r = &mut recv_task => match r {
                Ok(v) => v,
                Err(e) => Err(io::Error::other(format!("tun udp recv task join error: {e}"))),
            },
        };

        if !send_task.is_finished() {
            send_task.as_mut().abort();
            let _ = send_task.await;
        }
        if !recv_task.is_finished() {
            recv_task.as_mut().abort();
            let _ = recv_task.await;
        }

        hy_udp.close();
        sessions.lock().await.remove(&key);

        if let Some(logger) = &server.event_logger {
            if let Err(ref err) = result {
                logger.udp_error(&local_addr_text, Some(err));
            } else {
                logger.udp_error(&local_addr_text, None);
            }
        }
    });
}

fn build_tun_device(config: &TunConfig) -> io::Result<tun_rs::AsyncDevice> {
    let mut builder = DeviceBuilder::new()
        .name(config.name.clone())
        .mtu(config.mtu as u16);

    let mut has_addr = false;
    let mut first_v4 = true;
    let mut extra_v4 = Vec::<(Ipv4Addr, u8)>::new();

    for cidr in &config.inet4_address {
        let (ip, prefix) = parse_cidr(cidr)?;
        let ip = match ip {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid IPv4 address: {cidr}"),
                ));
            }
        };
        has_addr = true;
        if first_v4 {
            builder = builder.ipv4(ip, prefix, None::<Ipv4Addr>);
            first_v4 = false;
        } else {
            extra_v4.push((ip, prefix));
        }
    }

    for cidr in &config.inet6_address {
        let (ip, prefix) = parse_cidr(cidr)?;
        let ip = match ip {
            IpAddr::V6(v6) => v6,
            IpAddr::V4(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid IPv6 address: {cidr}"),
                ));
            }
        };
        has_addr = true;
        builder = builder.ipv6(ip, prefix);
    }

    if !has_addr {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tun.address must include at least one IPv4 or IPv6 CIDR",
        ));
    }

    let device = builder.build_async()?;
    for (ip, prefix) in extra_v4 {
        device.add_address_v4(ip, prefix)?;
    }
    Ok(device)
}

fn parse_cidr(cidr: &str) -> io::Result<(IpAddr, u8)> {
    let trimmed = cidr.trim();
    if trimmed.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "empty CIDR address",
        ));
    }

    let (ip_text, prefix_text) = match trimmed.split_once('/') {
        Some(v) => (v.0.trim(), Some(v.1.trim())),
        None => (trimmed, None),
    };
    let ip: IpAddr = ip_text.parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid CIDR address: {cidr}"),
        )
    })?;
    let max_prefix = if ip.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix_text {
        Some(v) if !v.is_empty() => v.parse::<u8>().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid CIDR prefix: {cidr}"),
            )
        })?,
        _ => max_prefix,
    };
    if prefix > max_prefix {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("CIDR prefix out of range: {cidr}"),
        ));
    }

    Ok((ip, prefix))
}

pub fn build_default_tun_server(
    hy_client: Arc<ReconnectableClient>,
    config: TunConfig,
    event_logger: Option<Arc<dyn EventLogger>>,
) -> Arc<TunServer> {
    Arc::new(TunServer {
        hy_client,
        event_logger,
        config,
        backend: Some(Arc::new(NetstackTunBackend)),
    })
}

#[allow(dead_code)]
async fn _close_hy_udp(conn: Arc<HyUdpConn>) {
    conn.close();
}
