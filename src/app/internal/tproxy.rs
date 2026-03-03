use std::collections::HashMap;
use std::error::Error;
use std::io;
#[cfg(target_os = "linux")]
use std::mem::{size_of, zeroed};
use std::net::SocketAddr;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{RwLock, mpsc};

use crate::app::internal::utils::copy_two_way;
use crate::core::client::{HyUdpConn, ReconnectableClient};

const UDP_BUFFER_SIZE: usize = 4096;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

pub trait TCPEventLogger: Send + Sync {
    fn connect(&self, addr: SocketAddr, req_addr: SocketAddr);
    fn error(
        &self,
        addr: SocketAddr,
        req_addr: SocketAddr,
        err: Option<&(dyn Error + Send + Sync)>,
    );
}

pub trait UDPEventLogger: Send + Sync {
    fn connect(&self, addr: SocketAddr, req_addr: SocketAddr);
    fn error(
        &self,
        addr: SocketAddr,
        req_addr: SocketAddr,
        err: Option<&(dyn Error + Send + Sync)>,
    );
}

pub struct TCPTProxy {
    pub hy_client: Arc<ReconnectableClient>,
    pub event_logger: Option<Arc<dyn TCPEventLogger>>,
}

impl TCPTProxy {
    pub async fn listen_and_serve(self: Arc<Self>, listener: TcpListener) -> io::Result<()> {
        loop {
            let (conn, _) = listener.accept().await?;
            let this = Arc::clone(&self);
            tokio::spawn(async move {
                this.handle(conn).await;
            });
        }
    }

    async fn handle(self: Arc<Self>, conn: TcpStream) {
        let addr = conn
            .peer_addr()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
        let req_addr = match get_original_dst(&conn) {
            Ok(v) => v,
            Err(err) => {
                if let Some(logger) = &self.event_logger {
                    logger.error(addr, SocketAddr::from(([0, 0, 0, 0], 0)), Some(&err));
                }
                return;
            }
        };

        if let Some(logger) = &self.event_logger {
            logger.connect(addr, req_addr);
        }

        let mut close_err: Option<Box<dyn Error + Send + Sync>> = None;
        let run = async {
            let hy_stream = self.hy_client.tcp(&req_addr.to_string()).await?;
            copy_two_way(conn, hy_stream).await?;
            Ok::<(), Box<dyn Error + Send + Sync>>(())
        }
        .await;

        if let Err(err) = run {
            close_err = Some(err);
        }

        if let Some(logger) = &self.event_logger {
            logger.error(addr, req_addr, close_err.as_deref());
        }
    }
}

#[cfg(target_os = "linux")]
fn get_original_dst(conn: &TcpStream) -> io::Result<SocketAddr> {
    use std::mem::{size_of, zeroed};
    use std::os::fd::AsRawFd;

    const SO_ORIGINAL_DST: libc::c_int = 80;
    const IP6T_SO_ORIGINAL_DST: libc::c_int = 80;

    // SAFETY: getsockopt writes a socket address into the provided storage buffer.
    // The buffer is sized as sockaddr_storage and interpreted based on returned family.
    unsafe {
        let fd = conn.as_raw_fd();

        let mut storage: libc::sockaddr_storage = zeroed();
        let mut len = size_of::<libc::sockaddr_storage>() as libc::socklen_t;

        let mut rc = libc::getsockopt(
            fd,
            libc::SOL_IPV6,
            IP6T_SO_ORIGINAL_DST,
            (&mut storage as *mut libc::sockaddr_storage).cast(),
            &mut len,
        );

        if rc != 0 {
            storage = zeroed();
            len = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            rc = libc::getsockopt(
                fd,
                libc::SOL_IP,
                SO_ORIGINAL_DST,
                (&mut storage as *mut libc::sockaddr_storage).cast(),
                &mut len,
            );
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
        }

        match storage.ss_family as i32 {
            libc::AF_INET => {
                let sin: libc::sockaddr_in = std::ptr::read((&storage as *const _) as *const _);
                let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                let port = u16::from_be(sin.sin_port);
                Ok(SocketAddr::from((ip, port)))
            }
            libc::AF_INET6 => {
                let sin6: libc::sockaddr_in6 =
                    std::ptr::read((&storage as *const _) as *const libc::sockaddr_in6);
                let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                let port = u16::from_be(sin6.sin6_port);
                Ok(SocketAddr::from((ip, port)))
            }
            _ => Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "address family not IPv4/IPv6",
            )),
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn get_original_dst(_conn: &TcpStream) -> io::Result<SocketAddr> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "TCP tproxy is only supported on Linux",
    ))
}

struct UdpPair {
    hy_conn: Arc<HyUdpConn>,
    req_addr: SocketAddr,
    send_tx: mpsc::Sender<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
struct UdpPairKey {
    src_addr: SocketAddr,
    req_addr: SocketAddr,
}

pub struct UDPTProxy {
    pub hy_client: Arc<ReconnectableClient>,
    pub timeout: Duration,
    pub event_logger: Option<Arc<dyn UDPEventLogger>>,
    pairs: Arc<RwLock<HashMap<UdpPairKey, Arc<UdpPair>>>>,
}

impl UDPTProxy {
    pub fn new(
        hy_client: Arc<ReconnectableClient>,
        timeout: Duration,
        event_logger: Option<Arc<dyn UDPEventLogger>>,
    ) -> Self {
        Self {
            hy_client,
            timeout,
            event_logger,
            pairs: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn listen_and_serve(self: Arc<Self>, socket: UdpSocket) -> io::Result<()> {
        let socket = Arc::new(socket);
        #[cfg(target_os = "linux")]
        enable_original_dst_recv(&socket)?;
        let mut buf = vec![0u8; UDP_BUFFER_SIZE];

        loop {
            let (n, src_addr, req_addr) = recv_with_req_addr(&socket, &mut buf).await?;
            let packet = buf[..n].to_vec();
            self.feed(Arc::clone(&socket), src_addr, req_addr, packet)
                .await;
        }
    }

    async fn feed(
        self: &Arc<Self>,
        socket: Arc<UdpSocket>,
        src_addr: SocketAddr,
        req_addr: SocketAddr,
        data: Vec<u8>,
    ) {
        let key = UdpPairKey { src_addr, req_addr };
        let pair = if let Some(existing) = self.pairs.read().await.get(&key).cloned() {
            existing
        } else {
            if let Some(logger) = &self.event_logger {
                logger.connect(src_addr, req_addr);
            }

            let hy_conn = match self.hy_client.udp().await {
                Ok(c) => Arc::new(c),
                Err(err) => {
                    if let Some(logger) = &self.event_logger {
                        logger.error(src_addr, req_addr, Some(err.as_ref()));
                    }
                    return;
                }
            };

            let (send_tx, send_rx) = mpsc::channel::<Vec<u8>>(1024);
            let pair = Arc::new(UdpPair {
                hy_conn,
                req_addr,
                send_tx,
            });
            let mut w = self.pairs.write().await;
            if let Some(existing) = w.get(&key).cloned() {
                existing
            } else {
                w.insert(key, Arc::clone(&pair));
                let this = Arc::clone(self);
                let socket_clone = Arc::clone(&socket);
                let pair_clone = Arc::clone(&pair);
                tokio::spawn(async move {
                    this.pair_loop(socket_clone, key, pair_clone, send_rx).await;
                });
                pair
            }
        };

        if pair.send_tx.send(data).await.is_err() {
            let err = io::Error::new(io::ErrorKind::BrokenPipe, "UDP tproxy pair is closed");
            if let Some(logger) = &self.event_logger {
                logger.error(src_addr, req_addr, Some(&err));
            }
            pair.hy_conn.close();
            self.pairs.write().await.remove(&key);
        }
    }

    async fn pair_loop(
        self: Arc<Self>,
        socket: Arc<UdpSocket>,
        key: UdpPairKey,
        pair: Arc<UdpPair>,
        mut send_rx: mpsc::Receiver<Vec<u8>>,
    ) {
        let timeout = if self.timeout.is_zero() {
            DEFAULT_TIMEOUT
        } else {
            self.timeout
        };
        let src_addr = key.src_addr;
        let req_addr = pair.req_addr;
        let req_addr_text = req_addr.to_string();

        let to_remote_hy = Arc::clone(&pair.hy_conn);
        let to_remote = tokio::spawn(async move {
            while let Some(data) = send_rx.recv().await {
                to_remote_hy.send(&data, &req_addr_text).await?;
            }
            Ok::<(), io::Error>(())
        });

        let to_local_hy = Arc::clone(&pair.hy_conn);
        let to_local = tokio::spawn(async move {
            loop {
                let recv = tokio::time::timeout(timeout, to_local_hy.receive()).await;
                match recv {
                    Ok(Ok((data, _))) => {
                        socket.send_to(&data, src_addr).await?;
                    }
                    Ok(Err(err)) => {
                        return Err(io::Error::other(err.to_string()));
                    }
                    Err(_) => {
                        return Ok(());
                    }
                }
            }
        });

        tokio::pin!(to_remote);
        tokio::pin!(to_local);
        let mut close_err: Option<Box<dyn Error + Send + Sync>> = None;
        let first = tokio::select! {
            r = &mut to_remote => r,
            r = &mut to_local => r,
        };

        match first {
            Ok(Ok(())) => {}
            Ok(Err(err)) => close_err = Some(Box::new(err)),
            Err(err) => {
                close_err = Some(Box::new(io::Error::other(format!(
                    "task join error: {err}"
                ))))
            }
        }

        if !to_remote.is_finished() {
            to_remote.as_mut().abort();
            let _ = to_remote.await;
        }
        if !to_local.is_finished() {
            to_local.as_mut().abort();
            let _ = to_local.await;
        }

        pair.hy_conn.close();
        self.pairs.write().await.remove(&key);

        if let Some(logger) = &self.event_logger {
            logger.error(src_addr, req_addr, close_err.as_deref());
        }
    }
}

async fn recv_with_req_addr(
    socket: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, SocketAddr)> {
    #[cfg(target_os = "linux")]
    {
        recv_with_req_addr_linux(socket, buf).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = socket;
        let _ = buf;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "UDP tproxy is only supported on Linux",
        ))
    }
}

#[cfg(target_os = "linux")]
const IP_RECVORIGDSTADDR: libc::c_int = 20;
#[cfg(target_os = "linux")]
const IP_ORIGDSTADDR: libc::c_int = 20;
#[cfg(target_os = "linux")]
const IPV6_RECVORIGDSTADDR: libc::c_int = 74;
#[cfg(target_os = "linux")]
const IPV6_ORIGDSTADDR: libc::c_int = 74;

#[cfg(target_os = "linux")]
fn enable_original_dst_recv(socket: &UdpSocket) -> io::Result<()> {
    let fd = socket.as_raw_fd();
    let on: libc::c_int = 1;
    let mut enabled = false;
    let mut last_err: Option<io::Error> = None;

    for (level, optname) in [
        (libc::SOL_IP, IP_RECVORIGDSTADDR),
        (libc::SOL_IPV6, IPV6_RECVORIGDSTADDR),
    ] {
        let rc = unsafe {
            libc::setsockopt(
                fd,
                level,
                optname,
                (&on as *const libc::c_int).cast(),
                size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc == 0 {
            enabled = true;
        } else {
            last_err = Some(io::Error::last_os_error());
        }
    }

    if enabled {
        Ok(())
    } else if let Some(err) = last_err {
        Err(err)
    } else {
        Err(io::Error::other(
            "failed to enable original destination on UDP socket",
        ))
    }
}

#[cfg(target_os = "linux")]
async fn recv_with_req_addr_linux(
    socket: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, SocketAddr)> {
    loop {
        socket.readable().await?;
        match recv_msg_with_req_addr(socket, buf) {
            Ok(result) => return Ok(result),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
            Err(err) => return Err(err),
        }
    }
}

#[cfg(target_os = "linux")]
fn recv_msg_with_req_addr(
    socket: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, SocketAddr)> {
    let fd = socket.as_raw_fd();
    let mut name_storage: libc::sockaddr_storage = unsafe { zeroed() };
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    let mut control = [0u8; 256];
    let mut msg: libc::msghdr = unsafe { zeroed() };
    msg.msg_name = (&mut name_storage as *mut libc::sockaddr_storage).cast();
    msg.msg_namelen = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = control.len();

    let n = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_DONTWAIT) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }

    let src_addr = sockaddr_storage_to_socket_addr(&name_storage)?;
    let req_addr = parse_original_dst_from_cmsg(&msg).unwrap_or_else(|| {
        socket
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)))
    });
    Ok((n as usize, src_addr, req_addr))
}

#[cfg(target_os = "linux")]
fn parse_original_dst_from_cmsg(msg: &libc::msghdr) -> Option<SocketAddr> {
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(msg as *const libc::msghdr);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_IP && (*cmsg).cmsg_type == IP_ORIGDSTADDR {
                let addr_ptr = libc::CMSG_DATA(cmsg).cast::<libc::sockaddr_in>();
                let sin = std::ptr::read_unaligned(addr_ptr);
                let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                let port = u16::from_be(sin.sin_port);
                return Some(SocketAddr::from((ip, port)));
            }
            if (*cmsg).cmsg_level == libc::SOL_IPV6 && (*cmsg).cmsg_type == IPV6_ORIGDSTADDR {
                let addr_ptr = libc::CMSG_DATA(cmsg).cast::<libc::sockaddr_in6>();
                let sin6 = std::ptr::read_unaligned(addr_ptr);
                let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                let port = u16::from_be(sin6.sin6_port);
                return Some(SocketAddr::from((ip, port)));
            }
            cmsg = libc::CMSG_NXTHDR(msg as *const libc::msghdr, cmsg);
        }
        None
    }
}

#[cfg(target_os = "linux")]
fn sockaddr_storage_to_socket_addr(storage: &libc::sockaddr_storage) -> io::Result<SocketAddr> {
    match storage.ss_family as i32 {
        libc::AF_INET => {
            let sin: libc::sockaddr_in = unsafe {
                std::ptr::read_unaligned((storage as *const _) as *const libc::sockaddr_in)
            };
            let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            let port = u16::from_be(sin.sin_port);
            Ok(SocketAddr::from((ip, port)))
        }
        libc::AF_INET6 => {
            let sin6: libc::sockaddr_in6 = unsafe {
                std::ptr::read_unaligned((storage as *const _) as *const libc::sockaddr_in6)
            };
            let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            let port = u16::from_be(sin6.sin6_port);
            Ok(SocketAddr::from((ip, port)))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported UDP sockaddr family",
        )),
    }
}
