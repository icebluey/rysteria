use std::error::Error;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};
use tokio_util::task::TaskTracker;

use crate::app::internal::utils::copy_two_way;
use crate::core::client::ReconnectableClient;

pub trait TCPEventLogger: Send + Sync {
    fn connect(&self, addr: SocketAddr, req_addr: SocketAddr);
    fn error(
        &self,
        addr: SocketAddr,
        req_addr: SocketAddr,
        err: Option<&(dyn Error + Send + Sync)>,
    );
}

pub struct TCPRedirect {
    pub hy_client: Arc<ReconnectableClient>,
    pub event_logger: Option<Arc<dyn TCPEventLogger>>,
}

impl TCPRedirect {
    pub async fn listen_and_serve(self: Arc<Self>, listener: TcpListener, tracker: TaskTracker) -> io::Result<()> {
        loop {
            let (conn, _) = listener.accept().await?;
            let this = Arc::clone(&self);
            tracker.spawn(async move {
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
        "TCP redirect is only supported on Linux",
    ))
}
