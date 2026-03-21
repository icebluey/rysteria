use std::error::Error;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;
use tokio_util::task::TaskTracker;

use crate::app::internal::utils::copy_two_way;
use crate::core::client::ReconnectableClient;

const SOCKS_VERSION: u8 = 0x05;
const SOCKS_METHOD_NONE: u8 = 0x00;
const SOCKS_METHOD_USERPASS: u8 = 0x02;
const SOCKS_METHOD_NO_ACCEPTABLE: u8 = 0xff;

const SOCKS_CMD_CONNECT: u8 = 0x01;
const SOCKS_CMD_UDP_ASSOCIATE: u8 = 0x03;

const SOCKS_ATYP_IPV4: u8 = 0x01;
const SOCKS_ATYP_DOMAIN: u8 = 0x03;
const SOCKS_ATYP_IPV6: u8 = 0x04;

const SOCKS_REPLY_SUCCEEDED: u8 = 0x00;
const SOCKS_REPLY_SERVER_FAILURE: u8 = 0x01;
const SOCKS_REPLY_COMMAND_NOT_SUPPORTED: u8 = 0x07;

const UDP_BUFFER_SIZE: usize = 4096;

pub trait EventLogger: Send + Sync {
    fn tcp_request(&self, addr: SocketAddr, req_addr: &str);
    fn tcp_error(&self, addr: SocketAddr, req_addr: &str, err: Option<&(dyn Error + Send + Sync)>);
    fn udp_request(&self, addr: SocketAddr);
    fn udp_error(&self, addr: SocketAddr, err: Option<&(dyn Error + Send + Sync)>);
}

pub struct Server {
    pub hy_client: Arc<ReconnectableClient>,
    pub auth_func: Option<Arc<dyn Fn(&str, &str) -> bool + Send + Sync>>,
    pub disable_udp: bool,
    pub event_logger: Option<Arc<dyn EventLogger>>,
}

struct SocksRequest {
    cmd: u8,
    addr: String,
}

impl Server {
    pub async fn serve(self: Arc<Self>, listener: TcpListener, tracker: TaskTracker) -> io::Result<()> {
        loop {
            let (conn, _) = listener.accept().await?;
            let server = Arc::clone(&self);
            tracker.spawn(async move {
                server.dispatch(conn).await;
            });
        }
    }

    pub async fn dispatch(self: Arc<Self>, conn: TcpStream) {
        let _ = self.dispatch_inner(conn).await;
    }

    async fn dispatch_inner(&self, mut conn: TcpStream) -> io::Result<()> {
        if !self.negotiate(&mut conn).await? {
            return Ok(());
        }

        let req = read_request(&mut conn).await?;
        match req.cmd {
            SOCKS_CMD_CONNECT => self.handle_tcp(conn, &req.addr).await,
            SOCKS_CMD_UDP_ASSOCIATE => {
                if self.disable_udp {
                    send_simple_reply(&mut conn, SOCKS_REPLY_COMMAND_NOT_SUPPORTED).await
                } else {
                    self.handle_udp(conn).await
                }
            }
            _ => send_simple_reply(&mut conn, SOCKS_REPLY_COMMAND_NOT_SUPPORTED).await,
        }
    }

    async fn negotiate(&self, conn: &mut TcpStream) -> io::Result<bool> {
        let mut first = [0u8; 2];
        conn.read_exact(&mut first).await?;
        if first[0] != SOCKS_VERSION {
            return Ok(false);
        }

        let methods_len = first[1] as usize;
        let mut methods = vec![0u8; methods_len];
        conn.read_exact(&mut methods).await?;

        let server_method = if self.auth_func.is_some() {
            SOCKS_METHOD_USERPASS
        } else {
            SOCKS_METHOD_NONE
        };

        if !methods.contains(&server_method) {
            conn.write_all(&[SOCKS_VERSION, SOCKS_METHOD_NO_ACCEPTABLE])
                .await?;
            return Ok(false);
        }

        conn.write_all(&[SOCKS_VERSION, server_method]).await?;

        if server_method == SOCKS_METHOD_USERPASS {
            let mut auth_head = [0u8; 2];
            conn.read_exact(&mut auth_head).await?;
            if auth_head[0] != 0x01 {
                conn.write_all(&[0x01, 0x01]).await?;
                return Ok(false);
            }

            let user_len = auth_head[1] as usize;
            let mut username = vec![0u8; user_len];
            conn.read_exact(&mut username).await?;

            let mut pass_len = [0u8; 1];
            conn.read_exact(&mut pass_len).await?;
            let mut password = vec![0u8; pass_len[0] as usize];
            conn.read_exact(&mut password).await?;

            let user = String::from_utf8_lossy(&username).into_owned();
            let pass = String::from_utf8_lossy(&password).into_owned();
            let ok = self
                .auth_func
                .as_ref()
                .map(|f| f(&user, &pass))
                .unwrap_or(true);
            let status = if ok { 0x00 } else { 0x01 };
            conn.write_all(&[0x01, status]).await?;
            return Ok(ok);
        }

        Ok(true)
    }

    async fn handle_tcp(&self, mut conn: TcpStream, req_addr: &str) -> io::Result<()> {
        let remote_addr = conn
            .peer_addr()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));

        if let Some(logger) = &self.event_logger {
            logger.tcp_request(remote_addr, req_addr);
        }

        let mut close_error: Option<Box<dyn Error + Send + Sync>> = None;
        let hy_conn = match self.hy_client.tcp(req_addr).await {
            Ok(conn) => conn,
            Err(err) => {
                let _ = send_simple_reply(&mut conn, SOCKS_REPLY_SERVER_FAILURE).await;
                close_error = Some(err);
                if let Some(logger) = &self.event_logger {
                    logger.tcp_error(remote_addr, req_addr, close_error.as_deref());
                }
                return Ok(());
            }
        };
        send_simple_reply(&mut conn, SOCKS_REPLY_SUCCEEDED).await?;
        if let Err(err) = copy_two_way(conn, hy_conn).await {
            close_error = Some(Box::new(err));
        }

        if let Some(logger) = &self.event_logger {
            logger.tcp_error(remote_addr, req_addr, close_error.as_deref());
        }
        Ok(())
    }

    async fn handle_udp(&self, mut conn: TcpStream) -> io::Result<()> {
        let remote_addr = conn
            .peer_addr()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));

        if let Some(logger) = &self.event_logger {
            logger.udp_request(remote_addr);
        }

        let host = conn
            .local_addr()
            .map(|a| a.ip())
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let udp_bind = SocketAddr::new(host, 0);
        let udp_socket = UdpSocket::bind(udp_bind).await?;

        let hy_udp = match self.hy_client.udp().await {
            Ok(c) => Arc::new(c),
            Err(err) => {
                let _ = send_simple_reply(&mut conn, SOCKS_REPLY_SERVER_FAILURE).await;
                if let Some(logger) = &self.event_logger {
                    logger.udp_error(remote_addr, Some(err.as_ref()));
                }
                return Ok(());
            }
        };

        send_udp_reply(&mut conn, udp_socket.local_addr()?).await?;

        let udp_socket = Arc::new(udp_socket);
        let relay = {
            let udp_socket = Arc::clone(&udp_socket);
            let hy_udp = Arc::clone(&hy_udp);
            tokio::spawn(async move { udp_server(udp_socket, hy_udp).await })
        };

        let hold = tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            loop {
                let n = conn.read(&mut buf).await?;
                if n == 0 {
                    return Ok::<(), io::Error>(());
                }
            }
        });

        let mut close_error: Option<Box<dyn Error + Send + Sync>> = None;
        tokio::pin!(relay);
        tokio::pin!(hold);
        tokio::select! {
            r = &mut relay => {
                match r {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => close_error = Some(Box::new(err)),
                    Err(err) => close_error = Some(Box::new(io::Error::other(err.to_string()))),
                }
            }
            r = &mut hold => {
                match r {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => close_error = Some(Box::new(err)),
                    Err(err) => close_error = Some(Box::new(io::Error::other(err.to_string()))),
                }
            }
        }
        if !relay.is_finished() {
            relay.as_mut().abort();
            let _ = relay.await;
        }
        if !hold.is_finished() {
            hold.as_mut().abort();
            let _ = hold.await;
        }

        hy_udp.close();

        if let Some(logger) = &self.event_logger {
            logger.udp_error(remote_addr, close_error.as_deref());
        }
        Ok(())
    }
}

async fn udp_server(
    udp_socket: Arc<UdpSocket>,
    hy_udp: Arc<crate::core::client::HyUdpConn>,
) -> io::Result<()> {
    let mut client_addr: Option<SocketAddr> = None;
    let mut remote_done_rx: Option<watch::Receiver<Option<String>>> = None;
    let mut buf = vec![0u8; UDP_BUFFER_SIZE];

    loop {
        let (n, addr) = if let Some(done_rx) = remote_done_rx.as_mut() {
            tokio::select! {
                changed = done_rx.changed() => {
                    if changed.is_ok() {
                        if let Some(reason) = done_rx.borrow().clone() {
                            if reason.is_empty() {
                                return Ok(());
                            }
                            return Err(io::Error::other(reason));
                        }
                    }
                    return Ok(());
                }
                recv = udp_socket.recv_from(&mut buf) => recv?,
            }
        } else {
            udp_socket.recv_from(&mut buf).await?
        };
        let Some((frag, target, payload)) = parse_udp_datagram(&buf[..n]) else {
            continue;
        };
        if frag != 0 {
            continue;
        }

        if client_addr.is_none() {
            client_addr = Some(addr);
        }
        if Some(addr) != client_addr {
            continue;
        }

        if remote_done_rx.is_none() {
            let udp_socket = Arc::clone(&udp_socket);
            let hy_udp = Arc::clone(&hy_udp);
            let Some(target_addr) = client_addr else {
                continue;
            };
            let (done_tx, done_rx) = watch::channel::<Option<String>>(None);
            remote_done_rx = Some(done_rx);
            tokio::spawn(async move {
                let signal = match remote_to_local_loop(udp_socket, hy_udp, target_addr).await {
                    Ok(()) => Some(String::new()),
                    Err(err) => Some(err.to_string()),
                };
                let _ = done_tx.send(signal);
            });
        }

        hy_udp.send(&payload, &target).await?;
    }
}

async fn remote_to_local_loop(
    udp_socket: Arc<UdpSocket>,
    hy_udp: Arc<crate::core::client::HyUdpConn>,
    client_addr: SocketAddr,
) -> io::Result<()> {
    loop {
        let (data, from) = hy_udp
            .receive()
            .await
            .map_err(|err| io::Error::other(err.to_string()))?;
        if let Some(datagram) = build_udp_datagram(&from, &data) {
            let _ = udp_socket.send_to(&datagram, client_addr).await?;
        }
    }
}

fn parse_udp_datagram(buf: &[u8]) -> Option<(u8, String, Vec<u8>)> {
    if buf.len() < 4 {
        return None;
    }
    if buf[0] != 0 || buf[1] != 0 {
        return None;
    }

    let frag = buf[2];
    let mut pos = 3;
    let atyp = *buf.get(pos)?;
    pos += 1;

    let host = match atyp {
        SOCKS_ATYP_IPV4 => {
            if buf.len() < pos + 4 {
                return None;
            }
            let ip = Ipv4Addr::new(buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]);
            pos += 4;
            ip.to_string()
        }
        SOCKS_ATYP_IPV6 => {
            if buf.len() < pos + 16 {
                return None;
            }
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&buf[pos..pos + 16]);
            pos += 16;
            Ipv6Addr::from(ip).to_string()
        }
        SOCKS_ATYP_DOMAIN => {
            let domain_len = *buf.get(pos)? as usize;
            pos += 1;
            if buf.len() < pos + domain_len {
                return None;
            }
            let domain = String::from_utf8_lossy(&buf[pos..pos + domain_len]).into_owned();
            pos += domain_len;
            domain
        }
        _ => return None,
    };

    if buf.len() < pos + 2 {
        return None;
    }
    let port = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    pos += 2;

    let payload = buf[pos..].to_vec();
    Some((frag, format!("{host}:{port}"), payload))
}

fn build_udp_datagram(from: &str, payload: &[u8]) -> Option<Vec<u8>> {
    let (atyp, addr_bytes, port) = encode_socks_addr(from)?;
    let mut out = Vec::with_capacity(3 + 1 + addr_bytes.len() + 2 + payload.len());
    out.extend_from_slice(&[0x00, 0x00, 0x00, atyp]);
    out.extend_from_slice(&addr_bytes);
    out.extend_from_slice(&port.to_be_bytes());
    out.extend_from_slice(payload);
    Some(out)
}

async fn read_request(conn: &mut TcpStream) -> io::Result<SocksRequest> {
    let mut head = [0u8; 4];
    conn.read_exact(&mut head).await?;
    if head[0] != SOCKS_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid socks version",
        ));
    }

    let addr = read_socks_addr(conn, head[3]).await?;
    Ok(SocksRequest { cmd: head[1], addr })
}

async fn read_socks_addr(conn: &mut TcpStream, atyp: u8) -> io::Result<String> {
    let host = match atyp {
        SOCKS_ATYP_IPV4 => {
            let mut ip = [0u8; 4];
            conn.read_exact(&mut ip).await?;
            Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]).to_string()
        }
        SOCKS_ATYP_IPV6 => {
            let mut ip = [0u8; 16];
            conn.read_exact(&mut ip).await?;
            Ipv6Addr::from(ip).to_string()
        }
        SOCKS_ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            conn.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            conn.read_exact(&mut domain).await?;
            String::from_utf8_lossy(&domain).into_owned()
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported address type",
            ));
        }
    };

    let mut port_bytes = [0u8; 2];
    conn.read_exact(&mut port_bytes).await?;
    let port = u16::from_be_bytes(port_bytes);
    Ok(format!("{host}:{port}"))
}

fn encode_socks_addr(addr: &str) -> Option<(u8, Vec<u8>, u16)> {
    if let Ok(socket_addr) = addr.parse::<SocketAddr>() {
        return match socket_addr.ip() {
            IpAddr::V4(ip) => Some((SOCKS_ATYP_IPV4, ip.octets().to_vec(), socket_addr.port())),
            IpAddr::V6(ip) => Some((SOCKS_ATYP_IPV6, ip.octets().to_vec(), socket_addr.port())),
        };
    }

    let (host, port) = split_host_port(addr)?;
    if host.len() > u8::MAX as usize {
        return None;
    }

    let mut bytes = Vec::with_capacity(host.len() + 1);
    bytes.push(host.len() as u8);
    bytes.extend_from_slice(host.as_bytes());
    Some((SOCKS_ATYP_DOMAIN, bytes, port))
}

fn split_host_port(addr: &str) -> Option<(String, u16)> {
    let idx = addr.rfind(':')?;
    let host = &addr[..idx];
    let port = addr[idx + 1..].parse::<u16>().ok()?;
    Some((host.to_string(), port))
}

async fn send_simple_reply(conn: &mut TcpStream, rep: u8) -> io::Result<()> {
    conn.write_all(&[SOCKS_VERSION, rep, 0x00, SOCKS_ATYP_IPV4, 0, 0, 0, 0, 0, 0])
        .await
}

async fn send_udp_reply(conn: &mut TcpStream, addr: SocketAddr) -> io::Result<()> {
    let (atyp, addr_bytes, port) = match addr.ip() {
        IpAddr::V4(ip) => (SOCKS_ATYP_IPV4, ip.octets().to_vec(), addr.port()),
        IpAddr::V6(ip) => (SOCKS_ATYP_IPV6, ip.octets().to_vec(), addr.port()),
    };

    let mut reply = vec![SOCKS_VERSION, SOCKS_REPLY_SUCCEEDED, 0x00, atyp];
    reply.extend_from_slice(&addr_bytes);
    reply.extend_from_slice(&port.to_be_bytes());
    conn.write_all(&reply).await
}
