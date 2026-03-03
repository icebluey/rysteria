use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream, UdpSocket, lookup_host};
use tokio_rustls::TlsConnector;
use url::Url;

pub trait TcpOutboundStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> TcpOutboundStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub type BoxTcpStream = Box<dyn TcpOutboundStream>;

/// Result of a successful TCP outbound connection.
/// Carries the stream together with the socket addresses so callers can
/// include them in error messages without downcasting the boxed stream.
pub struct TcpConnResult {
    pub stream: BoxTcpStream,
    pub local_addr: Option<SocketAddr>,
    pub peer_addr: Option<SocketAddr>,
}

#[async_trait]
pub trait UdpOutboundConn: Send + Sync {
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, String)>;
    async fn send_to(&self, data: &[u8], addr: &str) -> io::Result<usize>;
    fn close(&self) -> io::Result<()> {
        Ok(())
    }
}

pub type BoxUdpConn = Box<dyn UdpOutboundConn>;

#[async_trait]
pub trait PluggableOutbound: Send + Sync {
    async fn tcp(&self, req_addr: &str) -> io::Result<TcpConnResult>;
    async fn udp(&self, req_addr: &str) -> io::Result<BoxUdpConn>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct HostResolveResult {
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
}

#[async_trait]
pub trait HostResolver: Send + Sync {
    async fn resolve(&self, host: &str) -> io::Result<HostResolveResult>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemResolver;

#[async_trait]
impl HostResolver for SystemResolver {
    async fn resolve(&self, host: &str) -> io::Result<HostResolveResult> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(match ip {
                IpAddr::V4(v4) => HostResolveResult {
                    ipv4: Some(v4),
                    ipv6: None,
                },
                IpAddr::V6(v6) => HostResolveResult {
                    ipv4: None,
                    ipv6: Some(v6),
                },
            });
        }
        let mut result = HostResolveResult::default();
        for addr in lookup_host((host, 0u16)).await? {
            match addr.ip() {
                IpAddr::V4(v4) if result.ipv4.is_none() => result.ipv4 = Some(v4),
                IpAddr::V6(v6) if result.ipv6.is_none() => result.ipv6 = Some(v6),
                _ => {}
            }
            if result.ipv4.is_some() && result.ipv6.is_some() {
                break;
            }
        }
        Ok(result)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub enum DirectOutboundMode {
    #[default]
    Auto,
    PreferIpv6,
    PreferIpv4,
    Ipv6Only,
    Ipv4Only,
}

#[derive(Clone, Debug, Default)]
pub struct DirectOutboundOptions {
    pub mode: DirectOutboundMode,
    pub bind_ipv4: Option<Ipv4Addr>,
    pub bind_ipv6: Option<Ipv6Addr>,
    pub bind_device: Option<String>,
    pub fast_open: bool,
}

#[derive(Clone)]
pub struct DirectOutbound {
    pub options: DirectOutboundOptions,
    resolver: Option<Arc<dyn HostResolver>>,
}

impl Default for DirectOutbound {
    fn default() -> Self {
        Self {
            options: DirectOutboundOptions::default(),
            resolver: None,
        }
    }
}

impl DirectOutbound {
    pub fn new(options: DirectOutboundOptions) -> Self {
        Self {
            options,
            resolver: None,
        }
    }

    pub fn with_resolver(mut self, resolver: Option<Arc<dyn HostResolver>>) -> Self {
        self.resolver = resolver;
        self
    }

    fn select_candidate_addrs(&self, mut addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
        match self.options.mode {
            DirectOutboundMode::Auto => addrs,
            DirectOutboundMode::PreferIpv6 => {
                addrs.sort_by_key(|addr| if addr.is_ipv6() { 0 } else { 1 });
                addrs
            }
            DirectOutboundMode::PreferIpv4 => {
                addrs.sort_by_key(|addr| if addr.is_ipv4() { 0 } else { 1 });
                addrs
            }
            DirectOutboundMode::Ipv6Only => {
                addrs.into_iter().filter(|addr| addr.is_ipv6()).collect()
            }
            DirectOutboundMode::Ipv4Only => {
                addrs.into_iter().filter(|addr| addr.is_ipv4()).collect()
            }
        }
    }

    async fn resolve_target_addrs(&self, req_addr: &str) -> io::Result<Vec<SocketAddr>> {
        if let Ok(addr) = req_addr.parse::<SocketAddr>() {
            return Ok(vec![addr]);
        }

        let (host, port) = split_req_addr(req_addr)?;
        let mut addrs = Vec::new();
        if let Some(resolver) = &self.resolver {
            let resolved = resolver.resolve(&host).await?;
            if let Some(v4) = resolved.ipv4 {
                addrs.push(SocketAddr::new(IpAddr::V4(v4), port));
            }
            if let Some(v6) = resolved.ipv6 {
                addrs.push(SocketAddr::new(IpAddr::V6(v6), port));
            }
        }
        if addrs.is_empty() {
            addrs = lookup_host((host.as_str(), port)).await?.collect();
        }
        if addrs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("failed to resolve target address: {req_addr}"),
            ));
        }
        addrs = self.select_candidate_addrs(addrs);
        if addrs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no target address matches direct outbound mode",
            ));
        }
        Ok(addrs)
    }

    fn configure_tcp_socket(&self, socket: &TcpSocket, target: SocketAddr) -> io::Result<()> {
        if target.is_ipv4() {
            if let Some(ip) = self.options.bind_ipv4 {
                socket.bind(SocketAddr::new(IpAddr::V4(ip), 0))?;
            }
        } else if let Some(ip) = self.options.bind_ipv6 {
            socket.bind(SocketAddr::new(IpAddr::V6(ip), 0))?;
        }

        #[cfg(target_os = "linux")]
        {
            use std::ffi::CString;
            use std::os::fd::AsRawFd;

            let fd = socket.as_raw_fd();
            if let Some(device) = &self.options.bind_device {
                let dev = CString::new(device.as_str()).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "bindDevice contains NUL")
                })?;
                let rc = unsafe {
                    libc::setsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_BINDTODEVICE,
                        dev.as_ptr().cast(),
                        dev.as_bytes_with_nul().len() as libc::socklen_t,
                    )
                };
                if rc != 0 {
                    return Err(io::Error::last_os_error());
                }
            }

            if self.options.fast_open {
                let value: libc::c_int = 1;
                let rc = unsafe {
                    libc::setsockopt(
                        fd,
                        libc::IPPROTO_TCP,
                        libc::TCP_FASTOPEN_CONNECT,
                        (&value as *const libc::c_int).cast(),
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    )
                };
                if rc != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            if self.options.bind_device.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "direct.bindDevice is unsupported on this platform",
                ));
            }
            let _ = socket;
        }

        Ok(())
    }

    fn udp_bind_addr(&self) -> SocketAddr {
        match self.options.mode {
            DirectOutboundMode::Ipv6Only => {
                if let Some(ip) = self.options.bind_ipv6 {
                    SocketAddr::new(IpAddr::V6(ip), 0)
                } else {
                    SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
                }
            }
            _ => {
                if let Some(ip) = self.options.bind_ipv4 {
                    SocketAddr::new(IpAddr::V4(ip), 0)
                } else if let Some(ip) = self.options.bind_ipv6 {
                    SocketAddr::new(IpAddr::V6(ip), 0)
                } else {
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
                }
            }
        }
    }

    fn apply_udp_socket_options(&self, socket: &std::net::UdpSocket) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            use std::ffi::CString;
            use std::os::fd::AsRawFd;

            if let Some(device) = &self.options.bind_device {
                let dev = CString::new(device.as_str()).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "bindDevice contains NUL")
                })?;
                let fd = socket.as_raw_fd();
                let rc = unsafe {
                    libc::setsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_BINDTODEVICE,
                        dev.as_ptr().cast(),
                        dev.as_bytes_with_nul().len() as libc::socklen_t,
                    )
                };
                if rc != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            if self.options.bind_device.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "direct.bindDevice is unsupported on this platform",
                ));
            }
            let _ = socket;
        }

        Ok(())
    }

    async fn connect_addr(&self, addr: SocketAddr) -> io::Result<TcpStream> {
        let socket = if addr.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        self.configure_tcp_socket(&socket, addr)?;
        socket.connect(addr).await
    }

    async fn dial_dual_stack(
        &self,
        ipv4_addr: SocketAddr,
        ipv6_addr: SocketAddr,
    ) -> io::Result<TcpStream> {
        let v4 = self.connect_addr(ipv4_addr);
        let v6 = self.connect_addr(ipv6_addr);
        tokio::pin!(v4);
        tokio::pin!(v6);

        tokio::select! {
            r4 = &mut v4 => {
                match r4 {
                    Ok(stream) => Ok(stream),
                    Err(e4) => {
                        match v6.await {
                            Ok(stream) => Ok(stream),
                            Err(_) => Err(e4),
                        }
                    }
                }
            }
            r6 = &mut v6 => {
                match r6 {
                    Ok(stream) => Ok(stream),
                    Err(e6) => {
                        match v4.await {
                            Ok(stream) => Ok(stream),
                            Err(_) => Err(e6),
                        }
                    }
                }
            }
        }
    }
}

#[async_trait]
impl PluggableOutbound for DirectOutbound {
    async fn tcp(&self, req_addr: &str) -> io::Result<TcpConnResult> {
        let addrs = self.resolve_target_addrs(req_addr).await?;
        let mut last_err = None::<io::Error>;
        let mut tried = HashSet::new();

        if matches!(self.options.mode, DirectOutboundMode::Auto) {
            let first_v4 = addrs.iter().find(|addr| addr.is_ipv4()).copied();
            let first_v6 = addrs.iter().find(|addr| addr.is_ipv6()).copied();
            if let (Some(v4), Some(v6)) = (first_v4, first_v6) {
                tried.insert(v4);
                tried.insert(v6);
                match self.dial_dual_stack(v4, v6).await {
                    Ok(stream) => {
                        let local_addr = stream.local_addr().ok();
                        let peer_addr = stream.peer_addr().ok();
                        return Ok(TcpConnResult { stream: Box::new(stream), local_addr, peer_addr });
                    }
                    Err(err) => last_err = Some(err),
                }
            }
        }

        for addr in addrs {
            if tried.contains(&addr) {
                continue;
            }
            match self.connect_addr(addr).await {
                Ok(stream) => {
                    let local_addr = stream.local_addr().ok();
                    let peer_addr = stream.peer_addr().ok();
                    return Ok(TcpConnResult { stream: Box::new(stream), local_addr, peer_addr });
                }
                Err(err) => last_err = Some(err),
            }
        }

        Err(last_err.unwrap_or_else(|| io::Error::other("failed to connect target")))
    }

    async fn udp(&self, _req_addr: &str) -> io::Result<BoxUdpConn> {
        let bind_addr = self.udp_bind_addr();
        let std_socket = std::net::UdpSocket::bind(bind_addr)?;
        self.apply_udp_socket_options(&std_socket)?;
        std_socket.set_nonblocking(true)?;
        let socket = UdpSocket::from_std(std_socket)?;
        Ok(Box::new(DirectUdpConn { socket }))
    }
}

struct DirectUdpConn {
    socket: UdpSocket,
}

#[async_trait]
impl UdpOutboundConn for DirectUdpConn {
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, String)> {
        let (n, addr) = self.socket.recv_from(buf).await?;
        Ok((n, addr.to_string()))
    }

    async fn send_to(&self, data: &[u8], addr: &str) -> io::Result<usize> {
        self.socket.send_to(data, addr).await
    }
}

#[derive(Clone)]
pub struct SharedOutbound(pub Arc<dyn PluggableOutbound>);

impl SharedOutbound {
    pub fn new(inner: Arc<dyn PluggableOutbound>) -> Self {
        Self(inner)
    }
}

#[derive(Clone, Debug)]
pub struct Socks5Outbound {
    pub addr: String,
    pub username: String,
    pub password: String,
}

#[async_trait]
impl PluggableOutbound for Socks5Outbound {
    async fn tcp(&self, req_addr: &str) -> io::Result<TcpConnResult> {
        let mut conn = self.dial_and_negotiate().await?;
        let _ = self.send_command(&mut conn, 0x01, req_addr).await?;
        let local_addr = conn.local_addr().ok();
        let peer_addr = conn.peer_addr().ok();
        Ok(TcpConnResult { stream: Box::new(conn), local_addr, peer_addr })
    }

    async fn udp(&self, req_addr: &str) -> io::Result<BoxUdpConn> {
        let mut tcp_conn = self.dial_and_negotiate().await?;
        let relay_addr = self.send_command(&mut tcp_conn, 0x03, req_addr).await?;
        let relay_socket_addr = lookup_host(relay_addr.as_str())
            .await?
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "SOCKS5 UDP relay not found"))?;
        let bind_addr = if relay_socket_addr.is_ipv6() {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        };
        let udp = UdpSocket::bind(bind_addr).await?;
        udp.connect(relay_socket_addr).await?;

        let closed = Arc::new(AtomicBool::new(false));
        let hold_closed = Arc::clone(&closed);
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            loop {
                match tcp_conn.read(&mut buf).await {
                    Ok(0) | Err(_) => {
                        hold_closed.store(true, Ordering::SeqCst);
                        return;
                    }
                    Ok(_) => {}
                }
            }
        });

        Ok(Box::new(Socks5UdpConn { udp, closed }))
    }
}

impl Socks5Outbound {
    async fn dial_and_negotiate(&self) -> io::Result<TcpStream> {
        let mut conn = TcpStream::connect(self.addr.trim()).await?;

        let use_auth = !self.username.is_empty() || !self.password.is_empty();
        let mut methods = vec![0x00];
        if use_auth {
            methods.push(0x02);
        }
        let mut greet = vec![0x05, methods.len() as u8];
        greet.extend_from_slice(&methods);
        conn.write_all(&greet).await?;

        let mut method_resp = [0u8; 2];
        conn.read_exact(&mut method_resp).await?;
        if method_resp[0] != 0x05 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid SOCKS5 version",
            ));
        }
        if method_resp[1] == 0xFF {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SOCKS5 proxy refused authentication method",
            ));
        }
        match method_resp[1] {
            0x00 => {}
            0x02 => {
                if !use_auth {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "SOCKS5 proxy requires username/password auth",
                    ));
                }
                if self.username.len() > u8::MAX as usize || self.password.len() > u8::MAX as usize
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "SOCKS5 username/password too long",
                    ));
                }
                let mut auth_buf =
                    Vec::with_capacity(3 + self.username.len() + self.password.len());
                auth_buf.push(0x01);
                auth_buf.push(self.username.len() as u8);
                auth_buf.extend_from_slice(self.username.as_bytes());
                auth_buf.push(self.password.len() as u8);
                auth_buf.extend_from_slice(self.password.as_bytes());
                conn.write_all(&auth_buf).await?;
                let mut auth_resp = [0u8; 2];
                conn.read_exact(&mut auth_resp).await?;
                if auth_resp[0] != 0x01 || auth_resp[1] != 0x00 {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "SOCKS5 username/password auth failed",
                    ));
                }
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("SOCKS5 proxy selected unsupported method 0x{other:02x}"),
                ));
            }
        }
        Ok(conn)
    }

    async fn send_command(
        &self,
        conn: &mut TcpStream,
        command: u8,
        req_addr: &str,
    ) -> io::Result<String> {
        let (host, port) = split_req_addr(req_addr)?;
        let mut req = Vec::with_capacity(300);
        req.extend_from_slice(&[0x05, command, 0x00]);
        if let Ok(ip) = host.parse::<IpAddr>() {
            match ip {
                IpAddr::V4(v4) => {
                    req.push(0x01);
                    req.extend_from_slice(&v4.octets());
                }
                IpAddr::V6(v6) => {
                    req.push(0x04);
                    req.extend_from_slice(&v6.octets());
                }
            }
        } else {
            if host.len() > u8::MAX as usize {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "domain is too long for SOCKS5",
                ));
            }
            req.push(0x03);
            req.push(host.len() as u8);
            req.extend_from_slice(host.as_bytes());
        }
        req.extend_from_slice(&port.to_be_bytes());
        conn.write_all(&req).await?;

        let mut head = [0u8; 4];
        conn.read_exact(&mut head).await?;
        if head[0] != 0x05 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid SOCKS5 response version",
            ));
        }
        if head[1] != 0x00 {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("SOCKS5 request failed with code 0x{:02x}", head[1]),
            ));
        }
        let host = match head[3] {
            0x01 => {
                let mut ip = [0u8; 4];
                conn.read_exact(&mut ip).await?;
                IpAddr::V4(Ipv4Addr::from(ip)).to_string()
            }
            0x04 => {
                let mut ip = [0u8; 16];
                conn.read_exact(&mut ip).await?;
                IpAddr::V6(Ipv6Addr::from(ip)).to_string()
            }
            0x03 => {
                let mut len = [0u8; 1];
                conn.read_exact(&mut len).await?;
                let mut name = vec![0u8; len[0] as usize];
                conn.read_exact(&mut name).await?;
                String::from_utf8(name).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid SOCKS5 domain reply")
                })?
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid SOCKS5 address type",
                ));
            }
        };
        let mut port = [0u8; 2];
        conn.read_exact(&mut port).await?;
        let port = u16::from_be_bytes(port);
        if host.contains(':') && !host.starts_with('[') {
            Ok(format!("[{host}]:{port}"))
        } else {
            Ok(format!("{host}:{port}"))
        }
    }
}

struct Socks5UdpConn {
    udp: UdpSocket,
    closed: Arc<AtomicBool>,
}

#[async_trait]
impl UdpOutboundConn for Socks5UdpConn {
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, String)> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "SOCKS5 UDP association closed",
            ));
        }

        let mut packet = vec![0u8; buf.len() + 512];
        let n = self.udp.recv(&mut packet).await?;
        let (from, payload) = parse_socks5_udp_packet(&packet[..n])?;
        if payload.len() > buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SOCKS5 UDP payload too large",
            ));
        }
        buf[..payload.len()].copy_from_slice(payload);
        Ok((payload.len(), from))
    }

    async fn send_to(&self, data: &[u8], addr: &str) -> io::Result<usize> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "SOCKS5 UDP association closed",
            ));
        }
        let packet = build_socks5_udp_packet(addr, data)?;
        let _ = self.udp.send(&packet).await?;
        Ok(data.len())
    }

    fn close(&self) -> io::Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct HttpOutbound {
    pub proxy_url: Url,
    pub auth_header: Option<String>,
    pub insecure: bool,
}

#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer,
        _intermediates: &[rustls::pki_types::CertificateDer],
        _server_name: &rustls::pki_types::ServerName,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

fn build_https_proxy_tls_config(insecure: bool) -> rustls::ClientConfig {
    let mut cfg = if insecure {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    cfg
}

async fn establish_connect_tunnel<S>(
    mut stream: S,
    req_addr: &str,
    auth_header: Option<&str>,
) -> io::Result<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut req = String::new();
    req.push_str(&format!("CONNECT {req_addr} HTTP/1.1\r\n"));
    req.push_str(&format!("Host: {req_addr}\r\n"));
    req.push_str("Proxy-Connection: Keep-Alive\r\n");
    if let Some(auth) = auth_header {
        req.push_str(&format!("Proxy-Authorization: {auth}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await?;

    let mut head = Vec::with_capacity(512);
    loop {
        let mut b = [0u8; 1];
        stream.read_exact(&mut b).await?;
        head.push(b[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
        if head.len() >= 16 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP proxy response header too large",
            ));
        }
    }

    let head_text = std::str::from_utf8(&head).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP proxy response is not UTF-8",
        )
    })?;
    let status = head_text.lines().next().unwrap_or_default();
    if !status.contains(" 200 ") {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("HTTP proxy CONNECT failed: {status}"),
        ));
    }
    Ok(stream)
}

#[async_trait]
impl PluggableOutbound for HttpOutbound {
    async fn tcp(&self, req_addr: &str) -> io::Result<TcpConnResult> {
        let host = self.proxy_url.host_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "HTTP proxy URL has no host")
        })?;
        let port = self
            .proxy_url
            .port_or_known_default()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid HTTP proxy URL"))?;

        let proxy_addr = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };

        let scheme = self.proxy_url.scheme();
        match scheme {
            "http" => {
                let stream = TcpStream::connect(proxy_addr).await?;
                let local_addr = stream.local_addr().ok();
                let peer_addr = stream.peer_addr().ok();
                let stream =
                    establish_connect_tunnel(stream, req_addr, self.auth_header.as_deref()).await?;
                Ok(TcpConnResult { stream: Box::new(stream), local_addr, peer_addr })
            }
            "https" => {
                let stream = TcpStream::connect(proxy_addr).await?;
                let local_addr = stream.local_addr().ok();
                let peer_addr = stream.peer_addr().ok();
                let tls_cfg = build_https_proxy_tls_config(self.insecure);
                let connector = TlsConnector::from(Arc::new(tls_cfg));
                let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidInput, "invalid HTTPS proxy host")
                    })?;
                let tls_stream = connector.connect(server_name, stream).await?;
                let tls_stream =
                    establish_connect_tunnel(tls_stream, req_addr, self.auth_header.as_deref())
                        .await?;
                Ok(TcpConnResult { stream: Box::new(tls_stream), local_addr, peer_addr })
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported HTTP proxy scheme: {scheme}"),
            )),
        }
    }

    async fn udp(&self, _req_addr: &str) -> io::Result<BoxUdpConn> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "UDP over HTTP outbound is not supported",
        ))
    }
}

pub fn http_proxy_auth_header(username: &str, password: &str) -> Option<String> {
    if username.is_empty() && password.is_empty() {
        return None;
    }
    let raw = format!("{username}:{password}");
    Some(format!("Basic {}", BASE64_STD.encode(raw)))
}

fn parse_socks5_udp_packet(packet: &[u8]) -> io::Result<(String, &[u8])> {
    if packet.len() < 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SOCKS5 UDP packet too short",
        ));
    }
    if packet[0] != 0 || packet[1] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid SOCKS5 UDP RSV",
        ));
    }
    if packet[2] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fragmented SOCKS5 UDP packet is unsupported",
        ));
    }

    let mut idx = 3usize;
    let host = match packet[idx] {
        0x01 => {
            idx += 1;
            if packet.len() < idx + 4 + 2 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid SOCKS5 UDP IPv4 packet",
                ));
            }
            let ip = IpAddr::V4(Ipv4Addr::new(
                packet[idx],
                packet[idx + 1],
                packet[idx + 2],
                packet[idx + 3],
            ));
            idx += 4;
            ip.to_string()
        }
        0x04 => {
            idx += 1;
            if packet.len() < idx + 16 + 2 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid SOCKS5 UDP IPv6 packet",
                ));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&packet[idx..idx + 16]);
            idx += 16;
            IpAddr::V6(Ipv6Addr::from(octets)).to_string()
        }
        0x03 => {
            idx += 1;
            if packet.len() < idx + 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid SOCKS5 UDP domain packet",
                ));
            }
            let len = packet[idx] as usize;
            idx += 1;
            if packet.len() < idx + len + 2 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid SOCKS5 UDP domain length",
                ));
            }
            let host = std::str::from_utf8(&packet[idx..idx + len]).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid SOCKS5 UDP domain")
            })?;
            idx += len;
            host.to_string()
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported SOCKS5 UDP address type",
            ));
        }
    };

    if packet.len() < idx + 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing SOCKS5 UDP port",
        ));
    }
    let port = u16::from_be_bytes([packet[idx], packet[idx + 1]]);
    idx += 2;
    let payload = &packet[idx..];

    let from = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    Ok((from, payload))
}

fn build_socks5_udp_packet(addr: &str, payload: &[u8]) -> io::Result<Vec<u8>> {
    let (host, port) = split_req_addr(addr)?;
    let mut packet = Vec::with_capacity(payload.len() + 300);
    packet.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV(2) + FRAG(1)

    if let Ok(ip) = host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => {
                packet.push(0x01);
                packet.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                packet.push(0x04);
                packet.extend_from_slice(&v6.octets());
            }
        }
    } else {
        if host.len() > u8::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "domain is too long for SOCKS5 UDP",
            ));
        }
        packet.push(0x03);
        packet.push(host.len() as u8);
        packet.extend_from_slice(host.as_bytes());
    }
    packet.extend_from_slice(&port.to_be_bytes());
    packet.extend_from_slice(payload);
    Ok(packet)
}

fn split_req_addr(req_addr: &str) -> io::Result<(String, u16)> {
    if let Ok(sa) = req_addr.parse::<SocketAddr>() {
        return Ok((sa.ip().to_string(), sa.port()));
    }
    if let Some((host, port)) = req_addr.rsplit_once(':')
        && let Ok(port) = port.parse::<u16>()
    {
        return Ok((host.trim_matches('[').trim_matches(']').to_string(), port));
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("invalid request address: {req_addr}"),
    ))
}
