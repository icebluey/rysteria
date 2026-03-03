use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use tokio::net::{TcpListener, UdpSocket, lookup_host};

fn wildcard_port(addr: &str) -> Option<u16> {
    let mut chars = addr.chars();
    if chars.next() != Some(':') {
        return None;
    }
    let port = chars.as_str().trim();
    if port.is_empty() {
        return None;
    }
    port.parse::<u16>().ok()
}

async fn resolve_socket_addr(addr: &str) -> io::Result<SocketAddr> {
    if let Ok(parsed) = addr.parse::<SocketAddr>() {
        return Ok(parsed);
    }

    if let Some(port) = wildcard_port(addr) {
        return Ok(SocketAddr::from(([0, 0, 0, 0], port)));
    }

    let mut resolved = lookup_host(addr).await?;
    resolved.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("unable to resolve address: {addr}"),
        )
    })
}

pub async fn correct_tcp_listener(addr: &str) -> io::Result<TcpListener> {
    if let Some(port) = wildcard_port(addr) {
        let bind_addr = SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), port);
        if let Ok(listener) = TcpListener::bind(bind_addr).await {
            return Ok(listener);
        }
        return TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], port))).await;
    }
    let socket_addr = resolve_socket_addr(addr).await?;
    TcpListener::bind(socket_addr).await
}

pub async fn correct_udp_socket(addr: &str) -> io::Result<UdpSocket> {
    if let Some(port) = wildcard_port(addr) {
        let ipv6_addr = SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), port);
        if let Ok(sock) = UdpSocket::bind(ipv6_addr).await {
            return Ok(sock);
        }
    }
    let socket_addr = resolve_socket_addr(addr).await?;
    UdpSocket::bind(socket_addr).await
}

pub fn ip_family(ip: IpAddr) -> u8 {
    match ip {
        IpAddr::V4(_) => 4,
        IpAddr::V6(_) => 6,
    }
}
