pub mod app;
/// Rysteria: A pure-Rust rewrite of Hysteria 2.
///
/// Wire-level protocol compatible with Go Hysteria 2.
/// Binary name: rysteria.
pub mod core;
pub mod extras;

use std::net::{IpAddr, SocketAddr};

/// Convert an IPv4-mapped IPv6 address (::ffff:a.b.c.d) to its plain IPv4 form.
///
/// Dual-stack sockets on Linux/macOS represent IPv4 clients as ::ffff:x.x.x.x.
/// This helper unwraps the mapping so logs and error messages show the canonical
/// IPv4 address instead of the verbose mapped form.  Pure IPv6 addresses pass
/// through unchanged.
pub(crate) fn unmap_ipv4(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(ref v6) => v6
            .ip()
            .to_ipv4_mapped()
            .map(|v4| SocketAddr::new(IpAddr::V4(v4), v6.port()))
            .unwrap_or(addr),
        _ => addr,
    }
}
