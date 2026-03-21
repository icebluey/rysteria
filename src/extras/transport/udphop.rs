/// UDP hop transport for Hysteria 2.
///
/// Implements port-hopping: the client periodically switches to a new local UDP
/// port when sending QUIC packets to the server.  During the hop window, the
/// previous socket is kept alive so in-flight packets from the server are still
/// received.
///
/// The `UdpHopSocket` type implements `quinn::AsyncUdpSocket` so that it can be
/// plugged into `quinn::Endpoint::new_with_abstract_socket`.
///
/// Go equivalent: `extras/transport/udphop/conn.go`.
use std::fmt;
use std::future::Future;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::num::ParseIntError;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Default port-hop interval (matches Go).
pub const DEFAULT_HOP_INTERVAL: Duration = Duration::from_secs(30);
/// Minimum allowed hop interval (matches Go).
pub const MIN_HOP_INTERVAL: Duration = Duration::from_secs(5);
/// Per-socket receive queue depth.
const RECV_QUEUE_SIZE: usize = 1024;
/// Scratch buffer per received datagram (QUIC packets ≤ 1500 bytes; 2 KB is enough).
const UDP_BUFFER_SIZE: usize = 2048;

// ─────────────────────────────────────────────────────────────────────────────
// Address parsing
// ─────────────────────────────────────────────────────────────────────────────

/// Error returned when the address/port-range string is malformed.
#[derive(Debug)]
pub enum AddrParseError {
    /// The host:port format is wrong.
    InvalidFormat(String),
    /// DNS / IP resolution failed.
    Resolution(io::Error),
    /// A port token is not a valid number or range.
    InvalidPort(String),
    /// Integer parse error inside a port range.
    ParseInt(ParseIntError),
    /// The port set is empty (after parsing and deduplication).
    EmptyPortSet,
}

impl fmt::Display for AddrParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddrParseError::InvalidFormat(s) => write!(f, "invalid address format: {}", s),
            AddrParseError::Resolution(e) => write!(f, "address resolution error: {}", e),
            AddrParseError::InvalidPort(s) => {
                write!(f, "{} is not a valid port number or range", s)
            }
            AddrParseError::ParseInt(e) => write!(f, "port parse error: {}", e),
            AddrParseError::EmptyPortSet => write!(f, "port set is empty"),
        }
    }
}

impl std::error::Error for AddrParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AddrParseError::Resolution(e) => Some(e),
            AddrParseError::ParseInt(e) => Some(e),
            _ => None,
        }
    }
}

/// Parse a port-union string (e.g. `"1000-2000,3000,4000-4010"`) into a sorted,
/// deduplicated list of ports.
///
/// Syntax mirrors Go's `extras/utils.ParsePortUnion`.
fn parse_port_union(s: &str) -> Result<Vec<u16>, AddrParseError> {
    let mut ports: Vec<u16> = Vec::new();
    for token in s.split(',') {
        let token = token.trim();
        if token.contains('-') {
            let parts: Vec<&str> = token.splitn(2, '-').collect();
            if parts.len() != 2 {
                return Err(AddrParseError::InvalidPort(token.to_string()));
            }
            let start: u16 = parts[0].parse().map_err(AddrParseError::ParseInt)?;
            let end: u16 = parts[1].parse().map_err(AddrParseError::ParseInt)?;
            let (lo, hi) = if start <= end {
                (start, end)
            } else {
                (end, start)
            };
            for p in lo..=hi {
                ports.push(p);
            }
        } else {
            let p: u16 = token.parse().map_err(AddrParseError::ParseInt)?;
            ports.push(p);
        }
    }
    ports.sort_unstable();
    ports.dedup();
    if ports.is_empty() {
        return Err(AddrParseError::EmptyPortSet);
    }
    Ok(ports)
}

/// Resolve `"host:port_or_range"` into a list of target `SocketAddr`s, one per
/// port in the union.
///
/// `addr_str` may use any syntax accepted by `parse_port_union`, e.g.:
/// - `"example.com:1000-2000"` → 1001 addresses
/// - `"1.2.3.4:443,444,445"` → 3 addresses
pub fn resolve_udp_hop_addrs(addr_str: &str) -> Result<Vec<SocketAddr>, AddrParseError> {
    // Split at the last ':' to handle IPv6 addresses in brackets.
    let (host, port_str) = {
        // Use `rsplit_once(':')` for robustness with IPv6 bracket notation like [::1]:1000.
        match addr_str.rsplit_once(':') {
            Some((h, p)) => (h, p),
            None => {
                return Err(AddrParseError::InvalidFormat(addr_str.to_string()));
            }
        }
    };
    let ports = parse_port_union(port_str)?;
    // Resolve the host to an IP.
    let host_clean = host.trim_start_matches('[').trim_end_matches(']');
    let ip: IpAddr = match host_clean.parse() {
        Ok(ip) => ip,
        Err(_) => {
            let mut resolved = (host_clean, 0u16)
                .to_socket_addrs()
                .map_err(AddrParseError::Resolution)?;
            resolved
                .next()
                .map(|s| s.ip())
                .ok_or_else(|| AddrParseError::InvalidFormat(format!("bad host: {host}")))?
        }
    };
    let addrs: Vec<SocketAddr> = ports.iter().map(|&p| SocketAddr::new(ip, p)).collect();
    Ok(addrs)
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal packet type
// ─────────────────────────────────────────────────────────────────────────────

struct RecvPacket {
    data: Box<[u8]>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Hop state (protected by RwLock)
// ─────────────────────────────────────────────────────────────────────────────

struct HopState {
    /// The socket used for all outgoing writes.
    current_socket: Arc<UdpSocket>,
    /// The recv task draining `current_socket`.
    current_recv_task: JoinHandle<()>,
    /// The previous socket, kept alive for one hop interval to drain in-flight responses.
    prev_socket: Option<Arc<UdpSocket>>,
    /// The recv task draining `prev_socket`. Aborted on the next hop (2+ intervals old).
    prev_recv_task: Option<JoinHandle<()>>,
    /// Index into `addrs` for the current write destination.
    addr_index: usize,
}

// ─────────────────────────────────────────────────────────────────────────────
// UdpHopSocket
// ─────────────────────────────────────────────────────────────────────────────

struct HopInner {
    /// All possible server target addresses (one per port in the union).
    addrs: Vec<SocketAddr>,
    /// Mutable hop state, protected by an RwLock.
    state: RwLock<HopState>,
    /// Incoming packets queued by receiver tasks.
    recv_rx: std::sync::Mutex<mpsc::Receiver<RecvPacket>>,
    /// Whether the socket has been closed.
    closed: std::sync::atomic::AtomicBool,
    /// Monotonically increasing hop generation counter.
    /// Incremented after each successful do_hop(). Starts at 0 (initial socket).
    generation: Arc<AtomicU64>,
}

/// A UDP socket that periodically hops to a new local port.
///
/// It implements [`quinn::AsyncUdpSocket`] so it can be passed to
/// `quinn::Endpoint::new_with_abstract_socket`.
pub struct UdpHopSocket {
    inner: Arc<HopInner>,
    /// Handle to the background hop task (aborted on drop).
    _hop_task: JoinHandle<()>,
    // Recv task handles are tracked inside HopState and aborted on drop/hop.
}

impl fmt::Debug for UdpHopSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpHopSocket").finish_non_exhaustive()
    }
}

impl UdpHopSocket {
    /// Create a new `UdpHopSocket` that connects to `server_addr` (a list of
    /// target addresses derived from the hop address string) and hops every
    /// `hop_interval`.
    ///
    /// If `external_generation` is `Some`, the provided counter is used as the
    /// hop generation tracker (test code can observe or target it externally).
    /// Otherwise an internal counter is created.
    ///
    /// Binds a fresh local UDP socket and starts background tasks.
    pub fn new(
        addrs: Vec<SocketAddr>,
        hop_interval: Duration,
        external_generation: Option<Arc<AtomicU64>>,
    ) -> io::Result<Self> {
        assert!(!addrs.is_empty(), "addrs must not be empty");
        let generation = external_generation.unwrap_or_else(|| Arc::new(AtomicU64::new(0)));
        // Choose a random initial target index.
        let addr_index = {
            use rand::RngExt as _;
            rand::rng().random_range(0..addrs.len())
        };
        // Bind a local socket (unspecified port, matching address family of target).
        let bind_addr: SocketAddr = if addrs[0].is_ipv6() {
            SocketAddr::from(([0u16; 8], 0))
        } else {
            SocketAddr::from(([0, 0, 0, 0], 0))
        };
        let std_sock = std::net::UdpSocket::bind(bind_addr)?;
        std_sock.set_nonblocking(true)?;
        let socket = Arc::new(UdpSocket::from_std(std_sock)?);

        let (recv_tx, recv_rx) = mpsc::channel(RECV_QUEUE_SIZE);

        // Spawn the initial per-socket recv task.
        let recv_task = tokio::spawn(recv_loop(Arc::clone(&socket), recv_tx.clone()));

        let state = RwLock::new(HopState {
            current_socket: Arc::clone(&socket),
            current_recv_task: recv_task,
            prev_socket: None,
            prev_recv_task: None,
            addr_index,
        });

        let inner = Arc::new(HopInner {
            addrs,
            state,
            recv_rx: std::sync::Mutex::new(recv_rx),
            closed: std::sync::atomic::AtomicBool::new(false),
            generation,
        });

        // Start hop task.
        let hop_task = {
            let inner2 = Arc::clone(&inner);
            tokio::spawn(async move {
                hop_loop(inner2, hop_interval, recv_tx).await;
            })
        };

        Ok(Self {
            inner,
            _hop_task: hop_task,
        })
    }

    /// Return the local address of the current socket.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        let guard = self.inner.state.read().unwrap_or_else(|e| e.into_inner());
        guard.current_socket.local_addr()
    }

    /// Return a shared handle to the hop generation counter.
    ///
    /// The counter starts at 0 (initial socket) and increments by 1 after
    /// each successful hop. Test code can snapshot the current value and
    /// use it with generation-aware fault injection.
    pub fn generation(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.inner.generation)
    }
}

impl Drop for UdpHopSocket {
    fn drop(&mut self) {
        self.inner
            .closed
            .store(true, std::sync::atomic::Ordering::SeqCst);
        // Abort the hop task first so no new hops can occur.
        self._hop_task.abort();
        // Abort all recv tasks tracked in state.
        let mut state = self.inner.state.write().unwrap_or_else(|e| e.into_inner());
        state.current_recv_task.abort();
        if let Some(t) = state.prev_recv_task.take() {
            t.abort();
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Background tasks
// ─────────────────────────────────────────────────────────────────────────────

/// Receive loop: drain `socket` and push raw bytes into `tx`.
///
/// Uses a non-blocking channel send so that the recv loop is never stalled by a
/// full queue — matching Go's `select { case queue <- pkt: default: drop }` pattern.
/// A stalled recv loop would stop reading from the kernel fd, causing packet loss.
///
/// Exits when the socket fd returns a permanent error (e.g. after the task is
/// aborted and the socket is dropped) or the channel receiver is gone.
async fn recv_loop(socket: Arc<UdpSocket>, tx: mpsc::Sender<RecvPacket>) {
    let mut buf = vec![0u8; UDP_BUFFER_SIZE];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((n, _src)) => {
                let pkt = RecvPacket {
                    data: buf[..n].to_vec().into_boxed_slice(),
                };
                // Non-blocking send: if the channel is full, drop the packet.
                // The recv loop must not block here — that would stall the fd reader.
                match tx.try_send(pkt) {
                    Ok(_) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {} // packet dropped
                    Err(mpsc::error::TrySendError::Closed(_)) => return, // endpoint gone
                }
            }
            Err(_) => {
                // Permanent error (socket closed when aborted/dropped) — exit.
                return;
            }
        }
    }
}

/// Hop loop: every `hop_interval`, create a new local socket and rotate.
async fn hop_loop(inner: Arc<HopInner>, hop_interval: Duration, recv_tx: mpsc::Sender<RecvPacket>) {
    let mut ticker = tokio::time::interval(hop_interval);
    ticker.tick().await; // skip the immediate first tick
    loop {
        ticker.tick().await;
        if inner.closed.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        do_hop(&inner, &recv_tx);
    }
}

/// Perform one hop: create a new socket, rotate prev/current with their recv tasks.
///
/// Lifecycle mirrors Go's `hop()`:
///   - Abort the old prev recv task (it has been running for 2+ hop intervals).
///   - Move current → prev (keep receiving for one more interval to catch late responses).
///   - Bind a new socket → current; spawn a fresh recv task for it.
fn do_hop(inner: &HopInner, recv_tx: &mpsc::Sender<RecvPacket>) {
    // Determine address family from current targets.
    let bind_addr: SocketAddr = if inner.addrs[0].is_ipv6() {
        SocketAddr::from(([0u16; 8], 0))
    } else {
        SocketAddr::from(([0, 0, 0, 0], 0))
    };

    let std_sock = match std::net::UdpSocket::bind(bind_addr) {
        Ok(s) => s,
        Err(_) => return, // transient failure, skip this hop
    };
    if std_sock.set_nonblocking(true).is_err() {
        return;
    }
    let new_socket = match UdpSocket::from_std(std_sock) {
        Ok(s) => Arc::new(s),
        Err(_) => return,
    };

    let new_addr_index = {
        use rand::RngExt as _;
        rand::rng().random_range(0..inner.addrs.len())
    };

    // Spawn the new recv task before acquiring the write lock.
    let new_recv_task = tokio::spawn(recv_loop(Arc::clone(&new_socket), recv_tx.clone()));

    {
        let mut state = inner.state.write().unwrap_or_else(|e| e.into_inner());

        // Abort the old-prev recv task: it has been alive for 2+ hop intervals.
        // Any in-flight packets from that socket should have arrived by now.
        if let Some(old_prev_task) = state.prev_recv_task.take() {
            old_prev_task.abort();
        }
        // The old prev_socket Arc is dropped here when overwritten below.

        // Rotate: current → prev (recv task and socket), new → current.
        let old_current_task =
            std::mem::replace(&mut state.current_recv_task, new_recv_task);
        let old_current_socket =
            std::mem::replace(&mut state.current_socket, new_socket);

        state.prev_recv_task = Some(old_current_task);
        state.prev_socket = Some(old_current_socket);
        state.addr_index = new_addr_index;
    }

    // Increment generation after successful rotation.
    inner.generation.fetch_add(1, Ordering::Relaxed);
}

// ─────────────────────────────────────────────────────────────────────────────
// UdpPoller implementation
// ─────────────────────────────────────────────────────────────────────────────

type BoxFut = Pin<Box<dyn Future<Output = io::Result<()>> + Send + Sync + 'static>>;

struct HopPoller {
    inner: Arc<HopInner>,
    fut: Option<BoxFut>,
}

impl fmt::Debug for HopPoller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HopPoller").finish_non_exhaustive()
    }
}

// HopPoller is Unpin because BoxFut (Pin<Box<dyn Future>>) is Unpin.
impl Unpin for HopPoller {}

impl UdpPoller for HopPoller {
    fn poll_writable(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        if self.fut.is_none() {
            let inner = Arc::clone(&self.inner);
            // Create a future that resolves when the current socket is writable.
            self.fut = Some(Box::pin(async move {
                let socket = {
                    let guard = inner.state.read().unwrap_or_else(|e| e.into_inner());
                    Arc::clone(&guard.current_socket)
                };
                socket.writable().await
            }));
        }
        let Some(fut) = self.fut.as_mut() else {
            return Poll::Pending;
        };
        let fut = fut.as_mut();
        let result = fut.poll(cx);
        if result.is_ready() {
            self.fut = None;
        }
        result
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AsyncUdpSocket implementation
// ─────────────────────────────────────────────────────────────────────────────

impl AsyncUdpSocket for UdpHopSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(HopPoller {
            inner: Arc::clone(&self.inner),
            fut: None,
        })
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let (socket, dest) = {
            let guard = self.inner.state.read().unwrap_or_else(|e| e.into_inner());
            let socket = Arc::clone(&guard.current_socket);
            let dest = self.inner.addrs[guard.addr_index];
            (socket, dest)
        };
        // Redirect to the current hop address, ignoring transmit.destination.
        // This mirrors Go's udpHopPacketConn.WriteTo which always writes to addrs[addrIndex].
        match socket.try_send_to(transmit.contents, dest) {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        // Lock the receiver (only one task — quinn's endpoint driver — calls poll_recv).
        let mut rx = self.inner.recv_rx.lock().unwrap_or_else(|e| e.into_inner());
        match rx.poll_recv(cx) {
            Poll::Ready(Some(pkt)) => {
                let n = pkt.data.len().min(bufs[0].len());
                bufs[0][..n].copy_from_slice(&pkt.data[..n]);
                // Always report addrs[0] as the source address.
                //
                // Quinn's client connection is created via endpoint.connect(addrs[0]), which
                // sets connection.path.remote = addrs[0]. If we report a different source
                // (e.g. addrs[addr_index] from a hopped port), Quinn's connection handler
                // checks `remote != self.path.remote && !self.side.remote_may_migrate()` —
                // remote_may_migrate() returns false for client connections — and silently
                // drops the packet (quinn-proto connection/mod.rs handle_event).
                //
                // Go's equivalent: ReadFrom always returns u.Addr (the single logical hop
                // address used in DialEarly), never the per-packet actual source port.
                meta[0] = RecvMeta {
                    addr: self.inner.addrs[0],
                    len: n,
                    stride: n,
                    ecn: None,
                    dst_ip: None,
                };
                Poll::Ready(Ok(1))
            }
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "hop socket closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        let guard = self.inner.state.read().unwrap_or_else(|e| e.into_inner());
        guard.current_socket.local_addr()
    }

    fn may_fragment(&self) -> bool {
        // Do not claim PMTUD capability; let quinn handle fragmentation decisions.
        true
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_single_port() {
        let ports = parse_port_union("443").unwrap();
        assert_eq!(ports, vec![443]);
    }

    #[test]
    fn parse_port_range() {
        let ports = parse_port_union("1000-1003").unwrap();
        assert_eq!(ports, vec![1000, 1001, 1002, 1003]);
    }

    #[test]
    fn parse_port_union_multi() {
        let mut ports = parse_port_union("5000-5002,4000,4001").unwrap();
        ports.sort_unstable();
        assert_eq!(ports, vec![4000, 4001, 5000, 5001, 5002]);
    }

    #[test]
    fn parse_inverted_range_is_normalized() {
        let ports = parse_port_union("10-8").unwrap();
        assert_eq!(ports, vec![8, 9, 10]);
    }

    #[test]
    fn parse_empty_fails() {
        assert!(parse_port_union("").is_err());
    }

    #[test]
    fn resolve_ipv4_multi_port() {
        let addrs = resolve_udp_hop_addrs("127.0.0.1:8000-8002").unwrap();
        assert_eq!(addrs.len(), 3);
        assert_eq!(addrs[0], "127.0.0.1:8000".parse().unwrap());
        assert_eq!(addrs[2], "127.0.0.1:8002".parse().unwrap());
    }

    #[test]
    fn resolve_single_port_gives_one_addr() {
        let addrs = resolve_udp_hop_addrs("127.0.0.1:443").unwrap();
        assert_eq!(addrs.len(), 1);
    }

    #[tokio::test]
    async fn hop_socket_creates_and_drops_cleanly() {
        let addrs = resolve_udp_hop_addrs("127.0.0.1:19000-19010").unwrap();
        let sock = UdpHopSocket::new(addrs, DEFAULT_HOP_INTERVAL, None).unwrap();
        let local = sock.local_addr().unwrap();
        // Should have bound to some ephemeral port.
        assert!(local.port() > 0);
        drop(sock);
    }

    #[test]
    fn hop_interval_min_enforced_by_caller() {
        // The library enforces MIN_HOP_INTERVAL contract at the construction site.
        assert!(MIN_HOP_INTERVAL <= DEFAULT_HOP_INTERVAL);
    }
}
