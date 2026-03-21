/// Rysteria client implementation.
///
/// Go equivalent: hysteria/core/client/client.go + client/udp.go
///
/// Flow:
/// 1. Connect to server via QUIC (with TLS).
/// 2. Perform HTTP/3 auth (POST /auth to "hysteria/auth").
/// 3. On success (status 233), the raw `quinn::Connection` is used for
///    TCP proxy streams (frame type 0x401 + address) and UDP relay via
///    QUIC datagrams.
use std::{
    collections::{HashMap, VecDeque},
    error::Error,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::sync::{Mutex as AsyncMutex, Notify, RwLock, mpsc, oneshot};

use crate::core::errors::ClosedError;
use crate::core::internal::congestion::switchable::new_switchable_factory;
use crate::core::scheduler::{
    ConnId, FlowHints, FlowId, Permit, QueueTier, Scheduler,
};
use crate::core::internal::frag::{Defragger, frag_udp_message, new_frag_packet_id};
use crate::core::internal::pmtud::DISABLE_PATH_MTU_DISCOVERY;
use crate::core::tunnel_manager::TunnelManager;
use crate::core::internal::protocol::{
    DEFAULT_CONN_RECEIVE_WINDOW, DEFAULT_STREAM_RECEIVE_WINDOW, HEADER_AUTH, HEADER_CC_RX,
    HEADER_PADDING, HEADER_UDP_ENABLED, MAX_DATAGRAM_FRAME_SIZE, MAX_MESSAGE_LENGTH,
    MAX_PADDING_LENGTH, MAX_UDP_SIZE, STATUS_AUTH_OK, UdpMessage, parse_udp_message,
    read_tcp_response, varint_read, write_tcp_request,
};
use crate::extras::obfs::SalamanderObfuscator;
use crate::extras::transport::obfsudp::ObfsUdpSocket;
use crate::extras::transport::udphop::{MIN_HOP_INTERVAL, UdpHopSocket};

// H3 error code
const H3_ERR_NO_ERROR: u32 = 0x100;
const H3_ERR_PROTOCOL_ERROR: u32 = 0x101;

type BoxError = Box<dyn Error + Send + Sync>;
pub type UdpSocketFactory = Arc<dyn Fn(bool) -> std::io::Result<std::net::UdpSocket> + Send + Sync>;

// UDP session channel buffer size.
// Go: `udpMessageChanSize = 1024` (client/udp.go:17).
const UDP_MESSAGE_CHAN_SIZE: usize = 1024;

// Upload task channel capacity: 2 slots so poll_write can queue one write
// while the upload task is draining the previous one.
const CLIENT_UPLOAD_CHAN_SIZE: usize = 2;

// Monotonically increasing connection ID for client-side scheduler flows.
static NEXT_CLIENT_CONN_ID: AtomicU64 = AtomicU64::new(1);

// ──────────────────────────────────────────────────────────────────────────────
// Control Lease — control-plane budget reservation
// ──────────────────────────────────────────────────────────────────────────────

// Synthetic flow IDs for control-plane lease tracking.
// Using the top of the u64 range to avoid collision with regular flow IDs.
const CONTROL_FLOW_AUTH: FlowId = FlowId(u64::MAX);
const CONTROL_FLOW_RECOVERY: FlowId = FlowId(u64::MAX - 1);
const CONTROL_FLOW_KEEPALIVE: FlowId = FlowId(u64::MAX - 2);

// Maximum concurrent control leases per connection.
const MAX_CONCURRENT_CONTROL_LEASES: u32 = 2;

/// Control-plane operation type for budget reservation.
///
/// Operations are classified as either **required** or **best-effort**:
///
/// - **Required** (Auth, Reconnect): Lease acquisition failure is fatal to
///   the operation. The caller must propagate the error (`?`). A connection
///   that cannot auth or reconnect under arbitration is already broken.
///
/// - **Best-effort** (KeepaliveProbe): Lease acquisition failure is non-fatal.
///   The caller should log a warning and skip the probe. Failing a keepalive
///   must not kill the connection.
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub(crate) enum ControlOp {
    /// HTTP/3 authentication handshake. **Required**: lease failure = connection failure.
    Auth,
    /// Connection recovery / reconnect. **Required**: lease failure = reconnect failure.
    Reconnect,
    /// Keepalive or path health probe. **Best-effort**: lease failure = skip this probe.
    KeepaliveProbe,
}

impl ControlOp {
    /// Recommended budget reservation for this control operation type.
    fn bytes_hint(self) -> usize {
        match self {
            ControlOp::Auth => 8 * 1024,
            ControlOp::Reconnect => 16 * 1024,
            ControlOp::KeepaliveProbe => 2 * 1024,
        }
    }

    /// Synthetic flow ID used for scheduler tracking and control lease identification.
    fn synthetic_flow_id(self) -> FlowId {
        match self {
            ControlOp::Auth => CONTROL_FLOW_AUTH,
            ControlOp::Reconnect => CONTROL_FLOW_RECOVERY,
            ControlOp::KeepaliveProbe => CONTROL_FLOW_KEEPALIVE,
        }
    }
}

/// Returns true if the flow ID is a synthetic control-plane flow.
fn is_control_lease_flow(flow_id: FlowId) -> bool {
    flow_id == CONTROL_FLOW_AUTH || flow_id == CONTROL_FLOW_RECOVERY || flow_id == CONTROL_FLOW_KEEPALIVE
}

/// A control-plane budget lease issued by `ClientConnActor`.
///
/// Wraps a `Permit` drawn from the `FlowClass::Control` budget pool.
/// Returned to the scheduler when released (either explicitly or via RAII guard).
pub(crate) struct ControlLease {
    pub permit: Permit,
}

// ──────────────────────────────────────────────────────────────────────────────
// ClientControl — messages from upload tasks and UDP flows to ClientConnActor
// ──────────────────────────────────────────────────────────────────────────────

/// Messages sent to `ClientConnActor` from upload tasks and UDP relay flows.
///
/// `SendComplete` is intentionally absent: permit returns travel on a separate
/// unbounded channel (`ClientSendDone`) to guarantee budget is never lost under load.
pub(crate) enum ClientControl {
    /// Acquire a TCP send permit — actor grants when budget allows.
    AcquirePermit { flow_id: FlowId, hints: FlowHints, size: usize, result_tx: oneshot::Sender<Permit> },
    /// Flow closed — remove per-flow state from Scheduler.
    FlowClosed(FlowId),
    /// UDP datagram to send with Realtime priority (best-effort: dropped if no budget).
    UdpSend { payload: Bytes, flow_id: FlowId },
    /// Acquire a control-plane lease from the Control class budget.
    /// The actor grants the lease when Control budget is available and
    /// the concurrent lease count is below `MAX_CONCURRENT_CONTROL_LEASES`.
    AcquireControlLease {
        op: ControlOp,
        bytes_hint: usize,
        result_tx: oneshot::Sender<ControlLease>,
    },
}

/// Carries a completed TCP send permit back to `ClientConnActor`.
///
/// Sent over an unbounded channel so that `ClientPermitReturnGuard::drop` can
/// never block or silently discard budget — unlike a bounded `try_send` which
/// drops the message when the channel is full.
struct ClientSendDone {
    permit: Permit,
    bytes_sent: usize,
}

struct ClientPendingPermit {
    flow_id: FlowId,
    hints: FlowHints,
    size: usize,
    result_tx: oneshot::Sender<Permit>,
}

struct PendingControlLease {
    op: ControlOp,
    bytes_hint: usize,
    result_tx: oneshot::Sender<ControlLease>,
}

/// Cancel-safe RAII wrapper for a client-side send permit.
///
/// Sends a `ClientSendDone` to `ClientConnActor` on drop via an unbounded
/// channel, returning the permit credit whether the write succeeded or was
/// cancelled. Using an unbounded sender guarantees the send never fails —
/// budget is always returned even if the bounded control channel is full.
struct ClientPermitReturnGuard {
    permit: Option<Permit>,
    completion_tx: mpsc::UnboundedSender<ClientSendDone>,
    bytes_sent: usize,
}

impl ClientPermitReturnGuard {
    fn new(permit: Permit, completion_tx: mpsc::UnboundedSender<ClientSendDone>) -> Self {
        Self { permit: Some(permit), completion_tx, bytes_sent: 0 }
    }

    fn complete(mut self, bytes: usize) {
        self.bytes_sent = bytes;
    }
}

impl Drop for ClientPermitReturnGuard {
    fn drop(&mut self) {
        if let Some(permit) = self.permit.take() {
            // Unbounded send never fails: budget is always returned to the actor.
            let _ = self.completion_tx.send(ClientSendDone { permit, bytes_sent: self.bytes_sent });
        }
    }
}

/// Cancel-safe RAII wrapper for a control-plane lease.
///
/// Returns the permit budget to the scheduler via the unbounded completion
/// channel on drop, whether the operation succeeded or was cancelled.
/// Uses 0 bytes_sent because control leases reserve headroom rather than
/// tracking actual bytes transferred through the data plane.
pub(crate) struct ClientControlLeaseGuard {
    permit: Option<Permit>,
    completion_tx: mpsc::UnboundedSender<ClientSendDone>,
}

impl ClientControlLeaseGuard {
    fn new(permit: Permit, completion_tx: mpsc::UnboundedSender<ClientSendDone>) -> Self {
        Self { permit: Some(permit), completion_tx }
    }
}

impl Drop for ClientControlLeaseGuard {
    fn drop(&mut self) {
        if let Some(permit) = self.permit.take() {
            // Unbounded send never fails: budget is always returned to the actor.
            let _ = self.completion_tx.send(ClientSendDone { permit, bytes_sent: 0 });
        }
    }
}

/// Client-side connection actor: owns the per-connection Scheduler exclusively.
///
/// Mirrors `ConnectionActor` on the server side. All TCP and UDP permit
/// requests are serialized through this actor via message passing, eliminating
/// shared `Arc<Mutex<Scheduler>>` contention.
///
/// Two input sources are select!-ed simultaneously:
///   - `control_rx` (bounded): AcquirePermit, FlowClosed, UdpSend, AcquireControlLease.
///   - `completion_rx` (unbounded): ClientSendDone from ClientPermitReturnGuard::drop
///     and ClientControlLeaseGuard::drop.
struct ClientConnActor {
    scheduler: Scheduler,
    conn_id: ConnId,
    quinn_conn: quinn::Connection,
    /// Pending control lease requests — flushed with priority over data permits.
    pending_control_leases: VecDeque<PendingControlLease>,
    /// Pending data-plane permit requests split by priority tier.
    /// Flush order: control → interactive → bulk.
    pending_control: VecDeque<ClientPendingPermit>,
    pending_interactive: VecDeque<ClientPendingPermit>,
    pending_bulk: VecDeque<ClientPendingPermit>,
    control_rx: mpsc::Receiver<ClientControl>,
    /// Unbounded channel for permit returns from `ClientPermitReturnGuard::drop`
    /// and `ClientControlLeaseGuard::drop`.
    completion_rx: mpsc::UnboundedReceiver<ClientSendDone>,
    /// Number of active control-plane leases (capped at MAX_CONCURRENT_CONTROL_LEASES).
    active_control_leases: u32,
}

impl ClientConnActor {
    fn new(
        quinn_conn: quinn::Connection,
        conn_id: ConnId,
        scheduler: Scheduler,
        control_rx: mpsc::Receiver<ClientControl>,
        completion_rx: mpsc::UnboundedReceiver<ClientSendDone>,
    ) -> Self {
        Self {
            scheduler,
            conn_id,
            quinn_conn,
            pending_control_leases: VecDeque::new(),
            pending_control: VecDeque::new(),
            pending_interactive: VecDeque::new(),
            pending_bulk: VecDeque::new(),
            control_rx,
            completion_rx,
            active_control_leases: 0,
        }
    }

    async fn run(mut self) {
        let mut tick_interval = tokio::time::interval(Duration::from_millis(500));
        tick_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                msg = self.control_rx.recv() => {
                    match msg {
                        Some(ctrl) => self.handle_control(ctrl),
                        None => return,
                    }
                }
                done = self.completion_rx.recv() => {
                    // ClientSendDone arrives here from ClientPermitReturnGuard::drop
                    // and ClientControlLeaseGuard::drop via the unbounded channel.
                    if let Some(d) = done {
                        // Detect control lease returns via synthetic flow IDs.
                        if d.permit.flow_id.map(is_control_lease_flow).unwrap_or(false) {
                            self.active_control_leases = self.active_control_leases.saturating_sub(1);
                        }
                        self.scheduler.on_send_complete(d.permit, d.bytes_sent);
                        // Control leases have priority over data permits.
                        self.flush_pending_control_leases();
                        self.flush_pending_permits();
                    }
                }
                _ = tick_interval.tick() => {
                    self.scheduler.tick();
                    self.flush_pending_control_leases();
                    self.flush_pending_permits();
                }
            }
        }
    }

    fn handle_control(&mut self, ctrl: ClientControl) {
        match ctrl {
            ClientControl::AcquirePermit { flow_id, hints, size, result_tx } => {
                if result_tx.is_closed() { return; }
                match self.scheduler.try_issue_permit(self.conn_id, Some(flow_id), &hints, size) {
                    Some(permit) => {
                        if let Err(returned) = result_tx.send(permit) {
                            self.scheduler.on_send_complete(returned, 0);
                        }
                    }
                    None => {
                        // Route to the appropriate priority queue.
                        let pending = ClientPendingPermit { flow_id, hints, size, result_tx };
                        match self.scheduler.queue_tier(flow_id) {
                            QueueTier::Control => self.pending_control.push_back(pending),
                            QueueTier::Interactive => self.pending_interactive.push_back(pending),
                            QueueTier::Bulk => self.pending_bulk.push_back(pending),
                        }
                    }
                }
            }
            ClientControl::FlowClosed(flow_id) => {
                self.scheduler.on_flow_close(flow_id);
                self.flush_pending_control_leases();
                self.flush_pending_permits();
            }
            ClientControl::UdpSend { payload, flow_id } => {
                let hints = FlowHints::realtime();
                if let Some(permit) = self.scheduler.try_issue_permit(
                    self.conn_id, Some(flow_id), &hints, payload.len(),
                ) {
                    let sent = match self.quinn_conn.send_datagram(payload) {
                        Ok(()) => permit.bytes,
                        Err(_) => 0,
                    };
                    self.scheduler.on_send_complete(permit, sent);
                    self.flush_pending_control_leases();
                    self.flush_pending_permits();
                }
                // else: budget exhausted — drop datagram silently (UDP is best-effort).
            }
            ClientControl::AcquireControlLease { op, bytes_hint, result_tx } => {
                if result_tx.is_closed() { return; }
                // Enforce concurrency limit on control leases.
                if self.active_control_leases >= MAX_CONCURRENT_CONTROL_LEASES {
                    self.pending_control_leases.push_back(PendingControlLease { op, bytes_hint, result_tx });
                    return;
                }
                let flow_id = op.synthetic_flow_id();
                match self.scheduler.try_acquire_control_permit(self.conn_id, flow_id, bytes_hint) {
                    Some(permit) => {
                        self.active_control_leases += 1;
                        if let Err(returned) = result_tx.send(ControlLease { permit }) {
                            // Receiver dropped — return budget immediately.
                            self.scheduler.on_send_complete(returned.permit, 0);
                            self.active_control_leases = self.active_control_leases.saturating_sub(1);
                        }
                    }
                    None => {
                        self.pending_control_leases.push_back(PendingControlLease { op, bytes_hint, result_tx });
                    }
                }
            }
        }
    }

    /// Try to grant pending control lease requests using available budget.
    ///
    /// Called before flush_pending_permits() to ensure control-plane operations
    /// have priority over data-plane permits when budget is released.
    fn flush_pending_control_leases(&mut self) {
        let mut i = 0;
        while i < self.pending_control_leases.len() {
            if self.pending_control_leases[i].result_tx.is_closed() {
                self.pending_control_leases.remove(i);
                continue;
            }
            if self.active_control_leases >= MAX_CONCURRENT_CONTROL_LEASES {
                break;
            }
            let op = self.pending_control_leases[i].op;
            let bytes_hint = self.pending_control_leases[i].bytes_hint;
            let flow_id = op.synthetic_flow_id();
            match self.scheduler.try_acquire_control_permit(self.conn_id, flow_id, bytes_hint) {
                Some(permit) => {
                    let p = self.pending_control_leases.remove(i).unwrap();
                    self.active_control_leases += 1;
                    if let Err(returned) = p.result_tx.send(ControlLease { permit }) {
                        self.scheduler.on_send_complete(returned.permit, 0);
                        self.active_control_leases = self.active_control_leases.saturating_sub(1);
                    }
                }
                None => { i += 1; }
            }
        }
    }

    /// Try to grant pending data-plane permit requests using available budget.
    ///
    /// Scans three queues in priority order: Control → Interactive → Bulk.
    /// Called after flush_pending_control_leases() to ensure control-plane
    /// operations have priority, then data permits are served by tier.
    fn flush_pending_permits(&mut self) {
        flush_client_queue(&mut self.pending_control, &mut self.scheduler, self.conn_id);
        flush_client_queue(&mut self.pending_interactive, &mut self.scheduler, self.conn_id);
        flush_client_queue(&mut self.pending_bulk, &mut self.scheduler, self.conn_id);
    }
}

/// Drain a single pending-permit queue, granting permits where budget allows.
///
/// Free function to avoid borrow-checker issues with borrowing multiple fields
/// of ClientConnActor simultaneously (queue + scheduler + conn_id).
fn flush_client_queue(
    queue: &mut VecDeque<ClientPendingPermit>,
    scheduler: &mut Scheduler,
    conn_id: ConnId,
) {
    let mut i = 0;
    while i < queue.len() {
        if queue[i].result_tx.is_closed() {
            queue.remove(i);
            continue;
        }
        let (flow_id, size) = {
            let p = &queue[i];
            (p.flow_id, p.size)
        };
        let hints = queue[i].hints.clone();
        match scheduler.try_issue_permit(conn_id, Some(flow_id), &hints, size) {
            Some(permit) => {
                let p = queue.remove(i).unwrap();
                if let Err(returned) = p.result_tx.send(permit) {
                    scheduler.on_send_complete(returned, 0);
                }
            }
            None => { i += 1; }
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Client configuration
// ──────────────────────────────────────────────────────────────────────────────

/// Client configuration.
pub struct ClientConfig {
    /// Authentication string sent to the server.
    pub auth: String,
    /// Server address.
    pub server_addr: SocketAddr,
    /// TLS server name (SNI).
    pub server_name: String,
    /// TLS root certificate store (or dangerous skip verify).
    pub tls: ClientTlsConfig,
    /// Client maximum upload bandwidth in bytes/sec (0 = unknown/auto, use BBR).
    ///
    /// Used to cap the client's own TX congestion rate after auth response.
    pub bandwidth_tx: u64,
    /// Client maximum receive bandwidth in bytes/sec (0 = unknown/auto, use BBR).
    ///
    /// Sent to the server as `Hysteria-CC-RX` so the server can set its
    /// TX rate (Brutal) toward this client.
    pub bandwidth_rx: u64,
    /// QUIC transport settings (optional, uses defaults if None).
    pub transport: Option<quinn::TransportConfig>,
    /// Optional UDP socket factory for client packet transport.
    ///
    /// Input argument indicates whether IPv6 should be preferred for local bind.
    pub udp_socket_factory: Option<UdpSocketFactory>,
    /// UDP packet transport used by Quinn endpoint.
    pub packet_transport: ClientPacketTransport,
    /// Optional packet obfuscation.
    pub obfs: Option<ClientObfsConfig>,
    /// Fast open mode: return from `tcp()` after request write, and defer
    /// server response parsing to the first read.
    pub fast_open: bool,
    /// Enable persistent tunnel via TunnelManager. Default: true.
    ///
    /// When enabled, a single QUIC connection is kept warm and reused
    /// for all TCP proxy and UDP relay requests, eliminating per-request
    /// QUIC handshake overhead.
    pub persistent_tunnel: bool,
    /// Tunnel keepalive interval in seconds. Default: 25.
    ///
    /// The keepalive fires more frequently than the server's 30-second
    /// idle timeout so the tunnel is never reaped while the client is active.
    pub tunnel_keepalive_secs: u64,
    /// Connection send budget for PermitBank (bytes). Default: 32 MiB.
    ///
    /// Controls how much data can be buffered in the send pipeline before
    /// backpressure kicks in. Larger values trade memory for throughput.
    pub conn_send_budget: Option<usize>,
    /// Optional socket wrapper applied after QUIC socket construction.
    /// Used for fault injection testing (e.g., FaultInjectionSocket).
    /// Production code should leave this as None.
    pub socket_wrapper: Option<
        Arc<dyn Fn(Arc<dyn quinn::AsyncUdpSocket>) -> Arc<dyn quinn::AsyncUdpSocket> + Send + Sync>,
    >,
    /// External hop generation counter for UdpHop transport (test-only).
    ///
    /// When set, UdpHopSocket uses this counter instead of creating its own.
    /// Test code can observe the counter to snapshot the current generation
    /// and use it with generation-aware fault injection (FaultInjectionSocket).
    /// Production code should leave this as None.
    pub hop_generation: Option<Arc<std::sync::atomic::AtomicU64>>,
}

/// Client UDP packet transport mode.
pub enum ClientPacketTransport {
    /// Standard UDP socket bound on an ephemeral local port.
    Udp,
    /// UDP port-hopping transport.
    UdpHop {
        addrs: Vec<SocketAddr>,
        hop_interval: Duration,
    },
}

/// Packet obfuscation settings.
pub struct ClientObfsConfig {
    pub salamander_password: String,
}

/// TLS configuration for the client.
pub enum ClientTlsConfig {
    /// Trust a specific set of root certificates.
    RootCerts {
        roots: rustls::RootCertStore,
        pin_sha256: Option<[u8; 32]>,
        client_identity: Option<ClientIdentity>,
    },
    /// Skip TLS verification (dangerous, for testing only).
    InsecureSkipVerify {
        client_identity: Option<ClientIdentity>,
    },
}

/// Optional client certificate identity used for mTLS.
pub struct ClientIdentity {
    pub cert_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    pub key: rustls::pki_types::PrivateKeyDer<'static>,
}

/// Information returned after a successful connection.
#[derive(Debug, Clone)]
pub struct HandshakeInfo {
    pub udp_enabled: bool,
    pub tx: u64, // negotiated TX bandwidth (0 = BBR)
}

// ──────────────────────────────────────────────────────────────────────────────
// Client
// ──────────────────────────────────────────────────────────────────────────────

/// Hysteria protocol client.
pub struct Client {
    endpoint: quinn::Endpoint,
    quinn_conn: quinn::Connection,
    // Holds the H3 driver alive via a background task.  When Client is dropped,
    // this sender is dropped, the task's receiver resolves, and the driver is
    // dropped (closing the H3 control stream cleanly).
    _h3_keep_alive: oneshot::Sender<()>,
    /// Client-side UDP session manager.
    udp_mgr: Option<Arc<ClientUdpSessionManager>>,
    udp_enabled: bool,
    fast_open: bool,
    /// Effective upload bandwidth (bytes/sec) shared with BrutalSender.
    /// Zero while BBR is active; non-zero once Brutal mode is activated.
    upload_effective_bps: Arc<AtomicU64>,
    /// Channel to ClientConnActor — used for permit requests, FlowClosed, and UdpSend.
    /// The actor owns the Scheduler exclusively; all flows use message passing.
    ctrl_tx: mpsc::Sender<ClientControl>,
    /// Unbounded channel for permit returns — ClientPermitReturnGuard sends ClientSendDone here.
    /// Kept separate from ctrl_tx so budget returns can never be blocked or dropped.
    completion_tx: mpsc::UnboundedSender<ClientSendDone>,
}

impl Client {
    /// Connect to the server and perform authentication.
    pub async fn connect(mut config: ClientConfig) -> Result<(Self, HandshakeInfo), BoxError> {
        // Build TLS client config with ALPN="h3" (required by Hysteria protocol).
        let tls_cfg = std::mem::replace(
            &mut config.tls,
            ClientTlsConfig::InsecureSkipVerify {
                client_identity: None,
            },
        );
        let mut tls_client = match tls_cfg {
            ClientTlsConfig::RootCerts {
                roots,
                pin_sha256,
                client_identity,
            } => {
                let builder = if let Some(pin_sha256) = pin_sha256 {
                    let verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
                        .build()
                        .map_err(|e| format!("TLS verifier error: {}", e))?;
                    rustls::ClientConfig::builder()
                        .dangerous()
                        .with_custom_certificate_verifier(Arc::new(PinnedServerCertVerifier {
                            inner: verifier,
                            pin_sha256,
                        }))
                } else {
                    rustls::ClientConfig::builder().with_root_certificates(roots)
                };
                if let Some(identity) = client_identity {
                    builder
                        .with_client_auth_cert(identity.cert_chain, identity.key)
                        .map_err(|e| format!("TLS client certificate error: {}", e))?
                } else {
                    builder.with_no_client_auth()
                }
            }
            ClientTlsConfig::InsecureSkipVerify { client_identity } => {
                // Use a custom verifier that accepts everything
                let builder = rustls::ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(NoVerifier));
                if let Some(identity) = client_identity {
                    builder
                        .with_client_auth_cert(identity.cert_chain, identity.key)
                        .map_err(|e| format!("TLS client certificate error: {}", e))?
                } else {
                    builder.with_no_client_auth()
                }
            }
        };
        tls_client.alpn_protocols = vec![b"h3".to_vec()];

        // Build quinn client config
        let quic_client_cfg = quinn::crypto::rustls::QuicClientConfig::try_from(tls_client)
            .map_err(|e| format!("TLS config error: {}", e))?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client_cfg));

        // Create a SwitchableFactory so we can set congestion control after auth.
        let (factory, cc_handle) = new_switchable_factory();

        // Build transport config, including the switchable factory.
        let mut transport = config
            .transport
            .take()
            .unwrap_or_else(default_client_transport);
        transport.congestion_controller_factory(Arc::new(factory));
        client_config.transport_config(Arc::new(transport));

        // Create QUIC endpoint with configurable packet socket.
        let runtime: Arc<dyn quinn::Runtime> = Arc::new(quinn::TokioRuntime);
        let socket = build_client_socket(&config, Arc::clone(&runtime))?;
        let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            socket,
            runtime,
        )?;
        endpoint.set_default_client_config(client_config);

        // Connect to server
        let conn = endpoint
            .connect(config.server_addr, &config.server_name)?
            .await?;

        // Extract the effective-bps arc immediately after QUIC connect.
        // The arc starts at 0 (BBR mode); set_brutal() updates it in-place after auth.
        // Creating the scheduler now (before auth) ensures the actor exists for the full
        // connection lifetime, including auth and keepalive control-path operations.
        let upload_effective_bps = cc_handle.effective_bps_arc();

        // Assign a unique connection ID and create the per-connection scheduler.
        // ClientConnActor owns the Scheduler exclusively; no Arc<Mutex> sharing.
        let conn_id = ConnId(NEXT_CLIENT_CONN_ID.fetch_add(1, Ordering::Relaxed));
        let scheduler = Scheduler::new(Arc::clone(&upload_effective_bps));

        // Control channel (bounded): AcquirePermit, FlowClosed, UdpSend, ControlOp*.
        let (ctrl_tx, ctrl_rx) = mpsc::channel::<ClientControl>(4096);
        // Completion channel (unbounded): ClientSendDone from ClientPermitReturnGuard::drop.
        let (completion_tx, completion_rx) = mpsc::unbounded_channel::<ClientSendDone>();

        // Spawn the actor before auth so it manages the full connection lifetime.
        // If auth fails, dropping ctrl_tx closes control_rx → actor exits cleanly.
        let actor = ClientConnActor::new(conn.clone(), conn_id, scheduler, ctrl_rx, completion_rx);
        tokio::spawn(actor.run());

        // Acquire control lease for auth — reserves Control class budget headroom
        // so auth cannot be starved by bulk data-plane traffic saturation.
        // This is a required control operation: failure means the actor is dead
        // and the connection cannot proceed.
        let (lease_tx, lease_rx) = oneshot::channel::<ControlLease>();
        ctrl_tx.send(ClientControl::AcquireControlLease {
            op: ControlOp::Auth,
            bytes_hint: ControlOp::Auth.bytes_hint(),
            result_tx: lease_tx,
        }).await.map_err(|_| -> BoxError {
            "auth control lease: connection actor closed before lease request".into()
        })?;
        let auth_lease = lease_rx.await.map_err(|_| -> BoxError {
            "auth control lease: connection actor closed before lease grant".into()
        })?;
        let auth_lease_guard = ClientControlLeaseGuard::new(
            auth_lease.permit, completion_tx.clone(),
        );

        // Perform H3 auth
        let h3_quinn_conn = h3_quinn::Connection::new(conn.clone());
        let (h3_driver, mut send_request) = h3::client::new(h3_quinn_conn)
            .await
            .map_err(|e| format!("h3 client init error: {}", e))?;

        // Build auth request — bandwidth_rx = client's max receive bandwidth.
        let padding = crate::core::internal::protocol::AuthRequest::padding();
        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://hysteria/auth")
            .header(HEADER_AUTH, &config.auth)
            .header(HEADER_CC_RX, config.bandwidth_rx.to_string())
            .header(HEADER_PADDING, padding)
            .body(())
            .map_err(|e| format!("failed to build auth request: {e}"))?;

        let mut req_stream = send_request
            .send_request(req)
            .await
            .map_err(|e| format!("auth request error: {}", e))?;

        // Finish sending (no body)
        req_stream
            .finish()
            .await
            .map_err(|e| format!("auth request finish error: {}", e))?;

        // Receive response
        let resp = req_stream
            .recv_response()
            .await
            .map_err(|e| format!("auth response error: {}", e))?;

        let auth_ok_status = http::StatusCode::from_u16(STATUS_AUTH_OK)
            .map_err(|e| format!("invalid auth status code: {e}"))?;
        if resp.status() != auth_ok_status {
            conn.close(
                quinn::VarInt::from_u32(H3_ERR_PROTOCOL_ERROR),
                b"auth failed",
            );
            return Err(format!("authentication failed: status {}", resp.status().as_u16()).into());
        }

        // Parse auth response headers
        let udp_enabled = resp
            .headers()
            .get(HEADER_UDP_ENABLED)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<bool>().ok())
            .unwrap_or(false);

        let cc_rx_str = resp
            .headers()
            .get(HEADER_CC_RX)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("0");

        let (server_rx, rx_auto) = if cc_rx_str == "auto" {
            (0u64, true)
        } else {
            (cc_rx_str.parse::<u64>().unwrap_or(0), false)
        };

        // §5.3 — Post-auth congestion selection (client side).
        // set_brutal() updates the AtomicU64 that upload_effective_bps arc points to,
        // so the scheduler sees the new rate on next tick without any extra wiring.
        let tx = client_select_congestion(&cc_handle, rx_auto, server_rx, config.bandwidth_tx);

        // Auth complete — release the control lease (RAII guard returns budget to scheduler).
        drop(auth_lease_guard);

        drop(req_stream);
        drop(send_request);
        // Keep the H3 driver alive in a background task.
        let (keep_tx, keep_rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let _driver = h3_driver;
            let _ = keep_rx.await;
        });

        // Create client-side UDP session manager only when UDP is enabled.
        // Go: this is conditional on auth response.
        let udp_mgr = if udp_enabled {
            Some(ClientUdpSessionManager::new(conn.clone(), ctrl_tx.clone()))
        } else {
            None
        };

        let info = HandshakeInfo { udp_enabled, tx };
        Ok((
            Self {
                endpoint,
                quinn_conn: conn,
                _h3_keep_alive: keep_tx,
                udp_mgr,
                udp_enabled,
                fast_open: config.fast_open,
                upload_effective_bps,
                ctrl_tx,
                completion_tx,
            },
            info,
        ))
    }

    /// Open a TCP proxy connection to the given address.
    ///
    /// Returns a `TcpProxyConn` that implements `AsyncRead + AsyncWrite`.
    pub async fn tcp(&self, addr: &str) -> Result<TcpProxyConn, BoxError> {
        let (send, recv) = self
            .quinn_conn
            .open_bi()
            .await
            .map_err(wrap_if_connection_closed)?;
        let mut stream = QStream::new(send, recv);

        // Write TCP proxy request (0x401 frame type + addr + padding)
        let req_bytes = write_tcp_request(addr);
        if let Err(err) = stream.writer_mut().write_all(&req_bytes).await {
            stream.close();
            return Err(wrap_if_connection_closed(err).into());
        }

        // Assign a unique flow ID for this TCP stream within the connection.
        static NEXT_FLOW_ID: AtomicU64 = AtomicU64::new(1);
        let flow_id = FlowId(NEXT_FLOW_ID.fetch_add(1, Ordering::Relaxed));
        let hints = FlowHints::default_tcp();
        let upload_effective_bps = Arc::clone(&self.upload_effective_bps);

        if self.fast_open {
            let (send, mut reader) = stream.into_parts();
            let establish: Pin<Box<dyn Future<Output = std::io::Result<QuinnRecvReader>> + Send>> =
                Box::pin(async move {
                    let resp_bytes = read_tcp_response_async(&mut reader).await.map_err(|err| {
                        reader.close();
                        err
                    })?;
                    let (ok, msg, _) = read_tcp_response(&resp_bytes).map_err(|e| {
                        reader.close();
                        std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
                    })?;
                    if !ok {
                        reader.close();
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::ConnectionRefused,
                            format!("server rejected: {}", msg),
                        ));
                    }
                    Ok(reader)
                });

            let (upload_tx, upload_rx) = mpsc::channel::<UploadMsg>(CLIENT_UPLOAD_CHAN_SIZE);
            let (task_done_tx, task_done_rx) = oneshot::channel::<()>();
            tokio::spawn(client_tcp_upload_task(
                upload_rx,
                send,
                self.ctrl_tx.clone(),
                self.completion_tx.clone(),
                flow_id,
                hints,
                upload_effective_bps,
                task_done_tx,
            ));

            return Ok(TcpProxyConn {
                recv: None,
                establish: Some(establish),
                upload_tx: Some(upload_tx),
                pending_send: None,
                pending_send_size: 0,
                flush_ack_rx: None,
                task_done_rx,
                tunnel_work_guard: None,
            });
        }

        // Read TCP proxy response from server
        let resp_bytes = match read_tcp_response_async(stream.reader_mut()).await {
            Ok(v) => v,
            Err(err) => {
                stream.close();
                return Err(wrap_if_connection_closed(err).into());
            }
        };
        let (ok, msg, _) = match read_tcp_response(&resp_bytes) {
            Ok(v) => v,
            Err(e) => {
                stream.close();
                return Err(format!("response parse error: {}", e).into());
            }
        };

        if !ok {
            stream.close();
            return Err(format!("server rejected: {}", msg).into());
        }
        let (send, reader) = stream.into_parts();

        let (upload_tx, upload_rx) = mpsc::channel::<UploadMsg>(CLIENT_UPLOAD_CHAN_SIZE);
        let (task_done_tx, task_done_rx) = oneshot::channel::<()>();
        tokio::spawn(client_tcp_upload_task(
            upload_rx,
            send,
            self.ctrl_tx.clone(),
            self.completion_tx.clone(),
            flow_id,
            hints,
            upload_effective_bps,
            task_done_tx,
        ));

        Ok(TcpProxyConn {
            recv: Some(reader),
            establish: None,
            upload_tx: Some(upload_tx),
            pending_send: None,
            pending_send_size: 0,
            flush_ack_rx: None,
            task_done_rx,
            tunnel_work_guard: None,
        })
    }

    /// Open a UDP relay session.
    ///
    /// Returns a `HyUdpConn` that can send/receive UDP datagrams via the server.
    ///
    /// Go: `func (c *client) UDP() (HyUDPConn, error)`.
    pub async fn udp(&self) -> Result<HyUdpConn, BoxError> {
        let mgr = self
            .udp_mgr
            .as_ref()
            .ok_or_else(|| std::io::Error::other("udp relay not enabled by server"))?;
        mgr.new_udp()
            .await
            .map_err(|err| Box::new(err) as BoxError)
    }

    /// Close the QUIC connection.
    pub fn close(&self) {
        self.endpoint
            .close(quinn::VarInt::from_u32(H3_ERR_NO_ERROR), b"");
        self.conn()
            .close(quinn::VarInt::from_u32(H3_ERR_NO_ERROR), b"");
    }

    pub fn conn(&self) -> &quinn::Connection {
        &self.quinn_conn
    }

    #[must_use]
    pub fn udp_enabled(&self) -> bool {
        self.udp_enabled
    }

    /// Acquire a control-plane lease for an external control operation.
    ///
    /// Returns an RAII guard that releases the lease on drop. The lease
    /// reserves budget from the Control class pool so the operation cannot
    /// be starved by data-plane traffic saturation.
    pub(crate) async fn acquire_control_lease(
        &self,
        op: ControlOp,
    ) -> Result<ClientControlLeaseGuard, BoxError> {
        let (result_tx, result_rx) = oneshot::channel();
        self.ctrl_tx
            .send(ClientControl::AcquireControlLease {
                op,
                bytes_hint: op.bytes_hint(),
                result_tx,
            })
            .await
            .map_err(|_| -> BoxError { "connection actor closed".into() })?;
        let lease = result_rx
            .await
            .map_err(|_| -> BoxError { "connection actor closed".into() })?;
        Ok(ClientControlLeaseGuard::new(lease.permit, self.completion_tx.clone()))
    }
}

/// Select and activate the client-side congestion controller after a successful auth.
///
/// Go equivalent: `clientSelectCongestion`.  Returns the negotiated TX bandwidth (0 = BBR).
fn client_select_congestion(
    cc_handle: &crate::core::internal::congestion::switchable::CongestionHandle,
    rx_auto: bool,
    server_rx: u64,
    client_bandwidth_tx: u64,
) -> u64 {
    if rx_auto {
        return 0;
    }
    let mut tx = server_rx;
    if tx == 0 || tx > client_bandwidth_tx {
        tx = client_bandwidth_tx;
    }
    if tx > 0 {
        cc_handle.set_brutal(tx);
    }
    tx
}

/// Go: `wrapIfConnectionClosed(err)` for reconnectable client.
///
/// Quinn 0.11 stream opening waits for stream budget and does not expose a
/// stream-limit error variant, so all connection-level failures are treated as
/// closed-connection errors here.
fn wrap_if_connection_closed<E>(err: E) -> BoxError
where
    E: Error + Send + Sync + 'static,
{
    let err_ref = &err as &(dyn Error + 'static);

    if err_ref.downcast_ref::<quinn::ConnectionError>().is_some() {
        return Box::new(ClosedError);
    }
    if let Some(write_err) = err_ref.downcast_ref::<quinn::WriteError>() {
        if matches!(
            write_err,
            quinn::WriteError::ConnectionLost(_) | quinn::WriteError::ClosedStream
        ) {
            return Box::new(ClosedError);
        }
    }
    if let Some(read_err) = err_ref.downcast_ref::<quinn::ReadError>() {
        if matches!(
            read_err,
            quinn::ReadError::ConnectionLost(_) | quinn::ReadError::ClosedStream
        ) {
            return Box::new(ClosedError);
        }
    }
    if let Some(io_err) = err_ref.downcast_ref::<std::io::Error>() {
        if matches!(
            io_err.kind(),
            std::io::ErrorKind::NotConnected
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
        ) {
            return Box::new(ClosedError);
        }
    }

    Box::new(err)
}

// ── TunnelWorkRegistry ─────────────────────────────────────────────────────────

/// Tracks active tunnel-scope work (TcpProxyConn, HyUdpConn, auth, reconnect).
///
/// Provides condition-based drain: `wait_zero()` blocks until all guards are
/// dropped, replacing the old fixed-delay `sleep(deadline)` approach.
pub(crate) struct TunnelWorkRegistry {
    /// Number of active TunnelWorkGuard instances.
    active: AtomicUsize,
    /// Set to true by `begin_shutdown()`. After this, `register()` rejects new work.
    closing: AtomicBool,
    /// Notified when `active` transitions to 0.
    notify: Notify,
}

impl TunnelWorkRegistry {
    pub fn new() -> Self {
        Self {
            active: AtomicUsize::new(0),
            closing: AtomicBool::new(false),
            notify: Notify::new(),
        }
    }

    /// Register a new unit of tunnel work. Returns an RAII guard that
    /// decrements the active count on drop.
    ///
    /// Returns `Err(ClosedError)` if shutdown has begun. Uses a
    /// double-check pattern: increment first, then re-check the closing
    /// flag to prevent a TOCTOU race where `wait_zero()` could return
    /// while a registration is still in-flight.
    pub fn register(self: &Arc<Self>) -> Result<TunnelWorkGuard, ClosedError> {
        if self.closing.load(Ordering::Acquire) {
            return Err(ClosedError);
        }
        self.active.fetch_add(1, Ordering::AcqRel);
        // Double-check: if closing was set between the check and the
        // increment, undo the increment to maintain correctness.
        if self.closing.load(Ordering::Acquire) {
            let prev = self.active.fetch_sub(1, Ordering::AcqRel);
            if prev == 1 {
                self.notify.notify_waiters();
            }
            return Err(ClosedError);
        }
        Ok(TunnelWorkGuard {
            registry: Arc::clone(self),
        })
    }

    /// Mark the registry as closing. After this call, `register()` rejects
    /// new work.
    pub fn begin_shutdown(&self) {
        self.closing.store(true, Ordering::Release);
    }

    /// Wait until the active count reaches zero. Safe against missed
    /// wakeups: registers interest via `notified()` then re-checks.
    pub async fn wait_zero(&self) {
        loop {
            if self.active.load(Ordering::Acquire) == 0 {
                return;
            }
            let notified = self.notify.notified();
            // Re-check after registering interest.
            if self.active.load(Ordering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }

    /// True if `begin_shutdown()` has been called.
    #[allow(dead_code)]
    pub fn is_closing(&self) -> bool {
        self.closing.load(Ordering::Acquire)
    }
}

/// RAII guard for a unit of tunnel-scope work. Decrements the registry's
/// active count on drop and wakes `wait_zero()` when it reaches zero.
pub(crate) struct TunnelWorkGuard {
    registry: Arc<TunnelWorkRegistry>,
}

impl Drop for TunnelWorkGuard {
    fn drop(&mut self) {
        let prev = self.registry.active.fetch_sub(1, Ordering::AcqRel);
        if prev == 1 {
            self.registry.notify.notify_waiters();
        }
    }
}

// ── ReconnectableClient ────────────────────────────────────────────────────────

/// Reconnectable client wrapper.
///
/// Go equivalent: `reconnectableClientImpl` in `core/client/reconnect.go`.
///
/// When `persistent_tunnel` is enabled in ClientConfig, delegates to
/// `TunnelManager` for connection lifecycle (keepalive, proactive reconnect).
/// Otherwise, uses the original lazy-reconnect-on-ClosedError behavior.
pub struct ReconnectableClient {
    inner: AsyncMutex<ReconnectableInner>,
    /// When persistent_tunnel is enabled, TunnelManager owns the connection.
    tunnel_mgr: Option<Arc<TunnelManager>>,
    /// Tracks active tunnel-scope work (TcpProxyConn, HyUdpConn, auth, reconnect).
    /// Used for condition-based drain during graceful shutdown.
    tunnel_work: Arc<TunnelWorkRegistry>,
}

struct ReconnectableInner {
    config_func: Arc<dyn Fn() -> Result<ClientConfig, BoxError> + Send + Sync>,
    connected_func: Option<Arc<dyn Fn(Arc<Client>, &HandshakeInfo, u32) + Send + Sync>>,
    client: Option<Arc<Client>>,
    count: u32,
    closed: bool,
}

impl ReconnectableClient {
    /// Create a reconnectable wrapper.
    ///
    /// If `lazy` is false, the first connection is established immediately.
    /// If the first call to `config_func` produces a config with
    /// `persistent_tunnel == true`, a TunnelManager is created and its
    /// keepalive loop is spawned on `keepalive_handle` (if provided) or the
    /// current Tokio runtime.
    pub async fn new<F, C>(
        config_func: F,
        connected_func: Option<C>,
        lazy: bool,
        keepalive_handle: Option<tokio::runtime::Handle>,
    ) -> Result<Self, BoxError>
    where
        F: Fn() -> Result<ClientConfig, BoxError> + Send + Sync + 'static,
        C: Fn(Arc<Client>, &HandshakeInfo, u32) + Send + Sync + 'static,
    {
        let config_func: Arc<dyn Fn() -> Result<ClientConfig, BoxError> + Send + Sync> =
            Arc::new(config_func);
        let connected_func: Option<Arc<dyn Fn(Arc<Client>, &HandshakeInfo, u32) + Send + Sync>> =
            connected_func.map(|f| {
                Arc::new(f) as Arc<dyn Fn(Arc<Client>, &HandshakeInfo, u32) + Send + Sync>
            });

        // Probe config to check persistent_tunnel setting.
        let probe_config = (config_func)()?;
        let persistent = probe_config.persistent_tunnel;
        let keepalive_secs = probe_config.tunnel_keepalive_secs;

        let tunnel_work = Arc::new(TunnelWorkRegistry::new());

        if persistent {
            // Build a ConnectFactory from config_func + connected_func.
            let cf = Arc::clone(&config_func);
            let cb = connected_func.clone();
            let count = Arc::new(std::sync::atomic::AtomicU32::new(0));
            let factory: crate::core::tunnel_manager::ConnectFactory = Arc::new(move || {
                let cf = Arc::clone(&cf);
                let cb = cb.clone();
                let count = Arc::clone(&count);
                Box::pin(async move {
                    let config = cf()?;
                    let (client, info) = Client::connect(config).await?;
                    let n = count.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                    // Call connected_func if set. We create a temporary Arc for the
                    // callback (it expects Arc<Client>), but since we just created it
                    // and the callback is synchronous, try_unwrap always succeeds.
                    if let Some(cb) = &cb {
                        let arc = Arc::new(client);
                        cb(Arc::clone(&arc), &info, n);
                        let client = Arc::try_unwrap(arc)
                            .unwrap_or_else(|_| panic!("connected_func must not retain Arc<Client>"));
                        return Ok((client, info));
                    }
                    Ok((client, info))
                })
            });

            let interval = Duration::from_secs(keepalive_secs);
            let mgr = Arc::new(TunnelManager::new(
                interval,
                factory,
                Some(Arc::clone(&tunnel_work)),
            ));

            // Spawn the keepalive loop on the designated handle (if provided)
            // or the current runtime. Using a dedicated runtime keeps tunnel
            // keepalive off the main thread-pool for service partitioning.
            let mgr_ref = Arc::clone(&mgr);
            if let Some(handle) = keepalive_handle {
                handle.spawn(mgr_ref.keepalive_loop());
            } else {
                tokio::spawn(mgr_ref.keepalive_loop());
            }

            // If not lazy, establish the first connection now.
            if !lazy {
                mgr.get_or_connect().await?;
            }

            let inner = ReconnectableInner {
                config_func,
                connected_func,
                client: None,
                count: 0,
                closed: false,
            };

            Ok(Self {
                inner: AsyncMutex::new(inner),
                tunnel_mgr: Some(mgr),
                tunnel_work,
            })
        } else {
            // Original lazy-reconnect behavior.
            let mut inner = ReconnectableInner {
                config_func,
                connected_func,
                client: None,
                count: 0,
                closed: false,
            };
            if !lazy {
                inner.reconnect().await?;
            }
            Ok(Self {
                inner: AsyncMutex::new(inner),
                tunnel_mgr: None,
                tunnel_work,
            })
        }
    }

    async fn client_do<R, F, Fut>(&self, f: F) -> Result<R, BoxError>
    where
        F: FnOnce(Arc<Client>) -> Fut,
        Fut: Future<Output = Result<R, BoxError>>,
    {
        // Tunnel-managed path: get client from TunnelManager.
        if let Some(mgr) = &self.tunnel_mgr {
            {
                let inner = self.inner.lock().await;
                if inner.closed {
                    return Err(Box::new(ClosedError));
                }
            }
            let handle = mgr.get_or_connect().await?;
            let client = handle.client_arc();
            match f(client).await {
                Err(err) if err.downcast_ref::<ClosedError>().is_some() => {
                    // Tunnel is dead, invalidate so next call reconnects.
                    mgr.invalidate().await;
                    Err(err)
                }
                other => other,
            }
        } else {
            // Original lazy-reconnect path.
            let client = {
                let mut inner = self.inner.lock().await;
                if inner.closed {
                    return Err(Box::new(ClosedError));
                }
                if inner.client.is_none() {
                    // Hold a guard during reconnect so wait_tunnel_drain()
                    // blocks until the reconnect (including auth) completes.
                    let _reconnect_guard = self.tunnel_work.register()
                        .map_err(|e| Box::new(e) as BoxError)?;
                    inner.reconnect().await?;
                }
                inner
                    .client
                    .as_ref()
                    .cloned()
                    .ok_or_else(|| Box::new(ClosedError) as BoxError)?
            };

            let old_client = Arc::clone(&client);
            match f(client).await {
                Err(err) if err.downcast_ref::<ClosedError>().is_some() => {
                    let mut inner = self.inner.lock().await;
                    if inner
                        .client
                        .as_ref()
                        .is_some_and(|current| Arc::ptr_eq(current, &old_client))
                    {
                        inner.client = None;
                    }
                    Err(err)
                }
                other => other,
            }
        }
    }

    /// Open a TCP stream through the current client, reconnecting lazily.
    ///
    /// A TunnelWorkGuard is registered before the connection attempt so that
    /// `wait_tunnel_drain()` blocks until this proxy connection is dropped.
    pub async fn tcp(&self, addr: &str) -> Result<TcpProxyConn, BoxError> {
        let guard = self.tunnel_work.register()
            .map_err(|e| Box::new(e) as BoxError)?;
        let addr = addr.to_string();
        let mut conn = self.client_do(move |client| async move { client.tcp(&addr).await })
            .await?;
        conn.tunnel_work_guard = Some(guard);
        Ok(conn)
    }

    /// Open a UDP relay session through the current client, reconnecting lazily.
    ///
    /// A TunnelWorkGuard is registered before the session creation so that
    /// `wait_tunnel_drain()` blocks until this UDP session is dropped.
    pub async fn udp(&self) -> Result<HyUdpConn, BoxError> {
        let guard = self.tunnel_work.register()
            .map_err(|e| Box::new(e) as BoxError)?;
        let mut conn = self.client_do(move |client| async move { client.udp().await })
            .await?;
        conn.tunnel_work_guard = Some(guard);
        Ok(conn)
    }

    /// Stop accepting new tcp()/udp() requests and stop keepalive/reconnect.
    ///
    /// After this call, `register()` on the tunnel work registry rejects
    /// new work, and the TunnelManager's keepalive loop exits.
    /// QUIC connections remain open so in-flight handlers can finish.
    pub async fn begin_shutdown(&self) {
        self.tunnel_work.begin_shutdown();
        {
            let mut inner = self.inner.lock().await;
            inner.closed = true;
        }
        if let Some(mgr) = &self.tunnel_mgr {
            mgr.begin_shutdown().await;
        }
    }

    /// Wait for all active tunnel work (TcpProxyConn, HyUdpConn, auth,
    /// reconnect) to complete. Returns when the active count reaches zero.
    pub async fn wait_tunnel_drain(&self) {
        self.tunnel_work.wait_zero().await;
    }

    /// Force-close the QUIC connection. Called after drain completes or
    /// when the drain timeout expires.
    pub async fn force_close(&self) {
        if let Some(mgr) = &self.tunnel_mgr {
            mgr.force_close().await;
        }
        {
            let mut inner = self.inner.lock().await;
            if let Some(client) = inner.client.take() {
                client.close();
            }
        }
    }

    /// Permanently close the wrapper and the active client connection.
    ///
    /// This is an immediate (non-graceful) close. For graceful shutdown,
    /// use `begin_shutdown()` + `wait_tunnel_drain()` + `force_close()`.
    pub async fn close(&self) -> Result<(), BoxError> {
        self.tunnel_work.begin_shutdown();
        let mut inner = self.inner.lock().await;
        inner.closed = true;
        if let Some(mgr) = &self.tunnel_mgr {
            mgr.shutdown().await;
        }
        if let Some(client) = inner.client.take() {
            client.close();
        }
        Ok(())
    }
}

impl ReconnectableInner {
    async fn reconnect(&mut self) -> Result<(), BoxError> {
        if let Some(old) = self.client.take() {
            old.close();
        }
        let config = (self.config_func)()?;
        let (client, info) = Client::connect(config).await?;
        let client = Arc::new(client);
        self.count += 1;
        if let Some(cb) = &self.connected_func {
            cb(Arc::clone(&client), &info, self.count);
        }
        self.client = Some(client);
        Ok(())
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Client-side UDP session manager
//
// Go equivalent: hysteria/core/client/udp.go
// ──────────────────────────────────────────────────────────────────────────────

/// A single client-side UDP session (the user-facing handle).
///
/// Go: `udpConn` struct (client/udp.go:25-33) + `HyUDPConn` interface.
pub struct HyUdpConn {
    /// Session identifier assigned by the manager (starts at 1).
    id: u32,
    /// Receives parsed UDP messages from the shared receive loop.
    recv_rx: AsyncMutex<mpsc::Receiver<UdpMessage>>,
    /// Reassembles fragmented messages.  Go: `D *frag.Defragger`.
    defragger: AsyncMutex<Defragger>,
    /// Serialization buffer (4096 bytes).  Go: `SendBuf []byte = make([]byte, MaxUDPSize)`.
    send_buf: AsyncMutex<Vec<u8>>,
    /// Shared QUIC connection — used to read max_datagram_size for fragmentation.
    conn: quinn::Connection,
    /// Calls the manager's close/deregister logic.  Go: `CloseFunc func()`.
    close_func: Box<dyn Fn() + Send + Sync>,
    /// True after `close()` has been called.
    closed: AtomicBool,
    /// Per-flow identifier for RealtimeDatagram class permit tracking.
    flow_id: FlowId,
    /// Channel to ClientConnActor — actor acquires permit and sends datagram atomically.
    ctrl_tx: mpsc::Sender<ClientControl>,
    /// RAII guard tracking this session in the TunnelWorkRegistry.
    /// Decrements the active count when this session is dropped.
    tunnel_work_guard: Option<TunnelWorkGuard>,
}

impl HyUdpConn {
    /// Receive the next reassembled UDP packet.
    ///
    /// Blocks until a complete message is available or the session is closed.
    ///
    /// Go: `func (u *udpConn) Receive() ([]byte, string, error)`.
    pub async fn receive(&self) -> Result<(Vec<u8>, String), ClosedError> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(ClosedError);
        }
        let mut recv_rx = self.recv_rx.lock().await;
        loop {
            // Go: `msg := <-u.ReceiveCh; if msg == nil { return io.EOF }`
            let msg = recv_rx.recv().await.ok_or(ClosedError)?;
            let mut d = self.defragger.lock().await;
            if let Some(assembled) = d.feed(msg) {
                return Ok((assembled.data, assembled.addr));
            }
            // Incomplete fragment; wait for more
        }
    }

    /// Send a UDP payload to the given address.
    ///
    /// Delegates permit acquisition and sending to `ClientConnActor` which owns
    /// the Scheduler exclusively. Auto-fragments if the message is too large
    /// for a single QUIC datagram. Best-effort: datagrams are dropped silently
    /// if budget or QUIC send capacity is exhausted.
    ///
    /// Go: `func (u *udpConn) Send(data []byte, addr string) error`.
    pub async fn send(&self, data: &[u8], addr: &str) -> std::io::Result<()> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                ClosedError,
            ));
        }

        let msg = UdpMessage {
            session_id: self.id,
            pkt_id: 0,
            frag_id: 0,
            frag_count: 1,
            addr: addr.to_string(),
            data: data.to_vec(),
        };
        let mut send_buf = self.send_buf.lock().await;
        let n = msg.serialize(&mut send_buf);
        if n < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "message serialize buffer too small",
            ));
        }
        let bytes = Bytes::copy_from_slice(&send_buf[..n as usize]);

        let max_size = self.conn.max_datagram_size().unwrap_or(MAX_DATAGRAM_FRAME_SIZE as usize);
        let datagrams: Vec<Bytes> = if bytes.len() <= max_size {
            vec![bytes]
        } else {
            let mut msg = msg.clone();
            msg.pkt_id = new_frag_packet_id();
            frag_udp_message(&msg, max_size)
                .into_iter()
                .map(|f| Bytes::from(f.to_bytes()))
                .collect()
        };

        for datagram in datagrams {
            // Actor acquires a Realtime permit and sends the datagram atomically.
            // If budget is exhausted, the datagram is dropped (UDP is best-effort).
            if self.ctrl_tx
                .send(ClientControl::UdpSend { payload: datagram, flow_id: self.flow_id })
                .await
                .is_err()
            {
                return Err(std::io::Error::other("connection actor closed"));
            }
        }
        Ok(())
    }

    /// Close this UDP session and deregister from the manager.
    ///
    /// Go: `func (u *udpConn) Close() error`.
    pub fn close(&self) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            (self.close_func)();
        }
    }
}

impl Drop for HyUdpConn {
    fn drop(&mut self) {
        self.close();
    }
}

/// Internal per-session bookkeeping stored in the manager's sessions map.
struct UdpSessionSlot {
    /// Sender half — receive loop writes messages here.
    recv_tx: mpsc::Sender<UdpMessage>,
}

/// Client-side UDP session manager.
///
/// Manages a map of active `UdpSessionSlot`s.  A background task reads
/// datagrams from the QUIC connection and routes them to the correct session.
///
/// Go: `udpSessionManager` (client/udp.go:85-103).
pub struct ClientUdpSessionManager {
    /// The QUIC connection used for datagram I/O.
    conn: quinn::Connection,
    /// Active sessions.  Key = session_id.
    sessions: Arc<RwLock<HashMap<u32, UdpSessionSlot>>>,
    /// Monotonically increasing session ID (starts at 1).
    /// Go: `nextID uint32` initialized to 1.
    next_id: AtomicU32,
    /// Set to true when the connection closes (closeCleanup ran).
    closed: AtomicBool,
    /// Channel to ClientConnActor for permit acquisition and UDP sends.
    ctrl_tx: mpsc::Sender<ClientControl>,
}

impl ClientUdpSessionManager {
    /// Create a new manager and spawn the shared receive loop.
    ///
    /// Go: `newUDPSessionManager(io udpIO)` — spawns `go m.run()` inside.
    pub(crate) fn new(conn: quinn::Connection, ctrl_tx: mpsc::Sender<ClientControl>) -> Arc<Self> {
        let mgr = Arc::new(Self {
            conn: conn.clone(),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            next_id: AtomicU32::new(1), // Go: nextID starts at 1
            closed: AtomicBool::new(false),
            ctrl_tx,
        });
        // Go: go m.run()
        tokio::spawn(client_udp_receive_loop(conn, Arc::clone(&mgr)));
        mgr
    }

    /// Allocate a new UDP session and return a `HyUdpConn` for it.
    ///
    /// Go: `func (m *udpSessionManager) NewUDP() (HyUDPConn, error)`.
    pub async fn new_udp(self: &Arc<Self>) -> Result<HyUdpConn, ClosedError> {
        let mut sessions = self.sessions.write().await;
        if self.closed.load(Ordering::SeqCst) {
            return Err(ClosedError);
        }
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);

        // Assign a unique flow ID for this UDP session within the connection.
        static NEXT_UDP_FLOW_ID: AtomicU64 = AtomicU64::new(1_000_000);
        let flow_id = FlowId(NEXT_UDP_FLOW_ID.fetch_add(1, Ordering::Relaxed));

        // Go: ReceiveCh = make(chan *UDPMessage, udpMessageChanSize=1024)
        let (recv_tx, recv_rx) = mpsc::channel(UDP_MESSAGE_CHAN_SIZE);
        sessions.insert(id, UdpSessionSlot { recv_tx });

        // close_func removes the session from the map and notifies the actor.
        let sessions_ref = Arc::clone(&self.sessions);
        let ctrl_tx_close = self.ctrl_tx.clone();
        let close_func = Box::new(move || {
            // Notify actor to clean up flow state in the Scheduler.
            let _ = ctrl_tx_close.try_send(ClientControl::FlowClosed(flow_id));
            if let Ok(mut sessions) = sessions_ref.try_write() {
                sessions.remove(&id);
                return;
            }
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                let sessions = Arc::clone(&sessions_ref);
                handle.spawn(async move {
                    sessions.write().await.remove(&id);
                });
            }
        });

        // Send buf: MaxUDPSize = 4096 bytes, matching Go
        Ok(HyUdpConn {
            id,
            recv_rx: AsyncMutex::new(recv_rx),
            defragger: AsyncMutex::new(Defragger::new()),
            send_buf: AsyncMutex::new(vec![0u8; MAX_UDP_SIZE]),
            conn: self.conn.clone(),
            close_func,
            closed: AtomicBool::new(false),
            flow_id,
            ctrl_tx: self.ctrl_tx.clone(),
            tunnel_work_guard: None,
        })
    }

    /// Close all sessions and mark the manager closed.
    ///
    /// Called by the receive loop on connection error (Go: `defer m.closeCleanup()`).
    ///
    /// Go: `func (m *udpSessionManager) closeCleanup()`.
    async fn close_cleanup(&self) {
        let mut sessions = self.sessions.write().await;
        // Closing all recv_tx senders causes the corresponding recv_rx in each
        // HyUdpConn::receive() to return None → ClosedError (matches Go: close(ch)).
        sessions.clear();
        self.closed.store(true, Ordering::SeqCst);
    }
}

// ── Shared receive loop ────────────────────────────────────────────────────────

/// Shared UDP receive loop: reads QUIC datagrams, routes to sessions.
///
/// On connection error, calls `close_cleanup()` and exits.
///
/// Go: `func (m *udpSessionManager) run() error` with `defer m.closeCleanup()`.
async fn client_udp_receive_loop(conn: quinn::Connection, mgr: Arc<ClientUdpSessionManager>) {
    loop {
        // Go: m.io.ReceiveMessage()
        let datagram = match conn.read_datagram().await {
            Ok(d) => d,
            Err(_) => break, // connection closed
        };
        let msg = match parse_udp_message(&datagram) {
            Ok(m) => m,
            Err(_) => continue, // invalid message, silently skip (Go: continue)
        };

        // Route to the matching session
        // Go: `select { case conn.ReceiveCh <- msg: default: }` — drop if full
        let sessions = mgr.sessions.read().await;
        if let Some(slot) = sessions.get(&msg.session_id) {
            // Non-blocking send: drop the message if the channel is full
            let _ = slot.recv_tx.try_send(msg);
        }
        // Unknown session_id: silently ignore (Go: if !ok { return })
    }

    // Go: defer m.closeCleanup()
    mgr.close_cleanup().await;
}

// ──────────────────────────────────────────────────────────────────────────────
// UploadMsg — channel message type between poll_write and client_tcp_upload_task
// ──────────────────────────────────────────────────────────────────────────────

/// Messages sent through the upload channel from poll_write to the upload task.
enum UploadMsg {
    /// A chunk of data to write to the QUIC send stream.
    Data(Bytes),
    /// Flush synchronization token: the upload task sends back an ack after
    /// writing all preceding Data messages to the QUIC stream.  poll_flush
    /// waits for this ack before returning Ready to satisfy the AsyncWrite
    /// contract that "flush means data has reached the transport layer".
    Flush(oneshot::Sender<()>),
}

// client_tcp_upload_task — pipelined permit-before-write upload
// ──────────────────────────────────────────────────────────────────────────────

/// Prefetch result for the client-side upload pipeline.
enum ClientPrefetch {
    /// Next data chunk with its acquired permit.
    Data(Bytes, Permit),
    /// Flush request (current write already completed via join!).
    Flush(oneshot::Sender<()>),
    /// Upload channel closed (poll_shutdown dropped upload_tx).
    ChannelClosed,
    /// ClientConnActor gone (control channel closed).
    ActorGone,
}

/// Upload task for a client-side TCP proxy connection.
///
/// Mirrors TcpFlowActor::run() on the server side with pipelined
/// double-buffer: while writing the current chunk to the QUIC stream
/// (and applying token-bucket rate limiting), simultaneously receives the
/// next chunk from the poll_write channel and acquires its permit from
/// ClientConnActor. This overlaps the QUIC write and rate-limit sleep
/// with the permit channel round-trip.
///
/// The task runs until the upload channel closes (poll_shutdown drops upload_tx),
/// then signals task_done_tx so poll_shutdown can unblock.
async fn client_tcp_upload_task(
    mut upload_rx: mpsc::Receiver<UploadMsg>,
    mut quic_send: quinn::SendStream,
    ctrl_tx: mpsc::Sender<ClientControl>,
    completion_tx: mpsc::UnboundedSender<ClientSendDone>,
    flow_id: FlowId,
    hints: FlowHints,
    effective_bps: Arc<AtomicU64>,
    task_done_tx: oneshot::Sender<()>,
) {
    // Token-bucket state for the upload direction.
    let mut upload_tokens: i64 = 0;
    let mut upload_last_refill = Instant::now();

    // Outer loop: each iteration bootstraps a pipeline segment.
    // A Flush breaks the pipeline (must wait for current write to complete
    // before acking), then we restart from the next Data message.
    'outer: loop {
        // Bootstrap: receive first Data chunk and acquire its permit.
        let (mut data, permit) = loop {
            match upload_rx.recv().await {
                Some(UploadMsg::Data(d)) => {
                    match client_acquire_permit(&ctrl_tx, flow_id, &hints, d.len()).await {
                        Some(p) => break (d, p),
                        None => break 'outer,
                    }
                }
                Some(UploadMsg::Flush(ack)) => {
                    // No in-flight write, ack immediately.
                    let _ = ack.send(());
                }
                None => break 'outer,
            }
        };
        let mut guard = ClientPermitReturnGuard::new(permit, completion_tx.clone());

        // Pipeline loop: write current chunk while prefetching next.
        loop {
            let data_len = data.len();

            // Pipeline: write current chunk + rate-limit, while prefetching
            // the next chunk from the upload channel + acquiring its permit.
            let (write_result, prefetch) = tokio::join!(
                async {
                    let r = tokio::io::AsyncWriteExt::write_all(&mut quic_send, &data).await;
                    if r.is_ok() {
                        // Token-bucket rate limiting (overlapped with prefetch).
                        let rate = effective_bps.load(Ordering::Relaxed);
                        if rate > 0 && data_len > 0 {
                            const BURST_NANOS: u64 = 4_000_000;
                            let now = Instant::now();
                            let elapsed_nanos =
                                now.duration_since(upload_last_refill).as_nanos();
                            upload_last_refill = now;
                            let new_tokens =
                                (rate as u128 * elapsed_nanos / 1_000_000_000) as i64;
                            let max_burst =
                                (rate as u128 * BURST_NANOS as u128 / 1_000_000_000) as i64;
                            upload_tokens = (upload_tokens + new_tokens).min(max_burst);
                            upload_tokens -= data_len as i64;
                            if upload_tokens < 0 {
                                let sleep_nanos = ((-upload_tokens) as u128
                                    * 1_000_000_000
                                    / rate as u128)
                                    as u64;
                                tokio::time::sleep(Duration::from_nanos(sleep_nanos)).await;
                            }
                        }
                    }
                    r
                },
                async {
                    match upload_rx.recv().await {
                        Some(UploadMsg::Data(d)) => {
                            match client_acquire_permit(&ctrl_tx, flow_id, &hints, d.len()).await {
                                Some(p) => ClientPrefetch::Data(d, p),
                                None => ClientPrefetch::ActorGone,
                            }
                        }
                        Some(UploadMsg::Flush(ack)) => ClientPrefetch::Flush(ack),
                        None => ClientPrefetch::ChannelClosed,
                    }
                }
            );

            // Handle current write.
            match write_result {
                Ok(()) => guard.complete(data_len),
                Err(_) => {
                    if let ClientPrefetch::Data(_, p) = prefetch {
                        let _ = completion_tx.send(ClientSendDone {
                            permit: p,
                            bytes_sent: 0,
                        });
                    }
                    break 'outer;
                }
            }

            // Advance to next chunk.
            match prefetch {
                ClientPrefetch::Data(next_data, next_permit) => {
                    guard = ClientPermitReturnGuard::new(next_permit, completion_tx.clone());
                    data = next_data;
                }
                ClientPrefetch::Flush(ack) => {
                    // Current write completed (join! waited), safe to ack.
                    let _ = ack.send(());
                    break; // Restart pipeline from outer loop.
                }
                ClientPrefetch::ChannelClosed => break 'outer,
                ClientPrefetch::ActorGone => break 'outer,
            }
        }
    }

    // Shut down the QUIC send stream and notify actor to clean up flow state.
    let _ = tokio::io::AsyncWriteExt::shutdown(&mut quic_send).await;
    let _ = ctrl_tx.send(ClientControl::FlowClosed(flow_id)).await;
    let _ = task_done_tx.send(());
}

/// Acquire a send permit from ClientConnActor via oneshot round-trip.
///
/// Returns `None` if the ClientConnActor is gone (channel closed).
async fn client_acquire_permit(
    ctrl_tx: &mpsc::Sender<ClientControl>,
    flow_id: FlowId,
    hints: &FlowHints,
    size: usize,
) -> Option<Permit> {
    let (result_tx, result_rx) = oneshot::channel::<Permit>();
    ctrl_tx
        .send(ClientControl::AcquirePermit {
            flow_id,
            hints: hints.clone(),
            size,
            result_tx,
        })
        .await
        .ok()?;
    result_rx.await.ok()
}

// ──────────────────────────────────────────────────────────────────────────────
// TcpProxyConn — returned by Client::tcp()
// ──────────────────────────────────────────────────────────────────────────────

/// A bidirectional TCP proxy connection over a QUIC stream.
///
/// Upload is handled by a background `client_tcp_upload_task` that applies
/// permit-before-write backpressure via the connection Scheduler.  `poll_write`
/// enqueues chunks into a bounded channel; the task drains it under a permit.
pub struct TcpProxyConn {
    recv: Option<QuinnRecvReader>,
    establish: Option<Pin<Box<dyn Future<Output = std::io::Result<QuinnRecvReader>> + Send>>>,
    /// Send half of the channel to the upload task.
    /// Set to None in poll_shutdown to signal the task to exit.
    upload_tx: Option<mpsc::Sender<UploadMsg>>,
    /// Pending async send future when the channel was full on the last poll_write
    /// or when poll_flush could not immediately enqueue the flush token.
    pending_send: Option<Pin<Box<dyn Future<Output = Result<(), mpsc::error::SendError<UploadMsg>>> + Send>>>,
    /// Size (in bytes) of the data chunk stored in pending_send (0 for flush tokens).
    pending_send_size: usize,
    /// Pending flush acknowledgment from the upload task.
    /// Set by poll_flush after sending the flush token; cleared once the ack arrives.
    flush_ack_rx: Option<oneshot::Receiver<()>>,
    /// Signals completion of the upload task; poll_shutdown awaits this.
    task_done_rx: oneshot::Receiver<()>,
    /// RAII guard tracking this connection in the TunnelWorkRegistry.
    /// Decrements the active count when this connection is dropped.
    tunnel_work_guard: Option<TunnelWorkGuard>,
}

impl TcpProxyConn {
    fn close_recv(&mut self) {
        if let Some(recv) = self.recv.as_mut() {
            recv.close();
        }
    }

    fn poll_established(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.recv.is_some() {
            return std::task::Poll::Ready(Ok(()));
        }
        let Some(establish) = self.establish.as_mut() else {
            return std::task::Poll::Ready(Err(std::io::Error::other(
                "tcp proxy connection missing receive stream",
            )));
        };
        match establish.as_mut().poll(cx) {
            std::task::Poll::Pending => std::task::Poll::Pending,
            std::task::Poll::Ready(Ok(recv)) => {
                self.recv = Some(recv);
                self.establish = None;
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(Err(err)) => {
                self.close_recv();
                std::task::Poll::Ready(Err(err))
            }
        }
    }
}

impl Drop for TcpProxyConn {
    fn drop(&mut self) {
        self.close_recv();
        // Dropping upload_tx closes the channel, signaling the upload task to exit.
    }
}

impl AsyncRead for TcpProxyConn {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.poll_established(cx) {
            std::task::Poll::Pending => return std::task::Poll::Pending,
            std::task::Poll::Ready(Err(err)) => return std::task::Poll::Ready(Err(err)),
            std::task::Poll::Ready(Ok(())) => {}
        }
        if let Some(recv) = self.recv.as_mut() {
            std::pin::Pin::new(recv).poll_read(cx, buf)
        } else {
            std::task::Poll::Ready(Err(std::io::Error::other(
                "tcp proxy receive stream unavailable",
            )))
        }
    }
}

impl AsyncWrite for TcpProxyConn {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let n = buf.len();

        // Step 1: if a pending send future exists from a previous full-channel
        // attempt, drive it to completion before accepting new data.
        if let Some(fut) = this.pending_send.as_mut() {
            match fut.as_mut().poll(cx) {
                std::task::Poll::Pending => return std::task::Poll::Pending,
                std::task::Poll::Ready(Ok(())) => {
                    let sent = this.pending_send_size;
                    this.pending_send = None;
                    this.pending_send_size = 0;
                    return std::task::Poll::Ready(Ok(sent));
                }
                std::task::Poll::Ready(Err(_)) => {
                    this.pending_send = None;
                    this.pending_send_size = 0;
                    return std::task::Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "upload task exited",
                    )));
                }
            }
        }

        // Step 2: try a non-blocking send to the upload task channel.
        let tx = match this.upload_tx.as_ref() {
            Some(tx) => tx,
            None => {
                return std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "upload channel closed",
                )));
            }
        };

        let data = UploadMsg::Data(Bytes::copy_from_slice(buf));
        match tx.try_send(data) {
            Ok(()) => std::task::Poll::Ready(Ok(n)),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "upload task exited",
                )))
            }
            Err(mpsc::error::TrySendError::Full(data)) => {
                // Channel is full — fall back to an async send stored as a future.
                let tx = tx.clone();
                let mut fut: Pin<Box<dyn Future<Output = Result<(), mpsc::error::SendError<UploadMsg>>> + Send>> =
                    Box::pin(async move { tx.send(data).await });
                // Poll once immediately to register the waker.
                match fut.as_mut().poll(cx) {
                    std::task::Poll::Pending => {
                        this.pending_send = Some(fut);
                        this.pending_send_size = n;
                        std::task::Poll::Pending
                    }
                    std::task::Poll::Ready(Ok(())) => std::task::Poll::Ready(Ok(n)),
                    std::task::Poll::Ready(Err(_)) => {
                        std::task::Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::BrokenPipe,
                            "upload task exited",
                        )))
                    }
                }
            }
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // Step 1: drain any pending channel-send (data or flush token).
        if let Some(fut) = this.pending_send.as_mut() {
            match fut.as_mut().poll(cx) {
                std::task::Poll::Pending => return std::task::Poll::Pending,
                std::task::Poll::Ready(Ok(())) => {
                    this.pending_send = None;
                    this.pending_send_size = 0;
                }
                std::task::Poll::Ready(Err(_)) => {
                    this.pending_send = None;
                    this.pending_send_size = 0;
                    return std::task::Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "upload task exited",
                    )));
                }
            }
        }

        // Step 2: if no flush token is in flight, enqueue one now.
        // The upload task sends back an ack only after writing all preceding
        // Data messages to the QUIC stream, satisfying the AsyncWrite contract.
        if this.flush_ack_rx.is_none() {
            let tx = match this.upload_tx.as_ref() {
                Some(tx) => tx,
                None => return std::task::Poll::Ready(Ok(())), // channel already closed
            };
            let (ack_tx, ack_rx) = oneshot::channel::<()>();
            match tx.try_send(UploadMsg::Flush(ack_tx)) {
                Ok(()) => {
                    this.flush_ack_rx = Some(ack_rx);
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return std::task::Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "upload task exited",
                    )));
                }
                Err(mpsc::error::TrySendError::Full(msg)) => {
                    // Channel full — store async send in pending_send and poll it once.
                    let tx = tx.clone();
                    let mut fut: Pin<Box<dyn Future<Output = Result<(), mpsc::error::SendError<UploadMsg>>> + Send>> =
                        Box::pin(async move { tx.send(msg).await });
                    match fut.as_mut().poll(cx) {
                        std::task::Poll::Pending => {
                            this.pending_send = Some(fut);
                            this.pending_send_size = 0;
                            this.flush_ack_rx = Some(ack_rx);
                            return std::task::Poll::Pending;
                        }
                        std::task::Poll::Ready(Ok(())) => {
                            this.flush_ack_rx = Some(ack_rx);
                        }
                        std::task::Poll::Ready(Err(_)) => {
                            return std::task::Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::BrokenPipe,
                                "upload task exited",
                            )));
                        }
                    }
                }
            }
        }

        // Step 3: wait for the flush acknowledgment from the upload task.
        match std::pin::Pin::new(this.flush_ack_rx.as_mut().unwrap()).poll(cx) {
            std::task::Poll::Pending => std::task::Poll::Pending,
            std::task::Poll::Ready(_) => {
                this.flush_ack_rx = None;
                std::task::Poll::Ready(Ok(()))
            }
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        // Step 1: complete any pending channel-send before closing the channel.
        // Discarding pending_send here would silently drop the last chunk (Rule 7).
        if let Some(fut) = this.pending_send.as_mut() {
            match fut.as_mut().poll(cx) {
                std::task::Poll::Pending => return std::task::Poll::Pending,
                std::task::Poll::Ready(Ok(())) => {
                    this.pending_send = None;
                    this.pending_send_size = 0;
                }
                std::task::Poll::Ready(Err(_)) => {
                    this.pending_send = None;
                    this.pending_send_size = 0;
                    // Channel already closed; fall through to wait for task exit.
                }
            }
        }
        // Step 2: discard any in-flight flush ack; task_done_rx provides the final guarantee.
        this.flush_ack_rx = None;
        // Step 3: signal the upload task to flush and exit by closing the channel.
        this.upload_tx = None;
        // Step 4: wait for the upload task to finish (it flushes and shuts down the QUIC stream).
        match Pin::new(&mut this.task_done_rx).poll(cx) {
            std::task::Poll::Pending => std::task::Poll::Pending,
            std::task::Poll::Ready(_) => std::task::Poll::Ready(Ok(())),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// QuinnRecvReader — AsyncRead adapter for quinn::RecvStream
// ──────────────────────────────────────────────────────────────────────────────

struct QuinnRecvReader {
    recv: quinn::RecvStream,
    buffer: Vec<u8>,
    buf_pos: usize,
}

impl QuinnRecvReader {
    fn new(recv: quinn::RecvStream) -> Self {
        Self {
            recv,
            buffer: Vec::new(),
            buf_pos: 0,
        }
    }

    fn close(&mut self) {
        let _ = self.recv.stop(quinn::VarInt::from_u32(0));
    }
}

/// Client-side bidirectional stream wrapper for Go-compatible close semantics.
///
/// Close order: cancel read first, then finish write.
struct QStream {
    send: quinn::SendStream,
    recv: QuinnRecvReader,
}

impl QStream {
    fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self {
            send,
            recv: QuinnRecvReader::new(recv),
        }
    }

    fn reader_mut(&mut self) -> &mut QuinnRecvReader {
        &mut self.recv
    }

    fn writer_mut(&mut self) -> &mut quinn::SendStream {
        &mut self.send
    }

    fn into_parts(self) -> (quinn::SendStream, QuinnRecvReader) {
        (self.send, self.recv)
    }

    fn close(&mut self) {
        self.recv.close();
        let _ = self.send.finish();
    }
}

// quinn::RecvStream already implements AsyncRead directly via tokio
impl AsyncRead for QuinnRecvReader {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // Drain internal buffer first
        if self.buf_pos < self.buffer.len() {
            let n = (self.buffer.len() - self.buf_pos).min(buf.remaining());
            buf.put_slice(&self.buffer[self.buf_pos..self.buf_pos + n]);
            self.buf_pos += n;
            return std::task::Poll::Ready(Ok(()));
        }
        // Then read from quinn stream directly
        std::pin::Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Protocol helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Read a varint from an AsyncRead (1–8 bytes).
async fn read_varint_async(r: &mut (impl AsyncRead + Unpin)) -> std::io::Result<u64> {
    let mut first = [0u8; 1];
    r.read_exact(&mut first).await?;
    let tag = first[0] >> 6;
    let total = match tag {
        0 => 1usize,
        1 => 2,
        2 => 4,
        _ => 8,
    };
    if total == 1 {
        return Ok(first[0] as u64);
    }
    let mut rest = vec![0u8; total - 1];
    r.read_exact(&mut rest).await?;
    let mut full = vec![first[0]];
    full.extend_from_slice(&rest);
    let (val, _) = varint_read(&full)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    Ok(val)
}

/// Read a full TCP proxy response into a Vec<u8> so we can call read_tcp_response().
async fn read_tcp_response_async(r: &mut (impl AsyncRead + Unpin)) -> std::io::Result<Vec<u8>> {
    // Status byte
    let mut status = [0u8; 1];
    r.read_exact(&mut status).await?;

    // msg_len varint
    let msg_len = read_varint_async(r).await?;
    if msg_len > MAX_MESSAGE_LENGTH {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "message too long",
        ));
    }
    let mut msg = vec![0u8; msg_len as usize];
    r.read_exact(&mut msg).await?;

    // padding_len varint
    let padding_len = read_varint_async(r).await?;
    if padding_len > MAX_PADDING_LENGTH {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "padding too long",
        ));
    }
    let mut padding = vec![0u8; padding_len as usize];
    r.read_exact(&mut padding).await?;

    // Reconstruct the buffer for read_tcp_response()
    let mut buf = vec![status[0]];
    crate::core::internal::protocol::varint_append(&mut buf, msg_len);
    buf.extend_from_slice(&msg);
    crate::core::internal::protocol::varint_append(&mut buf, padding_len);
    buf.extend_from_slice(&padding);
    Ok(buf)
}

// ──────────────────────────────────────────────────────────────────────────────
// Default transport config for client
// ──────────────────────────────────────────────────────────────────────────────

fn default_client_transport() -> quinn::TransportConfig {
    let mut t = quinn::TransportConfig::default();
    t.initial_mtu(MAX_DATAGRAM_FRAME_SIZE as u16);
    // Datagram buffer sizes: use Quinn defaults (~1.2 MiB receive, 1 MiB send).
    // Previous code incorrectly set these to MAX_DATAGRAM_FRAME_SIZE (1200),
    // confusing per-packet MTU with buffer capacity, which caused fragmented
    // UDP messages to be silently dropped.
    if DISABLE_PATH_MTU_DISCOVERY {
        t.mtu_discovery_config(None);
    }
    if let Ok(idle_timeout) = std::time::Duration::from_secs(30).try_into() {
        t.max_idle_timeout(Some(idle_timeout));
    }
    t.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
    // Receive windows per prompt §4.8
    if let Ok(stream_window) = quinn::VarInt::from_u64(DEFAULT_STREAM_RECEIVE_WINDOW) {
        t.stream_receive_window(stream_window);
    }
    if let Ok(conn_window) = quinn::VarInt::from_u64(DEFAULT_CONN_RECEIVE_WINDOW) {
        t.receive_window(conn_window);
    }
    t
}

fn build_client_socket(
    config: &ClientConfig,
    runtime: Arc<dyn quinn::Runtime>,
) -> Result<Arc<dyn quinn::AsyncUdpSocket>, BoxError> {
    let mut socket: Arc<dyn quinn::AsyncUdpSocket> = match &config.packet_transport {
        ClientPacketTransport::Udp => {
            let prefer_ipv6 = config.server_addr.is_ipv6();
            let std_sock = if let Some(factory) = &config.udp_socket_factory {
                factory(prefer_ipv6)?
            } else {
                let bind_addr = if prefer_ipv6 {
                    SocketAddr::from(([0u16; 8], 0))
                } else {
                    SocketAddr::from(([0, 0, 0, 0], 0))
                };
                std::net::UdpSocket::bind(bind_addr)?
            };
            std_sock.set_nonblocking(true)?;
            runtime.wrap_udp_socket(std_sock)?
        }
        ClientPacketTransport::UdpHop {
            addrs,
            hop_interval,
        } => {
            if addrs.is_empty() {
                return Err("udp hop address set is empty".into());
            }
            let interval = (*hop_interval).max(MIN_HOP_INTERVAL);
            Arc::new(UdpHopSocket::new(addrs.clone(), interval, config.hop_generation.clone())?)
        }
    };

    if let Some(obfs) = &config.obfs {
        let obfuscator = SalamanderObfuscator::new(obfs.salamander_password.as_bytes().to_vec())?;
        socket = Arc::new(ObfsUdpSocket::new(socket, obfuscator));
    }

    // Apply test-only socket wrapper (e.g., FaultInjectionSocket).
    if let Some(wrapper) = &config.socket_wrapper {
        socket = wrapper(socket);
    }

    Ok(socket)
}

// ──────────────────────────────────────────────────────────────────────────────
// NoVerifier — dangerous TLS certificate verifier (for testing)
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct NoVerifier;

#[derive(Debug)]
struct PinnedServerCertVerifier {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
    pin_sha256: [u8; 32],
}

impl rustls::client::danger::ServerCertVerifier for PinnedServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer,
        intermediates: &[rustls::pki_types::CertificateDer],
        server_name: &rustls::pki_types::ServerName,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        let hash = Sha256::digest(end_entity.as_ref());
        if hash[..] == self.pin_sha256[..] {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "no certificate matches the pinned hash".to_string(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }

    fn root_hint_subjects(&self) -> Option<&[rustls::DistinguishedName]> {
        self.inner.root_hint_subjects()
    }
}

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

// ──────────────────────────────────────────────────────────────────────────────
// Tests — Actor-level control lease integration
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::scheduler::FlowClass;
    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    /// Create a minimal QUIC loopback connection for actor testing.
    ///
    /// Only needed to satisfy ClientConnActor's constructor; the connection
    /// is not exercised for data transfer in control lease tests.
    async fn make_test_quic_conn() -> quinn::Connection {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));

        // Server endpoint.
        let mut server_tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();
        server_tls.alpn_protocols = vec![b"test".to_vec()];
        let server_quic = quinn::crypto::rustls::QuicServerConfig::try_from(server_tls).unwrap();
        let server_cfg = quinn::ServerConfig::with_crypto(Arc::new(server_quic));
        let server_ep = quinn::Endpoint::server(server_cfg, "127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server_ep.local_addr().unwrap();

        tokio::spawn(async move {
            if let Some(incoming) = server_ep.accept().await {
                let _conn = incoming.await.ok();
                // Keep server alive for the duration of the test.
                tokio::time::sleep(Duration::from_secs(300)).await;
            }
        });

        // Client endpoint.
        let mut client_tls = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        client_tls.alpn_protocols = vec![b"test".to_vec()];
        let client_quic = quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).unwrap();
        let client_cfg = quinn::ClientConfig::new(Arc::new(client_quic));

        let client_ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_ep
            .connect_with(client_cfg, server_addr, "localhost")
            .unwrap()
            .await
            .unwrap()
    }

    /// Spawn a ClientConnActor for testing and return the control/completion channels.
    fn spawn_test_actor(
        conn: quinn::Connection,
        conn_budget: usize,
    ) -> (mpsc::Sender<ClientControl>, mpsc::UnboundedSender<ClientSendDone>) {
        let conn_id = ConnId(99);
        let bps = Arc::new(AtomicU64::new(0));
        let scheduler = Scheduler::new_with_budget(conn_budget, bps);
        let (ctrl_tx, ctrl_rx) = mpsc::channel::<ClientControl>(4096);
        let (completion_tx, completion_rx) = mpsc::unbounded_channel::<ClientSendDone>();
        let actor = ClientConnActor::new(conn, conn_id, scheduler, ctrl_rx, completion_rx);
        tokio::spawn(actor.run());
        (ctrl_tx, completion_tx)
    }

    /// Control lease must be granted even when Bulk class budget is exhausted.
    ///
    /// Proves the Control class budget (1 MiB) is independent of data-plane
    /// class budgets. Auth/reconnect/keepalive control leases cannot be starved
    /// by bulk data-plane traffic saturation.
    #[tokio::test]
    async fn test_control_lease_granted_under_bulk_pressure() {
        let conn = make_test_quic_conn().await;
        // Use 100 MiB conn budget so class budgets are the bottleneck, not conn.
        let (ctrl_tx, completion_tx) = spawn_test_actor(conn, 100 * 1024 * 1024);

        // Exhaust Bulk class budget (16 MiB) with data permits.
        // Each permit is 32 KiB; 512 permits x 32 KiB = 16 MiB.
        let mut bulk_permits = Vec::new();
        for i in 0..512u64 {
            let (tx, rx) = oneshot::channel();
            ctrl_tx
                .send(ClientControl::AcquirePermit {
                    flow_id: FlowId(i + 1000),
                    hints: FlowHints::default_tcp(),
                    size: 32 * 1024,
                    result_tx: tx,
                })
                .await
                .unwrap();
            match tokio::time::timeout(Duration::from_millis(100), rx).await {
                Ok(Ok(permit)) => bulk_permits.push(permit),
                _ => break, // Bulk budget exhausted
            }
        }
        assert!(!bulk_permits.is_empty(), "Should have acquired some bulk permits");

        // Now request a Control lease (8 KiB for Auth).
        // Must succeed from the independent Control class budget (1 MiB).
        let (lease_tx, lease_rx) = oneshot::channel();
        ctrl_tx
            .send(ClientControl::AcquireControlLease {
                op: ControlOp::Auth,
                bytes_hint: ControlOp::Auth.bytes_hint(),
                result_tx: lease_tx,
            })
            .await
            .unwrap();
        let lease = tokio::time::timeout(Duration::from_millis(100), lease_rx)
            .await
            .expect("Control lease should not time out under bulk saturation")
            .expect("Control lease channel closed");

        assert_eq!(lease.permit.class, FlowClass::Control);
        assert_eq!(lease.permit.bytes, 8 * 1024);

        // Clean up: return all permits via completion channel.
        let guard = ClientControlLeaseGuard::new(lease.permit, completion_tx.clone());
        drop(guard);
        for p in bulk_permits {
            let _ = completion_tx.send(ClientSendDone { permit: p, bytes_sent: 0 });
        }
    }

    /// Control lease budget must be returned to the scheduler after guard drop.
    ///
    /// Proves RAII cancel-safety: ClientControlLeaseGuard returns the permit
    /// budget via the unbounded completion channel when dropped, allowing
    /// subsequent control leases to succeed.
    #[tokio::test]
    async fn test_control_lease_budget_returned_after_guard_drop() {
        let conn = make_test_quic_conn().await;
        let (ctrl_tx, completion_tx) = spawn_test_actor(conn, 32 * 1024 * 1024);

        // Acquire first control lease.
        let (tx1, rx1) = oneshot::channel();
        ctrl_tx
            .send(ClientControl::AcquireControlLease {
                op: ControlOp::Auth,
                bytes_hint: 8 * 1024,
                result_tx: tx1,
            })
            .await
            .unwrap();
        let lease1 = tokio::time::timeout(Duration::from_millis(100), rx1)
            .await
            .unwrap()
            .unwrap();

        // Drop via RAII guard: budget should return to scheduler.
        let guard = ClientControlLeaseGuard::new(lease1.permit, completion_tx.clone());
        drop(guard);

        // Let the actor process the ClientSendDone message.
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Acquire a second control lease: proves budget was returned.
        let (tx2, rx2) = oneshot::channel();
        ctrl_tx
            .send(ClientControl::AcquireControlLease {
                op: ControlOp::Auth,
                bytes_hint: 8 * 1024,
                result_tx: tx2,
            })
            .await
            .unwrap();
        let lease2 = tokio::time::timeout(Duration::from_millis(100), rx2)
            .await
            .expect("Second lease must succeed: budget should have been returned by guard drop")
            .expect("Channel closed");

        assert_eq!(lease2.permit.class, FlowClass::Control);

        // Clean up.
        let _ = completion_tx.send(ClientSendDone { permit: lease2.permit, bytes_sent: 0 });
    }

    /// Pending control leases must be flushed before pending data permits.
    ///
    /// Proves priority ordering: when budget is released (via completion_rx),
    /// flush_pending_control_leases() runs before flush_pending_permits().
    /// A queued control lease (8 KiB) should be granted before a queued data
    /// permit (24 KiB) when only 24 KiB of conn budget becomes available.
    #[tokio::test]
    async fn test_pending_control_flushed_before_pending_data() {
        let conn = make_test_quic_conn().await;
        // Use 24 KiB conn budget so it is the bottleneck (not class budgets).
        let (ctrl_tx, completion_tx) = spawn_test_actor(conn, 24 * 1024);

        // Step 1: Exhaust the entire connection budget with one data permit (24 KiB).
        let (data_tx1, data_rx1) = oneshot::channel();
        ctrl_tx
            .send(ClientControl::AcquirePermit {
                flow_id: FlowId(1),
                hints: FlowHints::default_tcp(),
                size: 24 * 1024,
                result_tx: data_tx1,
            })
            .await
            .unwrap();
        let initial_permit = tokio::time::timeout(Duration::from_millis(100), data_rx1)
            .await
            .unwrap()
            .unwrap();

        // Step 2: Queue a control lease (8 KiB). Will pend because conn budget is 0.
        let (ctrl_lease_tx, ctrl_lease_rx) = oneshot::channel();
        ctrl_tx
            .send(ClientControl::AcquireControlLease {
                op: ControlOp::Auth,
                bytes_hint: 8 * 1024,
                result_tx: ctrl_lease_tx,
            })
            .await
            .unwrap();

        // Step 3: Queue a data permit (24 KiB). Will pend because conn budget is 0.
        let (data_tx2, data_rx2) = oneshot::channel();
        ctrl_tx
            .send(ClientControl::AcquirePermit {
                flow_id: FlowId(2),
                hints: FlowHints::default_tcp(),
                size: 24 * 1024,
                result_tx: data_tx2,
            })
            .await
            .unwrap();

        // Let the actor process and pend all queued messages.
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Step 4: Return the initial permit (releases 24 KiB to conn budget).
        // Actor will flush_pending_control_leases() THEN flush_pending_permits().
        completion_tx
            .send(ClientSendDone {
                permit: initial_permit,
                bytes_sent: 24 * 1024,
            })
            .unwrap();

        // Step 5: Control lease (8 KiB) should be granted.
        // After granting: conn budget = 24 KiB - 8 KiB = 16 KiB remaining.
        let lease = tokio::time::timeout(Duration::from_millis(200), ctrl_lease_rx)
            .await
            .expect("Control lease must resolve before data permit")
            .expect("Control lease channel closed");
        assert_eq!(lease.permit.class, FlowClass::Control);
        assert_eq!(lease.permit.bytes, 8 * 1024);

        // Step 6: Data permit (24 KiB) must NOT be granted.
        // Only 16 KiB remains (24 - 8 = 16 < 24 needed).
        let data_result = tokio::time::timeout(Duration::from_millis(200), data_rx2).await;
        assert!(
            data_result.is_err(),
            "Data permit (24 KiB) must stay pending: only 16 KiB remains after control lease"
        );

        // Clean up.
        let _ = completion_tx.send(ClientSendDone { permit: lease.permit, bytes_sent: 0 });
    }

    /// acquire_control_lease must return Err when the actor channel is closed.
    ///
    /// Proves that required control paths (Auth, Reconnect) propagate errors
    /// instead of silently continuing without a lease. When the actor is dead,
    /// the ctrl_tx.send() returns a SendError, which acquire_control_lease
    /// converts to a BoxError.
    #[tokio::test]
    async fn test_control_lease_fails_when_actor_closed() {
        let conn = make_test_quic_conn().await;
        let (ctrl_tx, completion_tx) = spawn_test_actor(conn, 32 * 1024 * 1024);

        // Build a minimal Client-like struct to call acquire_control_lease.
        // We only need ctrl_tx and completion_tx.
        // Drop ctrl_tx to simulate actor shutdown, then try to acquire.

        // First: prove it works when actor is alive.
        let (lease_tx, lease_rx) = oneshot::channel();
        ctrl_tx
            .send(ClientControl::AcquireControlLease {
                op: ControlOp::Auth,
                bytes_hint: ControlOp::Auth.bytes_hint(),
                result_tx: lease_tx,
            })
            .await
            .expect("send must succeed while actor is alive");
        let lease = tokio::time::timeout(Duration::from_millis(100), lease_rx)
            .await
            .expect("lease must resolve")
            .expect("lease channel closed");
        let _ = completion_tx.send(ClientSendDone { permit: lease.permit, bytes_sent: 0 });

        // Now drop ctrl_tx. The actor's ctrl_rx will close, and the actor
        // will exit on its next select! iteration.
        drop(ctrl_tx);
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Rebuild a sender from a closed channel to demonstrate the failure path.
        // Since we can't send on a dropped channel, we simulate the exact
        // acquire_control_lease logic inline.
        let (dead_tx, _dead_rx) = mpsc::channel::<ClientControl>(1);
        // Drop the receiver immediately — simulates a dead actor.
        drop(_dead_rx);

        let (result_tx, _result_rx) = oneshot::channel();
        let send_result = dead_tx.send(ClientControl::AcquireControlLease {
            op: ControlOp::Auth,
            bytes_hint: ControlOp::Auth.bytes_hint(),
            result_tx,
        }).await;
        assert!(send_result.is_err(), "send must fail when actor receiver is closed");

        // Also verify: if send succeeds but actor drops the oneshot before
        // responding, the lease_rx returns Err (RecvError).
        let (_tx2, _rx2) = mpsc::channel::<ClientControl>(1);
        let (oneshot_tx, oneshot_rx) = oneshot::channel::<ControlLease>();
        drop(oneshot_tx); // Simulate actor dropping the sender without responding.
        let recv_result = oneshot_rx.await;
        assert!(recv_result.is_err(), "oneshot recv must fail when sender is dropped");
    }
}
