/// Rysteria server implementation.
///
/// Go equivalent: hysteria/core/server/server.go
///
/// Architecture:
/// - `HyServerConn`: custom h3::quic::Connection<Bytes> wrapper that intercepts
///   TCP proxy streams (frame type 0x401) before h3 sees them.
/// - H3 accept loop handles auth (POST /auth).
/// - TCP proxy streams arrive via an mpsc channel and are relayed bidirectionally.
/// - UDP relay via QUIC datagrams (RFC 9221, plain datagrams — NOT H3 datagrams).
use std::{
    collections::HashMap,
    error::Error,
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use h3::quic::{
    self as quic, BidiStream as QuicBidiStream, ConnectionErrorIncoming,
    RecvStream as QuicRecvStream, SendStream as QuicSendStream,
    SendStreamUnframed as QuicSendStreamUnframed, StreamErrorIncoming, StreamId, WriteBuf,
};
use h3_quinn::Connection as H3QuinnConn;
use http_body_util::BodyExt;
use rand::RngExt;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::{Notify, RwLock, mpsc},
};
use tokio_util::sync::CancellationToken;

use std::sync::Mutex as StdMutex;

use crate::core::connection_actor::{ConnControl, ConnectionActor};
use crate::core::flow_actor;
use crate::core::internal::congestion::switchable::{CongestionHandle, new_switchable_factory};
use crate::core::internal::shard::{ConnId, ShardPool};
use crate::core::scheduler::{FlowHints, FlowId, Scheduler, UdpSessionId};
use crate::core::internal::frag::{Defragger, frag_udp_message, new_frag_packet_id};
use crate::core::internal::pmtud::DISABLE_PATH_MTU_DISCOVERY;
use crate::core::internal::protocol::{
    DEFAULT_CONN_RECEIVE_WINDOW, DEFAULT_STREAM_RECEIVE_WINDOW, FRAME_TYPE_TCP_REQUEST,
    HEADER_AUTH, HEADER_CC_RX, HEADER_PADDING, HEADER_UDP_ENABLED, MAX_ADDRESS_LENGTH,
    MAX_DATAGRAM_FRAME_SIZE, MAX_PADDING_LENGTH, MAX_UDP_SIZE, STATUS_AUTH_OK, UdpMessage,
    parse_udp_message, varint_read, write_tcp_response,
};
use crate::core::internal::utils::AtomicTime;
use crate::extras::auth::Authenticator;
use crate::unmap_ipv4;
use crate::extras::masq::MasqHandler;
use crate::extras::obfs::SalamanderObfuscator;
use crate::extras::outbounds::utils::{DirectOutbound, PluggableOutbound, UdpOutboundConn};
use crate::extras::tls::{GuardedCertResolver, SniGuardMode};
use crate::extras::trafficlogger::{StreamState, StreamStats, TrafficLogger};
use crate::extras::transport::obfsudp::ObfsUdpSocket;

// H3 error codes (RFC 9114 §8.1)
const H3_ERR_NO_ERROR: u32 = 0x100;
const H3_ERR_PROTOCOL_ERROR: u32 = 0x101;
const H3_MAX_FIELD_SECTION_SIZE: u64 = 1_048_576; // 1 MiB
const SPEEDTEST_DEST: &str = "@speedtest";
const SPEEDTEST_CHUNK_SIZE: usize = 64 * 1024;

// UDP session constants (§14.5)
const DEFAULT_UDP_IDLE_TIMEOUT_SECS: u64 = 60;
const UDP_IDLE_CLEANUP_INTERVAL_SECS: u64 = 1;

pub trait EventLogger: Send + Sync {
    fn connect(&self, addr: &SocketAddr, id: &str, tx: u64);
    fn disconnect(&self, addr: &SocketAddr, id: &str, err: Option<&(dyn Error + Send + Sync)>);
    fn tcp_request(&self, addr: &SocketAddr, id: &str, req_addr: &str);
    fn tcp_error(
        &self,
        addr: &SocketAddr,
        id: &str,
        req_addr: &str,
        err: Option<&(dyn Error + Send + Sync)>,
    );
    fn udp_request(&self, addr: &SocketAddr, id: &str, session_id: u32, req_addr: &str);
    fn udp_error(
        &self,
        addr: &SocketAddr,
        id: &str,
        session_id: u32,
        err: Option<&(dyn Error + Send + Sync)>,
    );
}

#[async_trait::async_trait]
pub trait RequestHook: Send + Sync {
    fn check(&self, is_udp: bool, req_addr: &str) -> bool;
    async fn tcp(
        &self,
        stream: &mut RecvStreamReader,
        req_addr: &mut String,
    ) -> io::Result<Vec<u8>>;
    fn udp(&self, data: &[u8], req_addr: &mut String) -> io::Result<()>;
}

pub type TransportConfigBuilder = Arc<dyn Fn() -> quinn::TransportConfig + Send + Sync>;

// ──────────────────────────────────────────────────────────────────────────────
// Public server config and Server struct
// ──────────────────────────────────────────────────────────────────────────────

/// Server configuration.
pub struct ServerConfig {
    /// Authentication backend.
    pub authenticator: Arc<dyn Authenticator>,
    /// TLS certificate chain (DER format).
    pub tls_cert: Vec<rustls::pki_types::CertificateDer<'static>>,
    /// TLS private key (DER format).
    pub tls_key: rustls::pki_types::PrivateKeyDer<'static>,
    /// Optional client-CA roots. If set, server requires mTLS client cert.
    pub tls_client_ca: Option<rustls::RootCertStore>,
    /// SNI guard mode applied at TLS handshake time.
    pub tls_sni_guard: SniGuardMode,
    /// Local bind address.
    pub addr: SocketAddr,
    /// QUIC transport settings (optional, uses defaults if None).
    pub transport: Option<quinn::TransportConfig>,
    /// Optional transport builder used for both endpoint config and per-connection config.
    ///
    /// This avoids relying on `TransportConfig: Clone` and ensures user-provided
    /// QUIC parameters are applied consistently on every accepted connection.
    pub transport_builder: Option<TransportConfigBuilder>,
    /// Server upload speed limit in bytes/sec (0 = no server-side cap).
    ///
    /// Go: `config.SpeedBps`.  Used in `server_select_congestion`.
    pub speed_bps: u64,
    /// Server download limit in bytes/sec sent to clients via `Hysteria-CC-RX`.
    pub speed_rx_bps: u64,
    /// If true, ignore client-declared bandwidth and keep BBR.
    pub ignore_client_bandwidth: bool,
    /// Optional server event logger.
    pub event_logger: Option<Arc<dyn EventLogger>>,
    /// Optional server traffic logger (including stream tracing).
    pub traffic_logger: Option<Arc<dyn TrafficLogger>>,
    /// Optional request hook (sniff / rewrite).
    pub request_hook: Option<Arc<dyn RequestHook>>,
    /// Optional pluggable outbound implementation.
    pub outbound: Option<Arc<dyn PluggableOutbound>>,
    /// Optional masquerade handler used on non-auth HTTP/3 requests.
    pub masq_handler: Option<Arc<dyn MasqHandler + Send + Sync>>,
    /// Disable UDP relay support.
    pub disable_udp: bool,
    /// Enable speed-test endpoint.
    pub speed_test: bool,
    /// Idle timeout for server UDP sessions.
    pub udp_idle_timeout: Duration,
    /// Optional Salamander obfuscation password.
    pub obfs_salamander_password: Option<String>,
    /// Number of ShardPool shard threads.
    ///
    /// Each authenticated QUIC connection is pinned to a fixed OS thread via
    /// `ShardPool`, eliminating cross-thread cache misses on hot-path connection
    /// state (Pingora NoSteal pattern).
    ///
    /// Default: number of available CPUs (`std::thread::available_parallelism()`).
    /// Set to 1 for single-threaded testing.
    pub shard_threads: Option<usize>,
}

/// QUIC/H3 server for Hysteria protocol.
pub struct Server {
    endpoint: quinn::Endpoint,
    config: Arc<ServerConfig>,
    /// Pre-built rustls TLS config (with ALPN="h3") shared across connections.
    tls: Arc<rustls::ServerConfig>,
}

impl Server {
    /// Create a new server, binding the QUIC endpoint.
    pub fn new(mut config: ServerConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        if config.outbound.is_none() {
            config.outbound = Some(Arc::new(DirectOutbound::default()));
        }

        // Build rustls TLS config with ALPN="h3" — used for ALL connections.
        let builder = rustls::ServerConfig::builder();
        let crypto_provider = Arc::clone(builder.crypto_provider());
        let cert_resolver = Arc::new(GuardedCertResolver::new(
            config.tls_cert.clone(),
            config.tls_key.clone_key(),
            config.tls_sni_guard,
            &crypto_provider,
        )?);
        let mut tls = if let Some(client_ca) = &config.tls_client_ca {
            let verifier =
                rustls::server::WebPkiClientVerifier::builder(Arc::new(client_ca.clone()))
                    .build()?;
            builder
                .with_client_cert_verifier(verifier)
                .with_cert_resolver(cert_resolver.clone())
        } else {
            builder
                .with_no_client_auth()
                .with_cert_resolver(cert_resolver)
        };
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let tls = Arc::new(tls);

        // Build the initial QUIC endpoint ServerConfig from the rustls config.
        // Per-connection transport configs (with per-connection SwitchableFactory)
        // are applied later via Incoming::accept_with().
        let quic_crypto = quinn_proto::crypto::rustls::QuicServerConfig::try_from(Arc::clone(&tls))
            .map_err(|e| format!("TLS QUIC config error: {}", e))?;

        let base_transport = if let Some(builder) = &config.transport_builder {
            builder()
        } else {
            config
                .transport
                .take()
                .unwrap_or_else(default_transport_config)
        };
        let transport = Arc::new(base_transport);

        let mut server_config = quinn::ServerConfig::with_crypto(
            Arc::new(quic_crypto) as Arc<dyn quinn_proto::crypto::ServerConfig>
        );
        server_config.transport_config(transport);

        let runtime: Arc<dyn quinn::Runtime> = Arc::new(quinn::TokioRuntime);
        let std_socket = std::net::UdpSocket::bind(config.addr)?;
        std_socket.set_nonblocking(true)?;
        let mut socket = runtime.wrap_udp_socket(std_socket)?;
        if let Some(psk) = &config.obfs_salamander_password {
            let obfs = SalamanderObfuscator::new(psk.as_bytes().to_vec())?;
            socket = Arc::new(ObfsUdpSocket::new(socket, obfs));
        }
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(server_config),
            socket,
            runtime,
        )?;
        Ok(Self {
            endpoint,
            config: Arc::new(config),
            tls,
        })
    }

    /// Accept connections forever, pinning each to a ShardPool shard.
    ///
    /// Creates one `ShardPool` for the lifetime of the server (Pingora NoSteal
    /// pattern). After TLS, each connection gets its own `ConnectionActor`
    /// spawned on a fixed OS thread — all sends for that connection go through
    /// the actor's `Scheduler` and never race across Tokio worker threads.
    pub async fn serve(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // One ShardPool per server lifetime. Connections are pinned via
        // `conn_id % shard_count` — always deterministic, always the same thread.
        let shard_count = self.config.shard_threads.unwrap_or_else(|| {
            std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4)
        });
        let shards = Arc::new(
            ShardPool::new(shard_count)
                .map_err(|e| format!("ShardPool creation failed: {e}"))?,
        );
        tracing::info!(shards = shard_count, "connection shard pool ready");

        // graceful shutdown via Ctrl+C / SIGTERM.
        // Stage 1: stop accept. Stage 2: drain (5s). Stage 3: force close.
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        tokio::spawn(async move {
            // Wait for Ctrl+C (also catches SIGINT on Unix).
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("shutdown signal received — stopping accept loop");
            let _ = shutdown_tx.send(true);
        });

        // Accept loop — Stage 1: stop when shutdown signal fires.
        loop {
            tokio::select! {
                // Shutdown takes priority: check it first to respond promptly.
                biased;
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break; // Stage 1 complete — stop accepting new connections.
                    }
                }
                incoming_opt = self.endpoint.accept() => {
                    let incoming = match incoming_opt {
                        None => break, // endpoint closed externally
                        Some(i) => i,
                    };
                    let config = Arc::clone(&self.config);
                    let tls = Arc::clone(&self.tls);
                    let shards = Arc::clone(&shards);
                    // Clone shutdown_rx so each connection task can detect Stage 2.
                    let conn_shutdown_rx = shutdown_rx.clone();

                    tokio::spawn(async move {
                        let remote_addr = unmap_ipv4(incoming.remote_address());

                        // Per-connection SwitchableFactory: each connection gets its own
                        // congestion handle so Brutal and BBR are isolated.
                        let (factory, cc_handle) = new_switchable_factory();
                        let mut transport = if let Some(builder) = &config.transport_builder {
                            builder()
                        } else {
                            default_transport_config()
                        };
                        transport.congestion_controller_factory(Arc::new(factory));

                        // Build per-connection QUIC ServerConfig (reuses pre-built TLS).
                        let quic_crypto = match quinn_proto::crypto::rustls::QuicServerConfig::try_from(Arc::clone(&tls)) {
                            Ok(c) => c,
                            Err(err) => {
                                tracing::warn!(addr = %remote_addr, error = %err, "QUIC server config error");
                                return;
                            }
                        };
                        let mut per_conn_cfg = quinn::ServerConfig::with_crypto(
                            Arc::new(quic_crypto) as Arc<dyn quinn_proto::crypto::ServerConfig>,
                        );
                        per_conn_cfg.transport_config(Arc::new(transport));

                        let connecting = match incoming.accept_with(Arc::new(per_conn_cfg)) {
                            Ok(c) => c,
                            Err(err) => {
                                tracing::warn!(addr = %remote_addr, error = %err, "QUIC connection rejected");
                                return;
                            }
                        };

                        match connecting.await {
                            Ok(conn) => {
                                // Assign a stable ConnId and build the send-path actor.
                                let actor_conn_id = ConnId(rand::random::<u64>());
                                let effective_bps = cc_handle.effective_bps_arc();

                                // Shared scheduler: ConnectionActor owns the Scheduler;
                                // TcpFlowActors borrow the Arc to call try_issue_permit.
                                let scheduler = Arc::new(StdMutex::new(Scheduler::new(
                                    Arc::clone(&effective_bps),
                                )));

                                // Control channel: TcpFlowActors → ConnectionActor.
                                let (ctrl_tx, ctrl_rx) = mpsc::channel::<ConnControl>(4096);

                                let actor = ConnectionActor::new(
                                    conn.clone(),
                                    Arc::clone(&scheduler),
                                    ctrl_rx,
                                );

                                // Spawn ConnectionActor on the shard that owns this ConnId.
                                // It never migrates — no cross-thread cache misses.
                                shards.pin(actor_conn_id).spawn(async move {
                                    actor.run().await;
                                });

                                let _ = handle_connection(
                                    conn,
                                    config,
                                    cc_handle,
                                    actor_conn_id,
                                    ctrl_tx,
                                    scheduler,
                                    conn_shutdown_rx,
                                )
                                .await;
                            }
                            Err(err) => {
                                tracing::warn!(addr = %remote_addr, error = %err, "TLS error");
                            }
                        }
                    });
                }
            }
        }

        // Stage 2: drain — wait for in-flight connections to close (up to 5 s).
        // wait_idle() returns as soon as all QUIC connections have closed.
        // Timeout ensures we don't block forever if a connection is stuck.
        tracing::info!("graceful shutdown: draining in-flight connections (up to 5s)");
        let _ = tokio::time::timeout(
            Duration::from_secs(5),
            self.endpoint.wait_idle(),
        )
        .await;

        // Stage 3: force close — send NO_ERROR to all remaining QUIC connections.
        self.endpoint.close(quinn::VarInt::from_u32(H3_ERR_NO_ERROR), b"shutdown");
        tracing::info!("graceful shutdown complete");

        Ok(())
    }

    /// Returns the local address this server is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.endpoint.local_addr().unwrap_or(self.config.addr)
    }

    /// Close the server endpoint.
    pub fn close(&self) {
        self.endpoint
            .close(quinn::VarInt::from_u32(H3_ERR_NO_ERROR), b"");
    }
}

fn default_transport_config() -> quinn::TransportConfig {
    let mut t = quinn::TransportConfig::default();
    // Enable datagrams for UDP relay
    t.initial_mtu(MAX_DATAGRAM_FRAME_SIZE as u16);
    // Datagram buffer sizes: use Quinn defaults (~1.2 MiB receive, 1 MiB send).
    // Previous code incorrectly set these to MAX_DATAGRAM_FRAME_SIZE (1200),
    // confusing per-packet MTU with buffer capacity, which caused fragmented
    // UDP messages to be silently dropped.
    if DISABLE_PATH_MTU_DISCOVERY {
        t.mtu_discovery_config(None);
    }
    t.max_concurrent_bidi_streams(quinn::VarInt::from_u32(1024));
    if let Ok(idle_timeout) = std::time::Duration::from_secs(30).try_into() {
        t.max_idle_timeout(Some(idle_timeout));
    }
    // Receive windows per prompt §4.8
    if let Ok(stream_window) = quinn::VarInt::from_u64(DEFAULT_STREAM_RECEIVE_WINDOW) {
        t.stream_receive_window(stream_window);
    }
    if let Ok(conn_window) = quinn::VarInt::from_u64(DEFAULT_CONN_RECEIVE_WINDOW) {
        t.receive_window(conn_window);
    }
    t
}

// ──────────────────────────────────────────────────────────────────────────────
// Per-connection handler
// ──────────────────────────────────────────────────────────────────────────────

async fn handle_connection(
    quinn_conn: quinn::Connection,
    config: Arc<ServerConfig>,
    cc_handle: CongestionHandle,
    actor_conn_id: ConnId,
    ctrl_tx: mpsc::Sender<ConnControl>,
    scheduler: Arc<StdMutex<Scheduler>>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let conn_id: u32 = rand::random();
    let auth_id = Arc::new(RwLock::new(None::<String>));
    let authenticated = Arc::new(AtomicBool::new(false));
    let auth_ready = Arc::new(Notify::new());

    // effective_bps is written by BrutalSender; stored in the Scheduler
    // for potential future rate-aware scheduling decisions.
    let _effective_bps = cc_handle.effective_bps_arc();

    let (tcp_tx, mut tcp_rx) = mpsc::unbounded_channel::<RawTcpStream>();
    let hy_conn = HyServerConn::new(
        H3QuinnConn::new(quinn_conn.clone()),
        quinn_conn.clone(),
        tcp_tx,
        Arc::clone(&authenticated),
    );

    let mut h3_builder = h3::server::builder();
    h3_builder.max_field_section_size(H3_MAX_FIELD_SECTION_SIZE);
    let mut h3_conn = h3_builder
        .build::<_, Bytes>(hy_conn)
        .await
        .map_err(|e| format!("h3 build error: {}", e))?;

    // Clone scheduler params for the UDP path (H3 request handler) before
    // the TCP consumer task moves the originals.
    let ctrl_tx_udp = ctrl_tx.clone();
    let scheduler_udp = Arc::clone(&scheduler);
    let actor_conn_id_udp = actor_conn_id;

    // Spawn TCP proxy consumer task.
    // Each inbound TCP proxy stream gets a unique FlowId so the Scheduler
    // can track per-flow credit and DRR fairness independently.
    {
        let config = Arc::clone(&config);
        let quinn_conn = quinn_conn.clone();
        let auth_id = Arc::clone(&auth_id);
        let authenticated = Arc::clone(&authenticated);
        let auth_ready = Arc::clone(&auth_ready);
        // FlowId counter: monotonically increasing u64 per connection.
        // Starts at 1 (0 is reserved).
        let flow_id_counter = Arc::new(AtomicU64::new(1));
        tokio::spawn(async move {
            if !authenticated.load(Ordering::Acquire) {
                tokio::select! {
                    _ = auth_ready.notified() => {}
                    _ = quinn_conn.closed() => return,
                }
            }
            if !authenticated.load(Ordering::Acquire) {
                return;
            }
            while let Some(raw) = tcp_rx.recv().await {
                let config = Arc::clone(&config);
                let quinn_conn = quinn_conn.clone();
                let auth_id = Arc::clone(&auth_id);
                let ctrl_tx = ctrl_tx.clone();
                let scheduler = Arc::clone(&scheduler);
                let flow_id = FlowId(flow_id_counter.fetch_add(1, Ordering::Relaxed));
                tokio::spawn(async move {
                    handle_tcp_stream(
                        raw,
                        quinn_conn,
                        config,
                        auth_id,
                        conn_id,
                        actor_conn_id,
                        ctrl_tx,
                        scheduler,
                        flow_id,
                    )
                    .await;
                });
            }
        });
    }

    // H3 request accept loop (handles auth).
    // The CongestionHandle is passed to the first request handler so that
    // congestion control is set immediately after the 233 response.
    // The udp_started flag ensures only one UDP manager is spawned per connection.
    let cc_handle_opt = Arc::new(tokio::sync::Mutex::new(Some(cc_handle)));
    let udp_started = Arc::new(AtomicBool::new(false));
    loop {
        tokio::select! {
            // when the server signals graceful shutdown, stop accepting
            // new H3 requests and tell ConnectionActor to drain existing items.
            biased;
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    // Send GracefulDrain: ConnectionActor will stop accepting new
                    // streams and exit once the scheduler is empty.
                    let _ = ctrl_tx_udp.send(ConnControl::GracefulDrain).await;
                    break;
                }
            }
            accept_result = h3_conn.accept() => {
                match accept_result {
                    Ok(None) | Err(_) => break,
                    Ok(Some(resolver)) => {
                        let (req, stream) = match resolver.resolve_request().await {
                            Ok(r) => r,
                            Err(_) => break,
                        };
                        // Spawn per-request handler so the accept loop stays responsive.
                        // Go: `go handleRequest(...)` per prompt §8.1.
                        let quinn_conn2 = quinn_conn.clone();
                        let udp_started2 = Arc::clone(&udp_started);
                        let config2 = Arc::clone(&config);
                        let auth_id2 = Arc::clone(&auth_id);
                        let cc_handle2 = Arc::clone(&cc_handle_opt);
                        let authenticated2 = Arc::clone(&authenticated);
                        let auth_ready2 = Arc::clone(&auth_ready);
                        let ctrl_tx3 = ctrl_tx_udp.clone();
                        let scheduler3 = Arc::clone(&scheduler_udp);
                        let conn_id3 = actor_conn_id_udp;
                        tokio::spawn(async move {
                            handle_h3_request(
                                req,
                                stream,
                                quinn_conn2,
                                config2,
                                cc_handle2,
                                udp_started2,
                                auth_id2,
                                authenticated2,
                                auth_ready2,
                                ctrl_tx3,
                                scheduler3,
                                conn_id3,
                            )
                            .await;
                        });
                    }
                }
            }
        }
    }

    if let Some(id) = auth_id.read().await.clone() {
        if let Some(tl) = &config.traffic_logger {
            tl.log_online_state(&id, false);
        }
        if let Some(el) = &config.event_logger {
            el.disconnect(&quinn_conn.remote_address(), &id, None);
        }
    }

    // Signal ConnectionActor to shut down cleanly before closing the QUIC connection.
    let _ = ctrl_tx_udp.send(ConnControl::Shutdown).await;
    let _ = quinn_conn.close(quinn::VarInt::from_u32(H3_ERR_NO_ERROR), b"");
    Ok(())
}

async fn handle_h3_request<S>(
    req: http::Request<()>,
    mut stream: h3::server::RequestStream<S, Bytes>,
    quinn_conn: quinn::Connection,
    config: Arc<ServerConfig>,
    cc_handle: Arc<tokio::sync::Mutex<Option<CongestionHandle>>>,
    udp_started: Arc<AtomicBool>,
    auth_id: Arc<RwLock<Option<String>>>,
    authenticated: Arc<AtomicBool>,
    auth_ready: Arc<Notify>,
    ctrl_tx: mpsc::Sender<ConnControl>,
    scheduler: Arc<StdMutex<Scheduler>>,
    actor_conn_id: ConnId,
) where
    S: QuicSendStream<Bytes>,
{
    let is_auth = req.method() == http::Method::POST
        && req.uri().host() == Some("hysteria")
        && req.uri().path() == "/auth";

    if !is_auth {
        send_masq_or_404(req, &mut stream, &config, quinn_conn.remote_address()).await;
        return;
    }

    let auth_str = req
        .headers()
        .get(HEADER_AUTH)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let cc_rx_str = req
        .headers()
        .get(HEADER_CC_RX)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("0");
    let rx: u64 = cc_rx_str.parse().unwrap_or(0);

    let remote = quinn_conn.remote_address();
    let mut first_auth = false;
    let authed_id = {
        let mut guard = auth_id.write().await;
        if let Some(existing) = guard.clone() {
            existing
        } else {
            let (ok, id) = config
                .authenticator
                .authenticate(remote, auth_str, rx)
                .await;
            if !ok {
                drop(guard);
                send_masq_or_404(req, &mut stream, &config, remote).await;
                return;
            }
            *guard = Some(id.clone());
            first_auth = true;
            id
        }
    };

    let padding = crate::core::internal::protocol::AuthResponse::padding();
    let resp_status = http::StatusCode::from_u16(STATUS_AUTH_OK).unwrap_or(http::StatusCode::OK);
    let resp_builder = http::Response::builder()
        .status(resp_status)
        .header(
            HEADER_UDP_ENABLED,
            if config.disable_udp { "false" } else { "true" },
        )
        .header(
            HEADER_CC_RX,
            if config.ignore_client_bandwidth {
                "auto".to_string()
            } else {
                config.speed_rx_bps.to_string()
            },
        )
        .header(HEADER_PADDING, padding);
    if let Ok(resp) = resp_builder.body(()) {
        let _ = stream.send_response(resp).await;
    }

    // §5.3 — Post-auth congestion selection (server side).
    // Consume the runtime congestion handle only after successful first auth.
    let cc = if first_auth {
        cc_handle.lock().await.take()
    } else {
        None
    };
    server_select_congestion(cc, rx, config.speed_bps, config.ignore_client_bandwidth);

    if first_auth {
        authenticated.store(true, Ordering::Release);
        auth_ready.notify_waiters();
        if let Some(tl) = &config.traffic_logger {
            tl.log_online_state(&authed_id, true);
        }
        if let Some(el) = &config.event_logger {
            el.connect(
                &remote,
                &authed_id,
                server_target_bps(rx, config.speed_bps, config.ignore_client_bandwidth),
            );
        }
    }

    // spawn UDP session manager (once per connection).
    if first_auth && !config.disable_udp && !udp_started.swap(true, Ordering::SeqCst) {
        let mgr = Arc::new(UdpSessionManager {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            idle_timeout_secs: if config.udp_idle_timeout.is_zero() {
                DEFAULT_UDP_IDLE_TIMEOUT_SECS
            } else {
                config.udp_idle_timeout.as_secs().max(1)
            },
            ctrl_tx: ctrl_tx.clone(),
            scheduler: Arc::clone(&scheduler),
            actor_conn_id,
        });
        let conn_clone = quinn_conn.clone();
        let traffic_logger = config.traffic_logger.clone();
        let event_logger = config.event_logger.clone();
        let request_hook = config.request_hook.clone();
        let outbound = config
            .outbound
            .clone()
            .unwrap_or_else(|| Arc::new(DirectOutbound::default()));
        tokio::spawn(async move {
            let _ = udp_manager_run(
                conn_clone,
                mgr,
                authed_id,
                traffic_logger,
                event_logger,
                request_hook,
                outbound,
                remote,
            )
            .await;
        });
    }

    let _ = stream.finish().await;
}

async fn send_masq_or_404<S>(
    req: http::Request<()>,
    stream: &mut h3::server::RequestStream<S, Bytes>,
    config: &ServerConfig,
    remote_addr: SocketAddr,
) where
    S: QuicSendStream<Bytes>,
{
    if let Some(handler) = &config.masq_handler {
        let response = handler.serve(req, remote_addr).await;
        let (parts, body) = response.into_parts();
        let body_bytes = body
            .collect()
            .await
            .map(|c| c.to_bytes())
            .unwrap_or_default();

        let mut builder = http::Response::builder().status(parts.status);
        for (name, value) in &parts.headers {
            builder = builder.header(name, value);
        }
        if let Ok(h3_resp) = builder.body(()) {
            let _ = stream.send_response(h3_resp).await;
            if !body_bytes.is_empty() {
                let _ = stream.send_data(body_bytes).await;
            }
            let _ = stream.finish().await;
            return;
        }
    }

    send_404(stream).await;
}

/// Select and activate the congestion controller after a successful auth.
///
/// Go equivalent:
/// ```go
/// func serverSelectCongestion(conn *quic.Conn, clientRx uint64, config *Config) {
///     speedBps := min(clientRx, config.SpeedBps)
///     if speedBps > 0 {
///         conn.SetCongestionControl(NewBrutal(speedBps))
///     } else {
///         conn.SetCongestionControl(NewBBR())
///     }
/// }
/// ```
fn server_select_congestion(
    cc_handle: Option<CongestionHandle>,
    client_rx: u64,
    server_speed_bps: u64,
    ignore_client_bandwidth: bool,
) {
    let handle = match cc_handle {
        Some(h) => h,
        None => return,
    };
    // Go semantics:
    // actual_tx starts from client_rx and is capped by server_speed_bps only when
    // server_speed_bps > 0. If actual_tx is 0, keep BBR (set_brutal(0) is a no-op).
    let speed_bps = server_target_bps(client_rx, server_speed_bps, ignore_client_bandwidth);
    // If speed_bps > 0, switch to Brutal; otherwise leave BBR active (no-op).
    handle.set_brutal(speed_bps);
}

#[inline]
fn server_target_bps(client_rx: u64, server_speed_bps: u64, ignore_client_bandwidth: bool) -> u64 {
    if ignore_client_bandwidth {
        return 0;
    }
    let mut actual_tx = client_rx;
    if server_speed_bps > 0 && actual_tx > server_speed_bps {
        actual_tx = server_speed_bps;
    }
    actual_tx
}

async fn send_404<S>(stream: &mut h3::server::RequestStream<S, Bytes>)
where
    S: QuicSendStream<Bytes>,
{
    if let Ok(resp) = http::Response::builder().status(404).body(()) {
        let _ = stream.send_response(resp).await;
    }
    let _ = stream.finish().await;
}

// ──────────────────────────────────────────────────────────────────────────────
// TCP proxy stream handler
// ──────────────────────────────────────────────────────────────────────────────

struct StreamTraceGuard {
    traffic_logger: Option<Arc<dyn TrafficLogger>>,
    stream_id: u64,
    stats: Arc<StreamStats>,
}

impl Drop for StreamTraceGuard {
    fn drop(&mut self) {
        self.stats.set_state(StreamState::Closed);
        if let Some(tl) = &self.traffic_logger {
            tl.untrace_stream(self.stream_id);
        }
    }
}

#[derive(Debug)]
enum DisconnectError {
    TrafficLimit,
}

impl std::fmt::Display for DisconnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TrafficLimit => write!(f, "traffic logger requested disconnect"),
        }
    }
}

impl std::error::Error for DisconnectError {}

fn traffic_limit_disconnect() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionReset,
        DisconnectError::TrafficLimit,
    )
}

async fn handle_tcp_stream(
    raw: RawTcpStream,
    quinn_conn: quinn::Connection,
    config: Arc<ServerConfig>,
    auth_id_ref: Arc<RwLock<Option<String>>>,
    conn_id: u32,
    actor_conn_id: ConnId,
    ctrl_tx: mpsc::Sender<ConnControl>,
    scheduler: Arc<StdMutex<Scheduler>>,
    flow_id: FlowId,
) {
    let auth_id = match auth_id_ref.read().await.clone() {
        Some(v) => v,
        None => {
            let _ = quinn_conn.close(
                quinn::VarInt::from_u32(H3_ERR_PROTOCOL_ERROR),
                b"unauthenticated tcp stream",
            );
            return;
        }
    };

    let RawTcpStream { send, recv, prefix } = raw;
    let stream_id =
        <h3_quinn::SendStream<Bytes> as QuicSendStream<Bytes>>::send_id(&send).into_inner();
    let mut stream = QStream::new(send, recv, prefix);
    let remote = quinn_conn.remote_address();

    let stream_stats = Arc::new(StreamStats::new(auth_id.clone(), conn_id));
    stream_stats.set_state(StreamState::Initial);
    stream_stats.touch();
    let _trace_guard = StreamTraceGuard {
        traffic_logger: config.traffic_logger.clone(),
        stream_id,
        stats: Arc::clone(&stream_stats),
    };
    if let Some(tl) = &config.traffic_logger {
        tl.trace_stream(stream_id, Arc::clone(&stream_stats));
    }

    // Read TCP proxy request (addr + padding), frame type already consumed
    let mut req_addr = match read_tcp_request_async(stream.reader_mut()).await {
        Ok(a) => a,
        Err(_) => {
            let _ = stream.close().await;
            return;
        }
    };
    stream_stats.set_req_addr(req_addr.clone());

    let mut putback = Vec::new();
    let mut hooked = false;
    if let Some(hook) = &config.request_hook {
        if hook.check(false, &req_addr) {
            hooked = true;
            stream_stats.set_state(StreamState::Hooking);
            let _ = stream
                .writer_mut()
                .write_all(&write_tcp_response(true, "RequestHook enabled"))
                .await;
            match hook.tcp(stream.reader_mut(), &mut req_addr).await {
                Ok(pb) => {
                    putback = pb;
                    stream_stats.set_hooked_req_addr(&req_addr);
                }
                Err(_) => {
                    let _ = stream.close().await;
                    return;
                }
            }
        }
    }

    if let Some(el) = &config.event_logger {
        el.tcp_request(&remote, &auth_id, &req_addr);
    }

    if config.speed_test && is_speedtest_dest(&req_addr) {
        let resp = write_tcp_response(true, "");
        if stream.writer_mut().write_all(&resp).await.is_err() {
            let _ = stream.close().await;
            return;
        }
        let (reader, writer) = stream.split_mut();
        let _ = handle_speedtest_stream(reader, writer).await;
        if let Some(el) = &config.event_logger {
            el.tcp_error(&remote, &auth_id, &req_addr, None);
        }
        let _ = stream.close().await;
        return;
    }

    stream_stats.set_state(StreamState::Connecting);

    // Connect to target
    let outbound = config
        .outbound
        .clone()
        .unwrap_or_else(|| Arc::new(DirectOutbound::default()));
    let target_result = match outbound.tcp(&req_addr).await {
        Ok(t) => t,
        Err(e) => {
            if !hooked {
                let resp = write_tcp_response(false, &e.to_string());
                let _ = stream.writer_mut().write_all(&resp).await;
            }
            if let Some(el) = &config.event_logger {
                el.tcp_error(&remote, &auth_id, &req_addr, Some(&e));
            }
            let _ = stream.close().await;
            return;
        }
    };
    let _tcp_local = target_result.local_addr;
    let _tcp_peer = target_result.peer_addr;
    let target = target_result.stream;

    // Send success response
    if !hooked {
        let resp = write_tcp_response(true, "Connected");
        if stream.writer_mut().write_all(&resp).await.is_err() {
            let _ = stream.close().await;
            return;
        }
    }

    stream_stats.set_state(StreamState::Established);

    // Split the QUIC stream into read/write halves.
    // The write half goes directly to TcpFlowActor — no serialization through
    // ConnectionActor. Each flow owns its QUIC stream writer independently.
    let (quic_recv, send_writer) = stream.into_split();

    // Split the outbound TCP connection into independent read/write halves.
    let (target_r, mut target_w) = tokio::io::split(target);

    // Write putback bytes (from request hook) to the outbound TCP socket
    // before the download loop starts forwarding QUIC data.
    if !putback.is_empty() {
        if target_w.write_all(&putback).await.is_err() {
            let _ = ctrl_tx.send(ConnControl::FlowClosed(flow_id)).await;
            if let Some(el) = &config.event_logger {
                el.tcp_error(&remote, &auth_id, &req_addr, None);
            }
            return;
        }
        stream_stats.tx.fetch_add(putback.len() as u64, Ordering::Relaxed);
        stream_stats.touch();
    }

    // Extract destination port for HeuristicClassifier (port-based hints).
    // Format: "host:port" or "[ipv6]:port".
    let dest_port = req_addr
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok());

    // Spawn upload (permit-before-read → direct QUIC write) and download (QUIC recv → TCP write).
    let hints = FlowHints { class: crate::core::scheduler::FlowClass::Bulk, dest_port, is_datagram_ingress: false };
    let (upload_handle, download_handle) = flow_actor::spawn_tcp_flow(
        flow_id,
        actor_conn_id,
        hints,
        target_r,
        target_w,
        quic_recv,
        send_writer,
        ctrl_tx.clone(),
        scheduler,
    );

    // Wait for either direction to complete. When one side finishes (EOF or
    // error), the other winds down naturally via QUIC stream / TCP close.
    tokio::select! {
        _ = upload_handle => {}
        _ = download_handle => {}
    }

    if let Some(el) = &config.event_logger {
        el.tcp_error(&remote, &auth_id, &req_addr, None);
    }
}

#[inline]
fn is_speedtest_dest(addr: &str) -> bool {
    let host = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr);
    host.eq_ignore_ascii_case(SPEEDTEST_DEST)
}

async fn handle_speedtest_stream(
    reader: &mut RecvStreamReader,
    writer: &mut SendStreamWriter,
) -> std::io::Result<()> {
    let req_type = reader.read_u8().await?;
    match req_type {
        0x01 => handle_speedtest_download(reader, writer).await,
        0x02 => handle_speedtest_upload(reader, writer).await,
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unknown speedtest request type: {req_type}"),
        )),
    }
}

async fn handle_speedtest_download(
    reader: &mut RecvStreamReader,
    writer: &mut SendStreamWriter,
) -> std::io::Result<()> {
    let size = reader.read_u32().await?;
    write_speedtest_status(writer, true, "OK").await?;

    let mut buf = vec![0u8; SPEEDTEST_CHUNK_SIZE];
    {
        let mut rng = rand::rng();
        for b in &mut buf {
            *b = rng.random();
        }
    }

    if size == u32::MAX {
        // Time-based mode: stream indefinitely until the client closes the connection.
        // The client sets a read deadline; when it fires the connection is dropped,
        // causing write_all to error. That error is silenced by the caller.
        loop {
            writer.write_all(&buf).await?;
        }
    } else {
        // Size-based mode: send exactly `size` bytes.
        let mut remaining = size;
        while remaining > 0 {
            let chunk = remaining.min(SPEEDTEST_CHUNK_SIZE as u32) as usize;
            writer.write_all(&buf[..chunk]).await?;
            remaining -= chunk as u32;
        }
        Ok(())
    }
}

async fn handle_speedtest_upload(
    reader: &mut RecvStreamReader,
    writer: &mut SendStreamWriter,
) -> std::io::Result<()> {
    let size = reader.read_u32().await?;
    write_speedtest_status(writer, true, "OK").await?;

    let mut buf = vec![0u8; SPEEDTEST_CHUNK_SIZE];
    let start = tokio::time::Instant::now();

    if size == u32::MAX {
        // Time-based mode: drain until the client closes the stream (write deadline
        // fires on the client side). EOF (Ok(0)) is the expected termination signal;
        // no UploadSummary is sent because the client uses local measurement.
        loop {
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                return Ok(()); // client closed stream after deadline — normal
            }
        }
    } else {
        // Size-based mode: read exactly `size` bytes, then send UploadSummary.
        let mut remaining = size;
        while remaining > 0 {
            let chunk = remaining.min(SPEEDTEST_CHUNK_SIZE as u32) as usize;
            let n = reader.read(&mut buf[..chunk]).await?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "speedtest upload stream closed before all bytes received",
                ));
            }
            remaining -= n as u32;
        }
        let duration_ms = start.elapsed().as_millis().min(u128::from(u32::MAX)) as u32;
        writer.write_all(&duration_ms.to_be_bytes()).await?;
        writer.write_all(&size.to_be_bytes()).await?;
        Ok(())
    }
}

async fn write_speedtest_status(
    writer: &mut SendStreamWriter,
    ok: bool,
    msg: &str,
) -> std::io::Result<()> {
    let msg_bytes = msg.as_bytes();
    if msg_bytes.len() > u16::MAX as usize {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "speedtest status message too long",
        ));
    }
    let mut out = Vec::with_capacity(3 + msg_bytes.len());
    out.push(if ok { 0 } else { 1 });
    out.extend_from_slice(&(msg_bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(msg_bytes);
    writer.write_all(&out).await
}

/// TCP proxy stream handle (read + write halves).
///
/// This is the server-side equivalent of Go `utils.QStream` semantics:
/// `Close()` cancels read first, then finishes write.
pub(crate) struct QStream {
    reader: RecvStreamReader,
    writer: SendStreamWriter,
}

impl QStream {
    fn new(send: h3_quinn::SendStream<Bytes>, recv: h3_quinn::RecvStream, prefix: Vec<u8>) -> Self {
        Self {
            reader: RecvStreamReader::new(recv, prefix),
            writer: SendStreamWriter { send },
        }
    }

    fn reader_mut(&mut self) -> &mut RecvStreamReader {
        &mut self.reader
    }

    fn writer_mut(&mut self) -> &mut SendStreamWriter {
        &mut self.writer
    }

    fn split_mut(&mut self) -> (&mut RecvStreamReader, &mut SendStreamWriter) {
        (&mut self.reader, &mut self.writer)
    }

    fn into_split(self) -> (RecvStreamReader, SendStreamWriter) {
        (self.reader, self.writer)
    }

    async fn close(&mut self) -> std::io::Result<()> {
        self.reader.cancel_read(0);
        self.writer.close().await
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// UDP relay session manager (server-side)
//
// Go equivalent: hysteria/core/server/udp.go
// ──────────────────────────────────────────────────────────────────────────────

/// Connection state of a server-side UDP session entry.
///
/// Transitions: Uninit → Connected (on first complete message) → Closed
enum EntryConnState {
    /// Not yet connected; waiting for the first complete message.
    Uninit,
    /// Socket has been created and the receive task is running.
    Connected {
        socket: Arc<dyn UdpOutboundConn>,
        recv_handle: tokio::task::JoinHandle<()>,
    },
    /// Session has been closed (idempotent sentinel).
    Closed,
}

type UdpExitFuture = Pin<Box<dyn Future<Output = ()> + Send>>;
type UdpExitFunc = Arc<dyn Fn(Option<io::Error>) -> UdpExitFuture + Send + Sync>;

/// A single server-side UDP proxy session.
///
/// Lazily initialized: the upstream UDP socket is opened only when the first
/// complete (possibly reassembled) UDP message arrives.
///
/// Go equivalent: `udpSessionEntry` (core/server/udp.go:32-46).
struct UdpSessionEntry {
    /// Session identifier (from the client's UDP message header).
    id: u32,
    /// Reassembly state for fragmented messages.
    defragger: tokio::sync::Mutex<Defragger>,
    /// If the dial function redirected to a different address, store it here.
    override_addr: tokio::sync::Mutex<Option<String>>,
    /// Original address before any redirect (sent back to the client).
    original_addr: tokio::sync::Mutex<Option<String>>,
    /// Unix-second timestamp of last activity.  Go: `utils.AtomicTime`.
    last: AtomicTime,
    /// The upstream UDP socket + running receive task.
    /// Protected by a Mutex to ensure init-once semantics.
    /// Go: `conn UDPConn` + `connLock sync.Mutex`.
    conn: tokio::sync::Mutex<EntryConnState>,
    /// True once `close_with_err` has completed (idempotency guard).
    closed: AtomicBool,
    /// Async dial function: `(addr, first_data) → (UDPConn, actual_addr)`.
    /// Called exactly once, inside the conn lock, on first complete message.
    /// Go: `DialFunc func(addr string, firstMsgData []byte) (UDPConn, actualAddr, err)`.
    dial_func: Arc<
        dyn Fn(
                String,
                Vec<u8>,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<
                            Output = std::io::Result<(Arc<dyn UdpOutboundConn>, String)>,
                        > + Send
                        + 'static,
                >,
            > + Send
            + Sync,
    >,
    /// Called after the session closes; removes this entry from the sessions map.
    /// Go: `ExitFunc func(err error)`.
    exit_func: UdpExitFunc,
    /// Channel to ConnectionActor for submitting UDP datagrams through Scheduler.
    ctrl_tx: mpsc::Sender<ConnControl>,
    /// Shared Scheduler for Realtime permit acquisition.
    sched: Arc<StdMutex<Scheduler>>,
    /// Connection identifier for permit requests.
    actor_conn_id: ConnId,
}

/// Server-side UDP session manager.
///
/// Manages the lifecycle of per-session UDP connections.
/// Each session is identified by a `session_id` (u32) from the client.
///
/// Go equivalent: `udpSessionManager` (core/server/udp.go:212-228).
struct UdpSessionManager {
    /// Active sessions, keyed by session_id.
    sessions: Arc<RwLock<HashMap<u32, Arc<UdpSessionEntry>>>>,
    /// Close idle sessions after this many seconds of inactivity.
    idle_timeout_secs: u64,
    /// Channel to ConnectionActor for submitting UDP datagrams through Scheduler.
    ctrl_tx: mpsc::Sender<ConnControl>,
    /// Shared Scheduler for Realtime permit acquisition.
    scheduler: Arc<StdMutex<Scheduler>>,
    /// Connection identifier for permit requests.
    actor_conn_id: ConnId,
}

// ── UdpSessionEntry methods ──────────────────────────────────────────────────

impl UdpSessionEntry {
    /// Idempotent close.  Aborts the receive task (if started) then calls
    /// `exit_func` to remove from the sessions map.
    ///
    /// Lock order: conn → sessions map (via exit_func).  Never reverse!
    ///
    /// Go: `func (e *udpSessionEntry) CloseWithErr(err error)`.
    async fn close_with_err(&self, err: Option<io::Error>) {
        // Idempotency guard (matches Go: `if e.closed { return }`)
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        // Abort receive task if running (Go: `e.conn.Close()`)
        let (handle, socket) = {
            let mut guard = self.conn.lock().await;
            match std::mem::replace(&mut *guard, EntryConnState::Closed) {
                EntryConnState::Connected {
                    socket,
                    recv_handle,
                } => (Some(recv_handle), Some(socket)),
                _ => (None, None),
            }
        }; // conn lock released
        if let Some(h) = handle {
            h.abort();
        }
        if let Some(sock) = socket {
            let _ = sock.close();
        }
        // Go: `e.ExitFunc(err)` — removes from sessions map
        (self.exit_func)(err).await;
    }
}

// ── Per-entry feed (standalone fn to get Arc<Self>) ─────────────────────────

/// Feed one UDP message fragment to the session entry.
///
/// On the first *complete* message, the upstream UDP socket is lazily dialed
/// and the per-session receive loop is spawned.
///
/// Go: `func (e *udpSessionEntry) Feed(msg *UDPMessage) (int, error)`.
async fn entry_feed(
    entry: Arc<UdpSessionEntry>,
    msg: UdpMessage,
    conn: &quinn::Connection,
    auth_id: &str,
    traffic_logger: Option<Arc<dyn TrafficLogger>>,
) {
    entry.last.update();

    // Defragment (returns Some when a complete message is ready)
    let assembled = {
        let mut d = entry.defragger.lock().await;
        d.feed(msg)
    };
    let assembled = match assembled {
        Some(m) => m,
        None => return, // incomplete fragment, wait for more
    };

    // ── Lazy socket init ──────────────────────────────────────────────────────
    {
        let mut guard = entry.conn.lock().await;
        if matches!(*guard, EntryConnState::Uninit) {
            // Guard against concurrent close
            if entry.closed.load(Ordering::SeqCst) {
                return;
            }
            let addr = assembled.addr.clone();
            let data = assembled.data.clone();

            // Dial while holding conn lock (matches Go: DialFunc inside connLock)
            let result = (entry.dial_func)(addr.clone(), data).await;
            match result {
                Err(_) => {
                    // Dial failed: release lock then close session
                    drop(guard);
                    entry
                        .close_with_err(Some(io::Error::new(
                            io::ErrorKind::ConnectionRefused,
                            "udp dial failed",
                        )))
                        .await;
                    return;
                }
                Ok((socket, actual_addr)) => {
                    if entry.closed.load(Ordering::SeqCst) {
                        return;
                    }
                    // Address override (ACL/hook may redirect)
                    if actual_addr != addr {
                        *entry.override_addr.lock().await = Some(actual_addr.clone());
                        *entry.original_addr.lock().await = Some(addr.clone());
                    }
                    // Spawn per-session receive loop (sends through Scheduler
                    // with Realtime priority via ConnectionActor).
                    let recv_handle = tokio::spawn(session_receive_loop(
                        Arc::clone(&entry),
                        Arc::clone(&socket),
                        conn.clone(),
                        auth_id.to_string(),
                        traffic_logger.clone(),
                        entry.ctrl_tx.clone(),
                        Arc::clone(&entry.sched),
                        entry.actor_conn_id,
                    ));
                    *guard = EntryConnState::Connected {
                        socket: Arc::clone(&socket),
                        recv_handle,
                    };
                }
            }
        }
    } // conn lock released

    // ── Forward data to upstream UDP socket ──────────────────────────────────
    // Get socket reference without holding conn lock during the async send
    let socket_opt = {
        let guard = entry.conn.lock().await;
        match &*guard {
            EntryConnState::Connected { socket, .. } => Some(Arc::clone(socket)),
            _ => None,
        }
    };
    if let Some(socket) = socket_opt {
        let send_addr = entry
            .override_addr
            .lock()
            .await
            .clone()
            .unwrap_or_else(|| assembled.addr.clone());
        if let Err(err) = socket.send_to(&assembled.data, &send_addr).await {
            entry.close_with_err(Some(err)).await;
        }
    }
}

// ── Manager run loop ─────────────────────────────────────────────────────────

/// Main UDP manager task: reads QUIC datagrams, routes to sessions.
///
/// Internally spawns the idle-cleanup loop and closes all sessions on exit.
///
/// Go: `func (m *udpSessionManager) Run() error`.
async fn udp_manager_run(
    conn: quinn::Connection,
    mgr: Arc<UdpSessionManager>,
    auth_id: String,
    traffic_logger: Option<Arc<dyn TrafficLogger>>,
    event_logger: Option<Arc<dyn EventLogger>>,
    request_hook: Option<Arc<dyn RequestHook>>,
    outbound: Arc<dyn PluggableOutbound>,
    remote_addr: SocketAddr,
) -> std::io::Result<()> {
    // Go: stopCh := make(chan struct{}); go m.idleCleanupLoop(stopCh); defer close(stopCh)
    let cancel = CancellationToken::new();
    let cleanup_handle = tokio::spawn(idle_cleanup_loop(Arc::clone(&mgr), cancel.clone()));

    let result = async {
        loop {
            // Go: m.io.ReceiveMessage() — reads a QUIC datagram and parses it
            let datagram = match conn.read_datagram().await {
                Ok(d) => d,
                Err(e) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionReset,
                        e.to_string(),
                    ));
                }
            };
            let msg = match parse_udp_message(&datagram) {
                Ok(m) => m,
                Err(_) => continue, // invalid message, skip (Go: continue loop)
            };

            if let Some(tl) = &traffic_logger {
                if !tl.log_traffic(&auth_id, msg.data.len() as u64, 0) {
                    conn.close(quinn::VarInt::from_u32(0x107), b"");
                    return Err(traffic_limit_disconnect());
                }
            }

            mgr_feed(
                &mgr,
                msg,
                &conn,
                &auth_id,
                traffic_logger.clone(),
                event_logger.clone(),
                request_hook.clone(),
                Arc::clone(&outbound),
                remote_addr,
            )
            .await;
        }
    }
    .await;

    // Go: defer close(stopCh)
    cancel.cancel();
    let _ = cleanup_handle.await;

    // Go: defer m.cleanup(false) — close ALL sessions on exit
    cleanup_all_sessions(&mgr).await;

    result
}

/// Idle session cleanup loop.  Runs every second.
///
/// Go: `func (m *udpSessionManager) idleCleanupLoop(stopCh <-chan struct{})`.
async fn idle_cleanup_loop(mgr: Arc<UdpSessionManager>, cancel: CancellationToken) {
    let mut interval = tokio::time::interval(Duration::from_secs(UDP_IDLE_CLEANUP_INTERVAL_SECS));
    loop {
        tokio::select! {
            _ = interval.tick() => cleanup_idle_sessions(&mgr).await,
            _ = cancel.cancelled() => return,
        }
    }
}

/// Scan the sessions map and close sessions that have been idle too long.
///
/// Two-phase lock pattern to avoid deadlock:
///   (RLock): collect expired entries.
///   call `close_with_err` on each (which internally write-locks sessions).
///
/// Go: `func (m *udpSessionManager) cleanup(idleOnly bool)` with `idleOnly=true`.
async fn cleanup_idle_sessions(mgr: &UdpSessionManager) {
    let expired: Vec<Arc<UdpSessionEntry>> = {
        let sessions = mgr.sessions.read().await;
        sessions
            .values()
            .filter(|e| e.last.is_idle(mgr.idle_timeout_secs))
            .cloned()
            .collect()
    }; // RLock released
    for entry in expired {
        entry.close_with_err(None).await;
    }
}

/// Close every session unconditionally (called on manager shutdown).
///
/// Go: `func (m *udpSessionManager) cleanup(idleOnly bool)` with `idleOnly=false`.
async fn cleanup_all_sessions(mgr: &UdpSessionManager) {
    let all: Vec<Arc<UdpSessionEntry>> = {
        let sessions = mgr.sessions.read().await;
        sessions.values().cloned().collect()
    };
    for entry in all {
        entry.close_with_err(None).await;
    }
}

/// Route one parsed UDP message to the correct session, creating it if needed.
///
/// Go: `func (m *udpSessionManager) feed(msg *UDPMessage)`.
async fn mgr_feed(
    mgr: &Arc<UdpSessionManager>,
    msg: UdpMessage,
    conn: &quinn::Connection,
    auth_id: &str,
    traffic_logger: Option<Arc<dyn TrafficLogger>>,
    event_logger: Option<Arc<dyn EventLogger>>,
    request_hook: Option<Arc<dyn RequestHook>>,
    outbound: Arc<dyn PluggableOutbound>,
    remote_addr: SocketAddr,
) {
    // Fast path: existing session
    let entry = {
        let sessions = mgr.sessions.read().await;
        sessions.get(&msg.session_id).cloned()
    };

    if let Some(e) = entry {
        entry_feed(e, msg, conn, auth_id, traffic_logger).await;
        return;
    }

    // Slow path: create new session
    let id = msg.session_id;
    let mgr_sessions = Arc::clone(&mgr.sessions);

    // exit_func removes the entry from the sessions map
    let auth_id_owned = auth_id.to_string();
    let exit_event_logger = event_logger.clone();
    let exit_func: UdpExitFunc = Arc::new(move |err: Option<io::Error>| {
        let exit_event_logger = exit_event_logger.clone();
        let mgr_sessions = Arc::clone(&mgr_sessions);
        let auth_id_owned = auth_id_owned.clone();
        Box::pin(async move {
            if let Some(el) = &exit_event_logger {
                let err_ref = err.as_ref().map(|e| e as &(dyn Error + Send + Sync));
                el.udp_error(&remote_addr, &auth_id_owned, id, err_ref);
            }
            mgr_sessions.write().await.remove(&id);
        })
    });

    // dial_func opens outbound UDP handle lazily on first complete datagram.
    let dial_auth_id = auth_id.to_string();
    let dial_func: Arc<
        dyn Fn(
                String,
                Vec<u8>,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<
                            Output = std::io::Result<(Arc<dyn UdpOutboundConn>, String)>,
                        > + Send
                        + 'static,
                >,
            > + Send
            + Sync,
    > = Arc::new(move |addr: String, data: Vec<u8>| {
        let event_logger = event_logger.clone();
        let request_hook = request_hook.clone();
        let outbound = Arc::clone(&outbound);
        let auth_id = dial_auth_id.clone();
        Box::pin(async move {
            let mut req_addr = addr;
            if let Some(hook) = &request_hook {
                if hook.check(true, &req_addr) {
                    hook.udp(&data, &mut req_addr)?;
                }
            }

            if let Some(el) = &event_logger {
                el.udp_request(&remote_addr, &auth_id, id, &req_addr);
            }

            let socket = outbound.udp(&req_addr).await?;
            Ok((Arc::from(socket), req_addr))
        })
    });

    let new_entry = Arc::new(UdpSessionEntry {
        id,
        defragger: tokio::sync::Mutex::new(Defragger::new()),
        override_addr: tokio::sync::Mutex::new(None),
        original_addr: tokio::sync::Mutex::new(None),
        last: AtomicTime::new(),
        conn: tokio::sync::Mutex::new(EntryConnState::Uninit),
        closed: AtomicBool::new(false),
        dial_func,
        exit_func,
        ctrl_tx: mgr.ctrl_tx.clone(),
        sched: Arc::clone(&mgr.scheduler),
        actor_conn_id: mgr.actor_conn_id,
    });

    {
        let mut sessions = mgr.sessions.write().await;
        sessions.insert(id, Arc::clone(&new_entry));
    }

    entry_feed(new_entry, msg, conn, auth_id, traffic_logger).await;
}

// ── Per-session upstream receive loop ────────────────────────────────────────

/// Reads UDP packets from the upstream socket and sends them to the client
/// through the ConnectionActor's Scheduler with Realtime priority.
///
/// Instead of sending QUIC datagrams directly, each packet is:
///   1. Encoded as UdpMessage and fragmented if needed.
///   2. Gated by a Realtime permit from the Scheduler's PermitBank.
///   3. Submitted to ConnectionActor via ConnControl::UdpDatagram.
///
/// This ensures UDP traffic gets strict priority over TCP bulk in the Scheduler
/// (Realtime > Bulk), preventing bulk downloads from starving real-time UDP.
///
/// Go: `func (e *udpSessionEntry) receiveLoop()`.
async fn session_receive_loop(
    entry: Arc<UdpSessionEntry>,
    socket: Arc<dyn UdpOutboundConn>,
    conn: quinn::Connection,
    auth_id: String,
    traffic_logger: Option<Arc<dyn TrafficLogger>>,
    ctrl_tx: mpsc::Sender<ConnControl>,
    scheduler: Arc<StdMutex<Scheduler>>,
    actor_conn_id: ConnId,
) {
    let mut udp_buf = vec![0u8; MAX_UDP_SIZE];
    let session_id = UdpSessionId(entry.id);
    let hints = FlowHints::realtime();

    loop {
        let (n, r_addr) = match socket.recv_from(&mut udp_buf).await {
            Ok(v) => v,
            Err(_) => {
                entry
                    .close_with_err(Some(io::Error::other("udp upstream recv error")))
                    .await;
                return;
            }
        };
        entry.last.update();

        // Use original address in reverse direction if override was applied
        let addr = {
            let oa = entry.original_addr.lock().await;
            oa.clone().unwrap_or(r_addr)
        };

        let msg = UdpMessage {
            session_id: entry.id,
            pkt_id: 0,
            frag_id: 0,
            frag_count: 1,
            addr,
            data: udp_buf[..n].to_vec(),
        };

        if let Some(tl) = &traffic_logger {
            if !tl.log_traffic(&auth_id, 0, n as u64) {
                conn.close(quinn::VarInt::from_u32(0x107), b"");
                entry.close_with_err(Some(traffic_limit_disconnect())).await;
                return;
            }
        }

        // Encode UdpMessage and fragment if needed, then send through Scheduler.
        let max_size = conn.max_datagram_size().unwrap_or(MAX_DATAGRAM_FRAME_SIZE as usize);
        let full_bytes = msg.to_bytes();
        let datagrams: Vec<Bytes> = if full_bytes.len() <= max_size {
            vec![Bytes::from(full_bytes)]
        } else {
            let mut msg = msg;
            msg.pkt_id = new_frag_packet_id();
            frag_udp_message(&msg, max_size)
                .into_iter()
                .map(|f| Bytes::from(f.to_bytes()))
                .collect()
        };

        for datagram in datagrams {
            // Acquire Realtime permit (short sleep retry, same pattern as TcpFlowActor).
            let permit = loop {
                let flow_id = FlowId(session_id.0 as u64);
                let maybe = {
                    let mut sched = scheduler.lock().unwrap();
                    sched.try_issue_permit(actor_conn_id, Some(flow_id), &hints, datagram.len())
                };
                if let Some(p) = maybe {
                    break p;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            };

            if ctrl_tx
                .send(ConnControl::UdpDatagram {
                    payload: datagram,
                    permit,
                })
                .await
                .is_err()
            {
                entry
                    .close_with_err(Some(io::Error::other("ConnectionActor closed")))
                    .await;
                return;
            }
        }
    }
}

// ── Auto-fragmentation helper ─────────────────────────────────────────────────

// ──────────────────────────────────────────────────────────────────────────────
// Protocol helpers — async stream reading
// ──────────────────────────────────────────────────────────────────────────────

/// Read a QUIC varint from an async reader (1–8 bytes).
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

/// Read a TCP proxy request from an async stream (frame type already consumed).
///
/// Go equivalent: `protocol.ReadTCPRequest` reading from a stream.
async fn read_tcp_request_async(r: &mut (impl AsyncRead + Unpin)) -> std::io::Result<String> {
    let addr_len = read_varint_async(r).await?;
    if addr_len == 0 || addr_len > MAX_ADDRESS_LENGTH {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid address length",
        ));
    }
    let mut addr_bytes = vec![0u8; addr_len as usize];
    r.read_exact(&mut addr_bytes).await?;
    let addr = String::from_utf8(addr_bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let padding_len = read_varint_async(r).await?;
    if padding_len > MAX_PADDING_LENGTH {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid padding length",
        ));
    }
    // Drain padding bytes
    let mut padding_buf = vec![0u8; padding_len as usize];
    r.read_exact(&mut padding_buf).await?;

    Ok(addr)
}

// ──────────────────────────────────────────────────────────────────────────────
// HyServerConn — custom h3::quic::Connection<Bytes> wrapper
//
// Intercepts TCP proxy streams (frame type 0x401) before h3 processes them.
// Non-TCP streams are wrapped and returned to h3 normally.
// ──────────────────────────────────────────────────────────────────────────────

struct HyServerConn {
    inner: H3QuinnConn,
    quinn_conn: quinn::Connection,
    tcp_tx: mpsc::UnboundedSender<RawTcpStream>,
    authenticated: Arc<AtomicBool>,
    /// Active peek state: we're reading bytes from a newly-accepted stream
    /// to determine its frame type.
    peeking: Option<PeekingStream>,
}

struct PeekingStream {
    send: h3_quinn::SendStream<Bytes>,
    recv: h3_quinn::RecvStream,
    buf: Vec<u8>,
}

/// A raw TCP proxy stream intercepted from the H3 connection.
pub(crate) struct RawTcpStream {
    pub(crate) send: h3_quinn::SendStream<Bytes>,
    pub(crate) recv: h3_quinn::RecvStream,
    /// Bytes already read from `recv` that come after the 0x401 varint.
    pub(crate) prefix: Vec<u8>,
}

impl HyServerConn {
    fn new(
        inner: H3QuinnConn,
        quinn_conn: quinn::Connection,
        tcp_tx: mpsc::UnboundedSender<RawTcpStream>,
        authenticated: Arc<AtomicBool>,
    ) -> Self {
        Self {
            inner,
            quinn_conn,
            tcp_tx,
            authenticated,
            peeking: None,
        }
    }
}

// ── h3::quic::OpenStreams<Bytes> for HyServerConn ────────────────────────────

impl quic::OpenStreams<Bytes> for HyServerConn {
    type BidiStream = HyBidiStream;
    type SendStream = h3_quinn::SendStream<Bytes>;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        match self.inner.poll_open_bidi(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(bidi)) => {
                let (send, recv) = bidi.split();
                Poll::Ready(Ok(HyBidiStream {
                    send,
                    recv: HyRecvStream {
                        prefix: Bytes::new(),
                        inner: recv,
                    },
                }))
            }
        }
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        self.inner.poll_open_send(cx)
    }

    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        // Specify Bytes to resolve the ambiguous Buf type parameter.
        <h3_quinn::Connection as quic::OpenStreams<Bytes>>::close(&mut self.inner, code, reason)
    }
}

// ── h3::quic::Connection<Bytes> for HyServerConn ────────────────────────────

impl quic::Connection<Bytes> for HyServerConn {
    type RecvStream = h3_quinn::RecvStream;
    type OpenStreams = HyOpenStreams;

    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::RecvStream, ConnectionErrorIncoming>> {
        <h3_quinn::Connection as quic::Connection<Bytes>>::poll_accept_recv(&mut self.inner, cx)
    }

    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, ConnectionErrorIncoming>> {
        loop {
            if self.peeking.is_some() {
                // Try to read more bytes to determine the frame type
                let poll_result = if let Some(ps) = self.peeking.as_mut() {
                    ps.recv.poll_data(cx)
                } else {
                    continue;
                };
                match poll_result {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(_)) => {
                        // Stream error during peek — discard stream
                        self.peeking = None;
                        continue;
                    }
                    Poll::Ready(Ok(None)) => {
                        // Stream closed before we could peek — discard
                        self.peeking = None;
                        continue;
                    }
                    Poll::Ready(Ok(Some(chunk))) => {
                        if let Some(ps) = self.peeking.as_mut() {
                            ps.buf.extend_from_slice(&chunk);
                        } else {
                            continue;
                        }

                        // Try to parse the leading frame-type varint first.
                        // QUIC may deliver the entire first H3 frame in one chunk,
                        // so we must attempt parsing before checking the buffer size.
                        let parse_result = if let Some(ps) = self.peeking.as_ref() {
                            varint_read(&ps.buf)
                        } else {
                            continue;
                        };

                        match parse_result {
                            Err(_) => {
                                // Could not parse varint yet.  If we have accumulated
                                // more than 8 bytes it will never succeed (varints
                                // are at most 8 bytes), so discard the stream.
                                if self
                                    .peeking
                                    .as_ref()
                                    .map(|ps| ps.buf.len())
                                    .unwrap_or_default()
                                    > 8
                                {
                                    self.peeking = None;
                                }
                                // Otherwise keep reading more bytes.
                                continue;
                            }
                            Ok((val, n)) => {
                                let Some(ps) = self.peeking.take() else {
                                    continue;
                                };
                                if val == FRAME_TYPE_TCP_REQUEST {
                                    if !self.authenticated.load(Ordering::Acquire) {
                                        self.quinn_conn.close(
                                            quinn::VarInt::from_u32(H3_ERR_PROTOCOL_ERROR),
                                            b"unauthenticated tcp stream",
                                        );
                                        continue;
                                    }
                                    // TCP proxy stream: send to channel
                                    let raw = RawTcpStream {
                                        send: ps.send,
                                        recv: ps.recv,
                                        prefix: ps.buf[n..].to_vec(),
                                    };
                                    let _ = self.tcp_tx.send(raw);
                                    // Continue to look for the next H3 stream
                                } else {
                                    // H3 stream: return with full prefix (h3 needs to re-read)
                                    let prefix = Bytes::copy_from_slice(&ps.buf);
                                    return Poll::Ready(Ok(HyBidiStream {
                                        send: ps.send,
                                        recv: HyRecvStream {
                                            prefix,
                                            inner: ps.recv,
                                        },
                                    }));
                                }
                            }
                        }
                    }
                }
            } else {
                // Accept the next incoming bidi stream
                match self.inner.poll_accept_bidi(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(bidi)) => {
                        let (send, recv) = bidi.split();
                        self.peeking = Some(PeekingStream {
                            send,
                            recv,
                            buf: Vec::new(),
                        });
                        // Loop to start reading bytes
                    }
                }
            }
        }
    }

    fn opener(&self) -> Self::OpenStreams {
        HyOpenStreams {
            inner: <h3_quinn::Connection as quic::Connection<Bytes>>::opener(&self.inner),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// HyOpenStreams — opener that returns HyBidiStream
// ──────────────────────────────────────────────────────────────────────────────

pub(crate) struct HyOpenStreams {
    inner: h3_quinn::OpenStreams,
}

impl quic::OpenStreams<Bytes> for HyOpenStreams {
    type BidiStream = HyBidiStream;
    type SendStream = h3_quinn::SendStream<Bytes>;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        match self.inner.poll_open_bidi(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(bidi)) => {
                let (send, recv) = bidi.split();
                Poll::Ready(Ok(HyBidiStream {
                    send,
                    recv: HyRecvStream {
                        prefix: Bytes::new(),
                        inner: recv,
                    },
                }))
            }
        }
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        self.inner.poll_open_send(cx)
    }

    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        // Specify Bytes to resolve the ambiguous Buf type parameter.
        <h3_quinn::OpenStreams as quic::OpenStreams<Bytes>>::close(&mut self.inner, code, reason)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// HyBidiStream — h3 bidi stream wrapper with optional prefix bytes
// ──────────────────────────────────────────────────────────────────────────────

pub(crate) struct HyBidiStream {
    send: h3_quinn::SendStream<Bytes>,
    recv: HyRecvStream,
}

impl quic::RecvStream for HyBidiStream {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, StreamErrorIncoming>> {
        self.recv.poll_data(cx)
    }

    fn stop_sending(&mut self, error_code: u64) {
        self.recv.stop_sending(error_code)
    }

    fn recv_id(&self) -> StreamId {
        self.recv.recv_id()
    }
}

impl quic::SendStream<Bytes> for HyBidiStream {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.send.poll_ready(cx)
    }

    fn send_data<T: Into<WriteBuf<Bytes>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
        self.send.send_data(data)
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.send.poll_finish(cx)
    }

    fn reset(&mut self, reset_code: u64) {
        self.send.reset(reset_code)
    }

    fn send_id(&self) -> StreamId {
        self.send.send_id()
    }
}

impl quic::SendStreamUnframed<Bytes> for HyBidiStream {
    fn poll_send<D: bytes::Buf>(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut D,
    ) -> Poll<Result<usize, StreamErrorIncoming>> {
        self.send.poll_send(cx, buf)
    }
}

impl quic::BidiStream<Bytes> for HyBidiStream {
    type SendStream = h3_quinn::SendStream<Bytes>;
    type RecvStream = HyRecvStream;

    fn split(self) -> (Self::SendStream, Self::RecvStream) {
        (self.send, self.recv)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// HyRecvStream — recv stream with optional leading prefix bytes
// ──────────────────────────────────────────────────────────────────────────────

pub(crate) struct HyRecvStream {
    /// Bytes to return before reading from the inner stream.
    prefix: Bytes,
    inner: h3_quinn::RecvStream,
}

impl quic::RecvStream for HyRecvStream {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, StreamErrorIncoming>> {
        if !self.prefix.is_empty() {
            let data = std::mem::take(&mut self.prefix);
            return Poll::Ready(Ok(Some(data)));
        }
        self.inner.poll_data(cx)
    }

    fn stop_sending(&mut self, error_code: u64) {
        self.inner.stop_sending(error_code)
    }

    fn recv_id(&self) -> StreamId {
        self.inner.recv_id()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// AsyncRead / AsyncWrite adapters for h3_quinn stream types
// ──────────────────────────────────────────────────────────────────────────────

/// AsyncRead adapter for h3_quinn::RecvStream with an optional byte prefix.
pub struct RecvStreamReader {
    recv: h3_quinn::RecvStream,
    prefix: Vec<u8>,
    prefix_pos: usize,
    current: Option<Bytes>,
    current_pos: usize,
}

impl RecvStreamReader {
    pub fn new(recv: h3_quinn::RecvStream, prefix: Vec<u8>) -> Self {
        Self {
            recv,
            prefix,
            prefix_pos: 0,
            current: None,
            current_pos: 0,
        }
    }

    pub fn cancel_read(&mut self, error_code: u64) {
        self.recv.stop_sending(error_code);
    }
}

impl AsyncRead for RecvStreamReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            // 1. Drain prefix
            if self.prefix_pos < self.prefix.len() {
                let n = (self.prefix.len() - self.prefix_pos).min(buf.remaining());
                buf.put_slice(&self.prefix[self.prefix_pos..self.prefix_pos + n]);
                self.prefix_pos += n;
                return Poll::Ready(Ok(()));
            }

            // 2. Drain current Bytes chunk.
            // Use take() to own the Bytes, avoiding a borrow-conflict when we later
            // mutate self.current_pos / self.current in the same scope.
            if let Some(current) = self.current.take() {
                let current_len = current.len();
                let pos = self.current_pos;
                let n = (current_len - pos).min(buf.remaining());
                buf.put_slice(&current[pos..pos + n]);
                self.current_pos += n;
                if self.current_pos < current_len {
                    // Still bytes left in this chunk — put it back.
                    self.current = Some(current);
                } else {
                    self.current_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }

            // 3. Poll for the next chunk from the QUIC stream
            match self.recv.poll_data(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        e.to_string(),
                    )));
                }
                Poll::Ready(Ok(None)) => return Poll::Ready(Ok(())), // EOF
                Poll::Ready(Ok(Some(chunk))) => {
                    self.current = Some(chunk);
                    self.current_pos = 0;
                    // loop to drain
                }
            }
        }
    }
}

/// AsyncWrite adapter for h3_quinn::SendStream<Bytes>.
/// Uses `SendStreamUnframed::poll_send` to bypass H3 framing.
pub(crate) struct SendStreamWriter {
    send: h3_quinn::SendStream<Bytes>,
}

impl AsyncWrite for SendStreamWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut slice: &[u8] = buf;
        match self.send.poll_send(cx, &mut slice) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(n)) => Poll::Ready(Ok(n)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.send.poll_finish(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))),
        }
    }
}

impl SendStreamWriter {
    async fn close(&mut self) -> std::io::Result<()> {
        std::future::poll_fn(|cx| match self.send.poll_finish(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))),
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::server_target_bps;

    #[test]
    fn server_target_bps_matches_go_server_cap_logic() {
        // server_speed_bps = 0 means "no server cap", so use client_rx directly.
        assert_eq!(server_target_bps(1000, 0, false), 1000);
        assert_eq!(server_target_bps(0, 1000, false), 0);
        assert_eq!(server_target_bps(2000, 1000, false), 1000);
        assert_eq!(server_target_bps(1000, 2000, false), 1000);
        assert_eq!(server_target_bps(1000, 2000, true), 0);
    }
}
