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
    collections::HashMap,
    error::Error,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::sync::{Mutex as AsyncMutex, RwLock, mpsc};

use crate::core::errors::ClosedError;
use crate::core::internal::congestion::switchable::new_switchable_factory;
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
    _h3_keep_alive: tokio::sync::oneshot::Sender<()>,
    /// Client-side UDP session manager.
    udp_mgr: Option<Arc<ClientUdpSessionManager>>,
    udp_enabled: bool,
    fast_open: bool,
    /// Effective upload bandwidth (bytes/sec) shared with BrutalSender.
    /// Zero while BBR is active; non-zero once Brutal mode is activated.
    /// Passed to each TcpProxyConn so poll_write can throttle upload.
    upload_effective_bps: Arc<AtomicU64>,
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
        let tx = client_select_congestion(&cc_handle, rx_auto, server_rx, config.bandwidth_tx);
        // Extract the effective-bps arc before cc_handle is dropped.
        // This arc is shared with BrutalSender; the copy loop reads it to enforce
        // the upload-direction token-bucket rate limit.
        let upload_effective_bps = cc_handle.effective_bps_arc();

        drop(req_stream);
        drop(send_request);
        // Keep the H3 driver alive in a background task.
        let (keep_tx, keep_rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let _driver = h3_driver;
            let _ = keep_rx.await;
        });

        // create client-side UDP session manager only when UDP is enabled.
        // Go: this is conditional on auth response.
        let udp_mgr = if udp_enabled {
            Some(ClientUdpSessionManager::new(conn.clone()))
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
            return Ok(TcpProxyConn {
                send,
                recv: None,
                establish: Some(establish),
                upload_rate: Arc::clone(&self.upload_effective_bps),
                upload_tokens: 0,
                upload_last_refill: Instant::now(),
                upload_sleep: None,
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

        Ok(TcpProxyConn {
            send,
            recv: Some(reader),
            establish: None,
            upload_rate: Arc::clone(&self.upload_effective_bps),
            upload_tokens: 0,
            upload_last_refill: Instant::now(),
            upload_sleep: None,
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
        mgr.new_udp().await.map_err(|err| Box::new(err) as BoxError)
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
    /// keepalive loop is spawned in the background.
    pub async fn new<F, C>(
        config_func: F,
        connected_func: Option<C>,
        lazy: bool,
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
            let mgr = Arc::new(TunnelManager::new(interval, factory));

            // Spawn background keepalive loop.
            tokio::spawn(Arc::clone(&mgr).keepalive_loop());

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
    pub async fn tcp(&self, addr: &str) -> Result<TcpProxyConn, BoxError> {
        let addr = addr.to_string();
        self.client_do(move |client| async move { client.tcp(&addr).await })
            .await
    }

    /// Open a UDP relay session through the current client, reconnecting lazily.
    pub async fn udp(&self) -> Result<HyUdpConn, BoxError> {
        self.client_do(move |client| async move { client.udp().await })
            .await
    }

    /// Permanently close the wrapper and the active client connection.
    pub async fn close(&self) -> Result<(), BoxError> {
        let mut inner = self.inner.lock().await;
        inner.closed = true;
        if let Some(mgr) = &self.tunnel_mgr {
            mgr.invalidate().await;
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
    /// Shared QUIC connection for sending datagrams.
    conn: quinn::Connection,
    /// Calls the manager's close/deregister logic.  Go: `CloseFunc func()`.
    close_func: Box<dyn Fn() + Send + Sync>,
    /// True after `close()` has been called.
    closed: AtomicBool,
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
    /// Auto-fragments if the message is too large for a single QUIC datagram.
    ///
    /// Go: `func (u *udpConn) Send(data []byte, addr string) error`.
    pub async fn send(&self, data: &[u8], addr: &str) -> std::io::Result<()> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                ClosedError,
            ));
        }
        // Go: try no-frag first
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
        let bytes = bytes::Bytes::copy_from_slice(&send_buf[..n as usize]);
        match self.conn.send_datagram_wait(bytes).await {
            Ok(()) => Ok(()),
            Err(quinn::SendDatagramError::TooLarge) => {
                // Go: `msg.PacketID = uint16(rand.Intn(0xFFFF)) + 1`
                let max_size = self.conn.max_datagram_size().unwrap_or(1200);
                let mut msg = msg.clone();
                msg.pkt_id = new_frag_packet_id();
                let frags = frag_udp_message(&msg, max_size);
                for frag in frags {
                    let frag_bytes = bytes::Bytes::from(frag.to_bytes());
                    self.conn
                        .send_datagram_wait(frag_bytes)
                        .await
                        .map_err(|e| {
                            std::io::Error::other(format!("udp datagram send failed: {e}"))
                        })?;
                }
                Ok(())
            }
            Err(e) => Err(std::io::Error::other(format!(
                "udp datagram send failed: {e}"
            ))),
        }
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
}

impl ClientUdpSessionManager {
    /// Create a new manager and spawn the shared receive loop.
    ///
    /// Go: `newUDPSessionManager(io udpIO)` — spawns `go m.run()` inside.
    pub fn new(conn: quinn::Connection) -> Arc<Self> {
        let mgr = Arc::new(Self {
            conn: conn.clone(),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            next_id: AtomicU32::new(1), // Go: nextID starts at 1
            closed: AtomicBool::new(false),
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

        // Go: ReceiveCh = make(chan *UDPMessage, udpMessageChanSize=1024)
        let (recv_tx, recv_rx) = mpsc::channel(UDP_MESSAGE_CHAN_SIZE);
        sessions.insert(id, UdpSessionSlot { recv_tx });

        // close_func removes the session from the map
        let sessions_ref = Arc::clone(&self.sessions);
        let close_func = Box::new(move || {
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
// TcpProxyConn — returned by Client::tcp()
// ──────────────────────────────────────────────────────────────────────────────

/// A bidirectional TCP proxy connection over a QUIC stream.
pub struct TcpProxyConn {
    send: quinn::SendStream,
    recv: Option<QuinnRecvReader>,
    establish: Option<Pin<Box<dyn Future<Output = std::io::Result<QuinnRecvReader>> + Send>>>,
    // ── Upload-direction token-bucket rate limiter ──────────────────────────
    // Driven by BrutalSender::update_ack_rate via the shared AtomicU64.
    // Zero means BBR is active and no limiting is applied.
    upload_rate: Arc<AtomicU64>,
    upload_tokens: i64,
    upload_last_refill: Instant,
    // When non-None, the next poll_write call blocks until this sleep resolves.
    upload_sleep: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl TcpProxyConn {
    fn close_stream_halves(&mut self) {
        if let Some(recv) = self.recv.as_mut() {
            recv.close();
        }
        let _ = self.send.finish();
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
                self.close_stream_halves();
                std::task::Poll::Ready(Err(err))
            }
        }
    }
}

impl Drop for TcpProxyConn {
    fn drop(&mut self) {
        self.close_stream_halves();
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
        // TcpProxyConn: Unpin (all fields are Unpin including Pin<Box<T>>),
        // so get_mut() is always safe here.
        let this = self.get_mut();

        // Step 1: If a rate-limit sleep from the previous write is still
        // pending, block until it resolves before accepting new data.
        // Do NOT reset tokens or last_refill here: the elapsed computation in
        // Step 3 will include the sleep duration (plus any over-sleep from
        // timer granularity), naturally crediting the correct number of tokens
        // and keeping the long-term average rate at bps/ack_rate.
        if let Some(sleep) = this.upload_sleep.as_mut() {
            match sleep.as_mut().poll(cx) {
                std::task::Poll::Pending => return std::task::Poll::Pending,
                std::task::Poll::Ready(_) => {
                    this.upload_sleep = None;
                }
            }
        }

        // Step 2: Forward the write to the underlying QUIC send stream.
        // quinn::SendStream has an inherent poll_write that returns WriteError;
        // calling via the AsyncWrite trait converts it to io::Error.
        let n = match <quinn::SendStream as tokio::io::AsyncWrite>::poll_write(
            std::pin::Pin::new(&mut this.send),
            cx,
            buf,
        ) {
            std::task::Poll::Pending => return std::task::Poll::Pending,
            std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
            std::task::Poll::Ready(Ok(n)) => n,
        };

        // Step 3: Token-bucket accounting for the upload direction.
        // rate == 0 means BBR is active — skip limiting entirely.
        let rate = this.upload_rate.load(Ordering::Relaxed);
        if rate > 0 && n > 0 {
            // 4 ms burst window, matching the server-side copy_tcp_to_quic.
            const BURST_NANOS: u64 = 4_000_000;
            let now = Instant::now();
            let elapsed_nanos = now.duration_since(this.upload_last_refill).as_nanos();
            this.upload_last_refill = now;
            let new_tokens = (rate as u128 * elapsed_nanos / 1_000_000_000) as i64;
            let max_burst = (rate as u128 * BURST_NANOS as u128 / 1_000_000_000) as i64;
            this.upload_tokens = (this.upload_tokens + new_tokens).min(max_burst);
            this.upload_tokens -= n as i64;
            if this.upload_tokens < 0 {
                let sleep_nanos =
                    ((-this.upload_tokens) as u128 * 1_000_000_000 / rate as u128) as u64;
                let mut sleep =
                    Box::pin(tokio::time::sleep(Duration::from_nanos(sleep_nanos)));
                // Poll the sleep once: it may resolve immediately if the debt
                // is tiny.  If still pending, store it so the next poll_write
                // call blocks until it fires.
                // Either way, do NOT reset tokens or last_refill: the next
                // call's elapsed computation will credit the sleep duration.
                if sleep.as_mut().poll(cx).is_pending() {
                    this.upload_sleep = Some(sleep);
                }
            }
        }

        // The write already completed successfully.  The caller will call
        // poll_write again with the next chunk; at that point Step 1 will
        // enforce the rate limit if a sleep was scheduled above.
        std::task::Poll::Ready(Ok(n))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.send).poll_shutdown(cx)
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
            Arc::new(UdpHopSocket::new(addrs.clone(), interval)?)
        }
    };

    if let Some(obfs) = &config.obfs {
        let obfuscator = SalamanderObfuscator::new(obfs.salamander_password.as_bytes().to_vec())?;
        socket = Arc::new(ObfsUdpSocket::new(socket, obfuscator));
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
