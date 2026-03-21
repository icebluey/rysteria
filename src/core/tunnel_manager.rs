/// TunnelManager — client-side persistent QUIC tunnel.
///
/// Separates tunnel lifetime from stream/session lifetime:
///   Tunnel:  long-lived QUIC connection + TLS + auth. Created once, kept warm.
///   Stream:  short-lived QUIC bidi stream per TCP proxy request.
///   Session: short-lived UDP relay session per UDP datagram exchange.
///
/// This eliminates per-request cold start:
///   Old: request → QUIC handshake (RTT×2) → TLS → auth → relay
///   New: request → open QUIC bidi stream on warm tunnel (< 1 ms) → relay
///
/// Port-hopping (UdpHopSocket) and Salamander obfuscation apply at the
/// quinn::Endpoint layer and are orthogonal to TunnelManager — they are
/// passed through unchanged when constructing a new tunnel.
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use tokio::sync::RwLock;

use crate::core::client::{Client, ControlOp, HandshakeInfo, TunnelWorkRegistry};
use crate::core::internal::shard::ConnId;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Factory that creates a new `(Client, HandshakeInfo)` on each call.
///
/// Mirrors the `config_func` pattern used by `ReconnectableClient`.
/// Each invocation must produce a fresh QUIC connection (TLS + auth).
pub type ConnectFactory = Arc<
    dyn Fn()
            -> Pin<Box<dyn Future<Output = Result<(Client, HandshakeInfo), BoxError>> + Send>>
        + Send
        + Sync,
>;

// ─────────────────────────────────────────────────────────────────────────────
// TunnelState
// ─────────────────────────────────────────────────────────────────────────────

/// Lifecycle state of a persistent QUIC tunnel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TunnelState {
    /// QUIC handshake in progress.
    Connecting = 0,
    /// QUIC connected; HTTP/3 auth in progress.
    Authenticating = 1,
    /// Auth complete — tunnel is warm and ready for stream/session creation.
    Warm = 2,
    /// Tunnel is alive but degraded (high loss, high RTT, or path change).
    Degraded = 3,
    /// Tunnel is closed and cannot be used.
    Closed = 4,
}

// ─────────────────────────────────────────────────────────────────────────────
// TunnelHandle
// ─────────────────────────────────────────────────────────────────────────────

/// Cheap cloneable handle to a warm tunnel.
///
/// Callers hold a TunnelHandle to open streams/sessions on the persistent
/// QUIC connection. Use `client_arc()` to get the underlying `Client` for
/// `tcp()` and `udp()` calls.
#[derive(Clone)]
#[allow(dead_code)]
pub(crate) struct TunnelHandle {
    /// Connection identifier (for shard affinity and logging).
    pub conn_id: ConnId,
    /// The authenticated `Client` backing this tunnel.
    client: Arc<Client>,
    /// Handshake info returned during authentication.
    pub info: HandshakeInfo,
    /// Tunnel lifecycle state. Written by the keepalive task; read by callers.
    state: Arc<AtomicU8>,
}

impl TunnelHandle {
    /// Create a new TunnelHandle wrapping an authenticated Client.
    pub fn new(
        conn_id: ConnId,
        client: Arc<Client>,
        info: HandshakeInfo,
    ) -> Self {
        let state = Arc::new(AtomicU8::new(TunnelState::Warm as u8));
        Self { conn_id, client, info, state }
    }

    /// Return an Arc clone of the underlying Client.
    ///
    /// Used by ReconnectableClient to obtain the Client for tcp()/udp() calls.
    pub fn client_arc(&self) -> Arc<Client> {
        Arc::clone(&self.client)
    }

    /// Read the current lifecycle state.
    pub fn state(&self) -> TunnelState {
        match self.state.load(Ordering::Relaxed) {
            0 => TunnelState::Connecting,
            1 => TunnelState::Authenticating,
            2 => TunnelState::Warm,
            3 => TunnelState::Degraded,
            _ => TunnelState::Closed,
        }
    }

    /// True if the tunnel is authenticated and ready for use.
    pub fn is_warm(&self) -> bool {
        self.state() == TunnelState::Warm
    }

    /// Update the lifecycle state (called by keepalive or error detection).
    pub fn set_state(&self, s: TunnelState) {
        self.state.store(s as u8, Ordering::Relaxed);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TunnelManager
// ─────────────────────────────────────────────────────────────────────────────

/// Manages the client's persistent QUIC tunnel to the server.
///
/// Thread-safe: multiple proxy request handlers can call `get_or_connect`
/// concurrently. The internal RwLock ensures only one task creates a
/// new tunnel at a time (double-checked locking).
pub(crate) struct TunnelManager {
    /// The current primary tunnel, if any.
    primary: Arc<RwLock<Option<TunnelHandle>>>,
    /// Keepalive interval. The server's idle timeout is 30 s; we use 25 s
    /// to ensure the tunnel is never reaped while the client is active.
    pub keepalive_interval: std::time::Duration,
    /// Factory for creating new Client connections.
    factory: ConnectFactory,
    /// set to true when shutdown() is called.
    /// keepalive_loop checks this flag and exits promptly on shutdown.
    shutting_down: Arc<AtomicBool>,
    /// Optional tunnel work registry. When present, connect_new_tunnel()
    /// holds a guard during the factory call (auth + reconnect) so that
    /// wait_tunnel_drain() blocks until the reconnect completes.
    tunnel_work: Option<Arc<TunnelWorkRegistry>>,
}

impl TunnelManager {
    /// Create a new TunnelManager with the given keepalive interval and factory.
    ///
    /// If `tunnel_work` is provided, a TunnelWorkGuard is held during
    /// each reconnect (factory call) so that graceful drain waits for
    /// in-progress reconnects to finish.
    pub fn new(
        keepalive_interval: std::time::Duration,
        factory: ConnectFactory,
        tunnel_work: Option<Arc<TunnelWorkRegistry>>,
    ) -> Self {
        Self {
            primary: Arc::new(RwLock::new(None)),
            keepalive_interval,
            factory,
            shutting_down: Arc::new(AtomicBool::new(false)),
            tunnel_work,
        }
    }

    /// Return the warm tunnel, creating one if needed.
    ///
    /// Fast path (O(1)): return the existing handle when it is warm.
    /// Slow path: call connect_new_tunnel() and store the result.
    ///
    /// Safe to call from multiple tasks concurrently: the RwLock ensures
    /// only one task runs the slow path at a time.
    pub async fn get_or_connect(&self) -> Result<TunnelHandle, BoxError> {
        // Fast path: return existing warm tunnel without write-locking.
        {
            let guard = self.primary.read().await;
            if let Some(h) = guard.as_ref() {
                if h.is_warm() {
                    return Ok(h.clone());
                }
            }
        }
        // Slow path: upgrade to write lock and create a new tunnel.
        // Re-check inside the write lock to avoid double-connect.
        let mut guard = self.primary.write().await;
        if let Some(h) = guard.as_ref() {
            if h.is_warm() {
                return Ok(h.clone());
            }
        }
        let handle = self.connect_new_tunnel().await?;
        *guard = Some(handle.clone());
        Ok(handle)
    }

    /// Establish a new QUIC connection, authenticate, and return a warm handle.
    ///
    /// Delegates to the factory function which calls `Client::connect()`
    /// with the appropriate `ClientConfig`. The auth control lease is acquired
    /// inside `Client::connect()`. An additional Reconnect control lease is
    /// held briefly during tunnel handle construction to make the reconnect
    /// operation visible to the scheduler for control-plane arbitration.
    async fn connect_new_tunnel(&self) -> Result<TunnelHandle, BoxError> {
        // Hold a tunnel work guard during the factory call (auth + reconnect)
        // so that wait_tunnel_drain() blocks until this reconnect completes.
        // If the registry is closing, the guard registration fails and we
        // skip the reconnect (shutdown is in progress).
        let _work_guard = self.tunnel_work.as_ref()
            .map(|tw| tw.register())
            .transpose()
            .map_err(|e| Box::new(e) as BoxError)?;
        let (client, info) = (self.factory)().await?;
        // Acquire a reconnect control lease from the new connection's actor.
        // This is a required control operation: if the actor is dead, the tunnel
        // cannot function and the reconnect must fail (TunnelManager retries naturally).
        let _reconnect_lease = client.acquire_control_lease(ControlOp::Reconnect).await
            .map_err(|e| -> BoxError {
                format!("reconnect control lease failed: {e}").into()
            })?;
        let conn_id = ConnId(rand::random::<u64>());
        Ok(TunnelHandle::new(conn_id, Arc::new(client), info))
    }

    /// Invalidate the current tunnel (e.g. after a detected failure).
    ///
    /// The next call to `get_or_connect` will create a fresh tunnel.
    pub async fn invalidate(&self) {
        let mut guard = self.primary.write().await;
        if let Some(h) = guard.as_ref() {
            h.set_state(TunnelState::Closed);
        }
        *guard = None;
    }

    /// Signal the keepalive loop to stop. Does NOT close the QUIC connection
    /// or invalidate the tunnel, so in-flight handlers can continue using it
    /// during a graceful drain period.
    pub async fn begin_shutdown(&self) {
        self.shutting_down.store(true, Ordering::Relaxed);
    }

    /// Force-close the QUIC connection on the active tunnel and clear the
    /// primary handle. Called after the drain deadline expires.
    pub async fn force_close(&self) {
        let mut guard = self.primary.write().await;
        if let Some(h) = guard.take() {
            h.set_state(TunnelState::Closed);
            h.client_arc().close();
        }
    }

    /// Full shutdown — stop the keepalive loop and force-close the tunnel.
    ///
    /// Equivalent to `begin_shutdown()` followed by `force_close()`.
    /// Used for immediate (non-graceful) close.
    #[allow(dead_code)]
    pub async fn shutdown(&self) {
        self.begin_shutdown().await;
        self.force_close().await;
    }

    /// Background keepalive task.
    ///
    /// Checks the tunnel health every `keepalive_interval`. If the tunnel
    /// is not warm, attempts to reconnect. Returns when cancelled or shutdown.
    pub async fn keepalive_loop(self: Arc<Self>) {
        loop {
            tokio::time::sleep(self.keepalive_interval).await;

            // exit keepalive loop when shutdown() has been called.
            if self.shutting_down.load(Ordering::Relaxed) {
                return;
            }

            let needs_reconnect = {
                let guard = self.primary.read().await;
                guard.as_ref().map(|h| !h.is_warm()).unwrap_or(true)
            };

            if needs_reconnect {
                if let Err(e) = self.get_or_connect().await {
                    tracing::warn!(error = %e, "tunnel keepalive: reconnect failed");
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests — TunnelManager reconnect automation
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;
    use std::time::Duration;

    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use crate::core::client::{Client, ClientConfig, ClientPacketTransport, ClientTlsConfig};
    use crate::core::server::{Server, ServerConfig};
    use crate::extras::auth::PasswordAuthenticator;
    use crate::extras::tls::SniGuardMode;

    fn make_cert() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
        (vec![cert_der], key_der)
    }

    async fn spawn_server(password: &str) -> std::net::SocketAddr {
        let (tls_cert, tls_key) = make_cert();
        let server = Server::new(ServerConfig {
            authenticator: Arc::new(PasswordAuthenticator {
                password: password.to_string(),
            }),
            tls_cert,
            tls_key,
            tls_client_ca: None,
            tls_sni_guard: SniGuardMode::Disable,
            addr: "127.0.0.1:0".parse().unwrap(),
            transport: None,
            transport_builder: None,
            speed_bps: 0,
            speed_rx_bps: 0,
            ignore_client_bandwidth: false,
            event_logger: None,
            traffic_logger: None,
            request_hook: None,
            outbound: None,
            masq_handler: None,
            disable_udp: false,
            speed_test: false,
            udp_idle_timeout: Duration::from_secs(60),
            obfs_salamander_password: None,
            shard_threads: Some(1),
        })
        .unwrap();
        let addr = server.local_addr();
        tokio::spawn(async move {
            let _ = server.serve().await;
        });
        addr
    }

    fn client_cfg(password: &str, server_addr: std::net::SocketAddr) -> ClientConfig {
        ClientConfig {
            auth: password.to_string(),
            server_addr,
            server_name: "localhost".to_string(),
            tls: ClientTlsConfig::InsecureSkipVerify { client_identity: None },
            bandwidth_tx: 0,
            bandwidth_rx: 0,
            transport: None,
            udp_socket_factory: None,
            packet_transport: ClientPacketTransport::Udp,
            obfs: None,
            fast_open: false,
            persistent_tunnel: true,
            tunnel_keepalive_secs: 25,
            conn_send_budget: None,
            socket_wrapper: None,
            hop_generation: None,
        }
    }

    async fn spawn_echo_server() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else { break };
                tokio::spawn(async move {
                    let (mut rd, mut wr) = stream.split();
                    let _ = tokio::io::copy(&mut rd, &mut wr).await;
                });
            }
        });
        addr
    }

    /// TunnelManager reconnects after invalidation and the new tunnel works.
    ///
    /// Proves:
    ///   - get_or_connect() creates a warm tunnel on first call.
    ///   - invalidate() marks the tunnel as closed.
    ///   - get_or_connect() after invalidation creates a NEW tunnel (different conn_id).
    ///   - The new tunnel goes through full auth (control lease code path exercised).
    ///   - TCP echo works through the new tunnel's Client.
    #[tokio::test]
    async fn test_tunnel_reconnect_after_invalidation() {
        let echo_addr = spawn_echo_server().await;
        let server_addr = spawn_server("tunnel_test").await;

        let connect_count = Arc::new(AtomicU32::new(0));
        let cc = Arc::clone(&connect_count);

        let factory: ConnectFactory = Arc::new(move || {
            let cc = Arc::clone(&cc);
            Box::pin(async move {
                let (client, info) =
                    Client::connect(client_cfg("tunnel_test", server_addr)).await?;
                cc.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok((client, info))
            })
        });

        let mgr = TunnelManager::new(Duration::from_secs(300), factory, None);

        // First connection.
        let handle1 = mgr.get_or_connect().await.expect("first connect failed");
        assert_eq!(handle1.state(), TunnelState::Warm);
        assert_eq!(connect_count.load(std::sync::atomic::Ordering::Relaxed), 1);

        // TCP echo through first tunnel.
        {
            let client = handle1.client_arc();
            let mut proxy = tokio::time::timeout(
                Duration::from_secs(5),
                client.tcp(&echo_addr.to_string()),
            )
            .await
            .expect("tcp() timed out")
            .expect("tcp() failed");

            proxy.write_all(b"tunnel1").await.unwrap();
            let mut buf = [0u8; 7];
            tokio::time::timeout(Duration::from_secs(3), proxy.read_exact(&mut buf))
                .await
                .expect("read timed out")
                .unwrap();
            assert_eq!(&buf, b"tunnel1");
        }

        // Invalidate tunnel (simulates connection death detection).
        mgr.invalidate().await;
        assert_eq!(handle1.state(), TunnelState::Closed);

        // Reconnect: get_or_connect() must create a new tunnel.
        let handle2 = mgr.get_or_connect().await.expect("reconnect failed");
        assert_eq!(handle2.state(), TunnelState::Warm);
        assert_eq!(connect_count.load(std::sync::atomic::Ordering::Relaxed), 2);

        // Different conn_id proves it is a new QUIC connection, not the old one.
        assert_ne!(
            handle1.conn_id.0, handle2.conn_id.0,
            "Reconnected tunnel must have a different conn_id"
        );

        // TCP echo through the new tunnel proves auth + control lease succeeded.
        {
            let client = handle2.client_arc();
            let mut proxy = tokio::time::timeout(
                Duration::from_secs(5),
                client.tcp(&echo_addr.to_string()),
            )
            .await
            .expect("tcp() timed out on reconnected tunnel")
            .expect("tcp() failed on reconnected tunnel");

            proxy.write_all(b"tunnel2").await.unwrap();
            let mut buf = [0u8; 7];
            tokio::time::timeout(Duration::from_secs(3), proxy.read_exact(&mut buf))
                .await
                .expect("read timed out on reconnected tunnel")
                .unwrap();
            assert_eq!(&buf, b"tunnel2");
        }

        // Clean up.
        handle1.client_arc().close();
        handle2.client_arc().close();
    }

    /// get_or_connect() deduplicates concurrent requests (double-checked locking).
    ///
    /// Proves that when multiple tasks call get_or_connect() concurrently,
    /// only one connection is established (the factory is called exactly once).
    #[tokio::test]
    async fn test_tunnel_concurrent_get_or_connect_deduplication() {
        let server_addr = spawn_server("dedup_test").await;

        let connect_count = Arc::new(AtomicU32::new(0));
        let cc = Arc::clone(&connect_count);

        let factory: ConnectFactory = Arc::new(move || {
            let cc = Arc::clone(&cc);
            Box::pin(async move {
                cc.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let (client, info) =
                    Client::connect(client_cfg("dedup_test", server_addr)).await?;
                Ok((client, info))
            })
        });

        let mgr = Arc::new(TunnelManager::new(Duration::from_secs(300), factory, None));

        // Spawn 4 concurrent get_or_connect() calls.
        let mut handles = Vec::new();
        for _ in 0..4 {
            let m = Arc::clone(&mgr);
            handles.push(tokio::spawn(async move {
                m.get_or_connect().await.expect("connect failed")
            }));
        }

        let mut conn_ids = Vec::new();
        for h in handles {
            let tunnel = h.await.unwrap();
            conn_ids.push(tunnel.conn_id.0);
        }

        // All 4 tasks must get the same tunnel (same conn_id).
        let first = conn_ids[0];
        for id in &conn_ids {
            assert_eq!(*id, first, "All concurrent callers must get the same tunnel");
        }

        // Factory should have been called exactly once.
        assert_eq!(
            connect_count.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "Factory must be called exactly once for concurrent requests"
        );
    }
}
