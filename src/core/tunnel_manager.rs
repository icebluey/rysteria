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

use crate::core::client::{Client, HandshakeInfo};
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
}

impl TunnelManager {
    /// Create a new TunnelManager with the given keepalive interval and factory.
    pub fn new(keepalive_interval: std::time::Duration, factory: ConnectFactory) -> Self {
        Self {
            primary: Arc::new(RwLock::new(None)),
            keepalive_interval,
            factory,
            shutting_down: Arc::new(AtomicBool::new(false)),
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
    /// with the appropriate `ClientConfig`.
    async fn connect_new_tunnel(&self) -> Result<TunnelHandle, BoxError> {
        let (client, info) = (self.factory)().await?;
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

    /// graceful shutdown — stop the keepalive loop and close the tunnel.
    ///
    /// Sets the shutdown flag (causing keepalive_loop to exit on its next wake),
    /// then invalidates the primary tunnel so the QUIC connection is closed.
    ///
    /// Called by the client process on receipt of SIGTERM / Ctrl+C.
    #[allow(dead_code)]
    pub async fn shutdown(&self) {
        self.shutting_down.store(true, Ordering::Relaxed);
        self.invalidate().await;
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
