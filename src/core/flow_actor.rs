/// TcpFlowActor — permit-before-read TCP proxy relay.
///
/// Handles one TCP proxy flow within a QUIC connection.
///
/// Upload path (local TCP → QUIC):
///   1. Acquire a send permit from PermitBank.
///   2. Read one chunk from the local TCP socket.
///   3. Write the chunk directly to the QUIC SendStream (no serialization).
///   Each flow owns its own QUIC stream writer, eliminating head-of-line
///   blocking between flows. QUIC streams have independent flow control,
///   so a slow receiver on one stream cannot block writes to other streams.
///
/// Download path (QUIC recv → local TCP):
///   Direct copy. No scheduler needed: the QUIC receive window acts as
///   the natural bound and TCP flow control back-pressures the window.
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::core::connection_actor::ConnControl;
use crate::core::internal::shard::ConnId;
use crate::core::scheduler::{FlowHints, FlowId, Scheduler};

// ─────────────────────────────────────────────────────────────────────────────
// TcpFlowActor
// ─────────────────────────────────────────────────────────────────────────────

/// Upload half of a TCP proxy flow.
///
/// Enforces permit-before-read backpressure:
///   permit acquired → read from local TCP → write directly to QUIC stream
pub(crate) struct TcpFlowActor<R, QW> {
    /// Unique identifier for this flow within the connection.
    pub flow_id: FlowId,
    /// Connection identifier — used when requesting permits from PermitBank.
    pub conn_id: ConnId,
    /// Classification hints for scheduler queue placement and quantum.
    pub hints: FlowHints,
    /// Read half of the local (outbound) TCP connection.
    pub local_read: R,
    /// Write half of the QUIC SendStream — owned exclusively by this actor.
    /// Each flow writes to its own QUIC stream independently, no serialization.
    pub quic_writer: QW,
    /// Channel to ConnectionActor — only used for FlowClosed notification.
    pub conn_tx: mpsc::Sender<ConnControl>,
    /// Shared access to the Scheduler's permit bank.
    ///
    /// Only `try_issue_permit` and `on_send_complete` are called inside brief
    /// critical sections.
    pub scheduler: Arc<StdMutex<Scheduler>>,
}

impl<R, QW> TcpFlowActor<R, QW>
where
    R: AsyncRead + Unpin + Send,
    QW: AsyncWrite + Unpin + Send,
{
    /// Upload loop: local TCP → QUIC stream (direct write, no serialization).
    ///
    /// Permit-before-read: only reads from local socket when a send permit
    /// is available. Naturally limits in-flight data to the permit budget.
    /// When the PermitBank is exhausted (QUIC send path saturated), the local
    /// kernel socket buffer absorbs upstream data and TCP flow control
    /// back-pressures the upstream sender — no memory bloat.
    ///
    /// Each flow writes directly to its own QUIC stream. QUIC streams have
    /// independent flow control, so a slow receiver on one stream (e.g., a
    /// 4K video player) cannot block writes to other streams.
    pub(crate) async fn run(mut self) {
        const BUF_SIZE: usize = 32 * 1024;
        let mut buf = vec![0u8; BUF_SIZE];

        loop {
            // Step 1: acquire a permit. Spin with a short sleep when the bank
            // is exhausted. 1 ms avoids thrashing the Mutex with busy-wait
            // and is well below human perception threshold.
            let permit = loop {
                let maybe = {
                    let mut sched = self.scheduler.lock().unwrap();
                    sched.try_issue_permit(self.conn_id, Some(self.flow_id), &self.hints, BUF_SIZE)
                };
                if let Some(p) = maybe {
                    break p;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            };

            // Step 2: read from local TCP (credit acquired, safe to read).
            let n = match self.local_read.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    // EOF or error — return the unused permit before closing.
                    // Without this, every closed flow leaks permit.bytes (32 KiB)
                    // from the PermitBank. After ~1024 flows the 32 MiB connection
                    // budget is exhausted and all new permits are denied forever.
                    self.scheduler.lock().unwrap().on_send_complete(permit, 0);
                    break;
                }
                Ok(n) => n,
            };

            // Step 3: write directly to the QUIC stream (independent flow control).
            let sent = match self.quic_writer.write_all(&buf[..n]).await {
                Ok(()) => n,
                Err(_) => {
                    // QUIC stream write error — return the permit and exit.
                    self.scheduler.lock().unwrap().on_send_complete(permit, 0);
                    break;
                }
            };

            // Step 4: return the permit and update stats.
            self.scheduler.lock().unwrap().on_send_complete(permit, sent);
        }

        // Shut down the QUIC stream writer (sends FIN) and notify ConnectionActor.
        let _ = self.quic_writer.shutdown().await;
        let _ = self.conn_tx.send(ConnControl::FlowClosed(self.flow_id)).await;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Download loop (free function — does not need Scheduler)
// ─────────────────────────────────────────────────────────────────────────────

/// Download loop: QUIC recv → local TCP write.
///
/// The download direction does not need permit-before-read because:
///   - QUIC receive window (DEFAULT_STREAM_RECEIVE_WINDOW = 8 MiB) bounds
///     the in-flight data from the remote peer.
///   - Local TCP write flow control back-pressures the QUIC window
///     automatically when the local socket buffer fills.
pub(crate) async fn download_loop<QR, W>(mut quic_recv: QR, mut local_write: W)
where
    QR: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    let mut buf = vec![0u8; 32 * 1024];

    loop {
        let n = match quic_recv.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if local_write.write_all(&buf[..n]).await.is_err() {
            break;
        }
    }

    // Send TCP FIN to the target server so it knows the client is done sending.
    // Without this, the target keeps the connection open (HTTP keep-alive),
    // preventing the upload path from seeing EOF and completing the flow.
    let _ = local_write.shutdown().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Convenience spawn helper
// ─────────────────────────────────────────────────────────────────────────────

/// Spawn the upload and download loops for one TCP proxy flow.
///
/// Upload: `local_read` → permit → write directly to `quic_writer`.
/// Download: QUIC `quic_recv` → `local_write`.
///
/// Returns the JoinHandles so the caller can `select!` on completion
/// (when either direction finishes, the other winds down naturally).
pub(crate) fn spawn_tcp_flow<R, QR, W, QW>(
    flow_id: FlowId,
    conn_id: ConnId,
    hints: FlowHints,
    local_read: R,
    local_write: W,
    quic_recv: QR,
    quic_writer: QW,
    conn_tx: mpsc::Sender<ConnControl>,
    scheduler: Arc<StdMutex<Scheduler>>,
) -> (tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>)
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
    QR: AsyncRead + Unpin + Send + 'static,
    QW: AsyncWrite + Unpin + Send + 'static,
{
    let actor = TcpFlowActor { flow_id, conn_id, hints, local_read, quic_writer, conn_tx, scheduler };

    let upload = tokio::spawn(async move {
        actor.run().await;
    });

    let download = tokio::spawn(async move {
        download_loop(quic_recv, local_write).await;
    });

    (upload, download)
}
