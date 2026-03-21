/// TcpFlowActor — pipelined permit-before-read TCP proxy relay.
///
/// Handles one TCP proxy flow within a QUIC connection.
///
/// Upload path (local TCP → QUIC):
///   Uses double-buffer pipelining: while writing the current chunk to the
///   QUIC stream, simultaneously acquires the next permit and reads the next
///   chunk from the local TCP socket. This overlaps the QUIC write with the
///   permit channel round-trip and TCP read, roughly doubling single-flow
///   throughput compared to stop-and-wait.
///
///   Each flow owns its own QUIC stream writer, eliminating head-of-line
///   blocking between flows. QUIC streams have independent flow control,
///   so a slow receiver on one stream cannot block writes to other streams.
///
/// Download path (QUIC recv → local TCP):
///   Direct copy. No scheduler needed: the QUIC receive window acts as
///   the natural bound and TCP flow control back-pressures the window.
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};

use crate::core::connection_actor::{ConnControl, SendDone};
use crate::core::scheduler::{FlowHints, FlowId, Permit};

// ─────────────────────────────────────────────────────────────────────────────
// PermitReturnGuard — cancellation-safe permit release via message passing
// ─────────────────────────────────────────────────────────────────────────────

/// Cancel-safe RAII wrapper for a server-side send permit.
///
/// Sends a `SendDone` message to `ConnectionActor` on drop via an unbounded
/// channel, returning the permit credit whether the write succeeded or was
/// cancelled. Using an unbounded sender guarantees the send never fails —
/// budget is always returned even if the bounded control channel is full.
struct PermitReturnGuard {
    permit: Option<Permit>,
    completion_tx: mpsc::UnboundedSender<SendDone>,
    bytes_sent: usize,
}

impl PermitReturnGuard {
    fn new(permit: Permit, completion_tx: mpsc::UnboundedSender<SendDone>) -> Self {
        Self { permit: Some(permit), completion_tx, bytes_sent: 0 }
    }

    /// Consume the guard with the actual byte count (successful write path).
    fn complete(mut self, bytes: usize) {
        self.bytes_sent = bytes;
        // Drop happens here with bytes_sent set to the actual value.
    }
}

impl Drop for PermitReturnGuard {
    fn drop(&mut self) {
        if let Some(permit) = self.permit.take() {
            // Unbounded send never fails: budget is always returned to the actor.
            let _ = self.completion_tx.send(SendDone {
                permit,
                bytes_sent: self.bytes_sent,
            });
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TcpFlowActor
// ─────────────────────────────────────────────────────────────────────────────

/// Upload half of a TCP proxy flow.
///
/// Enforces permit-before-read backpressure via ConnectionActor message passing,
/// with pipelined double-buffer: while writing the current chunk to QUIC,
/// acquires the next permit and reads the next chunk from TCP concurrently.
pub(crate) struct TcpFlowActor<R, QW> {
    /// Unique identifier for this flow within the connection.
    pub flow_id: FlowId,
    /// Classification hints for scheduler queue placement and quantum.
    pub hints: FlowHints,
    /// Read half of the local (outbound) TCP connection.
    pub local_read: R,
    /// Write half of the QUIC SendStream — owned exclusively by this actor.
    /// Each flow writes to its own QUIC stream independently, no serialization.
    pub quic_writer: QW,
    /// Channel to ConnectionActor — used for permit requests and FlowClosed notification.
    pub conn_tx: mpsc::Sender<ConnControl>,
    /// Unbounded channel for permit returns — PermitReturnGuard sends SendDone here on drop.
    /// Kept separate from conn_tx so budget returns can never be blocked or dropped.
    pub completion_tx: mpsc::UnboundedSender<SendDone>,
}

impl<R, QW> TcpFlowActor<R, QW>
where
    R: AsyncRead + Unpin + Send,
    QW: AsyncWrite + Unpin + Send,
{
    /// Upload loop: local TCP → QUIC stream (pipelined double-buffer).
    ///
    /// Uses two buffers to overlap the QUIC write of the current chunk with
    /// the permit acquisition and TCP read of the next chunk. While the QUIC
    /// stream absorbs the current data, the next permit is acquired from
    /// ConnectionActor and the next chunk is read from the local TCP socket.
    /// This hides the permit channel round-trip behind the QUIC write,
    /// roughly doubling single-flow throughput.
    ///
    /// Each flow writes directly to its own QUIC stream. QUIC streams have
    /// independent flow control, so a slow receiver on one stream (e.g., a
    /// 4K video player) cannot block writes to other streams.
    pub(crate) async fn run(self) {
        const BUF_SIZE: usize = 32 * 1024;
        let mut buf_write = vec![0u8; BUF_SIZE];
        let mut buf_read = vec![0u8; BUF_SIZE];

        // Destructure self so the borrow checker can see disjoint borrows
        // in the tokio::join! below (quic_writer vs local_read).
        let TcpFlowActor {
            flow_id, hints, mut local_read, mut quic_writer, conn_tx, completion_tx,
        } = self;

        // Bootstrap: acquire first permit and read first chunk.
        let permit = match acquire_permit(&conn_tx, flow_id, &hints, BUF_SIZE).await {
            Some(p) => p,
            None => {
                let _ = quic_writer.shutdown().await;
                let _ = conn_tx.send(ConnControl::FlowClosed(flow_id)).await;
                return;
            }
        };
        let (mut guard, mut write_len) = match local_read.read(&mut buf_write).await {
            Ok(0) | Err(_) => {
                // EOF or read error on first read — return permit and exit.
                let _ = completion_tx.send(SendDone { permit, bytes_sent: 0 });
                let _ = quic_writer.shutdown().await;
                let _ = conn_tx.send(ConnControl::FlowClosed(flow_id)).await;
                return;
            }
            Ok(n) => (PermitReturnGuard::new(permit, completion_tx.clone()), n),
        };

        loop {
            // Pipeline: write current chunk to QUIC while simultaneously
            // acquiring the next permit and reading into the alternate buffer.
            let (write_result, prefetch) = tokio::join!(
                quic_writer.write_all(&buf_write[..write_len]),
                async {
                    let p = acquire_permit(&conn_tx, flow_id, &hints, BUF_SIZE).await?;
                    match local_read.read(&mut buf_read).await {
                        Ok(0) | Err(_) => {
                            // EOF or read error — return unused permit.
                            let _ = completion_tx.send(SendDone {
                                permit: p,
                                bytes_sent: 0,
                            });
                            None
                        }
                        Ok(n) => Some((p, n)),
                    }
                }
            );

            // Handle current write.
            match write_result {
                Ok(()) => guard.complete(write_len),
                Err(_) => {
                    // QUIC write failed — return prefetched permit if acquired.
                    if let Some((p, _)) = prefetch {
                        let _ = completion_tx.send(SendDone {
                            permit: p,
                            bytes_sent: 0,
                        });
                    }
                    break;
                }
            }

            // Advance to next chunk.
            match prefetch {
                Some((next_permit, next_len)) => {
                    guard = PermitReturnGuard::new(next_permit, completion_tx.clone());
                    write_len = next_len;
                    std::mem::swap(&mut buf_write, &mut buf_read);
                }
                None => break,
            }
        }

        let _ = quic_writer.shutdown().await;
        let _ = conn_tx.send(ConnControl::FlowClosed(flow_id)).await;
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
// acquire_permit — channel round-trip to ConnectionActor
// ─────────────────────────────────────────────────────────────────────────────

/// Acquire a send permit from ConnectionActor via oneshot round-trip.
///
/// Returns `None` if the ConnectionActor is gone (channel closed).
async fn acquire_permit(
    conn_tx: &mpsc::Sender<ConnControl>,
    flow_id: FlowId,
    hints: &FlowHints,
    size: usize,
) -> Option<Permit> {
    let (result_tx, result_rx) = oneshot::channel::<Permit>();
    conn_tx
        .send(ConnControl::AcquirePermit {
            flow_id,
            hints: hints.clone(),
            size,
            result_tx,
        })
        .await
        .ok()?;
    result_rx.await.ok()
}

// ─────────────────────────────────────────────────────────────────────────────
// Convenience spawn helper
// ─────────────────────────────────────────────────────────────────────────────

/// Spawn the upload and download loops for one TCP proxy flow.
///
/// Upload: `local_read` → AcquirePermit → write directly to `quic_writer`.
/// Download: QUIC `quic_recv` → `local_write`.
///
/// Returns the JoinHandles so the caller can `select!` on completion
/// (when either direction finishes, the other winds down naturally).
pub(crate) fn spawn_tcp_flow<R, QR, W, QW>(
    flow_id: FlowId,
    hints: FlowHints,
    local_read: R,
    local_write: W,
    quic_recv: QR,
    quic_writer: QW,
    conn_tx: mpsc::Sender<ConnControl>,
    completion_tx: mpsc::UnboundedSender<SendDone>,
) -> (tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>)
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
    QR: AsyncRead + Unpin + Send + 'static,
    QW: AsyncWrite + Unpin + Send + 'static,
{
    let actor = TcpFlowActor {
        flow_id,
        hints,
        local_read,
        quic_writer,
        conn_tx,
        completion_tx,
    };

    let upload = tokio::spawn(async move {
        actor.run().await;
    });

    let download = tokio::spawn(async move {
        download_loop(quic_recv, local_write).await;
    });

    (upload, download)
}
