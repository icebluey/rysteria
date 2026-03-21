/// ConnectionActor — single owner of one authenticated QUIC connection's
/// control path and UDP datagram sends.
///
/// TCP proxy streams write directly to their own QUIC SendStream from
/// TcpFlowActor (no serialization through this actor). This eliminates
/// head-of-line blocking: each QUIC stream has independent flow control,
/// so a slow receiver on one stream cannot block writes to other streams.
///
/// This actor handles:
///   - Permit arbitration: owns Scheduler exclusively (no Arc<Mutex> sharing).
///     TcpFlowActors send AcquirePermit requests and await oneshot responses.
///     When budget is unavailable, requests queue until budget is replenished.
///   - UDP datagram sends via QUIC unreliable datagrams (best-effort).
///   - FlowClosed cleanup (on_flow_close in Scheduler).
///   - Periodic tick for Scheduler maintenance (reclassification, credits, reclaim).
///   - GracefulDrain / Shutdown lifecycle.
use std::collections::VecDeque;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::{mpsc, oneshot};

use crate::core::internal::shard::ConnId;
use crate::core::scheduler::{FlowHints, FlowId, Permit, QueueTier, Scheduler};

// ─────────────────────────────────────────────────────────────────────────────
// SendDone — permit return over the dedicated unbounded completion channel
// ─────────────────────────────────────────────────────────────────────────────

/// Carries a completed TCP send permit back to `ConnectionActor`.
///
/// Sent over an unbounded channel so that `PermitReturnGuard::drop` can never
/// block or silently discard budget — unlike a bounded `try_send` which drops
/// the message when the channel is full.
pub(crate) struct SendDone {
    pub permit: Permit,
    pub bytes_sent: usize,
}

// ─────────────────────────────────────────────────────────────────────────────
// ConnControl — messages from flow actors to ConnectionActor
// ─────────────────────────────────────────────────────────────────────────────

/// Messages sent to `ConnectionActor` from `TcpFlowActor` and UDP relay tasks.
///
/// `SendComplete` is intentionally absent: permit returns travel on a separate
/// unbounded channel (`SendDone`) to guarantee budget is never lost under load.
pub(crate) enum ConnControl {
    /// A UDP datagram to send via QUIC unreliable datagram.
    /// ConnectionActor acquires a RealtimeDatagram permit and sends atomically.
    /// Dropped if the connection budget is exhausted (UDP is best-effort).
    UdpDatagram { payload: Bytes, flow_id: FlowId },

    /// Acquire a TCP send permit — ConnectionActor grants when budget allows.
    /// If budget is unavailable, the request is queued until budget is replenished
    /// by a SendDone or tick event. result_tx receives the granted permit.
    AcquirePermit {
        flow_id: FlowId,
        hints: FlowHints,
        size: usize,
        result_tx: oneshot::Sender<Permit>,
    },

    /// TCP flow closed — remove per-flow state from Scheduler.
    FlowClosed(FlowId),

    /// Tear down this actor immediately.
    Shutdown,

    /// Stop accepting new streams; exit on next tick.
    GracefulDrain,
}

// ─────────────────────────────────────────────────────────────────────────────
// PendingPermit — queued permit request awaiting budget
// ─────────────────────────────────────────────────────────────────────────────

struct PendingPermit {
    flow_id: FlowId,
    hints: FlowHints,
    size: usize,
    result_tx: oneshot::Sender<Permit>,
}

// ─────────────────────────────────────────────────────────────────────────────
// ConnectionActor
// ─────────────────────────────────────────────────────────────────────────────

/// Single owner of one QUIC connection's Scheduler and UDP send path.
///
/// Runs entirely on one shard thread (pinned via `ShardPool`).
/// TCP streams are written directly by their owning TcpFlowActors, which
/// request permits via AcquirePermit messages and return them via SendDone.
///
/// Pending permit requests are split into three priority-ordered queues
/// (Control → Interactive → Bulk) so that small/new flows are not starved
/// by large bulk transfers under connection budget pressure.
pub(crate) struct ConnectionActor {
    /// Direct (non-shared) ownership of the per-connection Scheduler.
    /// No Arc<Mutex> — only this actor accesses it, eliminating lock overhead.
    scheduler: Scheduler,
    /// Connection identifier for PermitBank permit issuance.
    conn_id: ConnId,
    /// Pending permit requests split by priority tier.
    /// Flush order: control → interactive → bulk.
    pending_control: VecDeque<PendingPermit>,
    pending_interactive: VecDeque<PendingPermit>,
    pending_bulk: VecDeque<PendingPermit>,
    /// Receives control messages from flow actors.
    control_rx: mpsc::Receiver<ConnControl>,
    /// Unbounded channel for permit returns from `PermitReturnGuard::drop`.
    /// Unbounded guarantees that budget is never silently discarded even when
    /// the bounded control_rx is momentarily full under high concurrency.
    completion_rx: mpsc::UnboundedReceiver<SendDone>,
    /// QUIC connection (for sending datagrams and detecting close).
    quinn_conn: quinn::Connection,
    /// When true, exit on next iteration.
    draining: bool,
}

impl ConnectionActor {
    pub fn new(
        quinn_conn: quinn::Connection,
        conn_id: ConnId,
        scheduler: Scheduler,
        control_rx: mpsc::Receiver<ConnControl>,
        completion_rx: mpsc::UnboundedReceiver<SendDone>,
    ) -> Self {
        Self {
            scheduler,
            conn_id,
            pending_control: VecDeque::new(),
            pending_interactive: VecDeque::new(),
            pending_bulk: VecDeque::new(),
            control_rx,
            completion_rx,
            quinn_conn,
            draining: false,
        }
    }

    /// Run the actor event loop.
    ///
    /// Exits when `control_rx` is closed or a `Shutdown` message is received.
    /// `GracefulDrain` sets `draining = true` but does NOT exit — the actor
    /// continues processing FlowClosed and tick events until `handle_connection`
    /// signals Shutdown after all in-flight flows have converged.
    ///
    /// Tick interval fires every 500 ms to run Scheduler::tick() for
    /// reclassification, continuation credits, and permit reclaim.
    ///
    /// Two input sources are select!-ed simultaneously:
    ///   - `control_rx` (bounded): AcquirePermit, UdpDatagram, FlowClosed, Shutdown, GracefulDrain.
    ///   - `completion_rx` (unbounded): SendDone from PermitReturnGuard::drop (never silently dropped).
    pub async fn run(mut self) {
        let mut tick_interval = tokio::time::interval(Duration::from_millis(500));
        tick_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                msg = self.control_rx.recv() => {
                    match msg {
                        Some(ctrl) => {
                            if !self.handle_control(ctrl) {
                                return;
                            }
                        }
                        None => return, // channel closed
                    }
                }
                done = self.completion_rx.recv() => {
                    // SendDone arrives here from PermitReturnGuard::drop via the
                    // unbounded channel — budget is always returned, never discarded.
                    if let Some(d) = done {
                        self.scheduler.on_send_complete(d.permit, d.bytes_sent);
                        self.flush_pending_permits();
                    }
                    // completion_rx closing means all flow actors are gone, which
                    // is harmless — control_rx will also close shortly.
                }
                _ = tick_interval.tick() => {
                    // Periodic maintenance: reclassification, stale detection,
                    // permit reclaim.
                    self.scheduler.tick();
                    // After tick may reclaim stale permits, freeing budget for
                    // pending TCP permit requests.
                    self.flush_pending_permits();
                }
            }
        }
    }

    /// Handle one `ConnControl` message. Returns `false` to stop the loop.
    fn handle_control(&mut self, ctrl: ConnControl) -> bool {
        match ctrl {
            ConnControl::UdpDatagram { payload, flow_id } => {
                // Acquire a RealtimeDatagram permit and send the datagram atomically.
                // If budget is exhausted, the datagram is dropped (UDP is best-effort).
                let hints = FlowHints::realtime();
                if let Some(permit) = self.scheduler.try_issue_permit(
                    self.conn_id,
                    Some(flow_id),
                    &hints,
                    payload.len(),
                ) {
                    let sent = match self.quinn_conn.send_datagram(payload) {
                        Ok(()) => permit.bytes,
                        Err(_) => 0,
                    };
                    self.scheduler.on_send_complete(permit, sent);
                    // Budget was just returned — flush any waiting TCP requests.
                    self.flush_pending_permits();
                }
                // else: budget exhausted, drop datagram silently (best-effort UDP).
            }
            ConnControl::AcquirePermit { flow_id, hints, size, result_tx } => {
                // Skip cancelled requests immediately.
                if result_tx.is_closed() {
                    return true;
                }
                match self.scheduler.try_issue_permit(self.conn_id, Some(flow_id), &hints, size) {
                    Some(permit) => {
                        if let Err(returned) = result_tx.send(permit) {
                            // Receiver dropped between is_closed() and send — return budget.
                            self.scheduler.on_send_complete(returned, 0);
                        }
                    }
                    None => {
                        // Insufficient budget — route to the appropriate priority queue.
                        let pending = PendingPermit { flow_id, hints, size, result_tx };
                        match self.scheduler.queue_tier(flow_id) {
                            QueueTier::Control => self.pending_control.push_back(pending),
                            QueueTier::Interactive => self.pending_interactive.push_back(pending),
                            QueueTier::Bulk => self.pending_bulk.push_back(pending),
                        }
                    }
                }
            }
            ConnControl::FlowClosed(flow_id) => {
                self.scheduler.on_flow_close(flow_id);
                // Clean up any pending requests for this flow (result_tx is closed).
                self.flush_pending_permits();
            }
            ConnControl::Shutdown => {
                return false;
            }
            ConnControl::GracefulDrain => {
                self.draining = true;
            }
        }
        true
    }

    /// Try to grant pending permit requests using currently available budget.
    ///
    /// Scans three queues in priority order: Control → Interactive → Bulk.
    /// Called after every event that may have freed budget: SendComplete,
    /// UdpDatagram completion, FlowClosed, and periodic tick.
    fn flush_pending_permits(&mut self) {
        flush_queue(&mut self.pending_control, &mut self.scheduler, self.conn_id);
        flush_queue(&mut self.pending_interactive, &mut self.scheduler, self.conn_id);
        flush_queue(&mut self.pending_bulk, &mut self.scheduler, self.conn_id);
    }
}

/// Drain a single pending-permit queue, granting permits where budget allows.
///
/// Free function to avoid borrow-checker issues with borrowing multiple fields
/// of ConnectionActor simultaneously (queue + scheduler + conn_id).
fn flush_queue(
    queue: &mut VecDeque<PendingPermit>,
    scheduler: &mut Scheduler,
    conn_id: ConnId,
) {
    let mut i = 0;
    while i < queue.len() {
        // Remove cancelled requests (receiver dropped).
        if queue[i].result_tx.is_closed() {
            queue.remove(i);
            continue;
        }
        let (flow_id, size) = {
            let p = &queue[i];
            (p.flow_id, p.size)
        };
        // Borrow hints separately to avoid borrow checker issues.
        let hints = queue[i].hints.clone();
        match scheduler.try_issue_permit(conn_id, Some(flow_id), &hints, size) {
            Some(permit) => {
                // remove(i) always returns Some because i < len, verified above.
                let p = queue.remove(i).unwrap();
                if let Err(returned) = p.result_tx.send(permit) {
                    // Receiver just dropped — return the credit immediately.
                    scheduler.on_send_complete(returned, 0);
                }
                // Don't increment i — removal shifts remaining elements down.
            }
            None => {
                i += 1;
                // Budget exhausted for this class/conn; remaining requests
                // are also unlikely to succeed, but continue scanning in
                // case different classes still have budget available.
            }
        }
    }
}
