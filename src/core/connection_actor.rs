/// ConnectionActor — single owner of one authenticated QUIC connection's
/// control path and UDP datagram sends.
///
/// TCP proxy streams write directly to their own QUIC SendStream from
/// TcpFlowActor (no serialization through this actor). This eliminates
/// head-of-line blocking: each QUIC stream has independent flow control,
/// so a slow receiver on one stream cannot block writes to other streams.
///
/// This actor handles:
///   - UDP datagram sends via QUIC unreliable datagrams.
///   - FlowClosed cleanup (on_flow_close in Scheduler).
///   - Periodic tick for Scheduler maintenance (reclassification, credits, reclaim).
///   - GracefulDrain / Shutdown lifecycle.
///   - ApplyHint forwarding.
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::mpsc;

use crate::core::scheduler::{
    FlowId, Scheduler, VisibilityHint,
};

// ─────────────────────────────────────────────────────────────────────────────
// ConnControl — messages from flow actors to ConnectionActor
// ─────────────────────────────────────────────────────────────────────────────

/// Messages sent to `ConnectionActor` from `TcpFlowActor` and UDP relay tasks.
pub(crate) enum ConnControl {
    /// A UDP datagram ready to be sent via QUIC unreliable datagram.
    UdpDatagram { payload: Bytes, permit: crate::core::scheduler::Permit },

    /// TCP flow closed — remove per-flow state from Scheduler.
    FlowClosed(FlowId),

    /// Tear down this actor immediately.
    Shutdown,

    /// Stop accepting new streams; exit on next tick.
    GracefulDrain,

    /// Forward a client cooperation hint to the scheduler.
    ApplyHint(VisibilityHint),
}

// ─────────────────────────────────────────────────────────────────────────────
// ConnectionActor
// ─────────────────────────────────────────────────────────────────────────────

/// Single owner of one QUIC connection's control path and UDP sends.
///
/// Runs entirely on one shard thread (pinned via `ShardPool`).
/// TCP streams are written directly by their owning TcpFlowActors.
pub(crate) struct ConnectionActor {
    /// Shared scheduler — also Arc'd to TcpFlowActors for permit acquisition.
    pub scheduler: Arc<StdMutex<Scheduler>>,
    /// Receives control messages from flow actors.
    control_rx: mpsc::Receiver<ConnControl>,
    /// QUIC connection (for sending datagrams and detecting close).
    quinn_conn: quinn::Connection,
    /// When true, exit on next iteration.
    draining: bool,
}

impl ConnectionActor {
    pub fn new(
        quinn_conn: quinn::Connection,
        scheduler: Arc<StdMutex<Scheduler>>,
        control_rx: mpsc::Receiver<ConnControl>,
    ) -> Self {
        Self {
            scheduler,
            control_rx,
            quinn_conn,
            draining: false,
        }
    }

    /// Run the actor event loop.
    ///
    /// Exits when `control_rx` is closed, a `Shutdown` message is received,
    /// or `GracefulDrain` was received.
    ///
    /// Tick interval fires every 500 ms to run Scheduler::tick() for
    /// reclassification, continuation credits, and permit reclaim.
    pub async fn run(mut self) {
        let mut tick_interval = tokio::time::interval(Duration::from_millis(500));
        tick_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            if self.draining {
                return;
            }

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
                _ = tick_interval.tick() => {
                    // Periodic maintenance: reclassification, stale detection,
                    // continuation_credit update, permit reclaim.
                    self.scheduler.lock().unwrap().tick();
                }
            }
        }
    }

    /// Handle one `ConnControl` message. Returns `false` to stop the loop.
    fn handle_control(&mut self, ctrl: ConnControl) -> bool {
        match ctrl {
            ConnControl::UdpDatagram { payload, permit } => {
                // Send UDP datagram directly via QUIC unreliable datagram.
                let sent = match self.quinn_conn.send_datagram(payload.clone()) {
                    Ok(()) => payload.len(),
                    Err(_) => 0,
                };
                self.scheduler.lock().unwrap().on_send_complete(permit, sent);
            }
            ConnControl::FlowClosed(flow_id) => {
                self.scheduler.lock().unwrap().on_flow_close(flow_id);
            }
            ConnControl::Shutdown => {
                return false;
            }
            ConnControl::GracefulDrain => {
                self.draining = true;
            }
            ConnControl::ApplyHint(hint) => {
                self.scheduler.lock().unwrap().apply_hint(hint);
            }
        }
        true
    }
}
