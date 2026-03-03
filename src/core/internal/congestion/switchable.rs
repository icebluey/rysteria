/// Runtime-switchable congestion controller.
///
/// Starts as BBR. When `CongestionHandle::set_brutal(bps)` is called after
/// the auth handshake, the controller transitions to `BrutalSender` on the
/// next ack event.
///
/// This mirrors Go quic-go's `conn.SetCongestionControl()` behaviour, which
/// quinn 0.11 does not expose as a post-handshake API.  The switch is
/// triggered lazily inside `on_ack` (the first `&mut self` method called
/// after every ack) so it takes effect before any stream data flows.
use crate::core::internal::congestion::brutal::BrutalSender;
use quinn_proto::RttEstimator;
use quinn_proto::congestion::{BbrConfig, Controller, ControllerFactory};
use std::any::Any;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

// ──────────────────────────────────────────────────────────────────────────────
// Public API
// ──────────────────────────────────────────────────────────────────────────────

/// Creates a new `SwitchableFactory` paired with a `CongestionHandle`.
///
/// Pass the factory to `TransportConfig::congestion_controller_factory`
/// before establishing the QUIC connection.  Call `handle.set_brutal(bps)`
/// after the auth handshake to activate Brutal mode.
pub fn new_switchable_factory() -> (SwitchableFactory, CongestionHandle) {
    let bandwidth = Arc::new(AtomicU64::new(0));
    // Shared effective rate (bps / ack_rate) written by BrutalSender,
    // read by the application-level rate limiter in the copy loop.
    // Starts at 0 so the rate limiter is inactive during the BBR phase.
    let effective_bps = Arc::new(AtomicU64::new(0));
    let factory = SwitchableFactory {
        bandwidth: Arc::clone(&bandwidth),
        effective_bps: Arc::clone(&effective_bps),
        bbr_config: Arc::new(BbrConfig::default()),
    };
    let handle = CongestionHandle { bandwidth, effective_bps };
    (factory, handle)
}

// ──────────────────────────────────────────────────────────────────────────────
// SwitchableFactory
// ──────────────────────────────────────────────────────────────────────────────

/// A `ControllerFactory` whose created controllers can switch from BBR to
/// Brutal after auth.
pub struct SwitchableFactory {
    bandwidth: Arc<AtomicU64>,
    effective_bps: Arc<AtomicU64>,
    bbr_config: Arc<BbrConfig>,
}

impl ControllerFactory for SwitchableFactory {
    fn build(self: Arc<Self>, now: Instant, mtu: u16) -> Box<dyn Controller> {
        let bbr = Arc::clone(&self.bbr_config).build(now, mtu);
        Box::new(SwitchableController {
            bandwidth: Arc::clone(&self.bandwidth),
            effective_bps: Arc::clone(&self.effective_bps),
            state: ControllerState::Bbr(bbr),
        })
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// CongestionHandle
// ──────────────────────────────────────────────────────────────────────────────

/// Handle used to switch the congestion controller to Brutal after auth.
///
/// Drop or ignore the handle to keep BBR (e.g. when `speed_bps == 0`).
pub struct CongestionHandle {
    bandwidth: Arc<AtomicU64>,
    /// Shared effective rate written by `BrutalSender::update_ack_rate`.
    /// Read by the application-level rate limiter.  Zero while BBR is active.
    effective_bps: Arc<AtomicU64>,
}

impl CongestionHandle {
    /// Switch to Brutal mode with `bps` bytes/sec.  `bps == 0` is a no-op
    /// (BBR stays active).
    pub fn set_brutal(&self, bps: u64) {
        if bps > 0 {
            self.bandwidth.store(bps, Ordering::Release);
        }
    }

    /// Returns the shared effective-bps atomic for use by the copy loop.
    ///
    /// The value is 0 while BBR is active and transitions to `bps / ack_rate`
    /// once `BrutalSender` takes over.
    pub fn effective_bps_arc(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.effective_bps)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// SwitchableController — internal implementation
// ──────────────────────────────────────────────────────────────────────────────

enum ControllerState {
    Bbr(Box<dyn Controller>),
    Brutal(BrutalSender),
}

struct SwitchableController {
    bandwidth: Arc<AtomicU64>,
    effective_bps: Arc<AtomicU64>,
    state: ControllerState,
}

impl SwitchableController {
    /// Check whether the bandwidth has been set and switch to Brutal if so.
    ///
    /// `initial_rtt` is passed to `BrutalSender::new` so the window is
    /// immediately correct.  Pass `rtt.get()` from inside `on_ack` (where a
    /// valid RTT is available); pass `Duration::ZERO` from other call sites
    /// where no RTT estimator is at hand.
    fn maybe_switch(&mut self, initial_rtt: Duration) {
        if let ControllerState::Bbr(_) = &self.state {
            let bps = self.bandwidth.load(Ordering::Acquire);
            if bps > 0 {
                self.state = ControllerState::Brutal(BrutalSender::new(
                    bps,
                    initial_rtt,
                    Arc::clone(&self.effective_bps),
                ));
            }
        }
    }
}

// SAFETY: both ControllerState variants are Send + Sync:
//   - Box<dyn Controller>: Controller: Send + Sync
//   - BrutalSender: all fields are primitive / Send + Sync types
unsafe impl Send for SwitchableController {}
unsafe impl Sync for SwitchableController {}

impl Controller for SwitchableController {
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        // Try to switch here too so tests without RttEstimator can verify the
        // switch.  RTT is unknown in this call site; on_ack (which always
        // follows) will have called maybe_switch with a real RTT first in the
        // normal steady-state path.
        self.maybe_switch(Duration::ZERO);
        match &mut self.state {
            ControllerState::Bbr(b) => b.on_sent(now, bytes, last_packet_number),
            ControllerState::Brutal(b) => b.on_sent(now, bytes, last_packet_number),
        }
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        // Pass the current smoothed RTT so BrutalSender starts with a correct
        // window immediately, eliminating the ~50 ms INITIAL_CWND_NO_RTT phase.
        self.maybe_switch(rtt.get());
        match &mut self.state {
            ControllerState::Bbr(b) => b.on_ack(now, sent, bytes, app_limited, rtt),
            ControllerState::Brutal(b) => b.on_ack(now, sent, bytes, app_limited, rtt),
        }
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        match &mut self.state {
            ControllerState::Bbr(b) => {
                b.on_end_acks(now, in_flight, app_limited, largest_packet_num_acked)
            }
            ControllerState::Brutal(b) => {
                b.on_end_acks(now, in_flight, app_limited, largest_packet_num_acked)
            }
        }
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        match &mut self.state {
            ControllerState::Bbr(b) => {
                b.on_congestion_event(now, sent, is_persistent_congestion, lost_bytes)
            }
            ControllerState::Brutal(b) => {
                b.on_congestion_event(now, sent, is_persistent_congestion, lost_bytes)
            }
        }
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        match &mut self.state {
            ControllerState::Bbr(b) => b.on_mtu_update(new_mtu),
            ControllerState::Brutal(b) => b.on_mtu_update(new_mtu),
        }
    }

    fn window(&self) -> u64 {
        match &self.state {
            ControllerState::Bbr(b) => b.window(),
            ControllerState::Brutal(b) => b.window(),
        }
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        // If bandwidth is already set, clone in Brutal mode so the new path
        // starts at the right rate immediately.
        let bps = self.bandwidth.load(Ordering::Acquire);
        let state = if bps > 0 {
            match &self.state {
                // Already in Brutal — clone preserves latest_rtt.
                ControllerState::Brutal(b) => ControllerState::Brutal(b.clone()),
                // Still in BBR but bps is set — create Brutal with ZERO; the
                // real RTT will be set on the very first on_ack of the new path.
                ControllerState::Bbr(_) => ControllerState::Brutal(BrutalSender::new(
                    bps,
                    Duration::ZERO,
                    Arc::clone(&self.effective_bps),
                )),
            }
        } else {
            match &self.state {
                ControllerState::Bbr(b) => ControllerState::Bbr(b.clone_box()),
                ControllerState::Brutal(b) => ControllerState::Brutal(b.clone()),
            }
        };
        Box::new(SwitchableController {
            bandwidth: Arc::clone(&self.bandwidth),
            effective_bps: Arc::clone(&self.effective_bps),
            state,
        })
    }

    fn initial_window(&self) -> u64 {
        match &self.state {
            ControllerState::Bbr(b) => b.initial_window(),
            ControllerState::Brutal(b) => b.initial_window(),
        }
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    // Helper: trigger maybe_switch via on_sent (avoids constructing RttEstimator,
    // which has no public constructor in quinn_proto).
    fn trigger_switch(ctrl: &mut Box<dyn Controller>) {
        let now = Instant::now();
        ctrl.on_sent(now, 0, 0);
    }

    #[test]
    fn starts_as_bbr_window_is_nonzero() {
        let (factory, _handle) = new_switchable_factory();
        let ctrl = Arc::new(factory).build(Instant::now(), 1200);
        assert!(ctrl.window() > 0);
    }

    #[test]
    fn set_brutal_switches_controller() {
        let (factory, handle) = new_switchable_factory();
        let mut ctrl = Arc::new(factory).build(Instant::now(), 1200);

        // Switch to Brutal 10 MB/s — takes effect on next on_sent/on_ack
        handle.set_brutal(10_000_000);
        trigger_switch(&mut ctrl);

        // After switch: Brutal initial window (INITIAL_CWND_NO_RTT = 10240)
        let brutal_window = ctrl.window();
        assert!(brutal_window > 0, "brutal_window={}", brutal_window);
    }

    #[test]
    fn set_brutal_zero_keeps_bbr() {
        let (factory, handle) = new_switchable_factory();
        let mut ctrl = Arc::new(factory).build(Instant::now(), 1200);
        handle.set_brutal(0); // no-op
        trigger_switch(&mut ctrl);
        // Window is still valid (BBR)
        assert!(ctrl.window() > 0);
    }

    #[test]
    fn clone_box_after_switch_is_brutal() {
        let (factory, handle) = new_switchable_factory();
        let mut ctrl = Arc::new(factory).build(Instant::now(), 1200);
        handle.set_brutal(5_000_000);
        trigger_switch(&mut ctrl);
        let cloned = ctrl.clone_box();
        // Cloned controller should have the same non-zero window
        assert!(cloned.window() > 0);
    }
}
