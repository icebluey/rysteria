/// Brutal fixed-rate congestion controller.
///
/// Go equivalent: hysteria/core/internal/congestion/brutal/brutal.go
///
/// Implements `quinn_proto::congestion::Controller` for integration with quinn.
/// The algorithm tracks ack/loss counts in a 5-slot circular buffer (1 slot = 1 second)
/// and adjusts the effective bandwidth using an ack rate factor.
use crate::core::internal::congestion::common::{INITIAL_PACKET_SIZE, Pacer};
use once_cell::sync::Lazy;
use quinn_proto::RttEstimator;
use quinn_proto::congestion::{Controller, ControllerFactory};
use std::any::Any;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

// ──────────────────────────────────────────────────────────────────────────────
// Constants (must match Go exactly)
// ──────────────────────────────────────────────────────────────────────────────

/// Number of per-second slots in the sampling window.
/// Go: `pktInfoSlotCount = 5`
pub const PKT_INFO_SLOT_COUNT: usize = 5;

/// Minimum total sample count before ack rate is computed.
/// Go: `minSampleCount = 50`
pub const MIN_SAMPLE_COUNT: u64 = 50;

/// Minimum allowable ack rate (floor at 80%).
/// Go: `minAckRate = 0.8`
pub const MIN_ACK_RATE: f64 = 0.8;

/// Congestion window multiplier: `cwnd = bps * rtt * MULTIPLIER / ack_rate`.
/// Go: `congestionWindowMultiplier = 2` (used as float64 in calculation).
pub const CONGESTION_WINDOW_MULTIPLIER: f64 = 2.0;

/// Environment variable for enabling debug output.
/// Go: `debugEnv = "HYSTERIA_BRUTAL_DEBUG"` — we use `RYSTERIA_BRUTAL_DEBUG`.
pub const DEBUG_ENV: &str = "RYSTERIA_BRUTAL_DEBUG";

/// Minimum seconds between debug prints.
/// Go: `debugPrintInterval = 2`
pub const DEBUG_PRINT_INTERVAL: i64 = 2;

/// Congestion window returned when RTT is unknown (zero).
/// Go: `return 10240`
pub const INITIAL_CWND_NO_RTT: u64 = 10240;

// ──────────────────────────────────────────────────────────────────────────────
// Process-start reference time for slot indexing
// ──────────────────────────────────────────────────────────────────────────────

/// Monotonic reference time for computing second-level timestamp slots.
/// Go: `monotime.Time` (int64 nanos since process start, divided by 1e9 → seconds).
static START_TIME: Lazy<Instant> = Lazy::new(Instant::now);

/// Returns seconds elapsed since process start (monotone, consistent within process).
fn timestamp_secs(now: Instant) -> i64 {
    now.duration_since(*START_TIME).as_secs() as i64
}

// ──────────────────────────────────────────────────────────────────────────────
// PktInfo slot
// ──────────────────────────────────────────────────────────────────────────────

/// Per-second packet statistics slot.
/// Go: `pktInfo` struct.
#[derive(Clone, Copy, Debug, Default)]
pub struct PktInfo {
    /// Second-level timestamp this slot covers.
    pub timestamp: i64,
    /// Acked packets in this second.
    pub ack_count: u64,
    /// Lost packets in this second.
    pub loss_count: u64,
}

// ──────────────────────────────────────────────────────────────────────────────
// BrutalSender
// ──────────────────────────────────────────────────────────────────────────────

/// Brutal fixed-rate congestion controller.
///
/// Implements `quinn_proto::congestion::Controller`.
#[derive(Clone)]
pub struct BrutalSender {
    /// Target send rate in bytes/sec.
    /// Go: `bps congestion.ByteCount` (int64).
    bps: i64,

    /// Maximum datagram size, updated via `on_mtu_update`.
    /// Go: `maxDatagramSize congestion.ByteCount`.
    max_datagram_size: i64,

    /// Latest smoothed RTT, updated from `on_ack`.
    /// In Go, this is obtained from `rttStats.SmoothedRTT()`.
    latest_rtt: Duration,

    /// Token-bucket pacer.
    pacer: Pacer,

    /// Circular buffer of per-second statistics (5 slots).
    /// Go: `pktInfoSlots [pktInfoSlotCount]pktInfo`.
    pkt_info_slots: [PktInfo; PKT_INFO_SLOT_COUNT],

    /// Current ack rate estimate in (0.0, 1.0].
    /// Go: `ackRate float64`.
    ack_rate: f64,

    /// Whether debug output is enabled (`RYSTERIA_BRUTAL_DEBUG=true`).
    debug: bool,

    /// Timestamp of last debug ack-rate print.
    /// Go: `lastAckPrintTimestamp int64`.
    last_ack_print_timestamp: i64,

    /// Shared effective send rate: `bps / ack_rate` in bytes/sec.
    ///
    /// Updated after every `update_ack_rate` call so the application-level
    /// rate limiter in the copy loop can read the current target without
    /// going through the congestion controller machinery.
    /// Value 0 means "not yet active / unlimited".
    effective_bps: Arc<AtomicU64>,
}

impl fmt::Debug for BrutalSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BrutalSender")
            .field("bps", &self.bps)
            .field("max_datagram_size", &self.max_datagram_size)
            .field("ack_rate", &self.ack_rate)
            .field("latest_rtt", &self.latest_rtt)
            .finish()
    }
}

impl BrutalSender {
    /// Creates a new `BrutalSender` targeting `bps` bytes/sec.
    ///
    /// `initial_rtt` seeds `latest_rtt` so `window()` returns a correct value
    /// immediately, before the first `on_ack()` call.  Pass the current
    /// `RttEstimator::get()` value when switching from BBR, or
    /// `Duration::ZERO` when no RTT is yet available (e.g. standalone tests).
    ///
    /// `effective_bps` is a shared atomic that this sender updates whenever
    /// the effective send rate (`bps / ack_rate`) changes.  Pass an
    /// `Arc::new(AtomicU64::new(0))` when constructing outside the
    /// switchable-controller path (e.g. tests, standalone factory).
    ///
    /// Go: `NewBrutalSender(bps uint64) *BrutalSender`.
    pub fn new(bps: u64, initial_rtt: Duration, effective_bps: Arc<AtomicU64>) -> Self {
        let debug = std::env::var(DEBUG_ENV)
            .ok()
            .and_then(|v| v.parse::<bool>().ok())
            .unwrap_or(false);

        let bps_i64 = bps as i64;
        // Initial effective rate = bps (ack_rate = 1.0).
        effective_bps.store(bps, Ordering::Release);
        // Initial pacer bandwidth = bps / ack_rate = bps / 1.0 = bps
        let pacer = Pacer::new(bps_i64);

        Self {
            bps: bps_i64,
            max_datagram_size: INITIAL_PACKET_SIZE as i64,
            latest_rtt: initial_rtt,
            pacer,
            pkt_info_slots: [PktInfo::default(); PKT_INFO_SLOT_COUNT],
            ack_rate: 1.0,
            debug,
            last_ack_print_timestamp: 0,
            effective_bps,
        }
    }

    /// Computes the congestion window in bytes.
    ///
    /// Go: `GetCongestionWindow() congestion.ByteCount`.
    fn get_congestion_window(&self) -> u64 {
        // Go: if rtt <= 0 { return 10240 }
        if self.latest_rtt == Duration::ZERO {
            return INITIAL_CWND_NO_RTT;
        }
        // Go: float64(bps) * rtt.Seconds() * multiplier / ackRate
        let cwnd = (self.bps as f64 * self.latest_rtt.as_secs_f64() * CONGESTION_WINDOW_MULTIPLIER
            / self.ack_rate) as i64;
        // Go: if cwnd < maxDatagramSize { cwnd = maxDatagramSize }
        cwnd.max(self.max_datagram_size) as u64
    }

    /// Updates the per-second ack/loss slot at `timestamp`.
    fn update_slot(&mut self, timestamp: i64, ack_delta: u64, loss_delta: u64) {
        // Go: slot := currentTimestamp % pktInfoSlotCount
        let slot = (timestamp % PKT_INFO_SLOT_COUNT as i64) as usize;
        if self.pkt_info_slots[slot].timestamp == timestamp {
            self.pkt_info_slots[slot].ack_count += ack_delta;
            self.pkt_info_slots[slot].loss_count += loss_delta;
        } else {
            // Uninitialized or stale slot — reset
            self.pkt_info_slots[slot] = PktInfo {
                timestamp,
                ack_count: ack_delta,
                loss_count: loss_delta,
            };
        }
    }

    /// Recomputes `ack_rate` from the last `PKT_INFO_SLOT_COUNT` seconds.
    ///
    /// Go: `updateAckRate(currentTimestamp int64)`.
    fn update_ack_rate(&mut self, current_timestamp: i64) {
        let min_timestamp = current_timestamp - PKT_INFO_SLOT_COUNT as i64;
        let (mut ack_count, mut loss_count) = (0u64, 0u64);
        for info in &self.pkt_info_slots {
            if info.timestamp < min_timestamp {
                continue;
            }
            ack_count += info.ack_count;
            loss_count += info.loss_count;
        }

        // Not enough samples → treat as 100% ack rate
        if ack_count + loss_count < MIN_SAMPLE_COUNT {
            self.ack_rate = 1.0;
            if self.debug
                && current_timestamp - self.last_ack_print_timestamp >= DEBUG_PRINT_INTERVAL
            {
                self.last_ack_print_timestamp = current_timestamp;
                eprintln!(
                    "[BrutalSender] Not enough samples (total={}, ack={}, loss={})",
                    ack_count + loss_count,
                    ack_count,
                    loss_count
                );
            }
            return;
        }

        let rate = ack_count as f64 / (ack_count + loss_count) as f64;
        self.ack_rate = if rate < MIN_ACK_RATE {
            MIN_ACK_RATE
        } else {
            rate
        };

        // Sync pacer bandwidth: bps / ack_rate (matches Go's closure)
        let effective_bw = (self.bps as f64 / self.ack_rate) as i64;
        self.pacer.set_bandwidth(effective_bw);
        // Publish new effective rate for the application-level rate limiter.
        self.effective_bps
            .store(effective_bw as u64, Ordering::Release);

        if self.debug && current_timestamp - self.last_ack_print_timestamp >= DEBUG_PRINT_INTERVAL {
            let ack_rate = self.ack_rate;
            self.last_ack_print_timestamp = current_timestamp;
            eprintln!(
                "[BrutalSender] ACK rate: {:.2} (total={}, ack={}, loss={})",
                ack_rate,
                ack_count + loss_count,
                ack_count,
                loss_count
            );
        }
    }

    /// Returns a reference to the pacer (for testing).
    #[cfg(test)]
    pub fn pacer(&self) -> &Pacer {
        &self.pacer
    }

    /// Returns the current ack rate (for testing).
    #[cfg(test)]
    pub fn ack_rate(&self) -> f64 {
        self.ack_rate
    }

    /// Returns the pkt_info_slots (for testing).
    #[cfg(test)]
    pub fn pkt_info_slots(&self) -> &[PktInfo; PKT_INFO_SLOT_COUNT] {
        &self.pkt_info_slots
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Quinn Controller trait implementation
// ──────────────────────────────────────────────────────────────────────────────

impl Controller for BrutalSender {
    // ── Required methods ─────────────────────────────────────────────────────

    /// Called when a packet loss is detected.
    ///
    /// Maps to Go's `OnCongestionEventEx` loss tracking.
    /// Each call represents one lost packet (quinn calls this once per lost packet).
    fn on_congestion_event(
        &mut self,
        now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        _lost_bytes: u64,
    ) {
        // Go: b.pktInfoSlots[slot].LossCount += uint64(len(lostPackets))
        // In quinn, this is called once per lost packet → loss_delta = 1
        let ts = timestamp_secs(now);
        self.update_slot(ts, 0, 1);
        // Note: update_ack_rate is called in on_end_acks after the full batch
    }

    /// Called when the path MTU changes.
    ///
    /// Go: `SetMaxDatagramSize`.
    fn on_mtu_update(&mut self, new_mtu: u16) {
        let size = new_mtu as i64;
        self.max_datagram_size = size;
        self.pacer.set_max_datagram_size(size);
        if self.debug {
            eprintln!("[BrutalSender] SetMaxDatagramSize: {}", new_mtu);
        }
    }

    /// Returns the congestion window in bytes.
    ///
    /// Go: `GetCongestionWindow()`.
    fn window(&self) -> u64 {
        self.get_congestion_window()
    }

    /// Creates a boxed clone of this controller.
    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    /// Returns the initial congestion window.
    ///
    /// Used by quinn before any RTT sample is available.
    fn initial_window(&self) -> u64 {
        INITIAL_CWND_NO_RTT
    }

    /// Converts to `Box<dyn Any>` for downcasting.
    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }

    // ── Provided-method overrides ─────────────────────────────────────────────

    /// Called when a packet is sent.
    ///
    /// Go: `OnPacketSent → b.pacer.SentPacket(sentTime, bytes)`.
    fn on_sent(&mut self, now: Instant, bytes: u64, _last_packet_number: u64) {
        self.pacer.sent_packet(now, bytes as i64);
    }

    /// Called once per acked packet (after `on_end_acks` batch starts).
    ///
    /// Go: `OnCongestionEventEx` ack tracking.
    /// Updates RTT and increments ack_count in the current second's slot.
    fn on_ack(
        &mut self,
        now: Instant,
        _sent: Instant,
        _bytes: u64,
        _app_limited: bool,
        rtt: &RttEstimator,
    ) {
        // Update RTT (replaces Go's RTTStatsProvider.SmoothedRTT())
        // RttEstimator::get() returns smoothed RTT (or latest if no smoothed yet)
        self.latest_rtt = rtt.get();

        // Go: b.pktInfoSlots[slot].AckCount += uint64(len(ackedPackets))
        // In quinn, on_ack is called once per acked packet → ack_delta = 1
        let ts = timestamp_secs(now);
        self.update_slot(ts, 1, 0);
    }

    /// Called after all acks in a batch have been processed.
    ///
    /// Go: `OnCongestionEventEx` calls `updateAckRate` at the end.
    fn on_end_acks(
        &mut self,
        now: Instant,
        _in_flight: u64,
        _app_limited: bool,
        _largest_packet_num_acked: Option<u64>,
    ) {
        let ts = timestamp_secs(now);
        self.update_ack_rate(ts);
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// ControllerFactory
// ──────────────────────────────────────────────────────────────────────────────

/// Factory that creates `BrutalSender` instances for new connections.
pub struct BrutalControllerFactory {
    /// Target send rate in bytes/sec.
    pub bps: u64,
}

impl ControllerFactory for BrutalControllerFactory {
    fn build(self: Arc<Self>, _now: Instant, max_datagram_size: u16) -> Box<dyn Controller> {
        // Standalone factory path (not used in production; switchable path is used instead).
        let effective_bps = Arc::new(AtomicU64::new(0));
        let mut sender = BrutalSender::new(self.bps, Duration::ZERO, effective_bps);
        sender.on_mtu_update(max_datagram_size);
        Box::new(sender)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn make_sender(bps: u64) -> BrutalSender {
        BrutalSender::new(bps, Duration::ZERO, Arc::new(AtomicU64::new(0)))
    }

    // ── Window (congestion window) ───────────────────────────────────────────

    #[test]
    fn window_returns_initial_when_rtt_unknown() {
        let s = make_sender(10_000_000);
        assert_eq!(s.window(), INITIAL_CWND_NO_RTT);
    }

    #[test]
    fn window_scales_with_rtt() {
        let mut s = make_sender(10_000_000); // 10 MB/s
        s.latest_rtt = Duration::from_millis(100);
        // cwnd = 10_000_000 * 0.1 * 2.0 / 1.0 = 2_000_000
        let w = s.window();
        assert_eq!(w, 2_000_000, "window mismatch: got {}", w);
    }

    #[test]
    fn window_clamps_to_max_datagram_size() {
        let mut s = make_sender(100); // very low bandwidth
        s.latest_rtt = Duration::from_nanos(1); // very short RTT
        // cwnd = 100 * 1e-9 * 2.0 / 1.0 = tiny; should be clamped to max_datagram_size
        assert!(s.window() >= INITIAL_PACKET_SIZE);
    }

    #[test]
    fn window_with_ack_rate_below_1() {
        let mut s = make_sender(10_000_000);
        s.latest_rtt = Duration::from_millis(100);
        s.ack_rate = 0.8; // minimum allowed
        // cwnd = 10_000_000 * 0.1 * 2.0 / 0.8 = 2_500_000
        let w = s.window();
        assert_eq!(w, 2_500_000, "window with ack_rate=0.8: got {}", w);
    }

    // ── ACK rate calculation ─────────────────────────────────────────────────

    #[test]
    fn ack_rate_stays_1_when_insufficient_samples() {
        let mut s = make_sender(1_000_000);
        let ts = timestamp_secs(Instant::now());
        // Simulate 10 acks, 0 losses — below MIN_SAMPLE_COUNT (50)
        s.pkt_info_slots[0] = PktInfo {
            timestamp: ts,
            ack_count: 10,
            loss_count: 0,
        };
        s.update_ack_rate(ts);
        assert_eq!(s.ack_rate(), 1.0);
    }

    #[test]
    fn ack_rate_computed_from_samples() {
        let mut s = make_sender(1_000_000);
        let ts = timestamp_secs(Instant::now());
        // 80 acks, 20 losses → rate = 80/100 = 0.8
        s.pkt_info_slots[0] = PktInfo {
            timestamp: ts,
            ack_count: 80,
            loss_count: 20,
        };
        s.update_ack_rate(ts);
        assert!((s.ack_rate() - 0.8).abs() < 1e-9);
    }

    #[test]
    fn ack_rate_clamped_to_min() {
        let mut s = make_sender(1_000_000);
        let ts = timestamp_secs(Instant::now());
        // 50 acks, 200 losses → rate = 50/250 = 0.2 → clamped to 0.8
        s.pkt_info_slots[0] = PktInfo {
            timestamp: ts,
            ack_count: 50,
            loss_count: 200,
        };
        s.update_ack_rate(ts);
        assert_eq!(s.ack_rate(), MIN_ACK_RATE);
    }

    #[test]
    fn stale_slots_excluded_from_ack_rate() {
        let mut s = make_sender(1_000_000);
        let ts = 100i64;
        // Slot with very old timestamp — should be excluded
        s.pkt_info_slots[0] = PktInfo {
            timestamp: ts - PKT_INFO_SLOT_COUNT as i64 - 1,
            ack_count: 0,
            loss_count: 10000, // would drag rate to minimum if included
        };
        // Recent slots with perfect ack rate (100 acks)
        let slot = ((ts) % PKT_INFO_SLOT_COUNT as i64) as usize;
        s.pkt_info_slots[slot] = PktInfo {
            timestamp: ts,
            ack_count: 100,
            loss_count: 0,
        };
        s.update_ack_rate(ts);
        // With only the recent slot, ack_rate should be 1.0 (>= MIN_SAMPLE_COUNT satisfied)
        assert_eq!(s.ack_rate(), 1.0);
    }

    // ── Slot tracking ────────────────────────────────────────────────────────

    #[test]
    fn update_slot_initializes_new_timestamp() {
        let mut s = make_sender(1_000_000);
        let ts = 42i64;
        s.update_slot(ts, 10, 2);
        let slot = (ts % PKT_INFO_SLOT_COUNT as i64) as usize;
        assert_eq!(s.pkt_info_slots()[slot].timestamp, ts);
        assert_eq!(s.pkt_info_slots()[slot].ack_count, 10);
        assert_eq!(s.pkt_info_slots()[slot].loss_count, 2);
    }

    #[test]
    fn update_slot_accumulates_same_timestamp() {
        let mut s = make_sender(1_000_000);
        let ts = 42i64;
        s.update_slot(ts, 10, 2);
        s.update_slot(ts, 5, 1);
        let slot = (ts % PKT_INFO_SLOT_COUNT as i64) as usize;
        assert_eq!(s.pkt_info_slots()[slot].ack_count, 15);
        assert_eq!(s.pkt_info_slots()[slot].loss_count, 3);
    }

    #[test]
    fn update_slot_resets_on_new_timestamp() {
        let mut s = make_sender(1_000_000);
        // Fill slot at ts=5 (slot index = 5%5 = 0)
        s.update_slot(5, 100, 50);
        // Now ts=10 maps to same slot index (10%5 = 0) but different timestamp
        s.update_slot(10, 3, 1);
        let slot = 0;
        assert_eq!(s.pkt_info_slots()[slot].timestamp, 10);
        assert_eq!(s.pkt_info_slots()[slot].ack_count, 3);
        assert_eq!(s.pkt_info_slots()[slot].loss_count, 1);
    }

    // ── Clone ────────────────────────────────────────────────────────────────

    #[test]
    fn clone_produces_independent_copy() {
        let mut s = make_sender(5_000_000);
        s.latest_rtt = Duration::from_millis(50);
        s.ack_rate = 0.9;

        let cloned = s.clone();
        assert_eq!(cloned.window(), s.window());
        // Modifying clone does not affect original
        let mut cloned2 = cloned;
        cloned2.ack_rate = 0.5;
        assert_eq!(
            cloned2.ack_rate, 0.5,
            "clone should have independent ack_rate"
        );
        assert_eq!(s.ack_rate(), 0.9);
    }

    // ── Factory ──────────────────────────────────────────────────────────────

    #[test]
    fn factory_builds_sender_with_mtu() {
        let factory = Arc::new(BrutalControllerFactory { bps: 8_000_000 });
        let now = Instant::now();
        let controller = factory.build(now, 1400);
        // Should return 10240 as initial window (RTT unknown)
        assert_eq!(controller.window(), INITIAL_CWND_NO_RTT);
    }
}
