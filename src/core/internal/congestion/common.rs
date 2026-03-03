/// Token-bucket pacing algorithm.
///
/// Go equivalent: hysteria/core/internal/congestion/common/pacer.go
use std::time::{Duration, Instant};

// ──────────────────────────────────────────────────────────────────────────────
// Constants (must match Go exactly)
// ──────────────────────────────────────────────────────────────────────────────

/// Maximum number of burst packets the pacer allows.
/// Go: `maxBurstPackets = 10`
pub const MAX_BURST_PACKETS: u64 = 10;

/// Multiplier for the time-based burst size calculation.
/// Go: `maxBurstPacingDelayMultiplier = 4`
pub const MAX_BURST_PACING_DELAY_MULTIPLIER: u64 = 4;

/// Minimum inter-packet pacing delay in nanoseconds (1 ms).
/// Go: `congestion.MinPacingDelay = time.Millisecond`
/// Sourced from quic-go/internal/protocol/params.go.
pub const MIN_PACING_DELAY_NS: u64 = 1_000_000;

/// Initial packet size for bootstrapping the pacer.
/// Go: `congestion.InitialPacketSize = protocol.InitialPacketSize = 1280`
pub const INITIAL_PACKET_SIZE: u64 = 1280;

// ──────────────────────────────────────────────────────────────────────────────
// Pacer
// ──────────────────────────────────────────────────────────────────────────────

/// Token-bucket pacing algorithm used by `BrutalSender`.
///
/// Go equivalent: `common.Pacer` in hysteria.
/// The `getBandwidth` closure in Go is replaced by a `bandwidth` field that
/// `BrutalSender` updates whenever its `ack_rate` changes.
#[derive(Clone, Debug)]
pub struct Pacer {
    /// Remaining token budget from the last send, in bytes.
    /// Go: `budgetAtLastSent congestion.ByteCount` (int64).
    budget_at_last_sent: i64,

    /// Current maximum datagram size for burst calculation, in bytes.
    /// Go: `maxDatagramSize congestion.ByteCount`.
    max_datagram_size: i64,

    /// Time of the last packet sent; `None` means never sent.
    /// Go: `lastSentTime monotime.Time` (zero value = IsZero()).
    last_sent_time: Option<Instant>,

    /// Current effective bandwidth in bytes/sec.
    /// Go: result of `getBandwidth()` closure = `float64(bps) / ackRate`.
    /// Updated by `BrutalSender` after every `update_ack_rate` call.
    bandwidth: i64,
}

impl Pacer {
    /// Creates a new pacer with default initial state.
    ///
    /// Go: `NewPacer(getBandwidth)`.
    /// Initial budget = `MAX_BURST_PACKETS * INITIAL_PACKET_SIZE`.
    pub fn new(bandwidth: i64) -> Self {
        Self {
            // Go: budgetAtLastSent: maxBurstPackets * congestion.InitialPacketSize
            budget_at_last_sent: (MAX_BURST_PACKETS * INITIAL_PACKET_SIZE) as i64,
            max_datagram_size: INITIAL_PACKET_SIZE as i64,
            last_sent_time: None,
            bandwidth,
        }
    }

    /// Updates the stored bandwidth.
    /// Called by `BrutalSender` whenever `ack_rate` changes.
    pub fn set_bandwidth(&mut self, bw: i64) {
        self.bandwidth = bw;
    }

    /// Updates the maximum datagram size.
    /// Go: `(*Pacer).SetMaxDatagramSize`.
    pub fn set_max_datagram_size(&mut self, size: i64) {
        self.max_datagram_size = size;
    }

    /// Computes the maximum allowed burst size at the current bandwidth.
    ///
    /// Go: `(*Pacer).maxBurstSize`.
    /// `max(4ms * bandwidth, MAX_BURST_PACKETS * max_datagram_size)`
    fn max_burst_size(&self) -> i64 {
        let time_based = (MAX_BURST_PACING_DELAY_MULTIPLIER as i64 * MIN_PACING_DELAY_NS as i64)
            * self.bandwidth
            / 1_000_000_000;
        let packet_based = MAX_BURST_PACKETS as i64 * self.max_datagram_size;
        time_based.max(packet_based)
    }

    /// Computes the available token budget at time `now`.
    ///
    /// Go: `(*Pacer).Budget`.
    /// Returns the smaller of `max_burst_size` and the accumulated budget.
    pub fn budget(&self, now: Instant) -> i64 {
        let last = match self.last_sent_time {
            None => return self.max_burst_size(),
            Some(t) => t,
        };
        let elapsed_ns = now.duration_since(last).as_nanos() as i64;
        // Go: budget := budgetAtLastSent + getBandwidth()*elapsed_ns / 1e9
        // Protect against signed overflow (Go also checks budget < 0).
        let earned = self.bandwidth.saturating_mul(elapsed_ns) / 1_000_000_000;
        let mut budget = self.budget_at_last_sent.saturating_add(earned);
        if budget < 0 {
            // Go: if budget < 0 { budget = 1<<62 - 1 }
            budget = (1i64 << 62) - 1;
        }
        budget.min(self.max_burst_size())
    }

    /// Records that a packet of `size` bytes was sent at `send_time`.
    ///
    /// Go: `(*Pacer).SentPacket`.
    pub fn sent_packet(&mut self, send_time: Instant, size: i64) {
        let budget = self.budget(send_time);
        self.budget_at_last_sent = if size > budget { 0 } else { budget - size };
        self.last_sent_time = Some(send_time);
    }

    /// Returns when the next packet may be sent.
    ///
    /// Returns `None` if a packet can be sent immediately.
    /// Returns `Some(t)` where `t` is the earliest time the next send is allowed.
    ///
    /// Go: `(*Pacer).TimeUntilSend` returns `monotime.Time(0)` for "immediate".
    pub fn time_until_send(&self) -> Option<Instant> {
        if self.budget_at_last_sent >= self.max_datagram_size {
            return None; // immediate
        }
        let last = self.last_sent_time?; // None → immediate (never sent)
        if self.bandwidth <= 0 {
            return None; // bandwidth unknown → immediate
        }
        // Go: diff := 1e9 * uint64(maxDatagramSize - budgetAtLastSent)
        // Both values positive since we checked budget < max_datagram_size above.
        let need = (self.max_datagram_size - self.budget_at_last_sent) as u64;
        let diff = 1_000_000_000u64 * need;
        let bw = self.bandwidth as u64;
        // Go: d := diff / bw; if diff%bw > 0 { d++ }  (ceiling division)
        let d_ns = diff / bw + if diff % bw > 0 { 1 } else { 0 };
        let delay_ns = d_ns.max(MIN_PACING_DELAY_NS);
        Some(last + Duration::from_nanos(delay_ns))
    }

    /// Returns the stored maximum datagram size.
    pub fn max_datagram_size(&self) -> i64 {
        self.max_datagram_size
    }

    /// Returns the stored budget at last send.
    pub fn budget_at_last_sent(&self) -> i64 {
        self.budget_at_last_sent
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    const BW_1MBPS: i64 = 1_000_000; // 1 MB/s

    #[test]
    fn initial_budget_is_burst_size() {
        let p = Pacer::new(BW_1MBPS);
        // Before any send, budget() returns max_burst_size()
        let now = Instant::now();
        let b = p.budget(now);
        let expected_min = (MAX_BURST_PACKETS * INITIAL_PACKET_SIZE) as i64;
        assert!(
            b >= expected_min,
            "budget {} < expected min {}",
            b,
            expected_min
        );
    }

    #[test]
    fn sent_packet_reduces_budget() {
        let mut p = Pacer::new(BW_1MBPS);
        let now = Instant::now();
        let initial = p.budget(now);
        p.sent_packet(now, 1000);
        // After sending 1000 bytes, the budget should be exactly initial - 1000
        // (at the same instant, no time has elapsed).
        let after = p.budget(now);
        assert_eq!(after, initial - 1000);
    }

    #[test]
    fn budget_grows_over_time() {
        let mut p = Pacer::new(BW_1MBPS);
        let t0 = Instant::now();
        // Drain the budget
        let b = p.budget(t0);
        p.sent_packet(t0, b);
        assert_eq!(p.budget(t0), 0);

        // After 10ms, with 1MB/s bandwidth, we should have earned 10_000 bytes
        let t1 = t0 + Duration::from_millis(10);
        let earned = p.budget(t1);
        assert!(earned > 0, "budget should grow over time");
        // Approximate: 1_000_000 * 10_000_000 ns / 1_000_000_000 = 10_000 bytes
        assert!(
            earned >= 9_000 && earned <= 11_000,
            "unexpected earned budget: {}",
            earned
        );
    }

    #[test]
    fn time_until_send_immediate_if_budget_sufficient() {
        let p = Pacer::new(BW_1MBPS);
        // With fresh budget >= max_datagram_size, should be immediate
        assert!(p.time_until_send().is_none());
    }

    #[test]
    fn time_until_send_after_drain() {
        let mut p = Pacer::new(BW_1MBPS);
        let now = Instant::now();
        let b = p.budget(now);
        // Drain entirely
        p.sent_packet(now, b + 1000);
        assert_eq!(p.budget_at_last_sent(), 0);

        let send_time = p.time_until_send();
        assert!(send_time.is_some(), "should need to wait after drain");
        let t = send_time.unwrap();
        // Delay should be at least MIN_PACING_DELAY_NS (1ms)
        assert!(t >= now + Duration::from_nanos(MIN_PACING_DELAY_NS));
    }

    #[test]
    fn set_max_datagram_size_updates_field() {
        let mut p = Pacer::new(BW_1MBPS);
        p.set_max_datagram_size(2000);
        assert_eq!(p.max_datagram_size(), 2000);
    }
}
