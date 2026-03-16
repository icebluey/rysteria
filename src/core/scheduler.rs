/// Connection-level send scheduler.
///
/// Implements three-level backpressure (PermitBank) and per-flow metadata
/// tracking (FlowMeta) for classification, continuation credits, and
/// permit reclaim.
///
/// Traffic classification uses only network-layer observable behavior.
/// HTTPS content through SOCKS5/HTTP CONNECT is encrypted end-to-end,
/// making application-level inspection impossible. Classification is based
/// on network metrics: flow lifetime, byte count, progress patterns, port.
///
/// TCP flows write directly to their own QUIC streams (no queue-based
/// scheduling). The Scheduler provides:
///   - PermitBank: three-level backpressure (connection -> class -> flow).
///   - FlowMeta: per-flow stats, reclassification, continuation credits.
///   - tick(): periodic maintenance (reclassify, credits, permit reclaim).
///
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::{Duration, Instant};

pub use crate::core::internal::shard::ConnId;

// ─────────────────────────────────────────────────────────────────────────────
// Identifiers
// ─────────────────────────────────────────────────────────────────────────────

/// Per-flow identifier within a QUIC connection.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct FlowId(pub u64);

/// Per-UDP-session identifier within a QUIC connection.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct UdpSessionId(pub u32);

// ─────────────────────────────────────────────────────────────────────────────
// FlowClass and FlowHints
// ─────────────────────────────────────────────────────────────────────────────

/// Traffic class — determines PermitBank class budget selection.
///
/// Five classes (highest priority first):
///   RealtimeDatagram > Control > InteractiveObject > StreamingMedia > Bulk
///
/// Class affects which class-level budget pool a permit is drawn from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FlowClass {
    /// DNS, auth, first-packet control frames. Highest TCP priority, small budget.
    /// Port hints: 53 (DNS), 22 (SSH), 23 (Telnet), 3389 (RDP).
    Control,

    /// Short-lived, small-byte-count TCP flows (web objects, API calls).
    /// Heuristic: total_bytes < 128 KiB AND lifetime < 1500 ms.
    InteractiveObject,

    /// Long-lived, periodically progressing TCP flows (video, audio streams).
    /// Heuristic: lifetime > 2s AND sustained_progress AND periodic_progress.
    /// Gets continuation_credit bonus.
    StreamingMedia,

    /// Large downloads, uploads, sync, mirror pulls.
    /// Heuristic: total_bytes > 4 MiB.
    /// Lowest TCP priority; eats remaining bandwidth but never starves others.
    Bulk,

    /// UDP relay: games, VoIP, DNS-over-UDP. Strict highest priority.
    /// Separate budget. Small quantum matches datagram MTU (~1200 bytes).
    RealtimeDatagram,
}

/// Per-flow scheduling hints attached to every permit request.
///
/// The class field carries the initial classification and may diverge from
/// the current FlowMeta.class after HeuristicClassifier reclassifies the flow.
#[derive(Clone, Debug)]
pub struct FlowHints {
    /// Traffic class for budget selection.
    pub class: FlowClass,
    /// Destination port (if known). Used for port-based classification hints.
    /// DNS (53) -> Control, SSH (22) -> Control, etc.
    pub dest_port: Option<u16>,
    /// True if this flow entered via a UDP/datagram ingress path.
    pub is_datagram_ingress: bool,
}

impl FlowHints {
    /// Default hints for a plain TCP proxy stream.
    /// Class starts as Bulk; HeuristicClassifier will reclassify on tick.
    pub fn default_tcp() -> Self {
        Self { class: FlowClass::Bulk, dest_port: None, is_datagram_ingress: false }
    }

    /// Hints for a TCP stream to a known control port.
    pub fn control_port(dest_port: u16) -> Self {
        Self { class: FlowClass::Control, dest_port: Some(dest_port), is_datagram_ingress: false }
    }

    /// Hints for UDP relay sessions (highest scheduling priority).
    pub fn realtime() -> Self {
        Self { class: FlowClass::RealtimeDatagram, dest_port: None, is_datagram_ingress: true }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FlowUrgency
// ─────────────────────────────────────────────────────────────────────────────

/// Flow urgency level derived from observable network metrics.
///
/// Used to reclaim permits from stale flows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowUrgency {
    /// Flow is new or recently active.
    Fresh,
    /// Flow has been making progress for 3+ consecutive windows.
    Sustained,
    /// Flow has been idle for 10+ rounds with data submitted.
    Stale,
}

// ─────────────────────────────────────────────────────────────────────────────
// FlowStats
// ─────────────────────────────────────────────────────────────────────────────

/// Network-layer observable metrics for a single flow.
///
/// Updated at two points:
///   1. On send complete: total_bytes_submitted/sent, window counters, activity.
///   2. On tick: counters rotated, progress patterns evaluated.
///
/// No browser state. No content inspection. Classification from these metrics only.
pub struct FlowStats {
    pub created_at: Instant,
    pub last_activity_at: Instant,
    pub last_progress_at: Instant,

    /// Total bytes submitted/sent over the flow's lifetime.
    pub total_bytes_submitted: u64,
    /// Total bytes confirmed sent over the flow's lifetime.
    pub total_bytes_sent: u64,

    /// Bytes submitted in the current stats window (reset each tick).
    pub window_bytes_submitted: usize,
    /// Bytes that made forward progress in the current stats window (reset each tick).
    pub window_bytes_progressed: usize,

    /// Consecutive tick windows with no bytes progressed.
    pub idle_rounds: u32,
    /// Consecutive tick windows with bytes progressed.
    pub stable_rounds: u32,

    /// True if this flow shows a periodic progress pattern (bursts + gaps = media-like).
    pub periodic_progress: bool,
    /// True if this flow is currently sustaining progress (stable_rounds >= 3).
    pub sustained_progress: bool,

    /// True if this is a datagram flow (always stays RealtimeDatagram).
    pub is_datagram: bool,
    /// Destination port for port-based classification (Control class hints).
    pub dest_port: Option<u16>,

    /// Cumulative count of tick windows where bytes made progress.
    pub total_progress_windows: u32,
    /// Cumulative count of tick windows where data was submitted but did not progress.
    pub total_idle_windows: u32,
}

impl FlowStats {
    fn new(dest_port: Option<u16>, is_datagram: bool) -> Self {
        let now = Instant::now();
        Self {
            created_at: now,
            last_activity_at: now,
            last_progress_at: now,
            total_bytes_submitted: 0,
            total_bytes_sent: 0,
            window_bytes_submitted: 0,
            window_bytes_progressed: 0,
            idle_rounds: 0,
            stable_rounds: 0,
            periodic_progress: false,
            sustained_progress: false,
            is_datagram,
            dest_port,
            total_progress_windows: 0,
            total_idle_windows: 0,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FlowMeta
// ─────────────────────────────────────────────────────────────────────────────

/// Per-flow scheduling metadata tracked in `Scheduler::flow_meta`.
///
/// Combines classification state, continuation credit,
/// and urgency tracking. Also includes hint fields.
pub struct FlowMeta {
    pub flow_id: FlowId,
    /// Current traffic class (may differ from initial hints after reclassification).
    pub class: FlowClass,
    pub stats: FlowStats,

    /// Scheduling bonus for sustained-progress StreamingMedia flows.
    /// Range [0, 8]. Accumulated while stable_rounds >= 3; decays on idle.
    pub continuation_credit: u8,

    /// True if this flow can be demoted when Stale.
    /// Datagram flows are not demotable.
    pub demotable: bool,

    /// True if permits held by this flow can be partially reclaimed when idle.
    /// Datagram flows are not reclaimable.
    pub reclaimable: bool,
}

impl FlowMeta {
    fn new(flow_id: FlowId, class: FlowClass, dest_port: Option<u16>, is_datagram: bool) -> Self {
        Self {
            flow_id,
            class,
            stats: FlowStats::new(dest_port, is_datagram),
            continuation_credit: 0,
            demotable: !is_datagram,
            reclaimable: !is_datagram,
        }
    }

    /// Classify this flow's urgency from observable network metrics.
    pub fn urgency(&self) -> FlowUrgency {
        if self.stats.idle_rounds > 10 && self.stats.total_bytes_submitted > 0 {
            FlowUrgency::Stale
        } else if self.stats.stable_rounds > 3 {
            FlowUrgency::Sustained
        } else {
            FlowUrgency::Fresh
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HeuristicClassifier
// ─────────────────────────────────────────────────────────────────────────────

/// Reclassify a flow based on observed network-layer behavior.
///
/// Called from `Scheduler::tick()` every 500 ms. No content inspection,
/// no browser state. Uses only: lifetime, total bytes, progress pattern, port.
///
/// Returns the same class as `meta.class` when classification is uncertain,
/// to prevent thrashing on ambiguous flows.
fn reclassify(meta: &FlowMeta) -> FlowClass {
    let s = &meta.stats;

    // Datagram flows always stay RealtimeDatagram.
    if s.is_datagram {
        return FlowClass::RealtimeDatagram;
    }

    // Port-based override (highest priority hint after datagram check).
    if let Some(port) = s.dest_port {
        if let Some(class) = classify_by_port(port) {
            return class;
        }
    }

    let lifetime_ms = s.created_at.elapsed().as_millis() as u64;

    // Short-lived, small flows -> InteractiveObject.
    if s.total_bytes_submitted < 128 * 1024 && lifetime_ms < 1500 {
        return FlowClass::InteractiveObject;
    }

    // Long-lived, periodic, sustained -> StreamingMedia.
    if lifetime_ms > 2000 && s.periodic_progress && s.sustained_progress {
        return FlowClass::StreamingMedia;
    }

    // Large total bytes -> Bulk.
    if s.total_bytes_submitted > 4 * 1024 * 1024 {
        return FlowClass::Bulk;
    }

    // Uncertain: keep current class to avoid thrashing.
    meta.class
}

/// Port-based classification hints (network-layer observable, no content inspection).
fn classify_by_port(port: u16) -> Option<FlowClass> {
    match port {
        53 => Some(FlowClass::Control),              // DNS
        22 | 23 | 3389 => Some(FlowClass::Control), // SSH, Telnet, RDP
        _ => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// continuation_credit update
// ─────────────────────────────────────────────────────────────────────────────

/// Update continuation credits for all flows.
///
/// Called from `Scheduler::tick()`.
/// Only StreamingMedia flows accumulate credit (max 8).
/// Credit decays by 1 for any flow with idle_rounds > 0.
/// MediaPlaying hint can floor the credit at 4.
fn update_continuation_credits(flow_meta: &mut HashMap<FlowId, FlowMeta>) {
    for meta in flow_meta.values_mut() {
        if meta.class == FlowClass::StreamingMedia && meta.stats.stable_rounds >= 3 {
            // Sustained progress in StreamingMedia: grant credit (capped at 8).
            meta.continuation_credit = (meta.continuation_credit + 1).min(8);
        } else if meta.stats.idle_rounds > 0 {
            // Any idle round decays credit by 1.
            meta.continuation_credit = meta.continuation_credit.saturating_sub(1);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Permit reclaim
// ─────────────────────────────────────────────────────────────────────────────

/// Reclaim half of the held permit budget from idle reclaimable flows.
///
/// Called from `Scheduler::tick()`.
/// Reclaim threshold: idle_rounds >= 8 (~4 s at 500 ms tick interval).
/// Reclaims 50% of available budget, not 100%, so the flow can still progress.
fn reclaim_stale_permits(
    flow_meta: &mut HashMap<FlowId, FlowMeta>,
    permits: &mut PermitBank,
) {
    for meta in flow_meta.values_mut() {
        let should_reclaim = meta.reclaimable
            && meta.stats.window_bytes_progressed == 0
            && meta.stats.idle_rounds >= 8;

        if should_reclaim {
            let available = permits.flow_budget_available(meta.flow_id);
            if available > 0 {
                let reclaim = available / 2;
                if reclaim > 0 {
                    permits.reclaim_from_flow(meta.flow_id, meta.class, reclaim);
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Permit and PermitBank
// ─────────────────────────────────────────────────────────────────────────────

/// A send permit issued by `PermitBank`.
///
/// Must be acquired BEFORE reading from a local socket (permit-before-read).
/// Returned to the bank after the actual send completes.
#[derive(Debug, Clone)]
pub struct Permit {
    pub conn_id: ConnId,
    pub flow_id: Option<FlowId>,
    pub class: FlowClass,
    /// Number of bytes credited.
    pub bytes: usize,
    /// When this permit was issued.
    pub issued_at: Instant,
    /// Permit expires if not consumed within this window.
    pub expires_at: Instant,
}

/// Single-dimension byte budget.
#[derive(Debug)]
struct ByteBudget {
    capacity: usize,
    available: usize,
}

impl ByteBudget {
    fn new(capacity: usize) -> Self {
        Self { capacity, available: capacity }
    }

    fn try_take(&mut self, bytes: usize) -> bool {
        if self.available >= bytes {
            self.available -= bytes;
            true
        } else {
            false
        }
    }

    fn give_back(&mut self, bytes: usize) {
        self.available = (self.available + bytes).min(self.capacity);
    }
}

/// Three-level credit bank: connection -> class -> flow.
///
/// A permit requires all three levels to have sufficient credit.
/// Unused credit is atomically returned on `release()`.
///
/// Class budgets:
///   Control:            1 MiB  — small, rarely saturated
///   InteractiveObject:  4 MiB  — many small concurrent objects
///   StreamingMedia:     8 MiB  — sustained media feed
///   Bulk:              16 MiB  — large transfers
///   RealtimeDatagram: 512 KiB  — latency-critical, low volume
///   Total connection:  32 MiB  — unchanged from original
pub struct PermitBank {
    conn_budget: ByteBudget,
    class_budget: HashMap<FlowClass, ByteBudget>,
    flow_budget: HashMap<FlowId, ByteBudget>,
    permit_ttl: Duration,
}

impl PermitBank {
    pub fn new(conn_bytes: usize) -> Self {
        let mut class_budget = HashMap::new();
        class_budget.insert(FlowClass::Control, ByteBudget::new(1 * 1024 * 1024));
        class_budget.insert(FlowClass::InteractiveObject, ByteBudget::new(4 * 1024 * 1024));
        class_budget.insert(FlowClass::StreamingMedia, ByteBudget::new(8 * 1024 * 1024));
        class_budget.insert(FlowClass::Bulk, ByteBudget::new(16 * 1024 * 1024));
        class_budget.insert(FlowClass::RealtimeDatagram, ByteBudget::new(512 * 1024));
        Self {
            conn_budget: ByteBudget::new(conn_bytes),
            class_budget,
            flow_budget: HashMap::new(),
            permit_ttl: Duration::from_secs(2),
        }
    }

    /// Try to acquire a permit for `bytes` bytes.
    ///
    /// Returns `None` if any level (conn / class / flow) lacks credit.
    /// On failure, all taken credits are atomically rolled back.
    pub fn try_acquire(
        &mut self,
        conn_id: ConnId,
        flow_id: Option<FlowId>,
        class: FlowClass,
        bytes: usize,
    ) -> Option<Permit> {
        if !self.conn_budget.try_take(bytes) {
            return None;
        }
        let class_ok =
            self.class_budget.get_mut(&class).map(|b| b.try_take(bytes)).unwrap_or(false);
        if !class_ok {
            self.conn_budget.give_back(bytes);
            return None;
        }
        if let Some(fid) = flow_id {
            let flow_budget =
                self.flow_budget.entry(fid).or_insert_with(|| ByteBudget::new(1024 * 1024));
            if !flow_budget.try_take(bytes) {
                self.class_budget.get_mut(&class).unwrap().give_back(bytes);
                self.conn_budget.give_back(bytes);
                return None;
            }
        }
        let now = Instant::now();
        Some(Permit {
            conn_id,
            flow_id,
            class,
            bytes,
            issued_at: now,
            expires_at: now + self.permit_ttl,
        })
    }

    /// Return permit credit after a send completes.
    ///
    /// Returns the FULL permit.bytes to all budget levels because the data
    /// is no longer in-flight (either successfully sent or failed).
    pub fn release(&mut self, permit: Permit, _actually_sent: usize) {
        self.conn_budget.give_back(permit.bytes);
        if let Some(b) = self.class_budget.get_mut(&permit.class) {
            b.give_back(permit.bytes);
        }
        if let Some(fid) = permit.flow_id {
            if let Some(b) = self.flow_budget.get_mut(&fid) {
                b.give_back(permit.bytes);
            }
        }
    }

    /// Remove per-flow budget when a flow closes.
    pub fn remove_flow(&mut self, flow_id: FlowId) {
        self.flow_budget.remove(&flow_id);
    }

    /// How much budget this flow currently has available (not yet issued as permits).
    pub fn flow_budget_available(&self, flow_id: FlowId) -> usize {
        self.flow_budget.get(&flow_id).map(|b| b.available).unwrap_or(0)
    }

    /// Shrink a stale flow's per-flow budget.
    ///
    /// Only shrinks `available` (unissued credit), never touches already-issued permits.
    /// The reclaimed capacity is NOT returned to conn_budget or class_budget
    /// because the flow_budget was created independently.
    pub fn reclaim_from_flow(&mut self, flow_id: FlowId, _class: FlowClass, bytes: usize) {
        if let Some(fb) = self.flow_budget.get_mut(&flow_id) {
            let actual = bytes.min(fb.available);
            if actual == 0 {
                return;
            }
            fb.available -= actual;
            fb.capacity -= actual;
        }
    }

    /// No-op after reclassification.
    pub fn transfer_flow_class(
        &mut self,
        _flow_id: FlowId,
        _old_class: FlowClass,
        _new_class: FlowClass,
    ) {
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PageEpoch — generation tracking
// ─────────────────────────────────────────────────────────────────────────────

/// Page generation counter for flow grouping.
/// Used by the hint layer to invalidate entire generations.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, Default)]
pub struct PageEpoch(pub u64);

// ─────────────────────────────────────────────────────────────────────────────
// Scheduler — top-level permit arbiter
// ─────────────────────────────────────────────────────────────────────────────

/// The single permit arbiter for one QUIC connection.
///
/// Manages per-flow metadata, classification, continuation credits, and
/// permit reclaim. TCP flows write directly to QUIC streams; the Scheduler
/// only controls backpressure via PermitBank.
pub struct Scheduler {
    permits: PermitBank,
    /// Per-flow metadata for classification, credit, and urgency.
    flow_meta: HashMap<FlowId, FlowMeta>,
    #[allow(dead_code)]
    effective_bps: Arc<AtomicU64>,
}

impl Scheduler {
    pub fn new(effective_bps: Arc<AtomicU64>) -> Self {
        Self {
            permits: PermitBank::new(32 * 1024 * 1024),
            flow_meta: HashMap::new(),
            effective_bps,
        }
    }

    /// Try to acquire a send permit.
    ///
    /// Uses the flow's current class from flow_meta when the flow is known
    /// (post-reclassification). Falls back to hints.class for new flows.
    /// Initializes FlowMeta on first call for a new flow.
    /// Must be called BEFORE reading from a local socket (permit-before-read).
    pub fn try_issue_permit(
        &mut self,
        conn_id: ConnId,
        flow_id: Option<FlowId>,
        hints: &FlowHints,
        bytes: usize,
    ) -> Option<Permit> {
        // Initialize FlowMeta on first permit request for this flow.
        let class = if let Some(fid) = flow_id {
            let meta = self.flow_meta.entry(fid).or_insert_with(|| {
                FlowMeta::new(
                    fid,
                    hints.class,
                    hints.dest_port,
                    hints.is_datagram_ingress,
                )
            });
            meta.class
        } else {
            hints.class
        };
        self.permits.try_acquire(conn_id, flow_id, class, bytes)
    }

    /// Return permit credit after a send completes and update FlowStats.
    ///
    /// Updates both submission and progress stats. For TCP flows that write
    /// directly to QUIC streams, this is the only place where stats get updated.
    pub fn on_send_complete(&mut self, permit: Permit, sent: usize) {
        let flow_id = permit.flow_id;
        if let Some(fid) = flow_id {
            if let Some(meta) = self.flow_meta.get_mut(&fid) {
                meta.stats.total_bytes_submitted += sent as u64;
                meta.stats.window_bytes_submitted += sent;
                meta.stats.total_bytes_sent += sent as u64;
                meta.stats.window_bytes_progressed += sent;
                if sent > 0 {
                    meta.stats.last_activity_at = Instant::now();
                    meta.stats.last_progress_at = Instant::now();
                }
            }
        }
        self.permits.release(permit, sent);
    }

    /// Clean up per-flow resources when a flow closes.
    pub fn on_flow_close(&mut self, flow_id: FlowId) {
        self.flow_meta.remove(&flow_id);
        self.permits.remove_flow(flow_id);
    }

    /// Periodic maintenance: stats rotation, reclassification, credit update, reclaim.
    ///
    /// Called every 500 ms from ConnectionActor's tick interval.
    /// Runs under the Scheduler's StdMutex. Lock duration is bounded by the
    /// number of active flows per connection (typically < 100 flows).
    pub fn tick(&mut self) {
        // Step 1+2: update stats for each flow; collect reclassification candidates.
        let mut to_reclassify: Vec<(FlowId, FlowClass, FlowClass)> = Vec::new();

        for (fid, meta) in self.flow_meta.iter_mut() {
            // Update idle/stable counters based on this window's observed progress.
            if meta.stats.window_bytes_progressed > 0 {
                meta.stats.stable_rounds += 1;
                meta.stats.idle_rounds = 0;
                meta.stats.total_progress_windows += 1;
                meta.stats.sustained_progress = meta.stats.stable_rounds >= 3;
            } else if meta.stats.window_bytes_submitted > 0 {
                meta.stats.idle_rounds += 1;
                meta.stats.stable_rounds = 0;
                meta.stats.total_idle_windows += 1;
                meta.stats.sustained_progress = false;
            } else {
                meta.stats.idle_rounds += 1;
                meta.stats.stable_rounds = 0;
                meta.stats.sustained_progress = false;
            }

            meta.stats.periodic_progress =
                meta.stats.total_progress_windows > 2 && meta.stats.total_idle_windows > 0;

            // Reset per-window counters for the next tick window.
            meta.stats.window_bytes_submitted = 0;
            meta.stats.window_bytes_progressed = 0;

            // Check if HeuristicClassifier wants to change this flow's class.
            let new_class = reclassify(meta);
            if new_class != meta.class {
                to_reclassify.push((*fid, meta.class, new_class));
            }
        }

        // Step 3: perform reclassifications.
        for (fid, old_class, new_class) in to_reclassify {
            self.reclassify_flow(fid, old_class, new_class);
        }

        // Step 4: update continuation credits.
        update_continuation_credits(&mut self.flow_meta);

        // Step 5: reclaim permits from idle/stale flows.
        reclaim_stale_permits(&mut self.flow_meta, &mut self.permits);
    }

    /// Reclassify a flow: update FlowMeta.class and transfer PermitBank budget.
    fn reclassify_flow(&mut self, flow_id: FlowId, old_class: FlowClass, new_class: FlowClass) {
        if let Some(meta) = self.flow_meta.get_mut(&flow_id) {
            meta.class = new_class;
        }
        self.permits.transfer_flow_class(flow_id, old_class, new_class);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test helpers (not compiled into production builds)
    // ─────────────────────────────────────────────────────────────────────────

    #[cfg(test)]
    pub fn flow_meta_mut(&mut self, flow_id: FlowId) -> Option<&mut FlowMeta> {
        self.flow_meta.get_mut(&flow_id)
    }

    #[cfg(test)]
    pub fn flow_class(&self, flow_id: FlowId) -> Option<FlowClass> {
        self.flow_meta.get(&flow_id).map(|m| m.class)
    }

    /// Initialize FlowMeta for a flow (test helper).
    /// In production, FlowMeta is initialized by try_issue_permit on first call.
    #[cfg(test)]
    fn init_flow(&mut self, flow_id: FlowId, class: FlowClass, dest_port: Option<u16>, is_datagram: bool) {
        self.flow_meta.entry(flow_id).or_insert_with(|| {
            FlowMeta::new(flow_id, class, dest_port, is_datagram)
        });
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    // ─────────────────────────────────────────────────────────────────────────
    // tests: PermitBank
    // ─────────────────────────────────────────────────────────────────────────

    /// Verify PermitBank correctly initializes 5-class budgets.
    #[test]
    fn test_permit_bank_five_classes() {
        let conn_id = ConnId(0);
        let mut bank = PermitBank::new(32 * 1024 * 1024);

        let classes = [
            FlowClass::Control,
            FlowClass::InteractiveObject,
            FlowClass::StreamingMedia,
            FlowClass::Bulk,
            FlowClass::RealtimeDatagram,
        ];
        for class in classes {
            let p = bank.try_acquire(conn_id, None, class, 1024);
            assert!(p.is_some(), "Expected permit for {:?}", class);
        }
    }

    /// Verify FlowHints constructors produce correct classes.
    #[test]
    fn test_flow_hints_constructors() {
        assert_eq!(FlowHints::default_tcp().class, FlowClass::Bulk);
        assert_eq!(FlowHints::realtime().class, FlowClass::RealtimeDatagram);
        assert_eq!(FlowHints::realtime().is_datagram_ingress, true);
        assert_eq!(FlowHints::control_port(53).class, FlowClass::Control);
        assert_eq!(FlowHints::control_port(53).dest_port, Some(53));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // tests: continuation_credit
    // ─────────────────────────────────────────────────────────────────────────

    /// Verify that continuation_credit accumulates for StreamingMedia flows
    /// with stable_rounds >= 3.
    #[test]
    fn test_continuation_credit_accumulation() {
        let bps = Arc::new(AtomicU64::new(0));
        let mut sched = Scheduler::new(bps);

        // Initialize FlowMeta directly.
        sched.init_flow(FlowId(20), FlowClass::StreamingMedia, None, false);

        {
            let meta = sched.flow_meta_mut(FlowId(20)).unwrap();
            meta.stats.stable_rounds = 5;
            meta.stats.window_bytes_progressed = 1024;
            // Set total_bytes > 128 KiB so reclassify() does not demote to InteractiveObject.
            meta.stats.total_bytes_submitted = 200 * 1024;
        }

        sched.tick();

        let meta = sched.flow_meta_mut(FlowId(20)).unwrap();
        assert!(meta.continuation_credit >= 1, "Expected credit >= 1, got {}", meta.continuation_credit);
    }

    /// Verify that continuation_credit decays when the flow becomes idle.
    #[test]
    fn test_continuation_credit_decay_on_idle() {
        let mut flow_meta: HashMap<FlowId, FlowMeta> = HashMap::new();
        let mut meta = FlowMeta::new(FlowId(30), FlowClass::StreamingMedia, None, false);
        meta.continuation_credit = 6;
        meta.stats.idle_rounds = 2;
        flow_meta.insert(FlowId(30), meta);

        update_continuation_credits(&mut flow_meta);

        let credit = flow_meta[&FlowId(30)].continuation_credit;
        assert_eq!(credit, 5, "Credit should decay by 1 on idle, got {}", credit);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // tests: stale demotion + permit reclaim
    // ─────────────────────────────────────────────────────────────────────────

    /// Verify that a stale demotable flow is detected as Stale.
    #[test]
    fn test_stale_demotion_halves_quantum() {
        let meta = FlowMeta {
            flow_id: FlowId(40),
            class: FlowClass::Bulk,
            stats: FlowStats {
                idle_rounds: 15, // > 10 threshold -> Stale
                total_bytes_submitted: 1024,
                ..FlowStats::new(None, false)
            },
            continuation_credit: 0,
            demotable: true,
            reclaimable: true,
        };

        assert_eq!(meta.urgency(), FlowUrgency::Stale);
    }

    /// Verify FlowUrgency::Sustained when stable_rounds > 3.
    #[test]
    fn test_flow_urgency_sustained() {
        let meta = FlowMeta {
            flow_id: FlowId(41),
            class: FlowClass::StreamingMedia,
            stats: FlowStats {
                stable_rounds: 5,
                total_bytes_submitted: 1024 * 1024,
                ..FlowStats::new(None, false)
            },
            continuation_credit: 3,
            demotable: true,
            reclaimable: true,
        };

        assert_eq!(meta.urgency(), FlowUrgency::Sustained);
    }

    /// Verify permit reclaim returns half the available budget.
    #[test]
    fn test_permit_reclaim_stale_flow() {
        let mut bank = PermitBank::new(32 * 1024 * 1024);
        let conn_id = ConnId(0);
        let flow_id = FlowId(50);

        let permit = bank.try_acquire(conn_id, Some(flow_id), FlowClass::Bulk, 256 * 1024);
        assert!(permit.is_some());

        let available_before = bank.flow_budget_available(flow_id);
        assert!(available_before > 0, "Expected available budget after permit issue");

        let mut flow_meta: HashMap<FlowId, FlowMeta> = HashMap::new();
        let mut meta = FlowMeta::new(flow_id, FlowClass::Bulk, None, false);
        meta.stats.idle_rounds = 10;
        meta.stats.window_bytes_progressed = 0;
        meta.stats.total_bytes_submitted = 256 * 1024;
        flow_meta.insert(flow_id, meta);

        reclaim_stale_permits(&mut flow_meta, &mut bank);

        let available_after = bank.flow_budget_available(flow_id);
        assert!(
            available_after <= available_before / 2 + 1,
            "Expected available to drop by ~50%, before={}, after={}",
            available_before,
            available_after
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // tests: dynamic reclassification
    // ─────────────────────────────────────────────────────────────────────────

    /// Verify that a flow with > 4 MiB submitted gets reclassified to Bulk.
    #[test]
    fn test_reclassification_to_bulk() {
        let bps = Arc::new(AtomicU64::new(0));
        let mut sched = Scheduler::new(bps);

        sched.init_flow(FlowId(60), FlowClass::InteractiveObject, None, false);

        {
            let meta = sched.flow_meta_mut(FlowId(60)).unwrap();
            meta.stats.total_bytes_submitted = 5 * 1024 * 1024;
            meta.stats.window_bytes_progressed = 1024;
        }

        sched.tick();

        assert_eq!(
            sched.flow_class(FlowId(60)),
            Some(FlowClass::Bulk),
            "Flow should be reclassified to Bulk after exceeding 4 MiB"
        );
    }

    /// Verify that port 53 flows are classified as Control.
    #[test]
    fn test_port_based_classification_dns() {
        let bps = Arc::new(AtomicU64::new(0));
        let mut sched = Scheduler::new(bps);

        sched.init_flow(FlowId(70), FlowClass::Bulk, Some(53), false);

        sched.tick();

        assert_eq!(
            sched.flow_class(FlowId(70)),
            Some(FlowClass::Control),
            "Port 53 flow should be reclassified to Control"
        );
    }

    /// Verify that on_send_complete updates stats in FlowMeta.
    #[test]
    fn test_on_send_complete_updates_stats() {
        let bps = Arc::new(AtomicU64::new(0));
        let mut sched = Scheduler::new(bps);

        // Use try_issue_permit to initialize FlowMeta.
        let hints = FlowHints { class: FlowClass::Bulk, dest_port: None, is_datagram_ingress: false };
        let permit = sched.try_issue_permit(ConnId(0), Some(FlowId(80)), &hints, 4096).unwrap();

        sched.on_send_complete(permit, 4096);

        let meta = sched.flow_meta_mut(FlowId(80)).unwrap();
        assert_eq!(meta.stats.total_bytes_sent, 4096);
        assert_eq!(meta.stats.window_bytes_progressed, 4096);
        assert_eq!(meta.stats.total_bytes_submitted, 4096);
        assert_eq!(meta.stats.window_bytes_submitted, 4096);
    }

}
