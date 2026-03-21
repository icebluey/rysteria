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
/// Three classes: RealtimeDatagram (UDP), Control (port-based), Bulk (everything else).
/// Class affects which class-level budget pool a permit is drawn from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FlowClass {
    /// DNS, auth, first-packet control frames. Highest TCP priority, small budget.
    /// Port hints: 53 (DNS), 22 (SSH), 23 (Telnet), 3389 (RDP).
    Control,

    /// All TCP proxy traffic: downloads, uploads, web objects, video streams.
    /// Default class for all non-port-based, non-datagram flows.
    Bulk,

    /// UDP relay: games, VoIP, DNS-over-UDP. Strict highest priority.
    /// Separate budget. Small quantum matches datagram MTU (~1200 bytes).
    RealtimeDatagram,
}

/// Pending-permit queue tier for priority-ordered flush.
///
/// Determines which pending queue a permit request is routed to.
/// Flush order: Control → Interactive → Bulk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueueTier {
    /// Port-based Control flows (DNS, SSH, RDP). Highest flush priority.
    Control,
    /// Early-interactive flows, RealtimeDatagram.
    Interactive,
    /// Bulk flows.
    Bulk,
}

// Early-interactive window thresholds: new TCP flows route to the Interactive
// pending queue until either threshold is met. Budget class is NOT overridden;
// flows draw from their actual FlowClass budget (typically Bulk, 16 MiB).
const EARLY_INTERACTIVE_BYTES: u64 = 128 * 1024;
const EARLY_INTERACTIVE_DURATION: Duration = Duration::from_millis(1500);

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

    /// Hints for control-plane operations (auth, reconnect, keepalive).
    /// Uses FlowClass::Control budget without port-based classification.
    pub fn control() -> Self {
        Self { class: FlowClass::Control, dest_port: None, is_datagram_ingress: false }
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
/// Combines classification state and urgency tracking.
pub struct FlowMeta {
    pub flow_id: FlowId,
    /// Current traffic class (may differ from initial hints after reclassification).
    pub class: FlowClass,
    pub stats: FlowStats,

    /// True if this flow can be demoted when Stale.
    /// Datagram flows are not demotable.
    pub demotable: bool,

    /// True if permits held by this flow can be partially reclaimed when idle.
    /// Datagram flows are not reclaimable.
    pub reclaimable: bool,

    /// True during the early-interactive window (first 128 KiB or 1500 ms).
    /// While active, the flow routes to the Interactive pending queue
    /// regardless of its actual FlowClass, giving new flows higher priority
    /// when budget is contended. Datagram flows are never early-interactive.
    pub is_early_interactive: bool,
}

impl FlowMeta {
    fn new(flow_id: FlowId, class: FlowClass, dest_port: Option<u16>, is_datagram: bool) -> Self {
        Self {
            flow_id,
            class,
            stats: FlowStats::new(dest_port, is_datagram),
            demotable: !is_datagram,
            reclaimable: !is_datagram,
            is_early_interactive: !is_datagram,
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

    // All non-datagram, non-port-based flows stay in their current class.
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
///   Bulk:              30 MiB  — all TCP proxy traffic
///   RealtimeDatagram: 512 KiB  — latency-critical, low volume
///   Total connection:  32 MiB
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
        class_budget.insert(FlowClass::Bulk, ByteBudget::new(30 * 1024 * 1024));
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
    /// Only shrinks `available` (unissued credit), never touches `capacity`.
    /// Leaving `capacity` intact ensures the flow can recover to full speed
    /// after permits are returned, preventing a low-bandwidth deadlock where
    /// capacity falls below the minimum chunk size.
    pub fn reclaim_from_flow(&mut self, flow_id: FlowId, _class: FlowClass, bytes: usize) {
        if let Some(fb) = self.flow_budget.get_mut(&flow_id) {
            let actual = bytes.min(fb.available);
            if actual == 0 {
                return;
            }
            fb.available -= actual;
            // Intentionally not reducing capacity: capacity must stay at its
            // original value so give_back() can restore full credit when
            // outstanding permits are returned.
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

    /// Create a Scheduler with a custom connection budget (for testing).
    #[cfg(test)]
    pub fn new_with_budget(conn_bytes: usize, effective_bps: Arc<AtomicU64>) -> Self {
        Self {
            permits: PermitBank::new(conn_bytes),
            flow_meta: HashMap::new(),
            effective_bps,
        }
    }

    /// Try to acquire a control-plane permit (no FlowMeta tracking).
    ///
    /// Control leases use synthetic flow IDs for budget return identification
    /// but do not need FlowMeta (no reclassification, no continuation credits,
    /// no reclaim). The permit is always drawn from FlowClass::Control budget.
    pub fn try_acquire_control_permit(
        &mut self,
        conn_id: ConnId,
        flow_id: FlowId,
        bytes: usize,
    ) -> Option<Permit> {
        self.permits.try_acquire(conn_id, Some(flow_id), FlowClass::Control, bytes)
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
            // Early-interactive only affects queue routing (queue_tier()),
            // not budget class. Flows draw from their actual class budget.
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
                // Check bytes-based early-interactive exit eagerly.
                if meta.is_early_interactive
                    && meta.stats.total_bytes_submitted >= EARLY_INTERACTIVE_BYTES
                {
                    meta.is_early_interactive = false;
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

        // Step 3.5: check time-based early-interactive exit.
        // Only exit when the flow has actually submitted data. A flow still
        // waiting for its first server response (total_bytes_submitted == 0)
        // has not started transferring data, so keeping it in
        // early-interactive is zero-cost and ensures its first bytes get
        // priority treatment.
        for meta in self.flow_meta.values_mut() {
            if meta.is_early_interactive
                && meta.stats.total_bytes_submitted > 0
                && meta.stats.created_at.elapsed() >= EARLY_INTERACTIVE_DURATION
            {
                meta.is_early_interactive = false;
            }
        }

        // Step 4: reclaim permits from idle/stale flows.
        reclaim_stale_permits(&mut self.flow_meta, &mut self.permits);
    }

    /// Reclassify a flow: update FlowMeta.class and transfer PermitBank budget.
    fn reclassify_flow(&mut self, flow_id: FlowId, old_class: FlowClass, new_class: FlowClass) {
        if let Some(meta) = self.flow_meta.get_mut(&flow_id) {
            meta.class = new_class;
        }
        self.permits.transfer_flow_class(flow_id, old_class, new_class);
    }

    /// Determine which pending-permit queue tier a flow belongs to.
    ///
    /// Queue flush order: Control → Interactive → Bulk.
    /// During early-interactive, the flow routes to Interactive regardless of
    /// its FlowClass, unless reclassify has already promoted it to Control
    /// (prevents priority inversion for port-53/22/23/3389 flows).
    pub fn queue_tier(&self, flow_id: FlowId) -> QueueTier {
        if let Some(meta) = self.flow_meta.get(&flow_id) {
            // Control class overrides early-interactive (higher priority queue).
            if meta.is_early_interactive && meta.class != FlowClass::Control {
                return QueueTier::Interactive;
            }
            match meta.class {
                FlowClass::Control => QueueTier::Control,
                FlowClass::RealtimeDatagram => QueueTier::Interactive,
                FlowClass::Bulk => QueueTier::Bulk,
            }
        } else {
            // FlowMeta not yet created (before first try_issue_permit).
            QueueTier::Interactive
        }
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

    #[cfg(test)]
    pub fn is_early_interactive(&self, flow_id: FlowId) -> bool {
        self.flow_meta.get(&flow_id).map(|m| m.is_early_interactive).unwrap_or(false)
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
    fn test_permit_bank_three_classes() {
        let conn_id = ConnId(0);
        let mut bank = PermitBank::new(32 * 1024 * 1024);

        let classes = [
            FlowClass::Control,
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
            demotable: true,
            reclaimable: true,
            is_early_interactive: false,
        };

        assert_eq!(meta.urgency(), FlowUrgency::Stale);
    }

    /// Verify FlowUrgency::Sustained when stable_rounds > 3.
    #[test]
    fn test_flow_urgency_sustained() {
        let meta = FlowMeta {
            flow_id: FlowId(41),
            class: FlowClass::Bulk,
            stats: FlowStats {
                stable_rounds: 5,
                total_bytes_submitted: 1024 * 1024,
                ..FlowStats::new(None, false)
            },
            demotable: true,
            reclaimable: true,
            is_early_interactive: false,
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

    // ─────────────────────────────────────────────────────────────────────────
    // Regression proof tests (scheduler unit level)
    // ─────────────────────────────────────────────────────────────────────────

    /// R02 (unit): Permit budget is fully conserved after repeated issue+release cycles.
    ///
    /// Proves Rule 2: permits model in-flight occupancy, not total quota.
    /// If release() treated permits as "burned" bytes rather than returning
    /// them to the pool, the budget would deplete after enough cycles and
    /// try_acquire() would return None even when nothing is actually in flight.
    #[test]
    fn regression_02_permit_budget_conserved_after_cycles() {
        let mut bank = PermitBank::new(4 * 1024 * 1024);
        let conn_id = ConnId(0);
        let flow_id = FlowId(200);

        // 50 issue+release cycles: budget must never deplete.
        for round in 0u32..50 {
            let p = bank.try_acquire(conn_id, Some(flow_id), FlowClass::Bulk, 32 * 1024);
            assert!(
                p.is_some(),
                "round {round}: budget should be available after each release"
            );
            bank.release(p.unwrap(), 32 * 1024);
        }

        // Final permit must also succeed: budget fully conserved.
        let p = bank.try_acquire(conn_id, Some(flow_id), FlowClass::Bulk, 1024);
        assert!(p.is_some(), "Budget must be fully conserved after 50 cycles (R02)");
    }

    /// R03 (unit): Forward progress is possible after stale reclaim + permit release.
    ///
    /// Proves Rule 4: reclaim_from_flow() only reduces available, not capacity.
    /// After reclaim drains available to zero, releasing an outstanding permit
    /// calls give_back() which restores credit (capped at capacity, not at the
    /// reclaimed available). Without this invariant, the flow enters a permanent
    /// deadlock where available stays at zero even after releases.
    #[test]
    fn regression_03_forward_progress_after_reclaim_and_release() {
        let mut bank = PermitBank::new(32 * 1024 * 1024);
        let conn_id = ConnId(0);
        let flow_id = FlowId(201);

        // Issue a permit to initialize the flow budget entry.
        let permit = bank
            .try_acquire(conn_id, Some(flow_id), FlowClass::Bulk, 256 * 1024)
            .expect("Initial permit must succeed");

        // Simulate stale reclaim: drain all remaining available budget.
        let remaining = bank.flow_budget_available(flow_id);
        if remaining > 0 {
            bank.reclaim_from_flow(flow_id, FlowClass::Bulk, remaining);
        }
        assert_eq!(
            bank.flow_budget_available(flow_id),
            0,
            "After full reclaim, available must be 0"
        );

        // Release the outstanding permit. give_back() must restore credit because
        // capacity is unchanged by reclaim.
        bank.release(permit, 256 * 1024);

        let available_after = bank.flow_budget_available(flow_id);
        assert!(
            available_after > 0,
            "After release following reclaim, budget must recover (capacity unchanged): got {available_after}"
        );

        // Prove forward progress: a new permit must be issuable.
        let p2 = bank.try_acquire(conn_id, Some(flow_id), FlowClass::Bulk, 1024);
        assert!(
            p2.is_some(),
            "Forward progress must be possible after reclaim+release cycle (R03, Rule 4)"
        );
    }

    /// R08 (unit): Budget is returned to all levels after on_send_complete,
    /// enabling subsequent permit requests to succeed.
    ///
    /// Proves that on_send_complete() properly credits conn, class, and flow
    /// budget pools, so a waiting task can acquire a permit immediately after
    /// a send completes. This is the precondition for the ConnectionActor's
    /// pending-permit flush to work correctly (Rule 5 — event-driven wakeup).
    #[test]
    fn regression_08_notify_fires_on_send_complete() {
        let bps = Arc::new(AtomicU64::new(0));
        let mut sched = Scheduler::new(bps);

        let hints = FlowHints { class: FlowClass::Bulk, dest_port: None, is_datagram_ingress: false };
        let permit = sched
            .try_issue_permit(ConnId(0), Some(FlowId(202)), &hints, 1024)
            .expect("Permit must be issued");

        sched.on_send_complete(permit, 1024);

        // After on_send_complete, budget must be restored — a new permit succeeds.
        let p2 = sched.try_issue_permit(ConnId(0), Some(FlowId(202)), &hints, 1024);
        assert!(
            p2.is_some(),
            "Budget must be returned after on_send_complete so pending permits can be granted (R08)"
        );
    }

    /// R10 (unit): Cancel path (0 bytes sent) returns budget without leaking.
    ///
    /// Proves cancel-safety: calling on_send_complete(permit, 0) — the cancel
    /// path used when a task is cancelled before completing the write — returns
    /// the full credit to the pool without updating bytes_sent. Without this,
    /// every cancellation permanently leaks permit budget until the connection
    /// budget collapses.
    #[test]
    fn regression_10_permit_guard_drop_releases_with_zero_bytes() {
        let bps = Arc::new(AtomicU64::new(0));
        let mut sched = Scheduler::new(bps);

        let hints = FlowHints { class: FlowClass::Bulk, dest_port: None, is_datagram_ingress: false };
        let permit = sched
            .try_issue_permit(ConnId(0), Some(FlowId(203)), &hints, 1024)
            .expect("Permit must be issued");

        // Cancel path: return permit with 0 bytes sent.
        sched.on_send_complete(permit, 0);

        // Verify: total_bytes_sent is still 0 (no forward progress on cancel).
        let sent = sched
            .flow_meta_mut(FlowId(203))
            .map(|m| m.stats.total_bytes_sent)
            .unwrap_or(0);
        assert_eq!(sent, 0, "Cancel path must not update bytes_sent (R10)");

        // Verify: a new permit can be issued (budget was returned, not leaked).
        let p2 = sched.try_issue_permit(ConnId(0), Some(FlowId(203)), &hints, 1024);
        assert!(
            p2.is_some(),
            "After cancel (0 bytes), budget must be returned so new permits are issuable (R10)"
        );
    }

    /// Control class budget survives full data-plane class exhaustion.
    ///
    /// Proves that auth, reconnect, and keepalive control leases can always
    /// be acquired from the reserved 1 MiB Control budget even when all
    /// data-plane class budgets (Bulk, RealtimeDatagram) are fully saturated
    /// by in-flight permits.
    #[test]
    fn test_control_budget_survives_data_plane_exhaustion() {
        let mut bank = PermitBank::new(100 * 1024 * 1024);
        let conn_id = ConnId(0);

        // Exhaust all data-plane class budgets.
        let _bulk = bank.try_acquire(conn_id, None, FlowClass::Bulk, 30 * 1024 * 1024).unwrap();
        let _udp = bank.try_acquire(conn_id, None, FlowClass::RealtimeDatagram, 512 * 1024).unwrap();

        // Auth control lease (8 KiB) must still succeed.
        let ctrl_auth = bank.try_acquire(conn_id, None, FlowClass::Control, 8 * 1024);
        assert!(ctrl_auth.is_some(), "Auth control lease (8 KiB) must succeed under full data-plane saturation");

        // Reconnect control lease (16 KiB) must also succeed.
        let ctrl_reconnect = bank.try_acquire(conn_id, None, FlowClass::Control, 16 * 1024);
        assert!(ctrl_reconnect.is_some(), "Reconnect control lease (16 KiB) must succeed under full data-plane saturation");
    }

    /// R13 (unit): RealtimeDatagram budget is fully independent of TCP class budgets.
    ///
    /// Proves Rule 9 and Regression 13: exhausting the Bulk TCP class budget
    /// must not affect UDP relay permits. The three class budgets are separate
    /// ByteBudget pools; only the shared conn-level budget can create
    /// cross-class contention.
    #[test]
    fn regression_13_datagram_budget_independent_of_tcp_classes() {
        // Use a large conn budget so it doesn't become the constraint.
        let mut bank = PermitBank::new(100 * 1024 * 1024);
        let conn_id = ConnId(0);

        // Exhaust the entire Bulk class budget (30 MiB).
        let bulk_p =
            bank.try_acquire(conn_id, None, FlowClass::Bulk, 30 * 1024 * 1024);
        assert!(bulk_p.is_some(), "Must be able to exhaust Bulk budget");

        // Bulk is now fully exhausted — no more Bulk permits possible.
        let blocked = bank.try_acquire(conn_id, None, FlowClass::Bulk, 1);
        assert!(blocked.is_none(), "Bulk budget must be fully exhausted (R13)");

        // Despite Bulk being saturated, UDP must still be available.
        let udp_p = bank.try_acquire(conn_id, None, FlowClass::RealtimeDatagram, 1024);
        assert!(
            udp_p.is_some(),
            "RealtimeDatagram budget must be independent of TCP class budgets (R13, Rule 9)"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // tests: early-interactive window
    // ─────────────────────────────────────────────────────────────────────────

    /// New TCP flow gets is_early_interactive = true on first permit request.
    #[test]
    fn test_early_interactive_set_on_tcp_flow() {
        let bps = Arc::new(AtomicU64::new(0));
        let mut sched = Scheduler::new(bps);

        let hints = FlowHints::default_tcp();
        let _permit = sched.try_issue_permit(ConnId(0), Some(FlowId(300)), &hints, 1024);

        assert!(
            sched.is_early_interactive(FlowId(300)),
            "New TCP flow must have is_early_interactive = true"
        );
    }

    /// Datagram flows do NOT get early-interactive.
    #[test]
    fn test_early_interactive_not_set_on_datagram() {
        let bps = Arc::new(AtomicU64::new(0));
        let mut sched = Scheduler::new(bps);

        let hints = FlowHints::realtime();
        let _permit = sched.try_issue_permit(ConnId(0), Some(FlowId(301)), &hints, 1024);

        assert!(
            !sched.is_early_interactive(FlowId(301)),
            "Datagram flow must NOT have is_early_interactive"
        );
    }

    /// Early-interactive does NOT override budget class — flow draws from its
    /// actual class budget (Bulk). When Bulk is exhausted, early-interactive
    /// flow is also blocked, but routes to Interactive pending queue for
    /// higher priority when budget is freed.
    #[test]
    fn test_early_interactive_no_budget_override() {
        let bps = Arc::new(AtomicU64::new(0));
        let mut sched = Scheduler::new_with_budget(100 * 1024 * 1024, bps);

        // Exhaust Bulk class budget (30 MiB) using flow_id=None to bypass per-flow limit.
        let bulk_hints = FlowHints { class: FlowClass::Bulk, dest_port: None, is_datagram_ingress: false };
        let bulk_permit = sched.try_issue_permit(ConnId(0), None, &bulk_hints, 30 * 1024 * 1024);
        assert!(bulk_permit.is_some(), "Must exhaust Bulk class budget");

        // New TCP flow (early-interactive) also uses Bulk budget — should be blocked.
        let tcp_hints = FlowHints::default_tcp();
        let early_permit = sched.try_issue_permit(ConnId(0), Some(FlowId(312)), &tcp_hints, 4096);
        assert!(
            early_permit.is_none(),
            "Early-interactive flow must draw from Bulk budget (exhausted)"
        );

        // But queue_tier routes it to Interactive for higher priority when pending.
        assert!(sched.is_early_interactive(FlowId(312)));
        assert_eq!(sched.queue_tier(FlowId(312)), QueueTier::Interactive);
    }

    /// Early-interactive exits after 128 KiB of data submitted.
    #[test]
    fn test_early_interactive_exits_by_bytes() {
        let bps = Arc::new(AtomicU64::new(0));
        let mut sched = Scheduler::new(bps);

        let hints = FlowHints::default_tcp();
        let permit = sched.try_issue_permit(ConnId(0), Some(FlowId(320)), &hints, 128 * 1024).unwrap();

        assert!(sched.is_early_interactive(FlowId(320)), "Should be early-interactive before send");

        // Complete the send with 128 KiB — this should trigger exit.
        sched.on_send_complete(permit, 128 * 1024);

        assert!(
            !sched.is_early_interactive(FlowId(320)),
            "Early-interactive must exit after 128 KiB submitted"
        );
    }

    /// Early-interactive exits after 1500 ms when flow has sent data (checked in tick).
    #[test]
    fn test_early_interactive_exits_by_time() {
        let bps = Arc::new(AtomicU64::new(0));
        let mut sched = Scheduler::new(bps);

        let hints = FlowHints::default_tcp();
        let permit = sched.try_issue_permit(ConnId(0), Some(FlowId(321)), &hints, 1024).unwrap();

        assert!(sched.is_early_interactive(FlowId(321)));

        // Complete the send so total_bytes_submitted > 0 (required for time exit).
        sched.on_send_complete(permit, 1024);

        // Manually backdate created_at to simulate time passing.
        {
            let meta = sched.flow_meta_mut(FlowId(321)).unwrap();
            meta.stats.created_at = Instant::now() - Duration::from_millis(2000);
            meta.stats.window_bytes_progressed = 1;
        }

        sched.tick();

        assert!(
            !sched.is_early_interactive(FlowId(321)),
            "Early-interactive must exit after 1500 ms when bytes have been sent"
        );
    }

    /// Time-based early-interactive exit does NOT fire when total_bytes_submitted == 0.
    /// Flows waiting for server response have not started transferring data,
    /// so keeping them in the Interactive pending queue is zero-cost.
    #[test]
    fn test_early_interactive_time_exit_requires_bytes() {
        let bps = Arc::new(AtomicU64::new(0));
        let mut sched = Scheduler::new(bps);

        let hints = FlowHints::default_tcp();
        let _permit = sched.try_issue_permit(ConnId(0), Some(FlowId(340)), &hints, 1024);

        assert!(sched.is_early_interactive(FlowId(340)));

        // Backdate past the time threshold, but do NOT complete any sends.
        {
            let meta = sched.flow_meta_mut(FlowId(340)).unwrap();
            meta.stats.created_at = Instant::now() - Duration::from_millis(3000);
            meta.stats.window_bytes_progressed = 1;
        }

        sched.tick();

        assert!(
            sched.is_early_interactive(FlowId(340)),
            "Time-based exit must NOT fire when total_bytes_submitted == 0"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // tests: QueueTier routing
    // ─────────────────────────────────────────────────────────────────────────

    /// During early-interactive, queue_tier returns Interactive.
    #[test]
    fn test_queue_tier_during_early_interactive() {
        let bps = Arc::new(AtomicU64::new(0));
        let mut sched = Scheduler::new(bps);

        let hints = FlowHints::default_tcp();
        let _permit = sched.try_issue_permit(ConnId(0), Some(FlowId(330)), &hints, 1024);

        assert!(sched.is_early_interactive(FlowId(330)));
        assert_eq!(
            sched.queue_tier(FlowId(330)),
            QueueTier::Interactive,
            "Early-interactive flow must route to Interactive queue"
        );
    }

    /// After early-interactive exits, Bulk flow routes to Bulk queue.
    #[test]
    fn test_queue_tier_after_early_interactive_exits() {
        let bps = Arc::new(AtomicU64::new(0));
        let mut sched = Scheduler::new(bps);

        let hints = FlowHints::default_tcp();
        let permit = sched.try_issue_permit(ConnId(0), Some(FlowId(331)), &hints, 128 * 1024).unwrap();
        sched.on_send_complete(permit, 128 * 1024);

        assert!(!sched.is_early_interactive(FlowId(331)));
        assert_eq!(
            sched.queue_tier(FlowId(331)),
            QueueTier::Bulk,
            "After early-interactive exit, Bulk flow must route to Bulk queue"
        );
    }

    /// Control class overrides early-interactive in queue_tier.
    #[test]
    fn test_queue_tier_control_overrides_early_interactive() {
        let bps = Arc::new(AtomicU64::new(0));
        let mut sched = Scheduler::new(bps);

        // Create a flow with port 53 (DNS) — starts as Bulk with early-interactive.
        sched.init_flow(FlowId(332), FlowClass::Bulk, Some(53), false);

        // Before reclassify: early-interactive, class=Bulk, port=53.
        assert!(sched.is_early_interactive(FlowId(332)));
        assert_eq!(sched.queue_tier(FlowId(332)), QueueTier::Interactive);

        // Simulate tick which reclassifies port 53 to Control.
        {
            let meta = sched.flow_meta_mut(FlowId(332)).unwrap();
            meta.stats.window_bytes_progressed = 1; // prevent idle
        }
        sched.tick();

        assert_eq!(
            sched.flow_class(FlowId(332)),
            Some(FlowClass::Control),
            "Port 53 must be reclassified to Control"
        );
        // Control overrides early-interactive.
        assert_eq!(
            sched.queue_tier(FlowId(332)),
            QueueTier::Control,
            "Control class must override early-interactive for queue routing"
        );
    }

}
