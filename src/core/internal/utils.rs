/// Internal utility types.
///
/// Go equivalent: hysteria/core/internal/utils/
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

// ──────────────────────────────────────────────────────────────────────────────
// AtomicTime
// ──────────────────────────────────────────────────────────────────────────────

/// Atomically-stored Unix timestamp in seconds.
///
/// Go equivalent: `utils.AtomicTime` which stores `int64` Unix seconds.
/// Used for tracking UDP session last-active time.
#[derive(Debug, Default)]
pub struct AtomicTime {
    secs: AtomicU64,
}

impl AtomicTime {
    /// Creates a new `AtomicTime` initialized to the current time.
    pub fn new() -> Self {
        let now = unix_secs_now();
        Self {
            secs: AtomicU64::new(now),
        }
    }

    /// Updates to the current time.
    pub fn update(&self) {
        self.secs.store(unix_secs_now(), Ordering::Relaxed);
    }

    /// Loads the stored Unix timestamp in seconds.
    pub fn load(&self) -> u64 {
        self.secs.load(Ordering::Relaxed)
    }

    /// Returns `true` if the stored time is older than `idle_secs` seconds ago.
    pub fn is_idle(&self, idle_secs: u64) -> bool {
        let now = unix_secs_now();
        let last = self.load();
        now.saturating_sub(last) > idle_secs
    }
}

/// Returns the current Unix timestamp in whole seconds.
fn unix_secs_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_time_update_and_load() {
        let t = AtomicTime::new();
        let before = unix_secs_now();
        t.update();
        let stored = t.load();
        let after = unix_secs_now();
        assert!(stored >= before && stored <= after + 1);
    }

    #[test]
    fn atomic_time_is_idle_false_for_fresh() {
        let t = AtomicTime::new();
        // A fresh time should not be idle with a 10-second window
        assert!(!t.is_idle(10));
    }

    #[test]
    fn atomic_time_is_idle_true_for_old() {
        let t = AtomicTime::default();
        // Default stores 0 (epoch), which is definitely > 10s ago
        assert!(t.is_idle(10));
    }
}
