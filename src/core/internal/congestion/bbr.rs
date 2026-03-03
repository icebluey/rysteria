/// BBR congestion controller integration.
///
/// Uses quinn's built-in BBR controller. The Go implementation has a full
/// BBR implementation, but for Rysteria we delegate to quinn's native BBR.
///
/// Phase 2+: BBR is wired into the QUIC connection via TransportConfig.
use quinn_proto::congestion::{BbrConfig, ControllerFactory};
use std::sync::Arc;

/// Returns a factory that creates quinn's built-in BBR congestion controller.
///
/// Go: hysteria/core/internal/congestion/bbr/ — we delegate to quinn's built-in.
pub fn new_bbr_factory() -> Arc<dyn ControllerFactory> {
    Arc::new(BbrConfig::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn bbr_factory_builds_controller() {
        let factory = new_bbr_factory();
        let now = Instant::now();
        let ctrl = factory.build(now, 1200);
        // BBR initial window should be non-zero
        assert!(ctrl.window() > 0);
    }
}
