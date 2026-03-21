/// NoSteal shard pool — pins each QUIC connection to a fixed OS thread.
///
/// Inspired by Pingora's `NoStealRuntime` design:
///   - Each shard is a `new_current_thread` Tokio runtime on its own OS thread.
///   - Tasks spawned onto a shard never migrate to another thread.
///   - Eliminates cross-thread cache misses and reduces lock pressure on
///     hot-path per-connection state.
///
/// Connections are mapped via `conn_id % shard_count` — the same `ConnId`
/// always resolves to the same shard handle.
///
/// Built on top of `RyRuntime::new_no_steal()` to avoid duplicating the
/// runtime-creation and lifecycle-management logic.
use std::sync::Arc;
use tokio::runtime::Handle;

use crate::core::internal::runtime::RyRuntime;

/// Opaque u64 connection identifier. Generated once per authenticated connection.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct ConnId(pub u64);

/// Pool of single-threaded Tokio runtimes, each pinned to its own OS thread.
pub struct ShardPool {
    handles: Arc<Vec<Handle>>,
    /// Owns the `RyRuntime` instances; dropping them signals each shard to exit.
    _runtimes: Vec<RyRuntime>,
}

impl ShardPool {
    /// Create `threads` single-threaded runtimes, each on its own OS thread.
    ///
    /// Threads are named `ry-shard-{i}`. The pool is ready to accept spawns
    /// immediately after construction.
    pub fn new(threads: usize) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        if threads == 0 {
            return Err("shard count must be > 0".into());
        }
        let mut handles = Vec::with_capacity(threads);
        let mut runtimes = Vec::with_capacity(threads);

        for i in 0..threads {
            let rt = RyRuntime::new_no_steal(&format!("ry-shard-{i}"))?;
            handles.push(rt.handle().clone());
            runtimes.push(rt);
        }

        Ok(Self {
            handles: Arc::new(handles),
            _runtimes: runtimes,
        })
    }

    /// Return the runtime handle for the shard that owns `conn_id`.
    ///
    /// Mapping is deterministic: the same `ConnId` always returns the same handle.
    pub fn pin(&self, conn_id: ConnId) -> &Handle {
        &self.handles[(conn_id.0 as usize) % self.handles.len()]
    }

    /// Number of shards in the pool.
    pub fn len(&self) -> usize {
        self.handles.len()
    }

    /// True if the pool has no shards (always false for valid pools).
    pub fn is_empty(&self) -> bool {
        self.handles.is_empty()
    }
}
