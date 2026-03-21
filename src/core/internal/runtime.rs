/// First-class runtime abstraction for rysteria.
///
/// Provides a unified interface for both work-stealing (multi-thread) and
/// no-steal (single-thread, current-thread) Tokio runtimes. The no-steal
/// mode is used by `ShardPool` to pin connections to fixed OS threads,
/// eliminating cross-thread cache misses on hot-path per-connection state.
///
/// `RyRuntime` owns the underlying Tokio `Runtime` for lifecycle control:
/// dropping an `RyRuntime` signals its shard thread to exit cleanly.
use tokio::runtime::{Builder, Handle};
use tokio::sync::oneshot;

/// Execution mode for a `RyRuntime`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeMode {
    /// Multi-threaded work-stealing runtime (Tokio default multi-thread).
    Steal,
    /// Single-threaded no-steal runtime (Tokio current-thread).
    NoSteal,
}

/// A named, lifecycle-aware Tokio runtime instance.
///
/// Wraps either a work-stealing or no-steal Tokio runtime with an explicit
/// shutdown signal. Dropping this struct signals the shard thread to stop
/// accepting new tasks and exit.
pub struct RyRuntime {
    mode: RuntimeMode,
    handle: Handle,
    /// Dropping this sender delivers the shutdown signal to the shard thread.
    _shutdown_tx: oneshot::Sender<()>,
    /// OS thread join handle (present only for NoSteal runtimes).
    _thread: Option<std::thread::JoinHandle<()>>,
}

impl RyRuntime {
    /// Create a `NoSteal` runtime on its own named OS thread.
    ///
    /// The thread runs the runtime until the `RyRuntime` is dropped or
    /// `shutdown_tx` fires, after which all spawned tasks are cancelled.
    pub fn new_no_steal(name: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let rt = Builder::new_current_thread()
            .enable_all()
            .thread_name(name.to_string())
            .build()?;
        let handle = rt.handle().clone();
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        let thread = std::thread::Builder::new()
            .name(name.to_string())
            .spawn(move || {
                rt.block_on(async move {
                    let _ = shutdown_rx.await;
                });
            })?;

        Ok(Self {
            mode: RuntimeMode::NoSteal,
            handle,
            _shutdown_tx: shutdown_tx,
            _thread: Some(thread),
        })
    }

    /// Create a `Steal` multi-thread runtime with the given number of worker threads.
    ///
    /// Worker threads are named `name`. The runtime runs until the `RyRuntime`
    /// is dropped, at which point the shutdown signal is delivered and the
    /// owning thread exits.
    pub fn new_multi_thread(
        name: &str,
        worker_threads: usize,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let rt = Builder::new_multi_thread()
            .enable_all()
            .worker_threads(worker_threads)
            .thread_name(name.to_string())
            .build()?;
        let handle = rt.handle().clone();
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        // A dedicated OS thread owns the runtime and blocks until the shutdown
        // signal is delivered (i.e., RyRuntime is dropped).
        let thread = std::thread::Builder::new()
            .name(name.to_string())
            .spawn(move || {
                rt.block_on(async move {
                    let _ = shutdown_rx.await;
                });
            })?;

        Ok(Self {
            mode: RuntimeMode::Steal,
            handle,
            _shutdown_tx: shutdown_tx,
            _thread: Some(thread),
        })
    }

    /// Wrap the current Tokio runtime handle as a `Steal` runtime reference.
    ///
    /// Does not own the underlying runtime — shutdown is the caller's
    /// responsibility. Useful for passing the main Tokio runtime through the
    /// same `RyRuntime` interface.
    pub fn steal_current() -> Self {
        let (shutdown_tx, _) = oneshot::channel::<()>();
        Self {
            mode: RuntimeMode::Steal,
            handle: Handle::current(),
            _shutdown_tx: shutdown_tx,
            _thread: None,
        }
    }

    /// Tokio `Handle` for spawning tasks onto this runtime.
    pub fn handle(&self) -> &Handle {
        &self.handle
    }

    /// Whether this runtime uses work-stealing or no-steal scheduling.
    pub fn mode(&self) -> RuntimeMode {
        self.mode
    }
}

/// Returns the `Handle` of the currently active Tokio runtime.
///
/// Equivalent to `tokio::runtime::Handle::current()`, exposed here so
/// callers do not need to import the Tokio runtime module directly.
pub fn current_handle() -> Handle {
    Handle::current()
}
