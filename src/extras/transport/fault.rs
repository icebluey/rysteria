/// FaultInjectionSocket — programmable fault injection for QUIC transport testing.
///
/// Wraps a real `quinn::AsyncUdpSocket` and applies a configurable fault policy:
///   - Pass:              all packets forwarded normally.
///   - DropAll:           all send/recv silently dropped (simulates total network outage).
///   - Drop50:            50% random packet loss on send and recv (simulates degraded link).
///   - DropGeneration:    drop packets only while the hop generation counter matches
///                        a target value (simulates tuple-specific impairment for R14).
///
/// The policy type is stored in an `AtomicU8` and can be changed at any time from
/// any thread, allowing test code to inject and remove faults while traffic
/// is flowing through a live QUIC connection.
///
/// For generation-aware fault injection, two additional atomics are used:
///   - `target_generation` (AtomicU64): the hop generation to target.
///   - `current_generation` (AtomicU64, shared with UdpHopSocket): the live
///     generation counter incremented on each successful hop.
///
/// When the policy is DropGeneration, packets are only dropped while
/// `current_generation == target_generation`. After a hop increments the
/// counter, the fault clears automatically without test intervention.
use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::task::{Context, Poll};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};

/// Fault policy applied to the socket.
///
/// The discriminant is stored in an `AtomicU8`. For `DropGeneration`, the
/// target generation value is stored in a separate `AtomicU64`.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultPolicy {
    /// Forward all packets normally.
    Pass = 0,
    /// Drop all packets silently (total outage).
    DropAll = 1,
    /// Drop ~50% of packets randomly (degraded link).
    Drop50 = 2,
    /// Drop packets only while the current hop generation matches the target.
    /// The target value is set via `FaultPolicyHandle::set_drop_generation()`.
    DropGeneration = 3,
}

impl FaultPolicy {
    fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::DropAll,
            2 => Self::Drop50,
            3 => Self::DropGeneration,
            _ => Self::Pass,
        }
    }
}

/// Shared policy handle returned to test code for runtime fault injection.
#[derive(Clone)]
pub struct FaultPolicyHandle {
    policy: Arc<AtomicU8>,
    target_generation: Arc<AtomicU64>,
}

impl FaultPolicyHandle {
    /// Set a socket-wide fault policy (Pass, DropAll, or Drop50).
    pub fn set(&self, p: FaultPolicy) {
        self.policy.store(p as u8, Ordering::Relaxed);
    }

    /// Activate generation-targeted fault injection.
    ///
    /// Packets are dropped only while `current_generation == gen`. After a hop
    /// increments the counter past `gen`, the fault clears automatically.
    ///
    /// Ordering: target_generation is stored first, then policy is set to
    /// DropGeneration, so there is no window where the policy reads a stale target.
    pub fn set_drop_generation(&self, generation: u64) {
        self.target_generation.store(generation, Ordering::Relaxed);
        self.policy.store(FaultPolicy::DropGeneration as u8, Ordering::Relaxed);
    }

    /// Read the current fault policy.
    #[allow(dead_code)]
    pub fn get(&self) -> FaultPolicy {
        FaultPolicy::from_u8(self.policy.load(Ordering::Relaxed))
    }
}

/// A `quinn::AsyncUdpSocket` wrapper that injects faults based on an `AtomicU8` policy.
pub struct FaultInjectionSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    policy: Arc<AtomicU8>,
    /// Target hop generation for DropGeneration policy.
    target_generation: Arc<AtomicU64>,
    /// Live hop generation counter, shared with UdpHopSocket.
    /// None when generation-aware fault injection is not configured.
    current_generation: Option<Arc<AtomicU64>>,
}

impl fmt::Debug for FaultInjectionSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FaultInjectionSocket")
            .field("policy", &self.current_policy())
            .finish_non_exhaustive()
    }
}

impl FaultInjectionSocket {
    /// Wrap an inner socket with fault injection. Returns the socket and a
    /// handle for controlling the policy at runtime.
    #[allow(dead_code)]
    pub fn new(inner: Arc<dyn AsyncUdpSocket>) -> (Arc<Self>, FaultPolicyHandle) {
        let policy = Arc::new(AtomicU8::new(FaultPolicy::Pass as u8));
        let target_generation = Arc::new(AtomicU64::new(0));
        let handle = FaultPolicyHandle {
            policy: Arc::clone(&policy),
            target_generation: Arc::clone(&target_generation),
        };
        let sock = Arc::new(Self {
            inner,
            policy,
            target_generation,
            current_generation: None,
        });
        (sock, handle)
    }

    /// Wrap an inner socket with an existing policy atom (for use in closures).
    ///
    /// Used by R15 tests where the policy atom is created externally.
    /// No generation-aware fault injection is configured.
    pub fn with_policy(inner: Arc<dyn AsyncUdpSocket>, policy: Arc<AtomicU8>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            policy,
            target_generation: Arc::new(AtomicU64::new(0)),
            current_generation: None,
        })
    }

    /// Wrap an inner socket with generation-aware fault injection.
    ///
    /// `policy` and `target_generation` are controlled by test code.
    /// `current_generation` is the live hop generation counter shared with
    /// UdpHopSocket (incremented on each successful hop).
    pub fn with_generation(
        inner: Arc<dyn AsyncUdpSocket>,
        policy: Arc<AtomicU8>,
        target_generation: Arc<AtomicU64>,
        current_generation: Arc<AtomicU64>,
    ) -> Arc<Self> {
        Arc::new(Self {
            inner,
            policy,
            target_generation,
            current_generation: Some(current_generation),
        })
    }

    fn current_policy(&self) -> FaultPolicy {
        FaultPolicy::from_u8(self.policy.load(Ordering::Relaxed))
    }

    /// Returns true if this packet should be dropped under the current policy.
    fn should_drop(&self) -> bool {
        match self.current_policy() {
            FaultPolicy::Pass => false,
            FaultPolicy::DropAll => true,
            FaultPolicy::Drop50 => rand::random::<u8>() < 128,
            FaultPolicy::DropGeneration => {
                // Drop only if we have a generation reference and it matches the target.
                // If no generation handle is configured, treat as Pass (no-op).
                match &self.current_generation {
                    Some(current) => {
                        let target = self.target_generation.load(Ordering::Relaxed);
                        current.load(Ordering::Relaxed) == target
                    }
                    None => false,
                }
            }
        }
    }
}

impl AsyncUdpSocket for FaultInjectionSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        if self.should_drop() {
            // Silently consume the packet (pretend it was sent successfully).
            return Ok(());
        }
        self.inner.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let result = self.inner.poll_recv(cx, bufs, meta);

        if let Poll::Ready(Ok(n)) = &result {
            if *n > 0 && self.should_drop() {
                // Drop received packets by returning Pending.
                // Wake immediately so the poller re-polls (next poll may pass).
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        }

        result
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}
