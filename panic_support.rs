//! Panic coordination utilities shared between the panic handler, block driver,
//! and allocator. This module is `no_std` friendly and keeps all state in static
//! storage so the panic path can run without heap allocation.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::sync::RwLock;

/// Result returned by components that quiesce during a panic.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PanicQuiesceResult {
    pub drained: bool,
    pub in_flight: usize,
    pub flush_issued: bool,
}

/// Trait implemented by components that can freeze new work during a panic.
pub trait PanicQuiesce: Send + Sync {
    fn panic_freeze(&self) -> PanicQuiesceResult;
}

/// A minimal allocator telemetry snapshot suitable for panic reporting.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AllocatorPanicReport {
    pub epoch: u64,
    pub shards_total: u32,
    pub shards_with_pressure: u32,
    pub free_blocks: u64,
    pub last_errors: &'static [AllocatorEvent],
    pub events_head: usize,
    pub events_recorded: usize,
    pub double_free_guard_hits: u64,
}

/// Kind of allocator breadcrumb captured in the panic ring buffer.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllocatorEventKind {
    AllocationFailed,
    FreeFailed,
    HintCollision,
    DoubleFree,
    Pressure,
}

/// Allocator breadcrumb entry recorded without allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AllocatorEvent {
    pub ts_ns: u64,
    pub shard_id: Option<u16>,
    pub detail: u64,
    pub kind: AllocatorEventKind,
}

impl Default for AllocatorEvent {
    fn default() -> Self {
        Self {
            ts_ns: 0,
            shard_id: None,
            detail: 0,
            kind: AllocatorEventKind::AllocationFailed,
        }
    }
}

impl AllocatorEvent {
    pub const fn zeroed() -> Self {
        Self {
            ts_ns: 0,
            shard_id: None,
            detail: 0,
            kind: AllocatorEventKind::AllocationFailed,
        }
    }
}

const ALLOC_EVENT_CAPACITY: usize = 64;

struct AllocatorEventRing {
    write_cursor: AtomicUsize,
    buffer: UnsafeCell<[AllocatorEvent; ALLOC_EVENT_CAPACITY]>,
}

unsafe impl Sync for AllocatorEventRing {}

impl AllocatorEventRing {
    const fn new() -> Self {
        Self {
            write_cursor: AtomicUsize::new(0),
            buffer: UnsafeCell::new([AllocatorEvent::zeroed(); ALLOC_EVENT_CAPACITY]),
        }
    }

    fn record(&self, event: AllocatorEvent) {
        let slot = self.write_cursor.fetch_add(1, Ordering::AcqRel) % ALLOC_EVENT_CAPACITY;
        // SAFETY: buffer is a fixed-size static array guarded by atomic cursor.
        unsafe {
            (*self.buffer.get())[slot] = event;
        }
    }

    fn snapshot(
        &self,
    ) -> (
        &'static [AllocatorEvent; ALLOC_EVENT_CAPACITY],
        usize,
        usize,
    ) {
        let written = self.write_cursor.load(Ordering::Acquire);
        let head = written % ALLOC_EVENT_CAPACITY;
        let total = written;
        // SAFETY: buffer lives for 'static and is never deallocated.
        let slice = unsafe { &*self.buffer.get() };
        (slice, head, total)
    }
}

static ALLOC_EVENT_RING: AllocatorEventRing = AllocatorEventRing::new();

/// Record an allocator breadcrumb into the ring buffer. This function is
/// lock-free and allocation-free.
pub fn record_allocator_event(event: AllocatorEvent) {
    ALLOC_EVENT_RING.record(event);
}

/// Trait used by allocators to surface panic-friendly telemetry without
/// allocations or blocking.
pub trait AllocatorPanicReporter: Send + Sync {
    fn allocator_panic_report(&self) -> AllocatorPanicReport;
}

static PANIC_QUIESCE: RwLock<Option<&'static dyn PanicQuiesce>> = RwLock::new(None);
static ALLOCATOR_REPORTER: RwLock<Option<&'static dyn AllocatorPanicReporter>> = RwLock::new(None);

/// Register a panic quiesce handler (e.g., block driver). The handler must live
/// for the duration of the program; callers typically leak an `Arc` or place
/// the object in static storage.
pub fn register_panic_quiesce(handler: Option<&'static dyn PanicQuiesce>) {
    if let Ok(mut slot) = PANIC_QUIESCE.write() {
        *slot = handler;
    }
}

/// Register an allocator panic reporter that exposes allocator health in the
/// panic path.
pub fn register_allocator_reporter(handler: Option<&'static dyn AllocatorPanicReporter>) {
    if let Ok(mut slot) = ALLOCATOR_REPORTER.write() {
        *slot = handler;
    }
}

/// Invoke the registered quiesce handler if present.
pub fn try_panic_quiesce() -> Option<PanicQuiesceResult> {
    PANIC_QUIESCE
        .read()
        .ok()
        .and_then(|handler| handler.map(|h| h.panic_freeze()))
}

/// Obtain the allocator panic report, falling back to ring-only information if
/// no reporter has been registered.
pub fn allocator_panic_report() -> AllocatorPanicReport {
    if let Ok(guard) = ALLOCATOR_REPORTER.read() {
        if let Some(handler) = *guard {
            return handler.allocator_panic_report();
        }
    }

    let (events, head, total) = ALLOC_EVENT_RING.snapshot();
    AllocatorPanicReport {
        epoch: 0,
        shards_total: 0,
        shards_with_pressure: 0,
        free_blocks: 0,
        last_errors: events,
        events_head: head,
        events_recorded: total,
        double_free_guard_hits: 0,
    }
}

/// Snapshot the allocator panic ring without requiring a reporter. Useful for
/// callers that want to inspect breadcrumbs outside the panic path.
pub fn allocator_event_window() -> (
    &'static [AllocatorEvent; ALLOC_EVENT_CAPACITY],
    usize,
    usize,
) {
    ALLOC_EVENT_RING.snapshot()
}
