//! Cached allocator facade layering admission control and observability over the
//! shard-level allocator primitives. Designed for production use with
//! per-CPU caches, queue-depth aware throttling, and batch TRIM support for
//! healthier flash wear leveling.
#![cfg(feature = "std")]

use crate::sync::{Arc, Mutex};
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crate::journal::{AllocationRecordKind, Journal, JournalError};
use crate::panic_support::{
    allocator_event_window, record_allocator_event, register_allocator_reporter, AllocatorEvent,
    AllocatorEventKind, AllocatorPanicReport, AllocatorPanicReporter,
};
use crate::time::Clock;
use crate::{AllocError, BlockAddr, BlockDevice, VolumeAllocator, BLOCKS_PER_SHARD};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Tunables controlling cache sizing, trim batching, and queue admission.
#[derive(Clone, Debug)]
pub struct AllocatorConfig {
    /// Maximum cached blocks per logical CPU.
    pub cache_capacity: usize,
    /// Number of freed blocks before triggering a batched trim.
    pub trim_trigger: usize,
    /// Hard ceiling on blocks to include in a single trim batch.
    pub max_trim_batch: usize,
}

impl Default for AllocatorConfig {
    fn default() -> Self {
        Self {
            cache_capacity: 64,
            trim_trigger: 32,
            max_trim_batch: 256,
        }
    }
}

#[derive(Default)]
struct CpuCache {
    entries: Vec<BlockAddr>,
}

impl CpuCache {
    fn pop(&mut self) -> Option<BlockAddr> {
        self.entries.pop()
    }

    fn push(&mut self, addr: BlockAddr, capacity: usize) -> Option<BlockAddr> {
        self.entries.push(addr);
        if self.entries.len() > capacity {
            self.entries.pop()
        } else {
            None
        }
    }

    fn refill_from(&mut self, capacity: usize, source: &VolumeAllocator) {
        while self.entries.len() < capacity {
            match source.alloc_block() {
                Ok(addr) => self.entries.push(addr),
                Err(_) => break,
            }
        }
    }
}

struct TrimState {
    pending: Vec<BlockAddr>,
}

impl TrimState {
    fn new() -> Self {
        Self {
            pending: Vec::new(),
        }
    }

    fn enqueue(&mut self, addr: BlockAddr, max_batch: usize) {
        if self.pending.len() < max_batch {
            self.pending.push(addr);
        }
    }

    fn should_flush(&self, trigger: usize) -> bool {
        self.pending.len() >= trigger
    }

    fn drain(&mut self) -> Vec<BlockAddr> {
        let mut drained = Vec::new();
        std::mem::swap(&mut drained, &mut self.pending);
        drained
    }
}

/// Rolling metrics used for diagnostics and operational alerting.
#[derive(Default)]
pub struct AllocatorMetrics {
    allocations: AtomicU64,
    allocation_latency_ns: AtomicU64,
    frees: AtomicU64,
    free_latency_ns: AtomicU64,
    contention_events: AtomicU64,
}

impl AllocatorMetrics {
    fn record_alloc(&self, latency_ns: u64) {
        self.allocations.fetch_add(1, Ordering::Relaxed);
        self.allocation_latency_ns
            .fetch_add(latency_ns.max(1), Ordering::Relaxed);
    }

    fn record_free(&self, latency_ns: u64) {
        self.frees.fetch_add(1, Ordering::Relaxed);
        self.free_latency_ns
            .fetch_add(latency_ns.max(1), Ordering::Relaxed);
    }

    fn bump_contention(&self) {
        self.contention_events.fetch_add(1, Ordering::Relaxed);
    }
}

/// Immutable snapshot of allocator health suitable for diagnostics endpoints.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllocatorSnapshot {
    pub allocations: u64,
    pub frees: u64,
    pub avg_allocation_latency_ns: u64,
    pub avg_free_latency_ns: u64,
    pub contention_events: u64,
    pub shard_free_blocks: Vec<(u16, u64)>,
}

/// Thread-safe allocator wrapper with per-CPU caches, admission control, and
/// trim batching.
pub struct CachedVolumeAllocator<B: BlockDevice> {
    volume: Arc<VolumeAllocator>,
    device: Arc<B>,
    journal: Option<Arc<Journal<B>>>,
    caches: Vec<Mutex<CpuCache>>,
    inflight: AtomicUsize,
    max_inflight: usize,
    config: AllocatorConfig,
    trim_state: Mutex<TrimState>,
    metrics: AllocatorMetrics,
    clock: crate::time::SystemClock,
    pressure_threshold: u64,
}

impl<B: BlockDevice + 'static> CachedVolumeAllocator<B> {
    pub fn new(
        volume: VolumeAllocator,
        device: Arc<B>,
        journal: Option<Arc<Journal<B>>>,
        config: AllocatorConfig,
    ) -> Self {
        let cpu_count = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .max(1);

        let caches = (0..cpu_count)
            .map(|_| Mutex::new(CpuCache::default()))
            .collect();

        Self {
            volume: Arc::new(volume),
            max_inflight: device.queue_depth().max(1),
            device,
            journal,
            caches,
            inflight: AtomicUsize::new(0),
            config,
            trim_state: Mutex::new(TrimState::new()),
            metrics: AllocatorMetrics::default(),
            clock: crate::time::SystemClock::new(),
            pressure_threshold: BLOCKS_PER_SHARD / 8,
        }
    }

    fn cache_index(&self) -> usize {
        let mut hasher = DefaultHasher::new();
        std::thread::current().id().hash(&mut hasher);
        (hasher.finish() as usize) % self.caches.len()
    }

    fn admit(&self) {
        while self
            .inflight
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                if current < self.max_inflight {
                    Some(current + 1)
                } else {
                    None
                }
            })
            .is_err()
        {
            self.metrics.bump_contention();
            std::thread::yield_now();
        }
    }

    fn finish(&self) {
        self.inflight.fetch_sub(1, Ordering::AcqRel);
    }

    fn log_event(&self, kind: AllocatorEventKind, shard: Option<u16>, detail: u64) {
        record_allocator_event(AllocatorEvent {
            ts_ns: self.clock.now_ns(),
            shard_id: shard,
            detail,
            kind,
        });
    }

    fn error_code(err: &AllocError) -> u64 {
        match err {
            AllocError::NoSpace => 1,
            AllocError::DoubleFree => 2,
            AllocError::OutOfBounds => 3,
            AllocError::InvalidShard => 4,
            AllocError::WrongVolume => 5,
            AllocError::NetworkError => 6,
            AllocError::RemoteNodeDown => 7,
        }
    }

    pub fn alloc_block(&self) -> Result<BlockAddr, AllocError> {
        self.admit();
        let start = self.clock.now_ns();
        let cache_idx = self.cache_index();
        let mut cache = self.caches[cache_idx].lock().unwrap();

        if let Some(addr) = cache.pop() {
            self.finish();
            self.metrics.record_alloc(self.clock.now_ns() - start);
            self.record_allocation(addr, 1);
            return Ok(addr);
        }

        cache.refill_from(self.config.cache_capacity, &self.volume);
        let result = cache.pop().ok_or(AllocError::NoSpace).map(|addr| {
            self.record_allocation(addr, 1);
            addr
        });

        self.finish();
        let latency = self.clock.now_ns().saturating_sub(start);
        self.metrics.record_alloc(latency);
        if let Err(err) = &result {
            self.log_event(
                AllocatorEventKind::AllocationFailed,
                None,
                Self::error_code(err),
            );
        }
        result
    }

    pub fn free_block(&self, addr: BlockAddr) -> Result<(), AllocError> {
        self.admit();
        let start = self.clock.now_ns();
        let cache_idx = self.cache_index();
        {
            let mut cache = self.caches[cache_idx].lock().unwrap();
            if let Some(evicted) = cache.push(addr, self.config.cache_capacity) {
                if let Err(err) = self.volume.free_block(evicted) {
                    self.finish();
                    self.metrics
                        .record_free(self.clock.now_ns().saturating_sub(start));
                    self.log_event(
                        AllocatorEventKind::FreeFailed,
                        Some(evicted.shard_id()),
                        evicted.block_offset(),
                    );
                    return Err(err);
                }
                self.enqueue_trim(evicted);
            }
        }
        self.finish();
        self.metrics
            .record_free(self.clock.now_ns().saturating_sub(start));
        self.record_free(addr, 1);
        Ok(())
    }

    pub fn drain(&self) -> Result<(), AllocError> {
        for cache in &self.caches {
            let mut guard = cache.lock().unwrap();
            for addr in guard.entries.drain(..) {
                self.volume.free_block(addr)?;
                self.enqueue_trim(addr);
            }
        }
        self.flush_trims().map_err(|_| AllocError::NetworkError)
    }

    fn enqueue_trim(&self, addr: BlockAddr) {
        let mut state = self.trim_state.lock().unwrap();
        state.enqueue(addr, self.config.max_trim_batch);
        if state.should_flush(self.config.trim_trigger) {
            let _ = self.flush_trims_inner(&mut state);
        }
    }

    fn flush_trims(&self) -> Result<(), JournalError> {
        let mut state = self.trim_state.lock().unwrap();
        self.flush_trims_inner(&mut state)
    }

    fn flush_trims_inner(&self, state: &mut TrimState) -> Result<(), JournalError> {
        let mut pending = state.drain();
        if pending.is_empty() {
            return Ok(());
        }

        pending.sort_by_key(|addr| (addr.shard_id(), addr.block_offset()));
        let mut idx = 0;
        while idx < pending.len() {
            let start = pending[idx];
            let mut len = 1u64;
            while idx + 1 < pending.len()
                && pending[idx + 1].shard_id() == start.shard_id()
                && pending[idx + 1].block_offset() == start.block_offset() + len
            {
                len += 1;
                idx += 1;
            }

            self.device
                .trim_range(start, len)
                .map_err(JournalError::IoError)?;
            idx += 1;
        }

        Ok(())
    }

    pub fn diagnostics(&self) -> AllocatorSnapshot {
        let allocations = self.metrics.allocations.load(Ordering::Relaxed);
        let frees = self.metrics.frees.load(Ordering::Relaxed);
        let alloc_latency = self.metrics.allocation_latency_ns.load(Ordering::Relaxed);
        let free_latency = self.free_latency_ns();
        AllocatorSnapshot {
            allocations,
            frees,
            avg_allocation_latency_ns: if allocations == 0 {
                0
            } else {
                alloc_latency / allocations
            },
            avg_free_latency_ns: if frees == 0 { 0 } else { free_latency / frees },
            contention_events: self.metrics.contention_events.load(Ordering::Relaxed),
            shard_free_blocks: self.volume.shard_free_blocks(),
        }
    }

    fn free_latency_ns(&self) -> u64 {
        self.metrics.free_latency_ns.load(Ordering::Relaxed)
    }

    fn record_allocation(&self, addr: BlockAddr, count: u32) {
        if let Some(journal) = &self.journal {
            let _ = Self::emit_record(journal, AllocationRecordKind::Allocation, addr, count);
        }
    }

    fn record_free(&self, addr: BlockAddr, count: u32) {
        if let Some(journal) = &self.journal {
            let _ = Self::emit_record(journal, AllocationRecordKind::Free, addr, count);
        }
    }

    /// Leak and register this allocator as the panic reporter.
    pub fn register_for_panic(self: &Arc<Self>) {
        let leaked: &'static Self = unsafe { &*Arc::into_raw(self.clone()) };
        register_allocator_reporter(Some(leaked));
    }

    fn emit_record(
        journal: &Arc<Journal<B>>,
        kind: AllocationRecordKind,
        addr: BlockAddr,
        count: u32,
    ) -> Result<(), JournalError> {
        let mut tx = journal.begin();
        match kind {
            AllocationRecordKind::Allocation => tx.log_alloc(addr, count)?,
            AllocationRecordKind::Free => tx.log_free(addr, count)?,
        }
        journal.commit(&mut tx)
    }
}

impl<B: BlockDevice> AllocatorPanicReporter for CachedVolumeAllocator<B> {
    fn allocator_panic_report(&self) -> AllocatorPanicReport {
        let snapshot = self.volume.panic_snapshot(self.pressure_threshold);
        let (events, head, recorded) = allocator_event_window();

        AllocatorPanicReport {
            epoch: snapshot.epoch,
            shards_total: snapshot.shards_total,
            shards_with_pressure: snapshot.shards_with_pressure,
            free_blocks: snapshot.free_blocks,
            last_errors: events,
            events_head: head,
            events_recorded: recorded,
            double_free_guard_hits: snapshot.double_free_guard_hits,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MemoryBlockDevice;
    use crate::{AllocatorErrorCounters, ShardAllocator, VolumeAllocator, BLOCKS_PER_SHARD};
    use core::sync::atomic::AtomicU32;

    fn dummy_volume(node: u64, volume: u32) -> VolumeAllocator {
        let mut vol = VolumeAllocator::new(node, volume);
        // Add a shard with full capacity
        let shard = ShardAllocator::new(0, BLOCKS_PER_SHARD);
        vol.add_shard(shard).expect("add shard");
        vol
    }

    #[test]
    fn diagnostics_surface_metrics() {
        let device = Arc::new(MemoryBlockDevice::new(1, 1));
        let volume = dummy_volume(1, 1);
        let allocator =
            CachedVolumeAllocator::new(volume, device, None, AllocatorConfig::default());

        let snapshot = allocator.diagnostics();
        assert_eq!(snapshot.allocations, 0);
        assert_eq!(snapshot.frees, 0);
        assert!(!snapshot.shard_free_blocks.is_empty());
    }
}
