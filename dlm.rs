// PermFS Distributed Lock Manager — Lease-based locking for cluster consistency
#![cfg(feature = "std")]

use crate::{
    sync::{Arc, RwLock},
    time::Clock,
    BlockAddr, IoError,
};
use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(feature = "std")]
use std::collections::HashMap;
#[cfg(feature = "std")]
use std::time::{Duration, Instant};

// ============================================================================
// LOCK TYPES
// ============================================================================

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockMode {
    /// No lock held
    None = 0,
    /// Shared/read lock - multiple readers allowed
    Shared = 1,
    /// Exclusive/write lock - single writer only
    Exclusive = 2,
    /// Intent shared - planning to acquire shared locks on children
    IntentShared = 3,
    /// Intent exclusive - planning to acquire exclusive locks on children
    IntentExclusive = 4,
}

impl LockMode {
    /// Check if this mode is compatible with another
    pub fn is_compatible(&self, other: &LockMode) -> bool {
        match (self, other) {
            (LockMode::None, _) | (_, LockMode::None) => true,
            (LockMode::Shared, LockMode::Shared) => true,
            (LockMode::Shared, LockMode::IntentShared) => true,
            (LockMode::IntentShared, LockMode::Shared) => true,
            (LockMode::IntentShared, LockMode::IntentShared) => true,
            (LockMode::IntentShared, LockMode::IntentExclusive) => true,
            (LockMode::IntentExclusive, LockMode::IntentShared) => true,
            (LockMode::IntentExclusive, LockMode::IntentExclusive) => true,
            _ => false,
        }
    }
}

/// Lock identifier - can be inode, block, or range
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LockId {
    /// Lock on an inode
    Inode(u64),
    /// Lock on a block address
    Block(BlockAddr),
    /// Lock on a byte range within a file
    Range { inode: u64, start: u64, end: u64 },
    /// Lock on a directory path
    Path(u64), // hash of path
}

impl LockId {
    pub fn inode(ino: u64) -> Self {
        Self::Inode(ino)
    }

    pub fn block(addr: BlockAddr) -> Self {
        Self::Block(addr)
    }

    pub fn range(inode: u64, start: u64, end: u64) -> Self {
        Self::Range { inode, start, end }
    }
}

// ============================================================================
// LEASE-BASED LOCK
// ============================================================================

/// Lease duration in milliseconds
pub const DEFAULT_LEASE_DURATION_MS: u64 = 30000; // 30 seconds
pub const MIN_LEASE_DURATION_MS: u64 = 5000; // 5 seconds
pub const MAX_LEASE_DURATION_MS: u64 = 300000; // 5 minutes

/// Lock grant with lease information
#[derive(Clone, Debug)]
pub struct LockGrant {
    pub lock_id: LockId,
    pub mode: LockMode,
    pub owner: u64,          // Node ID that owns the lock
    pub sequence: u64,       // Monotonic sequence for fencing
    pub lease_start: u64,    // Timestamp (ns) when lease started
    pub lease_duration: u64, // Lease duration in ns
}

impl LockGrant {
    /// Check if lease is still valid
    pub fn is_valid(&self, current_time_ns: u64) -> bool {
        current_time_ns < self.lease_start + self.lease_duration
    }

    /// Time remaining on lease in nanoseconds
    pub fn time_remaining(&self, current_time_ns: u64) -> u64 {
        let expiry = self.lease_start + self.lease_duration;
        expiry.saturating_sub(current_time_ns)
    }
}

// ============================================================================
// LOCK REQUEST
// ============================================================================

#[derive(Clone, Debug)]
pub struct LockRequest {
    pub lock_id: LockId,
    pub mode: LockMode,
    pub requester: u64,         // Node ID requesting lock
    pub timeout_ns: u64,        // Max time to wait for lock
    pub lease_duration_ms: u64, // Requested lease duration
}

impl LockRequest {
    pub fn new(lock_id: LockId, mode: LockMode, requester: u64) -> Self {
        Self {
            lock_id,
            mode,
            requester,
            timeout_ns: 5_000_000_000, // 5 second default timeout
            lease_duration_ms: DEFAULT_LEASE_DURATION_MS,
        }
    }

    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ns = timeout_ms * 1_000_000;
        self
    }

    pub fn with_lease(mut self, lease_ms: u64) -> Self {
        self.lease_duration_ms = lease_ms.clamp(MIN_LEASE_DURATION_MS, MAX_LEASE_DURATION_MS);
        self
    }
}

// ============================================================================
// LOCK ERRORS
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockError {
    /// Lock is held by another node
    Contention,
    /// Timeout waiting for lock
    Timeout,
    /// Lock was not held
    NotHeld,
    /// Lease expired
    LeaseExpired,
    /// Invalid lock mode transition
    InvalidUpgrade,
    /// Deadlock detected
    Deadlock,
    /// Network error communicating with lock manager
    NetworkError,
    /// Internal error
    InternalError,
}

impl From<LockError> for IoError {
    fn from(e: LockError) -> Self {
        match e {
            LockError::Contention | LockError::Timeout => IoError::LockContention,
            LockError::LeaseExpired => IoError::LockContention,
            _ => IoError::IoFailed,
        }
    }
}

// ============================================================================
// LOCAL LOCK TABLE (per-node)
// ============================================================================

#[cfg(feature = "std")]
struct LockEntry {
    mode: LockMode,
    owner: u64,
    sequence: u64,
    lease_start: Instant,
    lease_duration: Duration,
    waiters: Vec<(u64, LockMode)>, // (node_id, requested_mode)
}

#[cfg(feature = "std")]
pub struct LocalLockTable {
    locks: RwLock<HashMap<LockId, LockEntry>>,
    sequence: AtomicU64,
    _local_node: u64,
}

#[cfg(feature = "std")]
impl LocalLockTable {
    pub fn new(local_node: u64) -> Self {
        Self {
            locks: RwLock::new(HashMap::new()),
            sequence: AtomicU64::new(1),
            _local_node: local_node,
        }
    }

    fn next_sequence(&self) -> u64 {
        self.sequence.fetch_add(1, Ordering::SeqCst)
    }

    /// Try to acquire a lock locally
    pub fn try_acquire(&self, request: &LockRequest) -> Result<LockGrant, LockError> {
        let mut locks = self.locks.write().unwrap();

        if let Some(entry) = locks.get_mut(&request.lock_id) {
            // Check if existing lock is expired
            if entry.lease_start.elapsed() > entry.lease_duration {
                // Lock expired, we can take it
                entry.mode = request.mode;
                entry.owner = request.requester;
                entry.sequence = self.next_sequence();
                entry.lease_start = Instant::now();
                entry.lease_duration = Duration::from_millis(request.lease_duration_ms);
                entry.waiters.clear();

                return Ok(LockGrant {
                    lock_id: request.lock_id,
                    mode: request.mode,
                    owner: request.requester,
                    sequence: entry.sequence,
                    lease_start: 0, // Will be filled by caller with proper timestamp
                    lease_duration: request.lease_duration_ms * 1_000_000,
                });
            }

            // Check compatibility
            if entry.mode.is_compatible(&request.mode) {
                // Compatible - can share
                if request.mode == LockMode::Exclusive {
                    return Err(LockError::Contention);
                }
                // For shared locks, update owner list would go here
                return Ok(LockGrant {
                    lock_id: request.lock_id,
                    mode: request.mode,
                    owner: request.requester,
                    sequence: entry.sequence,
                    lease_start: 0,
                    lease_duration: request.lease_duration_ms * 1_000_000,
                });
            }

            // Incompatible lock held
            return Err(LockError::Contention);
        }

        // Lock not held - acquire it
        let seq = self.next_sequence();
        locks.insert(
            request.lock_id,
            LockEntry {
                mode: request.mode,
                owner: request.requester,
                sequence: seq,
                lease_start: Instant::now(),
                lease_duration: Duration::from_millis(request.lease_duration_ms),
                waiters: Vec::new(),
            },
        );

        Ok(LockGrant {
            lock_id: request.lock_id,
            mode: request.mode,
            owner: request.requester,
            sequence: seq,
            lease_start: 0,
            lease_duration: request.lease_duration_ms * 1_000_000,
        })
    }

    /// Release a lock
    pub fn release(&self, lock_id: LockId, owner: u64, sequence: u64) -> Result<(), LockError> {
        let mut locks = self.locks.write().unwrap();

        if let Some(entry) = locks.get(&lock_id) {
            if entry.owner != owner {
                return Err(LockError::NotHeld);
            }
            if entry.sequence != sequence {
                return Err(LockError::LeaseExpired);
            }
        } else {
            return Err(LockError::NotHeld);
        }

        locks.remove(&lock_id);
        Ok(())
    }

    /// Renew a lease
    pub fn renew(
        &self,
        lock_id: LockId,
        owner: u64,
        sequence: u64,
        new_duration_ms: u64,
    ) -> Result<LockGrant, LockError> {
        let mut locks = self.locks.write().unwrap();

        if let Some(entry) = locks.get_mut(&lock_id) {
            if entry.owner != owner {
                return Err(LockError::NotHeld);
            }
            if entry.sequence != sequence {
                return Err(LockError::LeaseExpired);
            }
            if entry.lease_start.elapsed() > entry.lease_duration {
                return Err(LockError::LeaseExpired);
            }

            entry.lease_start = Instant::now();
            entry.lease_duration = Duration::from_millis(new_duration_ms);

            return Ok(LockGrant {
                lock_id,
                mode: entry.mode,
                owner,
                sequence,
                lease_start: 0,
                lease_duration: new_duration_ms * 1_000_000,
            });
        }

        Err(LockError::NotHeld)
    }

    /// Upgrade a shared lock to exclusive
    pub fn upgrade(
        &self,
        lock_id: LockId,
        owner: u64,
        sequence: u64,
    ) -> Result<LockGrant, LockError> {
        let mut locks = self.locks.write().unwrap();

        if let Some(entry) = locks.get_mut(&lock_id) {
            if entry.owner != owner {
                return Err(LockError::NotHeld);
            }
            if entry.sequence != sequence {
                return Err(LockError::LeaseExpired);
            }
            if entry.mode != LockMode::Shared {
                return Err(LockError::InvalidUpgrade);
            }

            // In a real implementation, we'd check if we're the only shared holder
            entry.mode = LockMode::Exclusive;
            let new_seq = self.next_sequence();
            entry.sequence = new_seq;
            entry.lease_start = Instant::now();

            return Ok(LockGrant {
                lock_id,
                mode: LockMode::Exclusive,
                owner,
                sequence: new_seq,
                lease_start: 0,
                lease_duration: entry.lease_duration.as_nanos() as u64,
            });
        }

        Err(LockError::NotHeld)
    }

    /// Check if a lock is held
    pub fn is_held(&self, lock_id: &LockId) -> bool {
        let locks = self.locks.read().unwrap();
        if let Some(entry) = locks.get(lock_id) {
            entry.lease_start.elapsed() <= entry.lease_duration
        } else {
            false
        }
    }

    /// Get lock holder info
    pub fn get_holder(&self, lock_id: &LockId) -> Option<(u64, LockMode)> {
        let locks = self.locks.read().unwrap();
        locks.get(lock_id).and_then(|entry| {
            if entry.lease_start.elapsed() <= entry.lease_duration {
                Some((entry.owner, entry.mode))
            } else {
                None
            }
        })
    }

    /// Clean up expired locks
    pub fn cleanup_expired(&self) -> usize {
        let mut locks = self.locks.write().unwrap();
        let before = locks.len();
        locks.retain(|_, entry| entry.lease_start.elapsed() <= entry.lease_duration);
        before - locks.len()
    }
}

// ============================================================================
// DISTRIBUTED LOCK MANAGER
// ============================================================================

#[cfg(feature = "std")]
pub struct DistributedLockManager {
    local_node: u64,
    local_table: Arc<LocalLockTable>,
    // In a real implementation, this would have:
    // - Connections to other nodes
    // - Consensus protocol for lock coordination
    // - Failure detection and recovery
}

#[cfg(feature = "std")]
impl DistributedLockManager {
    pub fn new(local_node: u64) -> Self {
        Self {
            local_node,
            local_table: Arc::new(LocalLockTable::new(local_node)),
        }
    }

    /// Acquire a lock with timeout
    pub fn acquire(&self, request: &LockRequest) -> Result<LockGrant, LockError> {
        let start = Instant::now();
        let timeout = Duration::from_nanos(request.timeout_ns);

        loop {
            match self.local_table.try_acquire(request) {
                Ok(mut grant) => {
                    grant.lease_start = crate::time::SystemClock::new().now_ns();
                    return Ok(grant);
                }
                Err(LockError::Contention) => {
                    if start.elapsed() >= timeout {
                        return Err(LockError::Timeout);
                    }
                    // Back off and retry
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Try to acquire without blocking
    pub fn try_acquire(&self, request: &LockRequest) -> Result<LockGrant, LockError> {
        let mut grant = self.local_table.try_acquire(request)?;
        grant.lease_start = crate::time::SystemClock::new().now_ns();
        Ok(grant)
    }

    /// Release a lock
    pub fn release(&self, grant: &LockGrant) -> Result<(), LockError> {
        self.local_table
            .release(grant.lock_id, grant.owner, grant.sequence)
    }

    /// Renew a lease
    pub fn renew(&self, grant: &LockGrant) -> Result<LockGrant, LockError> {
        let mut new_grant = self.local_table.renew(
            grant.lock_id,
            grant.owner,
            grant.sequence,
            grant.lease_duration / 1_000_000,
        )?;
        new_grant.lease_start = crate::time::SystemClock::new().now_ns();
        Ok(new_grant)
    }

    /// Upgrade a shared lock to exclusive
    pub fn upgrade(&self, grant: &LockGrant) -> Result<LockGrant, LockError> {
        let mut new_grant = self
            .local_table
            .upgrade(grant.lock_id, grant.owner, grant.sequence)?;
        new_grant.lease_start = crate::time::SystemClock::new().now_ns();
        Ok(new_grant)
    }

    /// Downgrade an exclusive lock to shared
    pub fn downgrade(&self, grant: &LockGrant) -> Result<LockGrant, LockError> {
        // For downgrade, we release and re-acquire as shared
        self.release(grant)?;
        let request = LockRequest::new(grant.lock_id, LockMode::Shared, grant.owner);
        self.acquire(&request)
    }

    /// Start background lease renewal for a grant
    pub fn start_renewal_thread(&self, grant: LockGrant) -> std::thread::JoinHandle<()> {
        let dlm = self.clone_inner();
        std::thread::spawn(move || {
            let mut current_grant = grant;
            let renewal_interval = Duration::from_millis(current_grant.lease_duration / 3_000_000);

            loop {
                std::thread::sleep(renewal_interval);
                match dlm.local_table.renew(
                    current_grant.lock_id,
                    current_grant.owner,
                    current_grant.sequence,
                    current_grant.lease_duration / 1_000_000,
                ) {
                    Ok(new_grant) => {
                        current_grant = new_grant;
                    }
                    Err(_) => {
                        // Lease expired or released
                        break;
                    }
                }
            }
        })
    }

    fn clone_inner(&self) -> Self {
        Self {
            local_node: self.local_node,
            local_table: Arc::clone(&self.local_table),
        }
    }
}

// ============================================================================
// LOCK GUARD (RAII)
// ============================================================================

#[cfg(feature = "std")]
pub struct LockGuard {
    dlm: Arc<DistributedLockManager>,
    grant: LockGrant,
}

#[cfg(feature = "std")]
impl LockGuard {
    pub fn new(dlm: Arc<DistributedLockManager>, grant: LockGrant) -> Self {
        Self { dlm, grant }
    }

    pub fn lock_id(&self) -> &LockId {
        &self.grant.lock_id
    }

    pub fn mode(&self) -> LockMode {
        self.grant.mode
    }

    pub fn sequence(&self) -> u64 {
        self.grant.sequence
    }

    /// Manually release the lock before guard is dropped
    pub fn release(self) -> Result<(), LockError> {
        self.dlm.release(&self.grant)
    }

    /// Try to upgrade to exclusive
    pub fn upgrade(mut self) -> Result<Self, LockError> {
        let new_grant = self.dlm.upgrade(&self.grant)?;
        self.grant = new_grant;
        Ok(self)
    }
}

#[cfg(feature = "std")]
impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = self.dlm.release(&self.grant);
    }
}

// ============================================================================
// SCOPED LOCK HELPERS
// ============================================================================

#[cfg(feature = "std")]
pub fn with_inode_lock<F, R>(
    dlm: &Arc<DistributedLockManager>,
    inode: u64,
    mode: LockMode,
    f: F,
) -> Result<R, LockError>
where
    F: FnOnce() -> R,
{
    let request = LockRequest::new(LockId::Inode(inode), mode, dlm.local_node);
    let grant = dlm.acquire(&request)?;
    let guard = LockGuard::new(Arc::clone(dlm), grant);
    let result = f();
    drop(guard);
    Ok(result)
}

#[cfg(feature = "std")]
pub fn with_range_lock<F, R>(
    dlm: &Arc<DistributedLockManager>,
    inode: u64,
    start: u64,
    end: u64,
    mode: LockMode,
    f: F,
) -> Result<R, LockError>
where
    F: FnOnce() -> R,
{
    let request = LockRequest::new(LockId::Range { inode, start, end }, mode, dlm.local_node);
    let grant = dlm.acquire(&request)?;
    let guard = LockGuard::new(Arc::clone(dlm), grant);
    let result = f();
    drop(guard);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lock_mode_compatibility() {
        assert!(LockMode::Shared.is_compatible(&LockMode::Shared));
        assert!(!LockMode::Shared.is_compatible(&LockMode::Exclusive));
        assert!(!LockMode::Exclusive.is_compatible(&LockMode::Shared));
        assert!(!LockMode::Exclusive.is_compatible(&LockMode::Exclusive));
        assert!(LockMode::IntentShared.is_compatible(&LockMode::IntentExclusive));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_local_lock_acquire_release() {
        let table = LocalLockTable::new(1);

        let req = LockRequest::new(LockId::Inode(100), LockMode::Exclusive, 1);
        let grant = table.try_acquire(&req).unwrap();

        assert_eq!(grant.mode, LockMode::Exclusive);
        assert_eq!(grant.owner, 1);

        // Can't acquire again
        let req2 = LockRequest::new(LockId::Inode(100), LockMode::Exclusive, 2);
        assert!(matches!(
            table.try_acquire(&req2),
            Err(LockError::Contention)
        ));

        // Release
        table
            .release(LockId::Inode(100), 1, grant.sequence)
            .unwrap();

        // Now can acquire
        let grant2 = table.try_acquire(&req2).unwrap();
        assert_eq!(grant2.owner, 2);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_shared_lock_multiple_holders() {
        let table = LocalLockTable::new(1);

        let req1 = LockRequest::new(LockId::Inode(100), LockMode::Shared, 1);
        let grant1 = table.try_acquire(&req1).unwrap();
        assert_eq!(grant1.mode, LockMode::Shared);

        // Second shared lock should work
        let req2 = LockRequest::new(LockId::Inode(100), LockMode::Shared, 2);
        let grant2 = table.try_acquire(&req2).unwrap();
        assert_eq!(grant2.mode, LockMode::Shared);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_dlm_acquire_timeout() {
        let dlm = DistributedLockManager::new(1);

        // Acquire exclusive lock
        let req1 = LockRequest::new(LockId::Inode(100), LockMode::Exclusive, 1);
        let _grant1 = dlm.acquire(&req1).unwrap();

        // Second acquire should timeout
        let req2 = LockRequest::new(LockId::Inode(100), LockMode::Exclusive, 2).with_timeout(100); // 100ms timeout
        let start = std::time::Instant::now();
        let result = dlm.acquire(&req2);
        assert!(matches!(result, Err(LockError::Timeout)));
        assert!(start.elapsed() >= Duration::from_millis(100));
    }
}
