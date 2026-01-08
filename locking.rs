// PermFS File Locking — POSIX advisory locks

#![cfg(feature = "std")]

use crate::sync::Mutex;
use std::collections::HashMap;

/// Lock type matching POSIX fcntl semantics
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockType {
    /// Shared (read) lock - F_RDLCK
    Read,
    /// Exclusive (write) lock - F_WRLCK
    Write,
    /// Unlock - F_UNLCK
    Unlock,
}

impl LockType {
    /// Convert from libc constants
    pub fn from_libc(typ: i32) -> Option<Self> {
        match typ as i16 {
            libc::F_RDLCK => Some(LockType::Read),
            libc::F_WRLCK => Some(LockType::Write),
            libc::F_UNLCK => Some(LockType::Unlock),
            _ => None,
        }
    }

    /// Convert to libc constant
    pub fn to_libc(self) -> i32 {
        match self {
            LockType::Read => libc::F_RDLCK as i32,
            LockType::Write => libc::F_WRLCK as i32,
            LockType::Unlock => libc::F_UNLCK as i32,
        }
    }
}

/// A file lock representing a byte range
#[derive(Debug, Clone)]
pub struct FileLock {
    /// Lock owner (typically pid or unique handle)
    pub owner: u64,
    /// Starting byte offset
    pub start: u64,
    /// Length in bytes (0 means to end of file)
    pub len: u64,
    /// Type of lock
    pub lock_type: LockType,
}

impl FileLock {
    /// Create a new file lock
    pub fn new(owner: u64, start: u64, len: u64, lock_type: LockType) -> Self {
        Self {
            owner,
            start,
            len,
            lock_type,
        }
    }

    /// Get the end offset (exclusive), or u64::MAX if len is 0 (to EOF)
    pub fn end(&self) -> u64 {
        if self.len == 0 {
            u64::MAX
        } else {
            self.start.saturating_add(self.len)
        }
    }

    /// Check if this lock overlaps with another range
    pub fn overlaps(&self, start: u64, end: u64) -> bool {
        let self_end = self.end();
        // Ranges overlap if neither is entirely before the other
        self.start < end && start < self_end
    }

    /// Check if this lock conflicts with a proposed lock
    /// Two locks conflict if they overlap and at least one is a write lock
    pub fn conflicts_with(&self, other: &FileLock) -> bool {
        // Same owner never conflicts with itself
        if self.owner == other.owner {
            return false;
        }

        // Must overlap to conflict
        if !self.overlaps(other.start, other.end()) {
            return false;
        }

        // Read locks don't conflict with each other
        matches!(
            (self.lock_type, other.lock_type),
            (LockType::Write, _) | (_, LockType::Write)
        )
    }
}

/// Result of a lock operation
#[derive(Debug)]
pub enum LockResult {
    /// Lock was acquired successfully
    Acquired,
    /// Lock would block - contains the conflicting lock
    WouldBlock(FileLock),
    /// Lock was released
    Released,
}

/// Per-inode lock list
#[derive(Debug, Default)]
struct InodeLocks {
    locks: Vec<FileLock>,
}

impl InodeLocks {
    /// Find a conflicting lock for the proposed lock
    fn find_conflict(&self, proposed: &FileLock) -> Option<&FileLock> {
        self.locks.iter().find(|existing| existing.conflicts_with(proposed))
    }

    /// Add a lock, merging/splitting existing locks from the same owner as needed
    fn add_lock(&mut self, lock: FileLock) {
        // Remove any existing locks from this owner that overlap
        self.remove_owner_range(lock.owner, lock.start, lock.end());

        // Add the new lock if it's not an unlock
        if lock.lock_type != LockType::Unlock {
            self.locks.push(lock);
        }
    }

    /// Remove locks from owner in the given range
    fn remove_owner_range(&mut self, owner: u64, start: u64, end: u64) {
        let mut i = 0;
        while i < self.locks.len() {
            let existing = &self.locks[i];
            if existing.owner != owner {
                i += 1;
                continue;
            }

            let ex_start = existing.start;
            let ex_end = existing.end();
            let ex_type = existing.lock_type;

            // Check if ranges overlap
            if ex_start >= end || start >= ex_end {
                // No overlap
                i += 1;
                continue;
            }

            // Remove the existing lock
            self.locks.remove(i);

            // Add back any portions outside the removed range
            if ex_start < start {
                // Keep the portion before the removed range
                self.locks.push(FileLock {
                    owner,
                    start: ex_start,
                    len: start - ex_start,
                    lock_type: ex_type,
                });
            }
            if ex_end > end && end != u64::MAX {
                // Keep the portion after the removed range
                let new_len = if ex_end == u64::MAX { 0 } else { ex_end - end };
                self.locks.push(FileLock {
                    owner,
                    start: end,
                    len: new_len,
                    lock_type: ex_type,
                });
            }
            // Don't increment i since we removed an element
        }
    }

    /// Remove all locks owned by the given owner
    fn remove_owner(&mut self, owner: u64) {
        self.locks.retain(|lock| lock.owner != owner);
    }

    /// Check if there are any locks remaining
    fn is_empty(&self) -> bool {
        self.locks.is_empty()
    }
}

/// Lock table managing all file locks
pub struct LockTable {
    /// Map from inode number to lock list
    locks: Mutex<HashMap<u64, InodeLocks>>,
}

impl Default for LockTable {
    fn default() -> Self {
        Self::new()
    }
}

impl LockTable {
    /// Create a new empty lock table
    pub fn new() -> Self {
        Self {
            locks: Mutex::new(HashMap::new()),
        }
    }

    /// Test if a lock would conflict (F_GETLK)
    /// Returns the conflicting lock if one exists, None otherwise
    pub fn test_lock(&self, ino: u64, lock: &FileLock) -> Option<FileLock> {
        let table = self.locks.lock().unwrap();
        if let Some(inode_locks) = table.get(&ino) {
            inode_locks.find_conflict(lock).cloned()
        } else {
            None
        }
    }

    /// Try to acquire a lock (F_SETLK - non-blocking)
    pub fn try_lock(&self, ino: u64, lock: FileLock) -> LockResult {
        let mut table = self.locks.lock().unwrap();
        let inode_locks = table.entry(ino).or_default();

        // Check for conflicts
        if let Some(conflict) = inode_locks.find_conflict(&lock) {
            return LockResult::WouldBlock(conflict.clone());
        }

        // Handle unlock
        if lock.lock_type == LockType::Unlock {
            inode_locks.remove_owner_range(lock.owner, lock.start, lock.end());
            if inode_locks.is_empty() {
                table.remove(&ino);
            }
            return LockResult::Released;
        }

        // Add the lock
        inode_locks.add_lock(lock);
        LockResult::Acquired
    }

    /// Release all locks held by an owner on an inode
    pub fn release_owner(&self, ino: u64, owner: u64) {
        let mut table = self.locks.lock().unwrap();
        if let Some(inode_locks) = table.get_mut(&ino) {
            inode_locks.remove_owner(owner);
            if inode_locks.is_empty() {
                table.remove(&ino);
            }
        }
    }

    /// Release all locks held by an owner across all inodes
    pub fn release_all_owner(&self, owner: u64) {
        let mut table = self.locks.lock().unwrap();
        let mut empty_inodes = Vec::new();

        for (ino, inode_locks) in table.iter_mut() {
            inode_locks.remove_owner(owner);
            if inode_locks.is_empty() {
                empty_inodes.push(*ino);
            }
        }

        for ino in empty_inodes {
            table.remove(&ino);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lock_overlap() {
        let lock = FileLock::new(1, 100, 50, LockType::Write);

        // Overlapping ranges
        assert!(lock.overlaps(50, 150));   // Overlaps at start
        assert!(lock.overlaps(120, 200));  // Overlaps at end
        assert!(lock.overlaps(110, 130));  // Contained within
        assert!(lock.overlaps(0, 200));    // Contains lock

        // Non-overlapping ranges
        assert!(!lock.overlaps(0, 100));   // Adjacent before
        assert!(!lock.overlaps(150, 200)); // Adjacent after
        assert!(!lock.overlaps(200, 300)); // Far after
    }

    #[test]
    fn test_lock_conflict() {
        let write_lock = FileLock::new(1, 100, 50, LockType::Write);
        let read_lock = FileLock::new(1, 100, 50, LockType::Read);
        let other_write = FileLock::new(2, 120, 20, LockType::Write);
        let other_read = FileLock::new(2, 120, 20, LockType::Read);

        // Same owner never conflicts
        let same_owner = FileLock::new(1, 100, 50, LockType::Write);
        assert!(!write_lock.conflicts_with(&same_owner));

        // Write conflicts with anything from different owner
        assert!(write_lock.conflicts_with(&other_write));
        assert!(write_lock.conflicts_with(&other_read));

        // Read doesn't conflict with read from different owner
        assert!(!read_lock.conflicts_with(&other_read));

        // Read conflicts with write from different owner
        assert!(read_lock.conflicts_with(&other_write));
    }

    #[test]
    fn test_lock_table_basic() {
        let table = LockTable::new();

        let lock1 = FileLock::new(1, 0, 100, LockType::Write);
        let lock2 = FileLock::new(2, 50, 100, LockType::Read);

        // First lock should succeed
        assert!(matches!(table.try_lock(1, lock1.clone()), LockResult::Acquired));

        // Conflicting lock should fail
        assert!(matches!(table.try_lock(1, lock2), LockResult::WouldBlock(_)));

        // Test lock should find conflict
        let test = FileLock::new(2, 50, 50, LockType::Write);
        assert!(table.test_lock(1, &test).is_some());

        // Release and retry
        table.release_owner(1, 1);
        let lock3 = FileLock::new(2, 0, 100, LockType::Write);
        assert!(matches!(table.try_lock(1, lock3), LockResult::Acquired));
    }

    #[test]
    fn test_multiple_read_locks() {
        let table = LockTable::new();

        let read1 = FileLock::new(1, 0, 100, LockType::Read);
        let read2 = FileLock::new(2, 0, 100, LockType::Read);
        let read3 = FileLock::new(3, 50, 50, LockType::Read);

        // Multiple read locks should all succeed
        assert!(matches!(table.try_lock(1, read1), LockResult::Acquired));
        assert!(matches!(table.try_lock(1, read2), LockResult::Acquired));
        assert!(matches!(table.try_lock(1, read3), LockResult::Acquired));

        // Write lock should fail while reads are held
        let write = FileLock::new(4, 50, 50, LockType::Write);
        assert!(matches!(table.try_lock(1, write), LockResult::WouldBlock(_)));
    }

    #[test]
    fn test_unlock() {
        let table = LockTable::new();

        let lock = FileLock::new(1, 0, 100, LockType::Write);
        assert!(matches!(table.try_lock(1, lock), LockResult::Acquired));

        // Unlock
        let unlock = FileLock::new(1, 0, 100, LockType::Unlock);
        assert!(matches!(table.try_lock(1, unlock), LockResult::Released));

        // Now another process can lock
        let lock2 = FileLock::new(2, 0, 100, LockType::Write);
        assert!(matches!(table.try_lock(1, lock2), LockResult::Acquired));
    }

    #[test]
    fn test_partial_unlock() {
        let table = LockTable::new();

        // Lock range 0-100
        let lock = FileLock::new(1, 0, 100, LockType::Write);
        assert!(matches!(table.try_lock(1, lock), LockResult::Acquired));

        // Unlock middle portion 30-70
        let unlock = FileLock::new(1, 30, 40, LockType::Unlock);
        assert!(matches!(table.try_lock(1, unlock), LockResult::Released));

        // Another process can now lock 30-70
        let lock2 = FileLock::new(2, 30, 40, LockType::Write);
        assert!(matches!(table.try_lock(1, lock2), LockResult::Acquired));

        // But not 0-30 or 70-100
        let lock3 = FileLock::new(3, 0, 30, LockType::Write);
        assert!(matches!(table.try_lock(1, lock3), LockResult::WouldBlock(_)));
    }
}
