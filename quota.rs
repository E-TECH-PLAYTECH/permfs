// PermFS Quotas — User/group storage limits

#![cfg(feature = "std")]

use crate::{BlockAddr, BlockDevice, ClusterTransport, FsResult, IoError, PermFs, Superblock, BLOCK_SIZE};
use std::collections::HashMap;
use std::sync::RwLock;

/// Default grace period: 7 days in nanoseconds
pub const DEFAULT_GRACE_PERIOD: u64 = 7 * 24 * 60 * 60 * 1_000_000_000;

/// Quota type: user or group
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QuotaType {
    User,
    Group,
}

/// Result of a quota check
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaCheckResult {
    /// Within limits
    Ok,
    /// Over soft limit but within grace period
    SoftLimitWarning,
    /// Over soft limit and grace period expired
    SoftLimitExceeded,
    /// Over hard limit
    HardLimitExceeded,
}

impl QuotaCheckResult {
    /// Returns true if the operation should be denied
    pub fn is_denied(&self) -> bool {
        matches!(self, QuotaCheckResult::SoftLimitExceeded | QuotaCheckResult::HardLimitExceeded)
    }
}

/// A single quota entry for a user or group
#[derive(Debug, Clone, Copy)]
pub struct QuotaEntry {
    /// User or group ID
    pub id: u32,
    /// Current block usage
    pub blocks_used: u64,
    /// Soft block limit (warning threshold)
    pub blocks_soft: u64,
    /// Hard block limit (cannot exceed)
    pub blocks_hard: u64,
    /// Current inode usage
    pub inodes_used: u64,
    /// Soft inode limit
    pub inodes_soft: u64,
    /// Hard inode limit
    pub inodes_hard: u64,
    /// Grace period duration in nanoseconds
    pub grace_period: u64,
    /// When grace period expires (0 = not in grace period)
    pub blocks_grace_expires: u64,
    /// When inode grace period expires
    pub inodes_grace_expires: u64,
}

impl Default for QuotaEntry {
    fn default() -> Self {
        Self {
            id: 0,
            blocks_used: 0,
            blocks_soft: 0, // 0 = no limit
            blocks_hard: 0,
            inodes_used: 0,
            inodes_soft: 0,
            inodes_hard: 0,
            grace_period: DEFAULT_GRACE_PERIOD,
            blocks_grace_expires: 0,
            inodes_grace_expires: 0,
        }
    }
}

impl QuotaEntry {
    /// Size of a serialized QuotaEntry
    pub const SIZE: usize = 76; // 4 + 8*9

    /// Create a new quota entry for a given ID
    pub fn new(id: u32) -> Self {
        Self {
            id,
            ..Default::default()
        }
    }

    /// Create a quota entry with limits
    pub fn with_limits(
        id: u32,
        blocks_soft: u64,
        blocks_hard: u64,
        inodes_soft: u64,
        inodes_hard: u64,
    ) -> Self {
        Self {
            id,
            blocks_soft,
            blocks_hard,
            inodes_soft,
            inodes_hard,
            ..Default::default()
        }
    }

    /// Check if blocks can be allocated
    pub fn check_blocks(&self, additional: u64, now: u64) -> QuotaCheckResult {
        let new_usage = self.blocks_used.saturating_add(additional);

        // Check hard limit first
        if self.blocks_hard > 0 && new_usage > self.blocks_hard {
            return QuotaCheckResult::HardLimitExceeded;
        }

        // Check soft limit
        if self.blocks_soft > 0 && new_usage > self.blocks_soft {
            if self.blocks_grace_expires == 0 {
                // First time exceeding soft limit - start grace period
                return QuotaCheckResult::SoftLimitWarning;
            } else if now >= self.blocks_grace_expires {
                // Grace period expired
                return QuotaCheckResult::SoftLimitExceeded;
            } else {
                // Still within grace period
                return QuotaCheckResult::SoftLimitWarning;
            }
        }

        QuotaCheckResult::Ok
    }

    /// Check if inodes can be allocated
    pub fn check_inodes(&self, additional: u64, now: u64) -> QuotaCheckResult {
        let new_usage = self.inodes_used.saturating_add(additional);

        // Check hard limit first
        if self.inodes_hard > 0 && new_usage > self.inodes_hard {
            return QuotaCheckResult::HardLimitExceeded;
        }

        // Check soft limit
        if self.inodes_soft > 0 && new_usage > self.inodes_soft {
            if self.inodes_grace_expires == 0 {
                return QuotaCheckResult::SoftLimitWarning;
            } else if now >= self.inodes_grace_expires {
                return QuotaCheckResult::SoftLimitExceeded;
            } else {
                return QuotaCheckResult::SoftLimitWarning;
            }
        }

        QuotaCheckResult::Ok
    }

    /// Add blocks to usage, updating grace period if needed
    pub fn add_blocks(&mut self, count: u64, now: u64) {
        self.blocks_used = self.blocks_used.saturating_add(count);

        // Start grace period if crossing soft limit
        if self.blocks_soft > 0
            && self.blocks_used > self.blocks_soft
            && self.blocks_grace_expires == 0
        {
            self.blocks_grace_expires = now + self.grace_period;
        }

        // Clear grace period if back under soft limit
        if self.blocks_soft == 0 || self.blocks_used <= self.blocks_soft {
            self.blocks_grace_expires = 0;
        }
    }

    /// Remove blocks from usage
    pub fn remove_blocks(&mut self, count: u64) {
        self.blocks_used = self.blocks_used.saturating_sub(count);

        // Clear grace period if back under soft limit
        if self.blocks_soft == 0 || self.blocks_used <= self.blocks_soft {
            self.blocks_grace_expires = 0;
        }
    }

    /// Add inodes to usage
    pub fn add_inodes(&mut self, count: u64, now: u64) {
        self.inodes_used = self.inodes_used.saturating_add(count);

        if self.inodes_soft > 0
            && self.inodes_used > self.inodes_soft
            && self.inodes_grace_expires == 0
        {
            self.inodes_grace_expires = now + self.grace_period;
        }

        if self.inodes_soft == 0 || self.inodes_used <= self.inodes_soft {
            self.inodes_grace_expires = 0;
        }
    }

    /// Remove inodes from usage
    pub fn remove_inodes(&mut self, count: u64) {
        self.inodes_used = self.inodes_used.saturating_sub(count);

        if self.inodes_soft == 0 || self.inodes_used <= self.inodes_soft {
            self.inodes_grace_expires = 0;
        }
    }

    /// Serialize to bytes
    pub fn serialize(&self, buf: &mut [u8]) {
        buf[0..4].copy_from_slice(&self.id.to_le_bytes());
        buf[4..12].copy_from_slice(&self.blocks_used.to_le_bytes());
        buf[12..20].copy_from_slice(&self.blocks_soft.to_le_bytes());
        buf[20..28].copy_from_slice(&self.blocks_hard.to_le_bytes());
        buf[28..36].copy_from_slice(&self.inodes_used.to_le_bytes());
        buf[36..44].copy_from_slice(&self.inodes_soft.to_le_bytes());
        buf[44..52].copy_from_slice(&self.inodes_hard.to_le_bytes());
        buf[52..60].copy_from_slice(&self.grace_period.to_le_bytes());
        buf[60..68].copy_from_slice(&self.blocks_grace_expires.to_le_bytes());
        buf[68..76].copy_from_slice(&self.inodes_grace_expires.to_le_bytes());
    }

    /// Deserialize from bytes
    pub fn deserialize(buf: &[u8]) -> Self {
        Self {
            id: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
            blocks_used: u64::from_le_bytes(buf[4..12].try_into().unwrap()),
            blocks_soft: u64::from_le_bytes(buf[12..20].try_into().unwrap()),
            blocks_hard: u64::from_le_bytes(buf[20..28].try_into().unwrap()),
            inodes_used: u64::from_le_bytes(buf[28..36].try_into().unwrap()),
            inodes_soft: u64::from_le_bytes(buf[36..44].try_into().unwrap()),
            inodes_hard: u64::from_le_bytes(buf[44..52].try_into().unwrap()),
            grace_period: u64::from_le_bytes(buf[52..60].try_into().unwrap()),
            blocks_grace_expires: u64::from_le_bytes(buf[60..68].try_into().unwrap()),
            inodes_grace_expires: u64::from_le_bytes(buf[68..76].try_into().unwrap()),
        }
    }
}

/// Header for quota block on disk
#[derive(Debug, Clone, Copy)]
struct QuotaBlockHeader {
    /// Magic number for validation
    magic: u32,
    /// Version
    version: u16,
    /// Quota type (0 = user, 1 = group)
    quota_type: u16,
    /// Number of entries in this block
    entry_count: u16,
    /// Padding
    _reserved: u16,
    /// Next quota block in chain
    next_block: BlockAddr,
}

const QUOTA_MAGIC: u32 = 0x51554F54; // "QUOT"
const QUOTA_VERSION: u16 = 1;
const QUOTA_HEADER_SIZE: usize = 40; // 4 + 2 + 2 + 2 + 2 + 32 - 4 padding = 40
const ENTRIES_PER_BLOCK: usize = (BLOCK_SIZE - QUOTA_HEADER_SIZE) / QuotaEntry::SIZE;

impl QuotaBlockHeader {
    fn serialize(&self, buf: &mut [u8]) {
        buf[0..4].copy_from_slice(&self.magic.to_le_bytes());
        buf[4..6].copy_from_slice(&self.version.to_le_bytes());
        buf[6..8].copy_from_slice(&self.quota_type.to_le_bytes());
        buf[8..10].copy_from_slice(&self.entry_count.to_le_bytes());
        buf[10..12].fill(0); // reserved
        let next_bytes = self.next_block.to_bytes();
        buf[12..44].copy_from_slice(&next_bytes[..32]);
    }

    fn deserialize(buf: &[u8]) -> Option<Self> {
        let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if magic != QUOTA_MAGIC {
            return None;
        }

        let mut next_bytes = [0u8; 32];
        next_bytes.copy_from_slice(&buf[12..44]);

        Some(Self {
            magic,
            version: u16::from_le_bytes([buf[4], buf[5]]),
            quota_type: u16::from_le_bytes([buf[6], buf[7]]),
            entry_count: u16::from_le_bytes([buf[8], buf[9]]),
            _reserved: 0,
            next_block: BlockAddr::from_bytes(&next_bytes),
        })
    }
}

/// In-memory quota table
pub struct QuotaTable {
    /// User quotas by UID
    user_quotas: RwLock<HashMap<u32, QuotaEntry>>,
    /// Group quotas by GID
    group_quotas: RwLock<HashMap<u32, QuotaEntry>>,
    /// Whether quotas are enabled
    enabled: bool,
    /// Block address of user quota data on disk
    user_quota_block: BlockAddr,
    /// Block address of group quota data on disk
    group_quota_block: BlockAddr,
    /// Dirty flag - needs to be written to disk
    dirty: RwLock<bool>,
}

impl QuotaTable {
    /// Create a new empty quota table (quotas disabled)
    pub fn new() -> Self {
        Self {
            user_quotas: RwLock::new(HashMap::new()),
            group_quotas: RwLock::new(HashMap::new()),
            enabled: false,
            user_quota_block: BlockAddr::NULL,
            group_quota_block: BlockAddr::NULL,
            dirty: RwLock::new(false),
        }
    }

    /// Create a quota table with storage locations
    pub fn with_blocks(user_block: BlockAddr, group_block: BlockAddr) -> Self {
        Self {
            user_quotas: RwLock::new(HashMap::new()),
            group_quotas: RwLock::new(HashMap::new()),
            enabled: true,
            user_quota_block: user_block,
            group_quota_block: group_block,
            dirty: RwLock::new(false),
        }
    }

    /// Check if quotas are enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable quotas
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable quotas
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Get a user quota entry (creates default if not exists)
    pub fn get_user_quota(&self, uid: u32) -> QuotaEntry {
        let quotas = self.user_quotas.read().unwrap();
        quotas.get(&uid).copied().unwrap_or_else(|| QuotaEntry::new(uid))
    }

    /// Get a group quota entry (creates default if not exists)
    pub fn get_group_quota(&self, gid: u32) -> QuotaEntry {
        let quotas = self.group_quotas.read().unwrap();
        quotas.get(&gid).copied().unwrap_or_else(|| QuotaEntry::new(gid))
    }

    /// Set user quota limits
    pub fn set_user_quota(&self, entry: QuotaEntry) {
        let mut quotas = self.user_quotas.write().unwrap();
        quotas.insert(entry.id, entry);
        *self.dirty.write().unwrap() = true;
    }

    /// Set group quota limits
    pub fn set_group_quota(&self, entry: QuotaEntry) {
        let mut quotas = self.group_quotas.write().unwrap();
        quotas.insert(entry.id, entry);
        *self.dirty.write().unwrap() = true;
    }

    /// Remove user quota
    pub fn remove_user_quota(&self, uid: u32) {
        let mut quotas = self.user_quotas.write().unwrap();
        quotas.remove(&uid);
        *self.dirty.write().unwrap() = true;
    }

    /// Remove group quota
    pub fn remove_group_quota(&self, gid: u32) {
        let mut quotas = self.group_quotas.write().unwrap();
        quotas.remove(&gid);
        *self.dirty.write().unwrap() = true;
    }

    /// Check if block allocation is allowed for user
    pub fn check_user_blocks(&self, uid: u32, additional: u64, now: u64) -> QuotaCheckResult {
        if !self.enabled {
            return QuotaCheckResult::Ok;
        }
        let quotas = self.user_quotas.read().unwrap();
        match quotas.get(&uid) {
            Some(entry) => entry.check_blocks(additional, now),
            None => QuotaCheckResult::Ok, // No quota set = unlimited
        }
    }

    /// Check if block allocation is allowed for group
    pub fn check_group_blocks(&self, gid: u32, additional: u64, now: u64) -> QuotaCheckResult {
        if !self.enabled {
            return QuotaCheckResult::Ok;
        }
        let quotas = self.group_quotas.read().unwrap();
        match quotas.get(&gid) {
            Some(entry) => entry.check_blocks(additional, now),
            None => QuotaCheckResult::Ok,
        }
    }

    /// Check if inode allocation is allowed for user
    pub fn check_user_inodes(&self, uid: u32, additional: u64, now: u64) -> QuotaCheckResult {
        if !self.enabled {
            return QuotaCheckResult::Ok;
        }
        let quotas = self.user_quotas.read().unwrap();
        match quotas.get(&uid) {
            Some(entry) => entry.check_inodes(additional, now),
            None => QuotaCheckResult::Ok,
        }
    }

    /// Check if inode allocation is allowed for group
    pub fn check_group_inodes(&self, gid: u32, additional: u64, now: u64) -> QuotaCheckResult {
        if !self.enabled {
            return QuotaCheckResult::Ok;
        }
        let quotas = self.group_quotas.read().unwrap();
        match quotas.get(&gid) {
            Some(entry) => entry.check_inodes(additional, now),
            None => QuotaCheckResult::Ok,
        }
    }

    /// Add blocks to user quota
    pub fn add_user_blocks(&self, uid: u32, count: u64, now: u64) {
        if !self.enabled {
            return;
        }
        let mut quotas = self.user_quotas.write().unwrap();
        let entry = quotas.entry(uid).or_insert_with(|| QuotaEntry::new(uid));
        entry.add_blocks(count, now);
        *self.dirty.write().unwrap() = true;
    }

    /// Add blocks to group quota
    pub fn add_group_blocks(&self, gid: u32, count: u64, now: u64) {
        if !self.enabled {
            return;
        }
        let mut quotas = self.group_quotas.write().unwrap();
        let entry = quotas.entry(gid).or_insert_with(|| QuotaEntry::new(gid));
        entry.add_blocks(count, now);
        *self.dirty.write().unwrap() = true;
    }

    /// Remove blocks from user quota
    pub fn remove_user_blocks(&self, uid: u32, count: u64) {
        if !self.enabled {
            return;
        }
        let mut quotas = self.user_quotas.write().unwrap();
        if let Some(entry) = quotas.get_mut(&uid) {
            entry.remove_blocks(count);
            *self.dirty.write().unwrap() = true;
        }
    }

    /// Remove blocks from group quota
    pub fn remove_group_blocks(&self, gid: u32, count: u64) {
        if !self.enabled {
            return;
        }
        let mut quotas = self.group_quotas.write().unwrap();
        if let Some(entry) = quotas.get_mut(&gid) {
            entry.remove_blocks(count);
            *self.dirty.write().unwrap() = true;
        }
    }

    /// Add inodes to user quota
    pub fn add_user_inodes(&self, uid: u32, count: u64, now: u64) {
        if !self.enabled {
            return;
        }
        let mut quotas = self.user_quotas.write().unwrap();
        let entry = quotas.entry(uid).or_insert_with(|| QuotaEntry::new(uid));
        entry.add_inodes(count, now);
        *self.dirty.write().unwrap() = true;
    }

    /// Add inodes to group quota
    pub fn add_group_inodes(&self, gid: u32, count: u64, now: u64) {
        if !self.enabled {
            return;
        }
        let mut quotas = self.group_quotas.write().unwrap();
        let entry = quotas.entry(gid).or_insert_with(|| QuotaEntry::new(gid));
        entry.add_inodes(count, now);
        *self.dirty.write().unwrap() = true;
    }

    /// Remove inodes from user quota
    pub fn remove_user_inodes(&self, uid: u32, count: u64) {
        if !self.enabled {
            return;
        }
        let mut quotas = self.user_quotas.write().unwrap();
        if let Some(entry) = quotas.get_mut(&uid) {
            entry.remove_inodes(count);
            *self.dirty.write().unwrap() = true;
        }
    }

    /// Remove inodes from group quota
    pub fn remove_group_inodes(&self, gid: u32, count: u64) {
        if !self.enabled {
            return;
        }
        let mut quotas = self.group_quotas.write().unwrap();
        if let Some(entry) = quotas.get_mut(&gid) {
            entry.remove_inodes(count);
            *self.dirty.write().unwrap() = true;
        }
    }

    /// Transfer blocks from one user to another (for chown)
    pub fn transfer_user_blocks(&self, from_uid: u32, to_uid: u32, count: u64, now: u64) {
        if !self.enabled {
            return;
        }
        self.remove_user_blocks(from_uid, count);
        self.add_user_blocks(to_uid, count, now);
    }

    /// Transfer blocks from one group to another (for chown)
    pub fn transfer_group_blocks(&self, from_gid: u32, to_gid: u32, count: u64, now: u64) {
        if !self.enabled {
            return;
        }
        self.remove_group_blocks(from_gid, count);
        self.add_group_blocks(to_gid, count, now);
    }

    /// Transfer inodes from one user to another
    pub fn transfer_user_inodes(&self, from_uid: u32, to_uid: u32, count: u64, now: u64) {
        if !self.enabled {
            return;
        }
        self.remove_user_inodes(from_uid, count);
        self.add_user_inodes(to_uid, count, now);
    }

    /// Transfer inodes from one group to another
    pub fn transfer_group_inodes(&self, from_gid: u32, to_gid: u32, count: u64, now: u64) {
        if !self.enabled {
            return;
        }
        self.remove_group_inodes(from_gid, count);
        self.add_group_inodes(to_gid, count, now);
    }

    /// Check if the table needs to be written to disk
    pub fn is_dirty(&self) -> bool {
        *self.dirty.read().unwrap()
    }

    /// Mark as clean after writing to disk
    pub fn mark_clean(&self) {
        *self.dirty.write().unwrap() = false;
    }

    /// List all user quotas
    pub fn list_user_quotas(&self) -> Vec<QuotaEntry> {
        let quotas = self.user_quotas.read().unwrap();
        quotas.values().copied().collect()
    }

    /// List all group quotas
    pub fn list_group_quotas(&self) -> Vec<QuotaEntry> {
        let quotas = self.group_quotas.read().unwrap();
        quotas.values().copied().collect()
    }
}

impl Default for QuotaTable {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// PermFs integration
// ============================================================================

impl<B: BlockDevice, T: ClusterTransport> PermFs<B, T> {
    /// Load quota table from disk
    pub fn load_quotas(
        &self,
        user_block: BlockAddr,
        group_block: BlockAddr,
    ) -> FsResult<QuotaTable> {
        let table = QuotaTable::with_blocks(user_block, group_block);

        // Load user quotas
        if user_block != BlockAddr::NULL {
            self.load_quota_chain(user_block, QuotaType::User, &table)?;
        }

        // Load group quotas
        if group_block != BlockAddr::NULL {
            self.load_quota_chain(group_block, QuotaType::Group, &table)?;
        }

        table.mark_clean();
        Ok(table)
    }

    /// Load a chain of quota blocks
    fn load_quota_chain(
        &self,
        start_block: BlockAddr,
        quota_type: QuotaType,
        table: &QuotaTable,
    ) -> FsResult<()> {
        let mut current = start_block;
        let mut buf = [0u8; BLOCK_SIZE];

        while current != BlockAddr::NULL {
            self.local_device.read_block(current, &mut buf)?;

            let header = QuotaBlockHeader::deserialize(&buf)
                .ok_or(IoError::ChecksumMismatch)?;

            // Verify type matches
            let expected_type = match quota_type {
                QuotaType::User => 0,
                QuotaType::Group => 1,
            };
            if header.quota_type != expected_type {
                return Err(IoError::InvalidAddress);
            }

            // Read entries
            let entry_start = QUOTA_HEADER_SIZE;
            for i in 0..header.entry_count as usize {
                let offset = entry_start + i * QuotaEntry::SIZE;
                if offset + QuotaEntry::SIZE > BLOCK_SIZE {
                    break;
                }
                let entry = QuotaEntry::deserialize(&buf[offset..]);
                match quota_type {
                    QuotaType::User => table.set_user_quota(entry),
                    QuotaType::Group => table.set_group_quota(entry),
                }
            }

            current = header.next_block;
        }

        Ok(())
    }

    /// Save quota table to disk
    pub fn save_quotas(&self, table: &QuotaTable, sb: &Superblock) -> FsResult<()> {
        if !table.is_dirty() {
            return Ok(());
        }

        // Save user quotas
        if table.user_quota_block != BlockAddr::NULL {
            let entries = table.list_user_quotas();
            self.save_quota_chain(table.user_quota_block, QuotaType::User, &entries, sb)?;
        }

        // Save group quotas
        if table.group_quota_block != BlockAddr::NULL {
            let entries = table.list_group_quotas();
            self.save_quota_chain(table.group_quota_block, QuotaType::Group, &entries, sb)?;
        }

        table.mark_clean();
        Ok(())
    }

    /// Save a list of entries to a quota block chain
    fn save_quota_chain(
        &self,
        start_block: BlockAddr,
        quota_type: QuotaType,
        entries: &[QuotaEntry],
        _sb: &Superblock,
    ) -> FsResult<()> {
        let mut buf = [0u8; BLOCK_SIZE];
        let mut current = start_block;
        let mut entry_idx = 0;

        while entry_idx < entries.len() {
            buf.fill(0);

            // Calculate how many entries fit in this block
            let entries_in_block = (entries.len() - entry_idx).min(ENTRIES_PER_BLOCK);

            // Write header
            let header = QuotaBlockHeader {
                magic: QUOTA_MAGIC,
                version: QUOTA_VERSION,
                quota_type: match quota_type {
                    QuotaType::User => 0,
                    QuotaType::Group => 1,
                },
                entry_count: entries_in_block as u16,
                _reserved: 0,
                next_block: if entry_idx + entries_in_block < entries.len() {
                    // Need another block - for now just use NULL (would need allocation)
                    BlockAddr::NULL
                } else {
                    BlockAddr::NULL
                },
            };
            header.serialize(&mut buf);

            // Write entries
            for i in 0..entries_in_block {
                let offset = QUOTA_HEADER_SIZE + i * QuotaEntry::SIZE;
                entries[entry_idx + i].serialize(&mut buf[offset..]);
            }

            self.local_device.write_block(current, &buf)?;

            entry_idx += entries_in_block;
            current = header.next_block;

            // If we need more blocks but have no chain, stop
            if current == BlockAddr::NULL && entry_idx < entries.len() {
                // TODO: Allocate additional blocks for overflow
                break;
            }
        }

        Ok(())
    }

    /// Check if a block allocation is allowed by quotas
    pub fn check_quota_blocks(
        &self,
        quotas: &QuotaTable,
        uid: u32,
        gid: u32,
        additional: u64,
    ) -> QuotaCheckResult {
        let now = self.current_time();

        // Check user quota
        let user_result = quotas.check_user_blocks(uid, additional, now);
        if user_result.is_denied() {
            return user_result;
        }

        // Check group quota
        let group_result = quotas.check_group_blocks(gid, additional, now);
        if group_result.is_denied() {
            return group_result;
        }

        // Return the "worst" warning
        match (user_result, group_result) {
            (QuotaCheckResult::SoftLimitWarning, _) => QuotaCheckResult::SoftLimitWarning,
            (_, QuotaCheckResult::SoftLimitWarning) => QuotaCheckResult::SoftLimitWarning,
            _ => QuotaCheckResult::Ok,
        }
    }

    /// Check if an inode allocation is allowed by quotas
    pub fn check_quota_inodes(
        &self,
        quotas: &QuotaTable,
        uid: u32,
        gid: u32,
        additional: u64,
    ) -> QuotaCheckResult {
        let now = self.current_time();

        let user_result = quotas.check_user_inodes(uid, additional, now);
        if user_result.is_denied() {
            return user_result;
        }

        let group_result = quotas.check_group_inodes(gid, additional, now);
        if group_result.is_denied() {
            return group_result;
        }

        match (user_result, group_result) {
            (QuotaCheckResult::SoftLimitWarning, _) => QuotaCheckResult::SoftLimitWarning,
            (_, QuotaCheckResult::SoftLimitWarning) => QuotaCheckResult::SoftLimitWarning,
            _ => QuotaCheckResult::Ok,
        }
    }

    /// Update quotas after block allocation
    pub fn update_quota_blocks_add(&self, quotas: &QuotaTable, uid: u32, gid: u32, count: u64) {
        let now = self.current_time();
        quotas.add_user_blocks(uid, count, now);
        quotas.add_group_blocks(gid, count, now);
    }

    /// Update quotas after block deallocation
    pub fn update_quota_blocks_remove(&self, quotas: &QuotaTable, uid: u32, gid: u32, count: u64) {
        quotas.remove_user_blocks(uid, count);
        quotas.remove_group_blocks(gid, count);
    }

    /// Update quotas after inode creation
    pub fn update_quota_inodes_add(&self, quotas: &QuotaTable, uid: u32, gid: u32, count: u64) {
        let now = self.current_time();
        quotas.add_user_inodes(uid, count, now);
        quotas.add_group_inodes(gid, count, now);
    }

    /// Update quotas after inode deletion
    pub fn update_quota_inodes_remove(&self, quotas: &QuotaTable, uid: u32, gid: u32, count: u64) {
        quotas.remove_user_inodes(uid, count);
        quotas.remove_group_inodes(gid, count);
    }

    /// Handle ownership change (chown) for quotas
    pub fn update_quota_chown(
        &self,
        quotas: &QuotaTable,
        old_uid: u32,
        old_gid: u32,
        new_uid: u32,
        new_gid: u32,
        blocks: u64,
    ) {
        let now = self.current_time();

        // Transfer blocks
        if old_uid != new_uid {
            quotas.transfer_user_blocks(old_uid, new_uid, blocks, now);
            quotas.transfer_user_inodes(old_uid, new_uid, 1, now);
        }

        if old_gid != new_gid {
            quotas.transfer_group_blocks(old_gid, new_gid, blocks, now);
            quotas.transfer_group_inodes(old_gid, new_gid, 1, now);
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quota_entry_basic() {
        let mut entry = QuotaEntry::with_limits(1000, 100, 200, 10, 20);

        assert_eq!(entry.check_blocks(50, 0), QuotaCheckResult::Ok);
        assert_eq!(entry.check_blocks(150, 0), QuotaCheckResult::SoftLimitWarning);
        assert_eq!(entry.check_blocks(250, 0), QuotaCheckResult::HardLimitExceeded);

        entry.add_blocks(50, 0);
        assert_eq!(entry.blocks_used, 50);
    }

    #[test]
    fn test_quota_entry_grace_period() {
        let mut entry = QuotaEntry::with_limits(1000, 100, 200, 10, 20);
        entry.grace_period = 1000; // 1000ns for testing

        // Add blocks to exceed soft limit
        entry.add_blocks(150, 100);
        assert!(entry.blocks_grace_expires > 0);
        assert_eq!(entry.blocks_grace_expires, 1100); // 100 + 1000

        // Within grace period
        assert_eq!(entry.check_blocks(10, 500), QuotaCheckResult::SoftLimitWarning);

        // Grace period expired
        assert_eq!(entry.check_blocks(10, 1200), QuotaCheckResult::SoftLimitExceeded);
    }

    #[test]
    fn test_quota_entry_serialization() {
        let entry = QuotaEntry::with_limits(1000, 100, 200, 10, 20);
        let mut buf = [0u8; QuotaEntry::SIZE];
        entry.serialize(&mut buf);

        let restored = QuotaEntry::deserialize(&buf);
        assert_eq!(restored.id, entry.id);
        assert_eq!(restored.blocks_soft, entry.blocks_soft);
        assert_eq!(restored.blocks_hard, entry.blocks_hard);
        assert_eq!(restored.inodes_soft, entry.inodes_soft);
        assert_eq!(restored.inodes_hard, entry.inodes_hard);
    }

    #[test]
    fn test_quota_table_basic() {
        let mut table = QuotaTable::new();
        table.enable();

        let entry = QuotaEntry::with_limits(1000, 100, 200, 10, 20);
        table.set_user_quota(entry);

        let retrieved = table.get_user_quota(1000);
        assert_eq!(retrieved.blocks_soft, 100);
        assert_eq!(retrieved.blocks_hard, 200);

        // Unknown user should get default (no limits)
        let unknown = table.get_user_quota(9999);
        assert_eq!(unknown.blocks_soft, 0);
        assert_eq!(unknown.blocks_hard, 0);
    }

    #[test]
    fn test_quota_table_check() {
        let mut table = QuotaTable::new();
        table.enable();

        let entry = QuotaEntry::with_limits(1000, 100, 200, 10, 20);
        table.set_user_quota(entry);

        assert_eq!(table.check_user_blocks(1000, 50, 0), QuotaCheckResult::Ok);
        assert_eq!(table.check_user_blocks(1000, 150, 0), QuotaCheckResult::SoftLimitWarning);
        assert_eq!(table.check_user_blocks(1000, 250, 0), QuotaCheckResult::HardLimitExceeded);

        // User without quota = unlimited
        assert_eq!(table.check_user_blocks(9999, 999999, 0), QuotaCheckResult::Ok);
    }

    #[test]
    fn test_quota_disabled() {
        let table = QuotaTable::new();
        // Quotas disabled by default

        let entry = QuotaEntry::with_limits(1000, 100, 200, 10, 20);
        table.set_user_quota(entry);

        // Even with limits set, disabled quotas always return Ok
        assert_eq!(table.check_user_blocks(1000, 999999, 0), QuotaCheckResult::Ok);
    }

    #[test]
    fn test_quota_transfer() {
        let mut table = QuotaTable::new();
        table.enable();

        // Set up user quotas
        table.add_user_blocks(1000, 100, 0);
        table.add_user_blocks(2000, 50, 0);

        // Transfer blocks
        table.transfer_user_blocks(1000, 2000, 30, 0);

        let user1 = table.get_user_quota(1000);
        let user2 = table.get_user_quota(2000);
        assert_eq!(user1.blocks_used, 70);
        assert_eq!(user2.blocks_used, 80);
    }
}
