// PermFS — Permutation-addressed Distributed Filesystem Protocol
// A practical distributed filesystem using 256-bit global block addressing
// Designed for cluster-scale storage with local-first allocation

#![cfg_attr(not(feature = "std"), no_std)]
#![allow(unused_unsafe)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, string::String, vec::Vec};
#[cfg(feature = "std")]
use std::{boxed::Box, string::String, vec::Vec};

use core::ptr::NonNull;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

// ============================================================================
// MODULE DECLARATIONS
// ============================================================================

pub mod checksum;
pub mod dir;
pub mod dlm;
pub mod extent;
pub mod journal;
pub mod mkfs;
pub mod ops;
pub mod os_porting;
pub mod time;
pub mod write;

#[cfg(feature = "fuse")]
pub mod fuse;
#[cfg(feature = "std")]
pub mod mock;
#[cfg(feature = "network")]
pub mod transport;
#[cfg(feature = "std")]
pub mod vfs;

// Re-exports
pub use checksum::{compute_inode_checksum, compute_superblock_checksum, crc32c, verify_checksum};
pub use time::Clock;

// ============================================================================
// 256-BIT BLOCK ADDRESSING
// ============================================================================

/// 256-bit block address: supports 2^256 unique blocks across the cluster
/// Layout: [block_offset:64][shard|volume:64][node_id:64][reserved:64]
#[derive(Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct BlockAddr {
    pub limbs: [u64; 4],
}

impl core::fmt::Debug for BlockAddr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "BlockAddr(node={}, vol={}, shard={}, off={})",
            self.node_id(),
            self.volume_id(),
            self.shard_id(),
            self.block_offset()
        )
    }
}

impl core::hash::Hash for BlockAddr {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.limbs.hash(state);
    }
}

impl BlockAddr {
    pub const NULL: Self = Self { limbs: [0; 4] };
    pub const MAX: Self = Self {
        limbs: [u64::MAX; 4],
    };

    #[inline]
    pub const fn new(node: u64, volume: u32, shard: u16, offset: u64) -> Self {
        Self {
            limbs: [
                offset,                                   // low 64 bits: block offset
                ((shard as u64) << 48) | (volume as u64), // shard + volume
                node,                                     // node id
                0,                                        // reserved/checksum
            ],
        }
    }

    #[inline]
    pub const fn node_id(&self) -> u64 {
        self.limbs[2]
    }
    #[inline]
    pub const fn volume_id(&self) -> u32 {
        self.limbs[1] as u32
    }
    #[inline]
    pub const fn shard_id(&self) -> u16 {
        (self.limbs[1] >> 48) as u16
    }
    #[inline]
    pub const fn block_offset(&self) -> u64 {
        self.limbs[0]
    }

    #[inline]
    pub fn is_null(&self) -> bool {
        *self == Self::NULL
    }

    #[inline]
    pub fn is_local(&self, local_node: u64) -> bool {
        self.node_id() == local_node
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut buf = [0u8; 32];
        buf[0..8].copy_from_slice(&self.limbs[0].to_le_bytes());
        buf[8..16].copy_from_slice(&self.limbs[1].to_le_bytes());
        buf[16..24].copy_from_slice(&self.limbs[2].to_le_bytes());
        buf[24..32].copy_from_slice(&self.limbs[3].to_le_bytes());
        buf
    }

    /// Deserialize from bytes
    pub fn from_bytes(buf: &[u8; 32]) -> Self {
        Self {
            limbs: [
                u64::from_le_bytes(buf[0..8].try_into().unwrap()),
                u64::from_le_bytes(buf[8..16].try_into().unwrap()),
                u64::from_le_bytes(buf[16..24].try_into().unwrap()),
                u64::from_le_bytes(buf[24..32].try_into().unwrap()),
            ],
        }
    }
}

// ============================================================================
// FILESYSTEM CONSTANTS
// ============================================================================

pub const BLOCK_SIZE: usize = 4096; // 4 KiB blocks
pub const BLOCKS_PER_SHARD: u64 = 1 << 20; // 1M blocks per shard = 4 GiB
pub const SHARDS_PER_VOLUME: u16 = 256; // 256 shards = 1 TiB per volume
pub const MAX_VOLUMES_PER_NODE: u32 = 4096; // 4 PiB max per node
pub const MAX_FILENAME_LEN: usize = 255;
pub const INODE_DIRECT_BLOCKS: usize = 12;
pub const INODE_INDIRECT_LEVELS: usize = 3;
pub const SUPERBLOCK_MAGIC: u64 = 0x5045524D_46530001; // "PERMFS\x00\x01"

// ============================================================================
// BLOCK TYPES
// ============================================================================

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BlockType {
    Free = 0,
    Superblock = 1,
    InodeTable = 2,
    InodeData = 3,
    Directory = 4,
    FileData = 5,
    IndirectPtr = 6,
    ExtentTree = 7,
    Journal = 8,
    Bitmap = 9,
}

// ============================================================================
// INODE STRUCTURE
// ============================================================================

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Inode {
    pub mode: u32, // file type + permissions
    pub uid: u32,
    pub gid: u32,
    pub flags: u32,
    pub size: u64,                                    // file size in bytes
    pub blocks: u64,                                  // allocated blocks count
    pub atime: u64,                                   // access time (ns since epoch)
    pub mtime: u64,                                   // modify time
    pub ctime: u64,                                   // change time
    pub crtime: u64,                                  // creation time
    pub nlink: u32,                                   // hard link count
    pub generation: u32,                              // inode generation (for NFS)
    pub direct: [BlockAddr; INODE_DIRECT_BLOCKS],     // direct block pointers
    pub indirect: [BlockAddr; INODE_INDIRECT_LEVELS], // single/double/triple indirect
    pub extent_root: BlockAddr,                       // extent tree root (alternative)
    pub xattr_block: BlockAddr,                       // extended attributes
    pub checksum: u64,
}

impl Inode {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    pub fn is_dir(&self) -> bool {
        (self.mode & 0o170000) == 0o040000
    }
    pub fn is_file(&self) -> bool {
        (self.mode & 0o170000) == 0o100000
    }
    pub fn is_symlink(&self) -> bool {
        (self.mode & 0o170000) == 0o120000
    }

    /// Compute and update checksum
    pub fn update_checksum(&mut self) {
        self.checksum = compute_inode_checksum(self);
    }

    /// Verify checksum
    pub fn verify_checksum(&self) -> bool {
        let expected = compute_inode_checksum(self);
        self.checksum == expected
    }
}

// ============================================================================
// DIRECTORY ENTRY
// ============================================================================

#[repr(C)]
pub struct DirEntry {
    pub inode: u64,    // inode number
    pub rec_len: u16,  // total entry length
    pub name_len: u8,  // filename length
    pub file_type: u8, // file type (cached)
    pub name: [u8; MAX_FILENAME_LEN],
}

// ============================================================================
// SUPERBLOCK
// ============================================================================

#[repr(C)]
pub struct Superblock {
    pub magic: u64, // 0x5045524D_46530001 ("PERMFS\x00\x01")
    pub version: u32,
    pub block_size: u32,
    pub total_blocks: u64,
    pub free_blocks: AtomicU64,
    pub total_inodes: u64,
    pub free_inodes: AtomicU64,
    pub node_id: u64,
    pub volume_id: u32,
    pub flags: u32,
    pub uuid: [u8; 16],
    pub volume_name: [u8; 64],
    pub mount_count: u32,
    pub max_mount_count: u32,
    pub state: u16, // clean/error
    pub errors_behavior: u16,
    pub first_inode_table: BlockAddr,
    pub journal_start: BlockAddr,
    pub root_inode: u64,
    pub checksum: u64,
}

impl Superblock {
    /// Update checksum
    pub fn update_checksum(&mut self) {
        self.checksum = compute_superblock_checksum(self);
    }

    /// Verify checksum
    pub fn verify_checksum(&self) -> bool {
        let expected = compute_superblock_checksum(self);
        self.checksum == expected
    }
}

// ============================================================================
// ERROR TYPES
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocError {
    NoSpace,
    DoubleFree,
    OutOfBounds,
    InvalidShard,
    WrongVolume,
    NetworkError,
    RemoteNodeDown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoError {
    NotFound,
    PermissionDenied,
    IoFailed,
    Corrupted,
    NetworkTimeout,
    InvalidAddress,
    ChecksumMismatch,
    LockContention,
    ReadOnly,
}

/// Filesystem operation result
pub type FsResult<T> = Result<T, IoError>;

// ============================================================================
// SHARD-BASED BLOCK ALLOCATOR
// ============================================================================

/// Per-shard allocation state — lock-free local allocation
pub struct ShardAllocator {
    shard_id: u16,
    /// Bitmap: 1 bit per block, 1M blocks = 128 KiB bitmap
    bitmap: NonNull<AtomicU64>,
    bitmap_words: usize,
    /// Hint for next free block search
    next_hint: AtomicU64,
    /// Free block count for this shard
    free_count: AtomicU64,
    /// Generation counter for ABA prevention
    generation: AtomicU32,
}

// Safety: bitmap is internally synchronized with atomics
unsafe impl Send for ShardAllocator {}
unsafe impl Sync for ShardAllocator {}

impl ShardAllocator {
    /// Allocate a block from this shard — lock-free
    pub fn alloc(&self) -> Option<u64> {
        let hint = self.next_hint.load(Ordering::Relaxed) as usize;

        // Bounded search: wrap around once
        for attempt in 0..(self.bitmap_words * 2) {
            let word_idx = (hint + attempt) % self.bitmap_words;
            let word = unsafe { &*self.bitmap.as_ptr().add(word_idx) };

            let mut current = word.load(Ordering::Relaxed);

            // Find first zero bit
            while current != u64::MAX {
                let bit = (!current).trailing_zeros() as u64;
                let mask = 1u64 << bit;

                // Try to claim it
                match word.compare_exchange_weak(
                    current,
                    current | mask,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        self.free_count.fetch_sub(1, Ordering::Relaxed);
                        let block = (word_idx as u64) * 64 + bit;
                        // Update hint for next allocation
                        self.next_hint.store(word_idx as u64, Ordering::Relaxed);
                        return Some(block);
                    }
                    Err(new) => current = new,
                }
            }
        }

        None // Shard exhausted
    }

    /// Free a block — lock-free
    pub fn free(&self, block_offset: u64) -> Result<(), AllocError> {
        let word_idx = (block_offset / 64) as usize;
        let bit = block_offset % 64;
        let mask = 1u64 << bit;

        if word_idx >= self.bitmap_words {
            return Err(AllocError::OutOfBounds);
        }

        let word = unsafe { &*self.bitmap.as_ptr().add(word_idx) };
        let prev = word.fetch_and(!mask, Ordering::AcqRel);

        if prev & mask == 0 {
            return Err(AllocError::DoubleFree);
        }

        self.free_count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    pub fn free_blocks(&self) -> u64 {
        self.free_count.load(Ordering::Relaxed)
    }
}

// ============================================================================
// VOLUME ALLOCATOR
// ============================================================================

/// Volume-level allocator: manages multiple shards
pub struct VolumeAllocator {
    node_id: u64,
    volume_id: u32,
    shards: [Option<Box<ShardAllocator>>; SHARDS_PER_VOLUME as usize],
    /// Current shard for round-robin allocation
    current_shard: AtomicU32,
}

impl VolumeAllocator {
    /// Allocate a block, trying local shards first
    pub fn alloc_block(&self) -> Result<BlockAddr, AllocError> {
        let start_shard = self.current_shard.fetch_add(1, Ordering::Relaxed) as u16;

        // Try all shards starting from current
        for i in 0..SHARDS_PER_VOLUME {
            let shard_id = (start_shard.wrapping_add(i)) % SHARDS_PER_VOLUME;

            if let Some(ref shard) = self.shards[shard_id as usize] {
                if let Some(offset) = shard.alloc() {
                    return Ok(BlockAddr::new(
                        self.node_id,
                        self.volume_id,
                        shard_id,
                        offset,
                    ));
                }
            }
        }

        Err(AllocError::NoSpace)
    }

    /// Free a block
    pub fn free_block(&self, addr: BlockAddr) -> Result<(), AllocError> {
        if addr.node_id() != self.node_id || addr.volume_id() != self.volume_id {
            return Err(AllocError::WrongVolume);
        }

        let shard_id = addr.shard_id() as usize;
        match &self.shards[shard_id] {
            Some(shard) => shard.free(addr.block_offset()),
            None => Err(AllocError::InvalidShard),
        }
    }

    pub fn total_free_blocks(&self) -> u64 {
        self.shards
            .iter()
            .filter_map(|s| s.as_ref())
            .map(|s| s.free_blocks())
            .sum()
    }
}

// ============================================================================
// BLOCK I/O TRAITS
// ============================================================================

/// Block I/O operations — trait for storage backends
pub trait BlockDevice: Send + Sync {
    fn read_block(&self, addr: BlockAddr, buf: &mut [u8; BLOCK_SIZE]) -> FsResult<()>;
    fn write_block(&self, addr: BlockAddr, buf: &[u8; BLOCK_SIZE]) -> FsResult<()>;
    fn sync(&self) -> FsResult<()>;
    fn trim(&self, addr: BlockAddr) -> FsResult<()>;
}

/// Network transport for remote block access
pub trait ClusterTransport: Send + Sync {
    fn read_remote(&self, node: u64, addr: BlockAddr, buf: &mut [u8; BLOCK_SIZE]) -> FsResult<()>;
    fn write_remote(&self, node: u64, addr: BlockAddr, buf: &[u8; BLOCK_SIZE]) -> FsResult<()>;
    fn alloc_remote(&self, node: u64, volume: u32) -> Result<BlockAddr, AllocError>;
    fn free_remote(&self, node: u64, addr: BlockAddr) -> Result<(), AllocError>;
}

// ============================================================================
// FILESYSTEM CONTEXT
// ============================================================================

/// PermFS filesystem instance
pub struct PermFs<B: BlockDevice, T: ClusterTransport> {
    pub node_id: u64,
    pub volumes: [Option<Box<VolumeAllocator>>; MAX_VOLUMES_PER_NODE as usize],
    pub local_device: B,
    pub cluster: T,
    pub mounted: AtomicU32,
    clock: time::SystemClock,
    verify_checksums: bool,
}

impl<B: BlockDevice, T: ClusterTransport> PermFs<B, T> {
    /// Create a new filesystem instance
    pub fn new(node_id: u64, device: B, transport: T) -> Self {
        Self {
            node_id,
            volumes: core::array::from_fn(|_| None),
            local_device: device,
            cluster: transport,
            mounted: AtomicU32::new(0),
            clock: time::SystemClock::new(),
            verify_checksums: true,
        }
    }

    /// Get current time in nanoseconds since epoch
    pub fn current_time(&self) -> u64 {
        self.clock.now_ns()
    }

    /// Enable or disable checksum verification
    pub fn set_verify_checksums(&mut self, enabled: bool) {
        self.verify_checksums = enabled;
    }
}

impl<B: BlockDevice, T: ClusterTransport> PermFs<B, T> {
    /// Read a block, handling local vs remote transparently
    pub fn read_block(&self, addr: BlockAddr, buf: &mut [u8; BLOCK_SIZE]) -> FsResult<()> {
        if addr.is_null() {
            return Err(IoError::InvalidAddress);
        }

        if addr.is_local(self.node_id) {
            self.local_device.read_block(addr, buf)
        } else {
            self.cluster.read_remote(addr.node_id(), addr, buf)
        }
    }

    /// Write a block, handling local vs remote transparently
    pub fn write_block(&self, addr: BlockAddr, buf: &[u8; BLOCK_SIZE]) -> FsResult<()> {
        if addr.is_null() {
            return Err(IoError::InvalidAddress);
        }

        if addr.is_local(self.node_id) {
            self.local_device.write_block(addr, buf)
        } else {
            self.cluster.write_remote(addr.node_id(), addr, buf)
        }
    }

    /// Allocate a block, preferring local then remote
    pub fn alloc_block(&self, preferred_volume: Option<u32>) -> Result<BlockAddr, AllocError> {
        // Try local volumes first
        let start = preferred_volume.unwrap_or(0) as usize;
        for i in 0..MAX_VOLUMES_PER_NODE as usize {
            let idx = (start + i) % MAX_VOLUMES_PER_NODE as usize;
            if let Some(ref vol) = self.volumes[idx] {
                if let Ok(addr) = vol.alloc_block() {
                    return Ok(addr);
                }
            }
        }

        Err(AllocError::NoSpace)
    }

    /// Free a block
    pub fn free_block(&self, addr: BlockAddr) -> Result<(), AllocError> {
        if addr.is_local(self.node_id) {
            let vol_id = addr.volume_id() as usize;
            match &self.volumes[vol_id] {
                Some(vol) => vol.free_block(addr),
                None => Err(AllocError::InvalidShard),
            }
        } else {
            self.cluster.free_remote(addr.node_id(), addr)
        }
    }
}

// ============================================================================
// INODE OPERATIONS
// ============================================================================

impl<B: BlockDevice, T: ClusterTransport> PermFs<B, T> {
    /// Read an inode from disk
    pub fn read_inode(&self, ino: u64, sb: &Superblock) -> FsResult<Inode> {
        let inodes_per_block = BLOCK_SIZE / Inode::SIZE;
        let block_idx = ino / inodes_per_block as u64;
        let offset_in_block = (ino % inodes_per_block as u64) as usize * Inode::SIZE;

        // Calculate inode table block address
        let mut table_addr = sb.first_inode_table;
        table_addr.limbs[0] += block_idx;

        let mut buf = [0u8; BLOCK_SIZE];
        self.read_block(table_addr, &mut buf)?;

        // Deserialize inode
        let inode_bytes = &buf[offset_in_block..offset_in_block + Inode::SIZE];
        let inode: Inode = unsafe { core::ptr::read(inode_bytes.as_ptr() as *const Inode) };

        // Verify checksum if enabled
        if self.verify_checksums && !inode.verify_checksum() {
            return Err(IoError::ChecksumMismatch);
        }

        Ok(inode)
    }

    /// Write an inode to disk
    pub fn write_inode(&self, ino: u64, inode: &Inode, sb: &Superblock) -> FsResult<()> {
        let inodes_per_block = BLOCK_SIZE / Inode::SIZE;
        let block_idx = ino / inodes_per_block as u64;
        let offset_in_block = (ino % inodes_per_block as u64) as usize * Inode::SIZE;

        let mut table_addr = sb.first_inode_table;
        table_addr.limbs[0] += block_idx;

        let mut buf = [0u8; BLOCK_SIZE];
        self.read_block(table_addr, &mut buf)?;

        // Update checksum before writing
        let mut inode_copy = *inode;
        inode_copy.update_checksum();

        // Serialize inode
        let inode_bytes = unsafe {
            core::slice::from_raw_parts(&inode_copy as *const Inode as *const u8, Inode::SIZE)
        };
        buf[offset_in_block..offset_in_block + Inode::SIZE].copy_from_slice(inode_bytes);

        self.write_block(table_addr, &buf)
    }

    /// Get block address for file offset, handling indirect blocks
    pub fn get_block_for_offset(&self, inode: &Inode, offset: u64) -> FsResult<BlockAddr> {
        let block_num = offset / BLOCK_SIZE as u64;
        let direct_limit = INODE_DIRECT_BLOCKS as u64;
        let ptrs_per_block = (BLOCK_SIZE / core::mem::size_of::<BlockAddr>()) as u64;

        if block_num < direct_limit {
            // Direct block
            let addr = inode.direct[block_num as usize];
            if addr.is_null() {
                return Err(IoError::NotFound);
            }
            return Ok(addr);
        }

        let mut remaining = block_num - direct_limit;

        // Single indirect
        if remaining < ptrs_per_block {
            return self.read_indirect_ptr(inode.indirect[0], remaining as usize);
        }
        remaining -= ptrs_per_block;

        // Double indirect
        let double_limit = ptrs_per_block * ptrs_per_block;
        if remaining < double_limit {
            let l1_idx = remaining / ptrs_per_block;
            let l2_idx = remaining % ptrs_per_block;
            let l1_addr = self.read_indirect_ptr(inode.indirect[1], l1_idx as usize)?;
            return self.read_indirect_ptr(l1_addr, l2_idx as usize);
        }
        remaining -= double_limit;

        // Triple indirect
        let l1_idx = remaining / (ptrs_per_block * ptrs_per_block);
        let l2_idx = (remaining / ptrs_per_block) % ptrs_per_block;
        let l3_idx = remaining % ptrs_per_block;

        let l1_addr = self.read_indirect_ptr(inode.indirect[2], l1_idx as usize)?;
        let l2_addr = self.read_indirect_ptr(l1_addr, l2_idx as usize)?;
        self.read_indirect_ptr(l2_addr, l3_idx as usize)
    }

    fn read_indirect_ptr(&self, block: BlockAddr, idx: usize) -> FsResult<BlockAddr> {
        if block.is_null() {
            return Err(IoError::NotFound);
        }

        let mut buf = [0u8; BLOCK_SIZE];
        self.read_block(block, &mut buf)?;

        let ptrs = unsafe {
            core::slice::from_raw_parts(
                buf.as_ptr() as *const BlockAddr,
                BLOCK_SIZE / core::mem::size_of::<BlockAddr>(),
            )
        };

        let addr = ptrs[idx];
        if addr.is_null() {
            Err(IoError::NotFound)
        } else {
            Ok(addr)
        }
    }
}

// ============================================================================
// FILE READ
// ============================================================================

impl<B: BlockDevice, T: ClusterTransport> PermFs<B, T> {
    /// Read file data
    pub fn read_file(&self, inode: &Inode, offset: u64, buf: &mut [u8]) -> FsResult<usize> {
        if offset >= inode.size {
            return Ok(0);
        }

        let mut total_read = 0usize;
        let mut file_offset = offset;
        let end = core::cmp::min(offset + buf.len() as u64, inode.size);

        while file_offset < end {
            let block_addr = self.get_block_for_offset(inode, file_offset)?;
            let offset_in_block = (file_offset % BLOCK_SIZE as u64) as usize;
            let bytes_in_block =
                core::cmp::min(BLOCK_SIZE - offset_in_block, (end - file_offset) as usize);

            let mut block_buf = [0u8; BLOCK_SIZE];
            self.read_block(block_addr, &mut block_buf)?;

            buf[total_read..total_read + bytes_in_block]
                .copy_from_slice(&block_buf[offset_in_block..offset_in_block + bytes_in_block]);

            total_read += bytes_in_block;
            file_offset += bytes_in_block as u64;
        }

        Ok(total_read)
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_addr_roundtrip() {
        let addr = BlockAddr::new(0xDEAD, 0xBEEF, 0x1234, 0xCAFEBABE);
        assert_eq!(addr.node_id(), 0xDEAD);
        assert_eq!(addr.volume_id(), 0xBEEF);
        assert_eq!(addr.shard_id(), 0x1234);
        assert_eq!(addr.block_offset(), 0xCAFEBABE);
    }

    #[test]
    fn test_block_addr_local_check() {
        let addr = BlockAddr::new(42, 1, 0, 100);
        assert!(addr.is_local(42));
        assert!(!addr.is_local(43));
    }

    #[test]
    fn test_block_addr_serialization() {
        let addr = BlockAddr::new(123, 456, 789, 101112);
        let bytes = addr.to_bytes();
        let recovered = BlockAddr::from_bytes(&bytes);
        assert_eq!(addr, recovered);
    }

    #[test]
    fn test_crc32c() {
        let data = b"Hello, PermFS!";
        let crc = crc32c(data);
        assert!(crc != 0);
        // Same data should produce same CRC
        assert_eq!(crc, crc32c(data));
    }
}
