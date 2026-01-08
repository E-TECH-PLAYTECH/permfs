// PermFS Format — Create and initialize a new filesystem

use crate::*;
use core::sync::atomic::{AtomicU64, Ordering};

// ============================================================================
// FILESYSTEM LAYOUT
// ============================================================================
//
// Block 0:          Superblock
// Block 1..N:       Inode bitmap (N = ceil(total_inodes / (BLOCK_SIZE * 8)))
// Block N+1..M:     Block bitmap (M-N = ceil(total_blocks / (BLOCK_SIZE * 8)))
// Block M+1..K:     Inode table (K-M = ceil(total_inodes / inodes_per_block))
// Block K+1..J:     Journal (configurable size)
// Block J+1..:      Data blocks

/// Filesystem creation parameters
pub struct MkfsParams {
    pub node_id: u64,
    pub volume_id: u32,
    pub total_blocks: u64,
    pub inode_ratio: u64,    // bytes per inode (default: 16384)
    pub journal_blocks: u64, // journal size (default: 1024 = 4 MiB)
    pub volume_name: [u8; 64],
    pub uuid: [u8; 16],
}

impl Default for MkfsParams {
    fn default() -> Self {
        Self {
            node_id: 0,
            volume_id: 0,
            total_blocks: 0,
            inode_ratio: 16384,
            journal_blocks: 1024,
            volume_name: [0; 64],
            uuid: [0; 16],
        }
    }
}

/// Result of mkfs operation
pub struct MkfsResult {
    pub superblock: Superblock,
    pub inode_bitmap_start: u64,
    pub block_bitmap_start: u64,
    pub inode_table_start: u64,
    pub journal_start: u64,
    pub data_start: u64,
}

impl<B: BlockDevice, T: ClusterTransport> PermFs<B, T> {
    /// Format a volume — create new empty filesystem
    pub fn mkfs(&self, params: &MkfsParams) -> FsResult<MkfsResult> {
        if params.total_blocks < 100 {
            return Err(IoError::InvalidAddress);
        }

        let total_bytes = params.total_blocks * BLOCK_SIZE as u64;
        let total_inodes = total_bytes / params.inode_ratio;
        let inodes_per_block = (BLOCK_SIZE / Inode::SIZE) as u64;
        let bits_per_block = (BLOCK_SIZE * 8) as u64;

        // Calculate layout
        let inode_bitmap_blocks = (total_inodes + bits_per_block - 1) / bits_per_block;
        let block_bitmap_blocks = (params.total_blocks + bits_per_block - 1) / bits_per_block;
        let inode_table_blocks = (total_inodes + inodes_per_block - 1) / inodes_per_block;

        let inode_bitmap_start = 1u64;
        let block_bitmap_start = inode_bitmap_start + inode_bitmap_blocks;
        let inode_table_start = block_bitmap_start + block_bitmap_blocks;
        let journal_start = inode_table_start + inode_table_blocks;
        let data_start = journal_start + params.journal_blocks;

        let metadata_blocks = data_start;
        let free_blocks = params.total_blocks.saturating_sub(metadata_blocks);

        // Create superblock
        let mut sb = Superblock {
            magic: SUPERBLOCK_MAGIC,
            version: 1,
            block_size: BLOCK_SIZE as u32,
            total_blocks: params.total_blocks,
            free_blocks: AtomicU64::new(free_blocks),
            total_inodes,
            free_inodes: AtomicU64::new(total_inodes - 1), // minus root inode
            node_id: params.node_id,
            volume_id: params.volume_id,
            flags: 0,
            uuid: params.uuid,
            volume_name: params.volume_name,
            mount_count: 0,
            max_mount_count: 20,
            state: 1,           // clean
            errors_behavior: 1, // continue
            first_inode_table: BlockAddr::new(
                params.node_id,
                params.volume_id,
                0,
                inode_table_start,
            ),
            journal_start: BlockAddr::new(params.node_id, params.volume_id, 0, journal_start),
            user_quota_block: BlockAddr::NULL,
            group_quota_block: BlockAddr::NULL,
            root_inode: 0,
            checksum: 0,
        };
        sb.update_checksum();

        // Write superblock
        let sb_addr = BlockAddr::new(params.node_id, params.volume_id, 0, 0);
        let mut buf = [0u8; BLOCK_SIZE];
        self.serialize_superblock(&sb, &mut buf);
        self.write_block(sb_addr, &buf)?;

        // Initialize inode bitmap (mark inode 0 as used for root)
        self.init_inode_bitmap(params, inode_bitmap_start, inode_bitmap_blocks)?;

        // Initialize block bitmap (mark metadata blocks as used)
        self.init_block_bitmap(params, block_bitmap_start, block_bitmap_blocks, data_start)?;

        // Initialize inode table with root directory
        self.init_root_inode(params, &sb)?;

        // Initialize journal
        self.init_journal(params, journal_start)?;

        Ok(MkfsResult {
            superblock: self.clone_superblock(&sb),
            inode_bitmap_start,
            block_bitmap_start,
            inode_table_start,
            journal_start,
            data_start,
        })
    }

    fn serialize_superblock(&self, sb: &Superblock, buf: &mut [u8; BLOCK_SIZE]) {
        buf.fill(0);
        buf[0..8].copy_from_slice(&sb.magic.to_le_bytes());
        buf[8..12].copy_from_slice(&sb.version.to_le_bytes());
        buf[12..16].copy_from_slice(&sb.block_size.to_le_bytes());
        buf[16..24].copy_from_slice(&sb.total_blocks.to_le_bytes());
        buf[24..32].copy_from_slice(&sb.free_blocks.load(Ordering::Relaxed).to_le_bytes());
        buf[32..40].copy_from_slice(&sb.total_inodes.to_le_bytes());
        buf[40..48].copy_from_slice(&sb.free_inodes.load(Ordering::Relaxed).to_le_bytes());
        buf[48..56].copy_from_slice(&sb.node_id.to_le_bytes());
        buf[56..60].copy_from_slice(&sb.volume_id.to_le_bytes());
        buf[60..64].copy_from_slice(&sb.flags.to_le_bytes());
        buf[64..80].copy_from_slice(&sb.uuid);
        buf[80..144].copy_from_slice(&sb.volume_name);
        buf[144..148].copy_from_slice(&sb.mount_count.to_le_bytes());
        buf[148..152].copy_from_slice(&sb.max_mount_count.to_le_bytes());
        buf[152..154].copy_from_slice(&sb.state.to_le_bytes());
        buf[154..156].copy_from_slice(&sb.errors_behavior.to_le_bytes());
        buf[156..188].copy_from_slice(&sb.first_inode_table.to_bytes());
        buf[188..220].copy_from_slice(&sb.journal_start.to_bytes());
        buf[220..252].copy_from_slice(&sb.user_quota_block.to_bytes());
        buf[252..284].copy_from_slice(&sb.group_quota_block.to_bytes());
        buf[284..292].copy_from_slice(&sb.root_inode.to_le_bytes());
        buf[292..300].copy_from_slice(&sb.checksum.to_le_bytes());
    }

    fn clone_superblock(&self, sb: &Superblock) -> Superblock {
        Superblock {
            magic: sb.magic,
            version: sb.version,
            block_size: sb.block_size,
            total_blocks: sb.total_blocks,
            free_blocks: AtomicU64::new(sb.free_blocks.load(Ordering::Relaxed)),
            total_inodes: sb.total_inodes,
            free_inodes: AtomicU64::new(sb.free_inodes.load(Ordering::Relaxed)),
            node_id: sb.node_id,
            volume_id: sb.volume_id,
            flags: sb.flags,
            uuid: sb.uuid,
            volume_name: sb.volume_name,
            mount_count: sb.mount_count,
            max_mount_count: sb.max_mount_count,
            state: sb.state,
            errors_behavior: sb.errors_behavior,
            first_inode_table: sb.first_inode_table,
            journal_start: sb.journal_start,
            user_quota_block: sb.user_quota_block,
            group_quota_block: sb.group_quota_block,
            root_inode: sb.root_inode,
            checksum: sb.checksum,
        }
    }

    fn init_inode_bitmap(&self, params: &MkfsParams, start: u64, blocks: u64) -> FsResult<()> {
        let mut buf = [0u8; BLOCK_SIZE];

        for i in 0..blocks {
            buf.fill(0);

            if i == 0 {
                buf[0] = 0x01; // Mark inode 0 (root) as used
            }

            let addr = BlockAddr::new(params.node_id, params.volume_id, 0, start + i);
            self.write_block(addr, &buf)?;
        }

        Ok(())
    }

    fn init_block_bitmap(
        &self,
        params: &MkfsParams,
        start: u64,
        blocks: u64,
        used_blocks: u64,
    ) -> FsResult<()> {
        let bits_per_block = BLOCK_SIZE * 8;
        let mut buf = [0u8; BLOCK_SIZE];
        let mut remaining_used = used_blocks;

        for i in 0..blocks {
            if remaining_used == 0 {
                buf.fill(0);
            } else if remaining_used >= bits_per_block as u64 {
                buf.fill(0xFF);
                remaining_used -= bits_per_block as u64;
            } else {
                buf.fill(0);
                let full_bytes = remaining_used / 8;
                let extra_bits = remaining_used % 8;

                for j in 0..full_bytes as usize {
                    buf[j] = 0xFF;
                }
                if extra_bits > 0 {
                    buf[full_bytes as usize] = (1u8 << extra_bits) - 1;
                }
                remaining_used = 0;
            }

            let addr = BlockAddr::new(params.node_id, params.volume_id, 0, start + i);
            self.write_block(addr, &buf)?;
        }

        Ok(())
    }

    fn init_root_inode(&self, params: &MkfsParams, sb: &Superblock) -> FsResult<()> {
        let root_data_block = BlockAddr::new(
            params.node_id,
            params.volume_id,
            0,
            sb.first_inode_table.block_offset()
                + (sb.total_inodes + (BLOCK_SIZE / Inode::SIZE) as u64 - 1)
                    / (BLOCK_SIZE / Inode::SIZE) as u64
                + params.journal_blocks,
        );

        let now = self.current_time();
        let mut root = Inode {
            mode: 0o040777, // directory + rwxrwxrwx (world-writable root)
            uid: 0,
            gid: 0,
            flags: 0,
            size: BLOCK_SIZE as u64,
            blocks: 1,
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
            nlink: 2, // . and itself
            generation: 0,
            direct: [BlockAddr::NULL; INODE_DIRECT_BLOCKS],
            indirect: [BlockAddr::NULL; INODE_INDIRECT_LEVELS],
            extent_root: BlockAddr::NULL,
            xattr_block: BlockAddr::NULL,
            checksum: 0,
        };
        root.direct[0] = root_data_block;
        root.update_checksum();

        self.write_inode(0, &root, sb)?;
        self.init_directory_block(root_data_block, 0, 0)?;

        Ok(())
    }

    fn init_journal(&self, params: &MkfsParams, start: u64) -> FsResult<()> {
        use crate::journal::{JournalHeader, TxState, JOURNAL_MAGIC};

        let header = JournalHeader {
            magic: JOURNAL_MAGIC,
            version: 1,
            state: TxState::Invalid,
            head_seq: 0,
            tail_seq: 0,
            first_block: BlockAddr::new(params.node_id, params.volume_id, 0, start + 1),
            block_count: params.journal_blocks - 1,
            max_transaction: 64,
            checksum: 0,
        };

        let mut buf = [0u8; BLOCK_SIZE];
        header.serialize(&mut buf);

        let addr = BlockAddr::new(params.node_id, params.volume_id, 0, start);
        self.write_block(addr, &buf)
    }
}

// ============================================================================
// MOUNT/UNMOUNT
// ============================================================================

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MountFlags {
    ReadOnly = 1,
    NoAtime = 2,
    Sync = 4,
}

/// Statistics from journal recovery
#[derive(Debug, Default, Clone)]
pub struct RecoveryStats {
    /// Number of transactions replayed
    pub transactions_replayed: u64,
    /// Number of blocks written during replay
    pub blocks_replayed: u64,
    /// Whether recovery was needed
    pub recovery_needed: bool,
}

impl<B: BlockDevice, T: ClusterTransport> PermFs<B, T> {
    /// Mount filesystem — read superblock, verify, set up state
    pub fn mount(&self, node_id: u64, volume_id: u32) -> FsResult<Superblock> {
        let sb_addr = BlockAddr::new(node_id, volume_id, 0, 0);
        let mut buf = [0u8; BLOCK_SIZE];
        self.read_block(sb_addr, &mut buf)?;

        let sb = self.deserialize_superblock(&buf)?;

        if sb.magic != SUPERBLOCK_MAGIC {
            return Err(IoError::Corrupted);
        }

        if self.verify_checksums && !sb.verify_checksum() {
            return Err(IoError::ChecksumMismatch);
        }

        self.mounted.fetch_add(1, Ordering::Relaxed);
        Ok(sb)
    }

    fn deserialize_superblock(&self, buf: &[u8; BLOCK_SIZE]) -> FsResult<Superblock> {
        Ok(Superblock {
            magic: u64::from_le_bytes(buf[0..8].try_into().unwrap()),
            version: u32::from_le_bytes(buf[8..12].try_into().unwrap()),
            block_size: u32::from_le_bytes(buf[12..16].try_into().unwrap()),
            total_blocks: u64::from_le_bytes(buf[16..24].try_into().unwrap()),
            free_blocks: AtomicU64::new(u64::from_le_bytes(buf[24..32].try_into().unwrap())),
            total_inodes: u64::from_le_bytes(buf[32..40].try_into().unwrap()),
            free_inodes: AtomicU64::new(u64::from_le_bytes(buf[40..48].try_into().unwrap())),
            node_id: u64::from_le_bytes(buf[48..56].try_into().unwrap()),
            volume_id: u32::from_le_bytes(buf[56..60].try_into().unwrap()),
            flags: u32::from_le_bytes(buf[60..64].try_into().unwrap()),
            uuid: buf[64..80].try_into().unwrap(),
            volume_name: buf[80..144].try_into().unwrap(),
            mount_count: u32::from_le_bytes(buf[144..148].try_into().unwrap()),
            max_mount_count: u32::from_le_bytes(buf[148..152].try_into().unwrap()),
            state: u16::from_le_bytes(buf[152..154].try_into().unwrap()),
            errors_behavior: u16::from_le_bytes(buf[154..156].try_into().unwrap()),
            first_inode_table: BlockAddr::from_bytes(buf[156..188].try_into().unwrap()),
            journal_start: BlockAddr::from_bytes(buf[188..220].try_into().unwrap()),
            user_quota_block: BlockAddr::from_bytes(buf[220..252].try_into().unwrap()),
            group_quota_block: BlockAddr::from_bytes(buf[252..284].try_into().unwrap()),
            root_inode: u64::from_le_bytes(buf[284..292].try_into().unwrap()),
            checksum: u64::from_le_bytes(buf[292..300].try_into().unwrap()),
        })
    }

    /// Unmount — sync and mark clean
    pub fn unmount(&self, sb: &mut Superblock) -> FsResult<()> {
        self.local_device.sync()?;

        sb.state = 1; // clean
        sb.mount_count += 1;
        sb.update_checksum();

        let sb_addr = BlockAddr::new(sb.node_id, sb.volume_id, 0, 0);
        let mut buf = [0u8; BLOCK_SIZE];
        self.serialize_superblock(sb, &mut buf);
        self.write_block(sb_addr, &buf)?;

        self.mounted.fetch_sub(1, Ordering::Relaxed);
        Ok(())
    }

    /// Recover journal after crash — replay committed but not checkpointed transactions
    #[cfg(feature = "std")]
    pub fn recover_journal(&self, sb: &Superblock) -> FsResult<RecoveryStats> {
        use crate::journal::{Journal, JournalHeader, JOURNAL_MAGIC};

        // Read journal header from disk
        let mut buf = [0u8; BLOCK_SIZE];
        self.read_block(sb.journal_start, &mut buf)?;

        let header = JournalHeader::deserialize(&buf);

        // Verify journal magic
        if header.magic != JOURNAL_MAGIC {
            // No valid journal, nothing to recover
            return Ok(RecoveryStats::default());
        }

        // Check if recovery is needed (uncommitted transactions exist)
        if header.tail_seq >= header.head_seq {
            // Journal is clean, no recovery needed
            return Ok(RecoveryStats::default());
        }

        // Create a wrapper that implements BlockDevice for our local_device
        let journal = Journal::new(JournalBlockDevice::new(&self.local_device), header);

        // Perform recovery
        let recovered = journal.recover().map_err(|_| IoError::Corrupted)?;

        let stats = RecoveryStats {
            transactions_replayed: recovered.len() as u64,
            blocks_replayed: 0, // We don't track this currently
            recovery_needed: !recovered.is_empty(),
        };

        if stats.recovery_needed {
            // Update journal header to mark recovery complete
            let new_header = JournalHeader {
                tail_seq: header.head_seq,
                ..header
            };
            let mut header_buf = [0u8; BLOCK_SIZE];
            new_header.serialize(&mut header_buf);
            self.write_block(sb.journal_start, &header_buf)?;
            self.local_device.sync()?;
        }

        Ok(stats)
    }
}

/// Wrapper to adapt a reference to BlockDevice for Journal use
#[cfg(feature = "std")]
struct JournalBlockDevice<'a, B: BlockDevice> {
    inner: &'a B,
}

#[cfg(feature = "std")]
impl<'a, B: BlockDevice> JournalBlockDevice<'a, B> {
    fn new(inner: &'a B) -> Self {
        Self { inner }
    }
}

#[cfg(feature = "std")]
impl<B: BlockDevice> BlockDevice for JournalBlockDevice<'_, B> {
    fn read_block(&self, addr: BlockAddr, buf: &mut [u8; BLOCK_SIZE]) -> FsResult<()> {
        self.inner.read_block(addr, buf)
    }

    fn write_block(&self, addr: BlockAddr, buf: &[u8; BLOCK_SIZE]) -> FsResult<()> {
        self.inner.write_block(addr, buf)
    }

    fn sync(&self) -> FsResult<()> {
        self.inner.sync()
    }

    fn trim(&self, addr: BlockAddr) -> FsResult<()> {
        self.inner.trim(addr)
    }
}
