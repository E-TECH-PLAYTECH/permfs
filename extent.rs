// PermFS Extent Tree — B+ tree for efficient large file block mapping

use crate::{BlockAddr, BlockDevice, ClusterTransport, FsResult, IoError, PermFs, BLOCK_SIZE};

// ============================================================================
// EXTENT STRUCTURE
// ============================================================================

/// Single extent: maps a range of logical blocks to physical blocks
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Extent {
    /// Starting logical block number within the file
    pub logical_block: u64,
    /// Starting physical block address
    pub physical_block: BlockAddr,
    /// Number of contiguous blocks in this extent
    pub length: u32,
    /// Flags (e.g., unwritten, compressed)
    pub flags: u32,
}

impl Extent {
    pub const SIZE: usize = core::mem::size_of::<Self>();
    pub const NULL: Self = Self {
        logical_block: 0,
        physical_block: BlockAddr::NULL,
        length: 0,
        flags: 0,
    };

    pub fn new(logical: u64, physical: BlockAddr, length: u32) -> Self {
        Self {
            logical_block: logical,
            physical_block: physical,
            length,
            flags: 0,
        }
    }

    pub fn is_null(&self) -> bool {
        self.length == 0 || self.physical_block.is_null()
    }

    /// Check if this extent contains the given logical block
    pub fn contains(&self, logical_block: u64) -> bool {
        logical_block >= self.logical_block
            && logical_block < self.logical_block + self.length as u64
    }

    /// Get physical block for a logical block within this extent
    pub fn get_physical(&self, logical_block: u64) -> Option<BlockAddr> {
        if !self.contains(logical_block) {
            return None;
        }
        let offset = logical_block - self.logical_block;
        let mut addr = self.physical_block;
        addr.limbs[0] += offset;
        Some(addr)
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..8].copy_from_slice(&self.logical_block.to_le_bytes());
        buf[8..40].copy_from_slice(&self.physical_block.to_bytes());
        buf[40..44].copy_from_slice(&self.length.to_le_bytes());
        buf[44..48].copy_from_slice(&self.flags.to_le_bytes());
        buf
    }

    /// Deserialize from bytes
    pub fn from_bytes(buf: &[u8; Self::SIZE]) -> Self {
        Self {
            logical_block: u64::from_le_bytes(buf[0..8].try_into().unwrap()),
            physical_block: BlockAddr::from_bytes(buf[8..40].try_into().unwrap()),
            length: u32::from_le_bytes(buf[40..44].try_into().unwrap()),
            flags: u32::from_le_bytes(buf[44..48].try_into().unwrap()),
        }
    }
}

// Extent flags
pub mod extent_flags {
    pub const UNWRITTEN: u32 = 0x0001; // Allocated but not written (hole)
    pub const COMPRESSED: u32 = 0x0002; // Data is compressed
    pub const ENCRYPTED: u32 = 0x0004; // Data is encrypted
}

// ============================================================================
// EXTENT TREE NODE
// ============================================================================

/// Extent tree node header
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ExtentHeader {
    /// Magic number for validation
    pub magic: u16,
    /// Number of valid entries
    pub entries: u16,
    /// Maximum entries in this node
    pub max_entries: u16,
    /// Depth (0 = leaf with extents, >0 = index with pointers)
    pub depth: u16,
    /// Generation for crash consistency
    pub generation: u32,
    /// Reserved
    pub reserved: u32,
}

pub const EXTENT_HEADER_MAGIC: u16 = 0xF30A;

impl ExtentHeader {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    pub fn new(max_entries: u16, depth: u16) -> Self {
        Self {
            magic: EXTENT_HEADER_MAGIC,
            entries: 0,
            max_entries,
            depth,
            generation: 0,
            reserved: 0,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.magic == EXTENT_HEADER_MAGIC
    }

    pub fn is_leaf(&self) -> bool {
        self.depth == 0
    }

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..2].copy_from_slice(&self.magic.to_le_bytes());
        buf[2..4].copy_from_slice(&self.entries.to_le_bytes());
        buf[4..6].copy_from_slice(&self.max_entries.to_le_bytes());
        buf[6..8].copy_from_slice(&self.depth.to_le_bytes());
        buf[8..12].copy_from_slice(&self.generation.to_le_bytes());
        buf[12..16].copy_from_slice(&self.reserved.to_le_bytes());
        buf
    }

    pub fn from_bytes(buf: &[u8; Self::SIZE]) -> Self {
        Self {
            magic: u16::from_le_bytes(buf[0..2].try_into().unwrap()),
            entries: u16::from_le_bytes(buf[2..4].try_into().unwrap()),
            max_entries: u16::from_le_bytes(buf[4..6].try_into().unwrap()),
            depth: u16::from_le_bytes(buf[6..8].try_into().unwrap()),
            generation: u32::from_le_bytes(buf[8..12].try_into().unwrap()),
            reserved: u32::from_le_bytes(buf[12..16].try_into().unwrap()),
        }
    }
}

/// Index entry for internal nodes (points to child node)
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ExtentIndex {
    /// Logical block this subtree covers (lowest in subtree)
    pub logical_block: u64,
    /// Block address of child node
    pub child: BlockAddr,
}

impl ExtentIndex {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..8].copy_from_slice(&self.logical_block.to_le_bytes());
        buf[8..40].copy_from_slice(&self.child.to_bytes());
        buf
    }

    pub fn from_bytes(buf: &[u8; Self::SIZE]) -> Self {
        Self {
            logical_block: u64::from_le_bytes(buf[0..8].try_into().unwrap()),
            child: BlockAddr::from_bytes(buf[8..40].try_into().unwrap()),
        }
    }
}

// ============================================================================
// EXTENT TREE OPERATIONS
// ============================================================================

/// Calculate max entries for leaf and index nodes
const fn max_leaf_entries() -> u16 {
    ((BLOCK_SIZE - ExtentHeader::SIZE) / Extent::SIZE) as u16
}

const fn max_index_entries() -> u16 {
    ((BLOCK_SIZE - ExtentHeader::SIZE) / ExtentIndex::SIZE) as u16
}

/// In-memory extent tree for a file
pub struct ExtentTree {
    root: BlockAddr,
    depth: u16,
    entries: u16,
}

impl ExtentTree {
    /// Create a new empty extent tree
    pub fn new() -> Self {
        Self {
            root: BlockAddr::NULL,
            depth: 0,
            entries: 0,
        }
    }

    /// Initialize from an existing root block
    pub fn from_root(root: BlockAddr) -> Self {
        Self {
            root,
            depth: 0, // Will be read from block
            entries: 0,
        }
    }

    pub fn root(&self) -> BlockAddr {
        self.root
    }

    pub fn is_empty(&self) -> bool {
        self.root.is_null()
    }
}

impl<B: BlockDevice, T: ClusterTransport> PermFs<B, T> {
    /// Lookup a logical block in the extent tree
    pub fn extent_lookup(&self, tree_root: BlockAddr, logical_block: u64) -> FsResult<Extent> {
        if tree_root.is_null() {
            return Err(IoError::NotFound);
        }

        let mut current = tree_root;
        let mut buf = [0u8; BLOCK_SIZE];

        loop {
            self.read_block(current, &mut buf)?;

            let header = ExtentHeader::from_bytes(buf[0..ExtentHeader::SIZE].try_into().unwrap());
            if !header.is_valid() {
                return Err(IoError::Corrupted);
            }

            if header.is_leaf() {
                // Search leaf entries
                let entries_start = ExtentHeader::SIZE;
                for i in 0..header.entries as usize {
                    let offset = entries_start + i * Extent::SIZE;
                    let extent =
                        Extent::from_bytes(buf[offset..offset + Extent::SIZE].try_into().unwrap());

                    if extent.contains(logical_block) {
                        return Ok(extent);
                    }
                }
                return Err(IoError::NotFound);
            } else {
                // Search index entries to find child
                let entries_start = ExtentHeader::SIZE;
                let mut next_child = BlockAddr::NULL;

                for i in 0..header.entries as usize {
                    let offset = entries_start + i * ExtentIndex::SIZE;
                    let index = ExtentIndex::from_bytes(
                        buf[offset..offset + ExtentIndex::SIZE].try_into().unwrap(),
                    );

                    if logical_block >= index.logical_block {
                        next_child = index.child;
                    } else {
                        break;
                    }
                }

                if next_child.is_null() {
                    return Err(IoError::NotFound);
                }
                current = next_child;
            }
        }
    }

    /// Insert an extent into the tree
    pub fn extent_insert(
        &self,
        tree_root: &mut BlockAddr,
        extent: Extent,
        volume_id: u32,
    ) -> FsResult<()> {
        if tree_root.is_null() {
            // Create new root leaf
            let root = self
                .alloc_block(Some(volume_id))
                .map_err(|_| IoError::IoFailed)?;
            let mut buf = [0u8; BLOCK_SIZE];

            let mut header = ExtentHeader::new(max_leaf_entries(), 0);
            header.entries = 1;

            buf[0..ExtentHeader::SIZE].copy_from_slice(&header.to_bytes());
            buf[ExtentHeader::SIZE..ExtentHeader::SIZE + Extent::SIZE]
                .copy_from_slice(&extent.to_bytes());

            self.write_block(root, &buf)?;
            *tree_root = root;
            return Ok(());
        }

        // Find leaf and insert
        let result = self.extent_insert_recursive(*tree_root, extent, volume_id)?;

        if let Some((new_extent, new_child)) = result {
            // Root split - create new root
            let new_root = self
                .alloc_block(Some(volume_id))
                .map_err(|_| IoError::IoFailed)?;
            let mut buf = [0u8; BLOCK_SIZE];

            // Read old root to get its first key
            let mut old_buf = [0u8; BLOCK_SIZE];
            self.read_block(*tree_root, &mut old_buf)?;
            let old_header =
                ExtentHeader::from_bytes(old_buf[0..ExtentHeader::SIZE].try_into().unwrap());
            let old_first_key = if old_header.is_leaf() {
                let ext = Extent::from_bytes(
                    old_buf[ExtentHeader::SIZE..ExtentHeader::SIZE + Extent::SIZE]
                        .try_into()
                        .unwrap(),
                );
                ext.logical_block
            } else {
                let idx = ExtentIndex::from_bytes(
                    old_buf[ExtentHeader::SIZE..ExtentHeader::SIZE + ExtentIndex::SIZE]
                        .try_into()
                        .unwrap(),
                );
                idx.logical_block
            };

            let mut header = ExtentHeader::new(max_index_entries(), old_header.depth + 1);
            header.entries = 2;

            let idx0 = ExtentIndex {
                logical_block: old_first_key,
                child: *tree_root,
            };
            let idx1 = ExtentIndex {
                logical_block: new_extent.logical_block,
                child: new_child,
            };

            buf[0..ExtentHeader::SIZE].copy_from_slice(&header.to_bytes());
            buf[ExtentHeader::SIZE..ExtentHeader::SIZE + ExtentIndex::SIZE]
                .copy_from_slice(&idx0.to_bytes());
            buf[ExtentHeader::SIZE + ExtentIndex::SIZE..ExtentHeader::SIZE + 2 * ExtentIndex::SIZE]
                .copy_from_slice(&idx1.to_bytes());

            self.write_block(new_root, &buf)?;
            *tree_root = new_root;
        }

        Ok(())
    }

    /// Recursive insert - returns Some if split occurred
    fn extent_insert_recursive(
        &self,
        node: BlockAddr,
        extent: Extent,
        volume_id: u32,
    ) -> FsResult<Option<(Extent, BlockAddr)>> {
        let mut buf = [0u8; BLOCK_SIZE];
        self.read_block(node, &mut buf)?;

        let mut header = ExtentHeader::from_bytes(buf[0..ExtentHeader::SIZE].try_into().unwrap());
        if !header.is_valid() {
            return Err(IoError::Corrupted);
        }

        if header.is_leaf() {
            // Insert into leaf
            return self.extent_insert_leaf(node, &mut buf, &mut header, extent, volume_id);
        }

        // Find child and recurse
        let entries_start = ExtentHeader::SIZE;
        let mut child_idx = 0;

        for i in 0..header.entries as usize {
            let offset = entries_start + i * ExtentIndex::SIZE;
            let index = ExtentIndex::from_bytes(
                buf[offset..offset + ExtentIndex::SIZE].try_into().unwrap(),
            );
            if extent.logical_block >= index.logical_block {
                child_idx = i;
            } else {
                break;
            }
        }

        let child_offset = entries_start + child_idx * ExtentIndex::SIZE;
        let child_index = ExtentIndex::from_bytes(
            buf[child_offset..child_offset + ExtentIndex::SIZE]
                .try_into()
                .unwrap(),
        );

        let split_result = self.extent_insert_recursive(child_index.child, extent, volume_id)?;

        if let Some((split_key, split_child)) = split_result {
            // Child split - insert new index entry
            return self.extent_insert_index(
                node,
                &mut buf,
                &mut header,
                split_key,
                split_child,
                child_idx + 1,
                volume_id,
            );
        }

        Ok(None)
    }

    fn extent_insert_leaf(
        &self,
        node: BlockAddr,
        buf: &mut [u8; BLOCK_SIZE],
        header: &mut ExtentHeader,
        extent: Extent,
        volume_id: u32,
    ) -> FsResult<Option<(Extent, BlockAddr)>> {
        let entries_start = ExtentHeader::SIZE;

        // Find insertion point (keep sorted by logical_block)
        let mut insert_pos = header.entries as usize;
        for i in 0..header.entries as usize {
            let offset = entries_start + i * Extent::SIZE;
            let existing =
                Extent::from_bytes(buf[offset..offset + Extent::SIZE].try_into().unwrap());
            if extent.logical_block < existing.logical_block {
                insert_pos = i;
                break;
            }
        }

        if (header.entries as u16) < header.max_entries {
            // Room in this node - shift and insert
            for i in (insert_pos..header.entries as usize).rev() {
                let src = entries_start + i * Extent::SIZE;
                let dst = entries_start + (i + 1) * Extent::SIZE;
                buf.copy_within(src..src + Extent::SIZE, dst);
            }

            let offset = entries_start + insert_pos * Extent::SIZE;
            buf[offset..offset + Extent::SIZE].copy_from_slice(&extent.to_bytes());
            header.entries += 1;

            buf[0..ExtentHeader::SIZE].copy_from_slice(&header.to_bytes());
            self.write_block(node, buf)?;
            return Ok(None);
        }

        // Need to split
        let new_node = self
            .alloc_block(Some(volume_id))
            .map_err(|_| IoError::IoFailed)?;
        let mut new_buf = [0u8; BLOCK_SIZE];

        let mid = header.entries as usize / 2;
        let mut new_header = ExtentHeader::new(header.max_entries, 0);

        // Collect all entries including new one
        let mut all_extents = Vec::with_capacity(header.entries as usize + 1);
        for i in 0..header.entries as usize {
            let offset = entries_start + i * Extent::SIZE;
            all_extents.push(Extent::from_bytes(
                buf[offset..offset + Extent::SIZE].try_into().unwrap(),
            ));
        }
        all_extents.insert(insert_pos, extent);

        // Split entries
        header.entries = mid as u16;
        new_header.entries = (all_extents.len() - mid) as u16;

        // Write first half to original node
        for (i, ext) in all_extents[..mid].iter().enumerate() {
            let offset = entries_start + i * Extent::SIZE;
            buf[offset..offset + Extent::SIZE].copy_from_slice(&ext.to_bytes());
        }
        // Clear rest
        buf[entries_start + mid * Extent::SIZE..].fill(0);
        buf[0..ExtentHeader::SIZE].copy_from_slice(&header.to_bytes());
        self.write_block(node, buf)?;

        // Write second half to new node
        new_buf[0..ExtentHeader::SIZE].copy_from_slice(&new_header.to_bytes());
        for (i, ext) in all_extents[mid..].iter().enumerate() {
            let offset = ExtentHeader::SIZE + i * Extent::SIZE;
            new_buf[offset..offset + Extent::SIZE].copy_from_slice(&ext.to_bytes());
        }
        self.write_block(new_node, &new_buf)?;

        // Return split key (first key of new node)
        Ok(Some((all_extents[mid], new_node)))
    }

    fn extent_insert_index(
        &self,
        node: BlockAddr,
        buf: &mut [u8; BLOCK_SIZE],
        header: &mut ExtentHeader,
        key: Extent,
        child: BlockAddr,
        insert_pos: usize,
        volume_id: u32,
    ) -> FsResult<Option<(Extent, BlockAddr)>> {
        let entries_start = ExtentHeader::SIZE;
        let new_index = ExtentIndex {
            logical_block: key.logical_block,
            child,
        };

        if (header.entries as u16) < header.max_entries {
            // Room in this node
            for i in (insert_pos..header.entries as usize).rev() {
                let src = entries_start + i * ExtentIndex::SIZE;
                let dst = entries_start + (i + 1) * ExtentIndex::SIZE;
                buf.copy_within(src..src + ExtentIndex::SIZE, dst);
            }

            let offset = entries_start + insert_pos * ExtentIndex::SIZE;
            buf[offset..offset + ExtentIndex::SIZE].copy_from_slice(&new_index.to_bytes());
            header.entries += 1;

            buf[0..ExtentHeader::SIZE].copy_from_slice(&header.to_bytes());
            self.write_block(node, buf)?;
            return Ok(None);
        }

        // Need to split internal node
        let new_node = self
            .alloc_block(Some(volume_id))
            .map_err(|_| IoError::IoFailed)?;
        let mut new_buf = [0u8; BLOCK_SIZE];

        let mid = header.entries as usize / 2;
        let mut new_header = ExtentHeader::new(header.max_entries, header.depth);

        // Collect all index entries including new one
        let mut all_indices = Vec::with_capacity(header.entries as usize + 1);
        for i in 0..header.entries as usize {
            let offset = entries_start + i * ExtentIndex::SIZE;
            all_indices.push(ExtentIndex::from_bytes(
                buf[offset..offset + ExtentIndex::SIZE].try_into().unwrap(),
            ));
        }
        all_indices.insert(insert_pos, new_index);

        // Split
        header.entries = mid as u16;
        new_header.entries = (all_indices.len() - mid) as u16;

        // Write first half
        for (i, idx) in all_indices[..mid].iter().enumerate() {
            let offset = entries_start + i * ExtentIndex::SIZE;
            buf[offset..offset + ExtentIndex::SIZE].copy_from_slice(&idx.to_bytes());
        }
        buf[entries_start + mid * ExtentIndex::SIZE..].fill(0);
        buf[0..ExtentHeader::SIZE].copy_from_slice(&header.to_bytes());
        self.write_block(node, buf)?;

        // Write second half
        new_buf[0..ExtentHeader::SIZE].copy_from_slice(&new_header.to_bytes());
        for (i, idx) in all_indices[mid..].iter().enumerate() {
            let offset = ExtentHeader::SIZE + i * ExtentIndex::SIZE;
            new_buf[offset..offset + ExtentIndex::SIZE].copy_from_slice(&idx.to_bytes());
        }
        self.write_block(new_node, &new_buf)?;

        // Return split key
        let split_extent = Extent::new(all_indices[mid].logical_block, BlockAddr::NULL, 0);
        Ok(Some((split_extent, new_node)))
    }

    /// Remove an extent covering the given logical block
    pub fn extent_remove(&self, tree_root: &mut BlockAddr, logical_block: u64) -> FsResult<Extent> {
        if tree_root.is_null() {
            return Err(IoError::NotFound);
        }

        let removed = self.extent_remove_recursive(*tree_root, logical_block)?;

        // Check if root is now empty index node
        let mut buf = [0u8; BLOCK_SIZE];
        self.read_block(*tree_root, &mut buf)?;
        let header = ExtentHeader::from_bytes(buf[0..ExtentHeader::SIZE].try_into().unwrap());

        if !header.is_leaf() && header.entries == 1 {
            // Collapse root
            let idx = ExtentIndex::from_bytes(
                buf[ExtentHeader::SIZE..ExtentHeader::SIZE + ExtentIndex::SIZE]
                    .try_into()
                    .unwrap(),
            );
            let old_root = *tree_root;
            *tree_root = idx.child;
            let _ = self.free_block(old_root);
        } else if header.entries == 0 {
            let old_root = *tree_root;
            *tree_root = BlockAddr::NULL;
            let _ = self.free_block(old_root);
        }

        Ok(removed)
    }

    fn extent_remove_recursive(&self, node: BlockAddr, logical_block: u64) -> FsResult<Extent> {
        let mut buf = [0u8; BLOCK_SIZE];
        self.read_block(node, &mut buf)?;

        let mut header = ExtentHeader::from_bytes(buf[0..ExtentHeader::SIZE].try_into().unwrap());
        if !header.is_valid() {
            return Err(IoError::Corrupted);
        }

        let entries_start = ExtentHeader::SIZE;

        if header.is_leaf() {
            // Find and remove from leaf
            for i in 0..header.entries as usize {
                let offset = entries_start + i * Extent::SIZE;
                let extent =
                    Extent::from_bytes(buf[offset..offset + Extent::SIZE].try_into().unwrap());

                if extent.contains(logical_block) {
                    // Remove by shifting
                    for j in i..header.entries as usize - 1 {
                        let src = entries_start + (j + 1) * Extent::SIZE;
                        let dst = entries_start + j * Extent::SIZE;
                        buf.copy_within(src..src + Extent::SIZE, dst);
                    }
                    header.entries -= 1;
                    buf[0..ExtentHeader::SIZE].copy_from_slice(&header.to_bytes());
                    self.write_block(node, &buf)?;
                    return Ok(extent);
                }
            }
            return Err(IoError::NotFound);
        }

        // Internal node - find child
        let mut child_idx = 0;
        for i in 0..header.entries as usize {
            let offset = entries_start + i * ExtentIndex::SIZE;
            let index = ExtentIndex::from_bytes(
                buf[offset..offset + ExtentIndex::SIZE].try_into().unwrap(),
            );
            if logical_block >= index.logical_block {
                child_idx = i;
            } else {
                break;
            }
        }

        let child_offset = entries_start + child_idx * ExtentIndex::SIZE;
        let child_index = ExtentIndex::from_bytes(
            buf[child_offset..child_offset + ExtentIndex::SIZE]
                .try_into()
                .unwrap(),
        );

        self.extent_remove_recursive(child_index.child, logical_block)
    }

    /// Iterate all extents in the tree
    pub fn extent_iter<F>(&self, tree_root: BlockAddr, mut callback: F) -> FsResult<()>
    where
        F: FnMut(&Extent) -> bool,
    {
        if tree_root.is_null() {
            return Ok(());
        }

        self.extent_iter_recursive(tree_root, &mut callback)
    }

    fn extent_iter_recursive<F>(&self, node: BlockAddr, callback: &mut F) -> FsResult<()>
    where
        F: FnMut(&Extent) -> bool,
    {
        let mut buf = [0u8; BLOCK_SIZE];
        self.read_block(node, &mut buf)?;

        let header = ExtentHeader::from_bytes(buf[0..ExtentHeader::SIZE].try_into().unwrap());
        if !header.is_valid() {
            return Err(IoError::Corrupted);
        }

        let entries_start = ExtentHeader::SIZE;

        if header.is_leaf() {
            for i in 0..header.entries as usize {
                let offset = entries_start + i * Extent::SIZE;
                let extent =
                    Extent::from_bytes(buf[offset..offset + Extent::SIZE].try_into().unwrap());
                if !callback(&extent) {
                    return Ok(());
                }
            }
        } else {
            for i in 0..header.entries as usize {
                let offset = entries_start + i * ExtentIndex::SIZE;
                let index = ExtentIndex::from_bytes(
                    buf[offset..offset + ExtentIndex::SIZE].try_into().unwrap(),
                );
                self.extent_iter_recursive(index.child, callback)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extent_basics() {
        let ext = Extent::new(100, BlockAddr::new(1, 0, 0, 500), 10);
        assert!(ext.contains(100));
        assert!(ext.contains(105));
        assert!(ext.contains(109));
        assert!(!ext.contains(99));
        assert!(!ext.contains(110));
    }

    #[test]
    fn test_extent_get_physical() {
        let ext = Extent::new(100, BlockAddr::new(1, 0, 0, 500), 10);
        let phys = ext.get_physical(105).unwrap();
        assert_eq!(phys.block_offset(), 505);
    }

    #[test]
    fn test_extent_serialization() {
        let ext = Extent::new(123, BlockAddr::new(1, 2, 3, 456), 789);
        let bytes = ext.to_bytes();
        let recovered = Extent::from_bytes(&bytes);
        assert_eq!(ext.logical_block, recovered.logical_block);
        assert_eq!(ext.physical_block, recovered.physical_block);
        assert_eq!(ext.length, recovered.length);
    }

    #[test]
    fn test_header_serialization() {
        let header = ExtentHeader::new(100, 2);
        let bytes = header.to_bytes();
        let recovered = ExtentHeader::from_bytes(&bytes);
        assert_eq!(header.magic, recovered.magic);
        assert_eq!(header.max_entries, recovered.max_entries);
        assert_eq!(header.depth, recovered.depth);
    }
}
