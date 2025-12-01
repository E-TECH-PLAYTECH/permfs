// PermFS Write Path & Inode Allocation

use crate::*;
use core::sync::atomic::Ordering;

// ============================================================================
// INODE BITMAP ALLOCATOR
// ============================================================================

impl<B: BlockDevice, T: ClusterTransport> PermFs<B, T> {
    /// Allocate a free inode number
    pub fn alloc_inode(&self, sb: &Superblock) -> FsResult<u64> {
        let bits_per_block = (BLOCK_SIZE * 8) as u64;
        let bitmap_blocks = (sb.total_inodes + bits_per_block - 1) / bits_per_block;

        let mut buf = [0u8; BLOCK_SIZE];

        for block_idx in 0..bitmap_blocks {
            let mut bitmap_addr = sb.first_inode_table;
            bitmap_addr.limbs[0] = 1 + block_idx; // Block 0 = superblock, 1+ = bitmap

            self.read_block(bitmap_addr, &mut buf)?;

            for word_idx in 0..(BLOCK_SIZE / 8) {
                let word =
                    u64::from_le_bytes(buf[word_idx * 8..(word_idx + 1) * 8].try_into().unwrap());

                if word != u64::MAX {
                    let bit = (!word).trailing_zeros() as u64;
                    let ino = block_idx * bits_per_block + (word_idx as u64) * 64 + bit;

                    if ino >= sb.total_inodes {
                        continue;
                    }

                    // Set the bit
                    let new_word = word | (1u64 << bit);
                    buf[word_idx * 8..(word_idx + 1) * 8].copy_from_slice(&new_word.to_le_bytes());

                    self.write_block(bitmap_addr, &buf)?;
                    sb.free_inodes.fetch_sub(1, Ordering::Relaxed);
                    return Ok(ino);
                }
            }
        }

        Err(IoError::IoFailed) // No free inodes
    }

    /// Free an inode number
    pub fn free_inode(&self, ino: u64, sb: &Superblock) -> FsResult<()> {
        let bits_per_block = (BLOCK_SIZE * 8) as u64;
        let block_idx = ino / bits_per_block;
        let bit_in_block = ino % bits_per_block;
        let word_idx = (bit_in_block / 64) as usize;
        let bit_in_word = bit_in_block % 64;

        let mut bitmap_addr = sb.first_inode_table;
        bitmap_addr.limbs[0] = 1 + block_idx;

        let mut buf = [0u8; BLOCK_SIZE];
        self.read_block(bitmap_addr, &mut buf)?;

        let word = u64::from_le_bytes(buf[word_idx * 8..(word_idx + 1) * 8].try_into().unwrap());

        let new_word = word & !(1u64 << bit_in_word);
        buf[word_idx * 8..(word_idx + 1) * 8].copy_from_slice(&new_word.to_le_bytes());

        self.write_block(bitmap_addr, &buf)?;
        sb.free_inodes.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

// ============================================================================
// WRITE FILE IMPLEMENTATION
// ============================================================================

impl<B: BlockDevice, T: ClusterTransport> PermFs<B, T> {
    /// Write data to a file, allocating blocks as needed
    pub fn write_file(
        &self,
        inode: &mut Inode,
        offset: u64,
        data: &[u8],
        sb: &Superblock,
    ) -> FsResult<usize> {
        if data.is_empty() {
            return Ok(0);
        }

        let mut written = 0usize;
        let mut file_offset = offset;
        let end_offset = offset + data.len() as u64;

        while file_offset < end_offset {
            let offset_in_block = (file_offset % BLOCK_SIZE as u64) as usize;
            let bytes_to_write = core::cmp::min(
                BLOCK_SIZE - offset_in_block,
                (end_offset - file_offset) as usize,
            );

            // Get or allocate block
            let block_addr = match self.get_block_for_offset(inode, file_offset) {
                Ok(addr) => addr,
                Err(IoError::NotFound) => {
                    // Allocate new block
                    let new_block = self
                        .alloc_block(Some(sb.volume_id))
                        .map_err(|_| IoError::IoFailed)?;
                    self.set_block_for_offset(inode, file_offset, new_block, sb)?;
                    inode.blocks += 1;
                    new_block
                }
                Err(e) => return Err(e),
            };

            // Read-modify-write if partial block
            let mut buf = [0u8; BLOCK_SIZE];
            if offset_in_block != 0 || bytes_to_write != BLOCK_SIZE {
                let _ = self.read_block(block_addr, &mut buf);
            }

            buf[offset_in_block..offset_in_block + bytes_to_write]
                .copy_from_slice(&data[written..written + bytes_to_write]);

            self.write_block(block_addr, &buf)?;

            written += bytes_to_write;
            file_offset += bytes_to_write as u64;
        }

        // Update size if we extended the file
        if offset + written as u64 > inode.size {
            inode.size = offset + written as u64;
        }

        inode.mtime = self.current_time();
        inode.ctime = self.current_time();

        Ok(written)
    }

    /// Set block address for a file offset, allocating indirect blocks as needed
    pub fn set_block_for_offset(
        &self,
        inode: &mut Inode,
        offset: u64,
        block: BlockAddr,
        sb: &Superblock,
    ) -> FsResult<()> {
        let block_num = offset / BLOCK_SIZE as u64;
        let direct_limit = INODE_DIRECT_BLOCKS as u64;
        let ptrs_per_block = (BLOCK_SIZE / core::mem::size_of::<BlockAddr>()) as u64;

        if block_num < direct_limit {
            inode.direct[block_num as usize] = block;
            return Ok(());
        }

        let mut remaining = block_num - direct_limit;

        // Single indirect
        if remaining < ptrs_per_block {
            if inode.indirect[0].is_null() {
                inode.indirect[0] = self
                    .alloc_block(Some(sb.volume_id))
                    .map_err(|_| IoError::IoFailed)?;
                self.zero_block(inode.indirect[0])?;
                inode.blocks += 1;
            }
            return self.write_indirect_ptr(inode.indirect[0], remaining as usize, block);
        }
        remaining -= ptrs_per_block;

        // Double indirect
        let double_limit = ptrs_per_block * ptrs_per_block;
        if remaining < double_limit {
            if inode.indirect[1].is_null() {
                inode.indirect[1] = self
                    .alloc_block(Some(sb.volume_id))
                    .map_err(|_| IoError::IoFailed)?;
                self.zero_block(inode.indirect[1])?;
                inode.blocks += 1;
            }

            let l1_idx = remaining / ptrs_per_block;
            let l2_idx = remaining % ptrs_per_block;

            let mut l1_block = self
                .read_indirect_ptr(inode.indirect[1], l1_idx as usize)
                .unwrap_or(BlockAddr::NULL);

            if l1_block.is_null() {
                l1_block = self
                    .alloc_block(Some(sb.volume_id))
                    .map_err(|_| IoError::IoFailed)?;
                self.zero_block(l1_block)?;
                self.write_indirect_ptr(inode.indirect[1], l1_idx as usize, l1_block)?;
                inode.blocks += 1;
            }

            return self.write_indirect_ptr(l1_block, l2_idx as usize, block);
        }
        remaining -= double_limit;

        // Triple indirect
        if inode.indirect[2].is_null() {
            inode.indirect[2] = self
                .alloc_block(Some(sb.volume_id))
                .map_err(|_| IoError::IoFailed)?;
            self.zero_block(inode.indirect[2])?;
            inode.blocks += 1;
        }

        let l1_idx = remaining / (ptrs_per_block * ptrs_per_block);
        let l2_idx = (remaining / ptrs_per_block) % ptrs_per_block;
        let l3_idx = remaining % ptrs_per_block;

        let mut l1_block = self
            .read_indirect_ptr(inode.indirect[2], l1_idx as usize)
            .unwrap_or(BlockAddr::NULL);
        if l1_block.is_null() {
            l1_block = self
                .alloc_block(Some(sb.volume_id))
                .map_err(|_| IoError::IoFailed)?;
            self.zero_block(l1_block)?;
            self.write_indirect_ptr(inode.indirect[2], l1_idx as usize, l1_block)?;
            inode.blocks += 1;
        }

        let mut l2_block = self
            .read_indirect_ptr(l1_block, l2_idx as usize)
            .unwrap_or(BlockAddr::NULL);
        if l2_block.is_null() {
            l2_block = self
                .alloc_block(Some(sb.volume_id))
                .map_err(|_| IoError::IoFailed)?;
            self.zero_block(l2_block)?;
            self.write_indirect_ptr(l1_block, l2_idx as usize, l2_block)?;
            inode.blocks += 1;
        }

        self.write_indirect_ptr(l2_block, l3_idx as usize, block)
    }

    /// Write a pointer into an indirect block
    fn write_indirect_ptr(&self, block: BlockAddr, idx: usize, ptr: BlockAddr) -> FsResult<()> {
        let mut buf = [0u8; BLOCK_SIZE];
        self.read_block(block, &mut buf)?;

        let offset = idx * core::mem::size_of::<BlockAddr>();
        buf[offset..offset + 32].copy_from_slice(&ptr.to_bytes());

        self.write_block(block, &buf)
    }

    /// Zero out a block
    fn zero_block(&self, addr: BlockAddr) -> FsResult<()> {
        let buf = [0u8; BLOCK_SIZE];
        self.write_block(addr, &buf)
    }

    /// Truncate file, freeing blocks beyond new size
    pub fn truncate_internal(
        &self,
        inode: &mut Inode,
        new_size: u64,
        sb: &Superblock,
    ) -> FsResult<()> {
        if new_size >= inode.size {
            inode.size = new_size;
            return Ok(());
        }

        let old_blocks = (inode.size + BLOCK_SIZE as u64 - 1) / BLOCK_SIZE as u64;
        let new_blocks = (new_size + BLOCK_SIZE as u64 - 1) / BLOCK_SIZE as u64;

        // Free blocks from new_blocks to old_blocks
        for block_num in new_blocks..old_blocks {
            if let Ok(addr) = self.get_block_for_offset(inode, block_num * BLOCK_SIZE as u64) {
                let _ = self.free_block(addr);
                inode.blocks = inode.blocks.saturating_sub(1);
            }
        }

        // Zero partial block at end if needed
        if new_size > 0 {
            let last_block_offset = (new_size - 1) / BLOCK_SIZE as u64 * BLOCK_SIZE as u64;
            let bytes_in_last = (new_size % BLOCK_SIZE as u64) as usize;
            if bytes_in_last > 0 {
                if let Ok(addr) = self.get_block_for_offset(inode, last_block_offset) {
                    let mut buf = [0u8; BLOCK_SIZE];
                    self.read_block(addr, &mut buf)?;
                    buf[bytes_in_last..].fill(0);
                    self.write_block(addr, &buf)?;
                }
            }
        }

        inode.size = new_size;
        inode.mtime = self.current_time();
        inode.ctime = self.current_time();

        Ok(())
    }

    /// Free all blocks belonging to an inode
    pub fn free_inode_blocks(&self, inode: &Inode) -> FsResult<()> {
        // Free direct blocks
        for addr in &inode.direct {
            if !addr.is_null() {
                let _ = self.free_block(*addr);
            }
        }

        // Free single indirect
        if !inode.indirect[0].is_null() {
            self.free_indirect_tree(inode.indirect[0], 1)?;
        }

        // Free double indirect
        if !inode.indirect[1].is_null() {
            self.free_indirect_tree(inode.indirect[1], 2)?;
        }

        // Free triple indirect
        if !inode.indirect[2].is_null() {
            self.free_indirect_tree(inode.indirect[2], 3)?;
        }

        Ok(())
    }

    /// Recursively free indirect block tree
    fn free_indirect_tree(&self, block: BlockAddr, depth: usize) -> FsResult<()> {
        if depth == 0 || block.is_null() {
            return Ok(());
        }

        let mut buf = [0u8; BLOCK_SIZE];
        self.read_block(block, &mut buf)?;

        let ptrs_count = BLOCK_SIZE / core::mem::size_of::<BlockAddr>();

        for i in 0..ptrs_count {
            let offset = i * 32;
            let ptr = BlockAddr::from_bytes(buf[offset..offset + 32].try_into().unwrap());

            if !ptr.is_null() {
                if depth == 1 {
                    let _ = self.free_block(ptr);
                } else {
                    self.free_indirect_tree(ptr, depth - 1)?;
                }
            }
        }

        self.free_block(block).map_err(|_| IoError::IoFailed)?;
        Ok(())
    }
}
