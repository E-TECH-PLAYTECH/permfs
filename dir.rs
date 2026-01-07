// PermFS Directory Operations

use crate::*;

// ============================================================================
// DIRECTORY ENTRY HELPERS
// ============================================================================

impl DirEntry {
    pub const HEADER_SIZE: usize = 12; // inode(8) + rec_len(2) + name_len(1) + file_type(1)
    pub const MIN_SIZE: usize = Self::HEADER_SIZE + 1; // at least 1 char name

    /// Create a new directory entry
    pub fn new(inode: u64, name: &[u8], file_type: u8) -> Self {
        let mut entry = Self {
            inode,
            rec_len: Self::entry_size(name.len()) as u16,
            name_len: name.len() as u8,
            file_type,
            name: [0u8; MAX_FILENAME_LEN],
        };
        entry.name[..name.len()].copy_from_slice(name);
        entry
    }

    /// Calculate aligned entry size for a name
    #[inline]
    pub fn entry_size(name_len: usize) -> usize {
        // Align to 8 bytes
        (Self::HEADER_SIZE + name_len + 7) & !7
    }

    /// Get the name as a slice
    pub fn name_slice(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    /// Check if entry is deleted (inode == 0)
    pub fn is_deleted(&self) -> bool {
        self.inode == 0
    }

    /// Safely read a DirEntry from a byte slice at the given offset.
    /// Returns None if there isn't enough data or rec_len is 0.
    pub fn read_from_bytes(buf: &[u8], offset: usize) -> Option<Self> {
        if offset + Self::HEADER_SIZE > buf.len() {
            return None;
        }

        let inode = u64::from_le_bytes(buf[offset..offset + 8].try_into().ok()?);
        let rec_len = u16::from_le_bytes(buf[offset + 8..offset + 10].try_into().ok()?);
        let name_len = buf[offset + 10];
        let file_type = buf[offset + 11];

        if rec_len == 0 {
            return None;
        }

        let name_start = offset + Self::HEADER_SIZE;
        let name_end = name_start + (name_len as usize).min(MAX_FILENAME_LEN);
        if name_end > buf.len() {
            return None;
        }

        let mut name = [0u8; MAX_FILENAME_LEN];
        let copy_len = (name_len as usize).min(MAX_FILENAME_LEN);
        if name_start + copy_len <= buf.len() {
            name[..copy_len].copy_from_slice(&buf[name_start..name_start + copy_len]);
        }

        Some(Self {
            inode,
            rec_len,
            name_len,
            file_type,
            name,
        })
    }

    /// Safely write a DirEntry to a byte slice at the given offset.
    /// Returns false if there isn't enough space.
    pub fn write_to_bytes(&self, buf: &mut [u8], offset: usize) -> bool {
        let total_size = Self::HEADER_SIZE + self.name_len as usize;
        if offset + total_size > buf.len() {
            return false;
        }

        buf[offset..offset + 8].copy_from_slice(&self.inode.to_le_bytes());
        buf[offset + 8..offset + 10].copy_from_slice(&self.rec_len.to_le_bytes());
        buf[offset + 10] = self.name_len;
        buf[offset + 11] = self.file_type;
        buf[offset + Self::HEADER_SIZE..offset + Self::HEADER_SIZE + self.name_len as usize]
            .copy_from_slice(&self.name[..self.name_len as usize]);

        true
    }

    /// Update the rec_len field in a byte buffer at the given offset.
    pub fn write_rec_len(buf: &mut [u8], offset: usize, rec_len: u16) {
        if offset + 10 <= buf.len() {
            buf[offset + 8..offset + 10].copy_from_slice(&rec_len.to_le_bytes());
        }
    }

    /// Update the inode field in a byte buffer at the given offset (for deletion).
    pub fn write_inode(buf: &mut [u8], offset: usize, inode: u64) {
        if offset + 8 <= buf.len() {
            buf[offset..offset + 8].copy_from_slice(&inode.to_le_bytes());
        }
    }
}

// File type constants (matching ext4)
pub mod file_type {
    pub const UNKNOWN: u8 = 0;
    pub const REGULAR: u8 = 1;
    pub const DIRECTORY: u8 = 2;
    pub const CHARDEV: u8 = 3;
    pub const BLOCKDEV: u8 = 4;
    pub const FIFO: u8 = 5;
    pub const SOCKET: u8 = 6;
    pub const SYMLINK: u8 = 7;
}

// ============================================================================
// DIRECTORY IMPLEMENTATION
// ============================================================================

impl<B: BlockDevice, T: ClusterTransport> PermFs<B, T> {
    /// Find a directory entry by name
    pub fn find_dirent(&self, parent: &Inode, name: &[u8]) -> FsResult<u64> {
        if name.is_empty() || name.len() > MAX_FILENAME_LEN {
            return Err(IoError::NotFound);
        }

        let mut offset = 0u64;
        let mut buf = [0u8; BLOCK_SIZE];

        while offset < parent.size {
            let block_addr = self.get_block_for_offset(parent, offset)?;
            self.read_block(block_addr, &mut buf)?;

            let mut pos = 0usize;
            while pos + DirEntry::HEADER_SIZE <= BLOCK_SIZE {
                let entry = match DirEntry::read_from_bytes(&buf, pos) {
                    Some(e) => e,
                    None => break, // End of entries or invalid
                };

                if !entry.is_deleted() && entry.name_len as usize == name.len() {
                    if &entry.name[..name.len()] == name {
                        return Ok(entry.inode);
                    }
                }

                pos += entry.rec_len as usize;
            }

            offset += BLOCK_SIZE as u64;
        }

        Err(IoError::NotFound)
    }

    /// Add a directory entry to parent
    pub fn add_dirent(
        &self,
        parent_ino: u64,
        name: &[u8],
        child_ino: u64,
        file_type: u8,
        sb: &Superblock,
    ) -> FsResult<()> {
        if name.is_empty() || name.len() > MAX_FILENAME_LEN {
            return Err(IoError::InvalidAddress);
        }

        let mut parent = self.read_inode(parent_ino, sb)?;
        let needed_size = DirEntry::entry_size(name.len());

        // Search existing blocks for space
        let mut offset = 0u64;
        let mut buf = [0u8; BLOCK_SIZE];

        while offset < parent.size {
            let block_addr = self.get_block_for_offset(&parent, offset)?;
            self.read_block(block_addr, &mut buf)?;

            if let Some(insert_pos) = self.find_dirent_slot(&buf, needed_size) {
                // Found space — insert here
                let entry = DirEntry::new(child_ino, name, file_type);
                self.insert_dirent_at(&mut buf, insert_pos, &entry, needed_size);
                self.write_block(block_addr, &buf)?;

                parent.mtime = self.current_time();
                parent.ctime = self.current_time();
                self.write_inode(parent_ino, &parent, sb)?;
                return Ok(());
            }

            offset += BLOCK_SIZE as u64;
        }

        // No space in existing blocks — allocate new block
        let new_block = self
            .alloc_block(Some(sb.volume_id))
            .map_err(|_| IoError::IoFailed)?;

        // Initialize new directory block
        buf.fill(0);
        let mut entry = DirEntry::new(child_ino, name, file_type);
        // Set rec_len to fill rest of block (last entry convention)
        entry.rec_len = BLOCK_SIZE as u16;
        entry.write_to_bytes(&mut buf, 0);

        self.write_block(new_block, &buf)?;

        // Update inode to point to new block
        let parent_size = parent.size;
        self.set_block_for_offset(&mut parent, parent_size, new_block, sb)?;
        parent.size += BLOCK_SIZE as u64;
        parent.blocks += 1;
        parent.mtime = self.current_time();
        parent.ctime = self.current_time();
        self.write_inode(parent_ino, &parent, sb)?;

        Ok(())
    }

    /// Remove a directory entry by name
    pub fn remove_dirent(&self, parent_ino: u64, name: &[u8], sb: &Superblock) -> FsResult<()> {
        let mut parent = self.read_inode(parent_ino, sb)?;
        let mut offset = 0u64;
        let mut buf = [0u8; BLOCK_SIZE];

        while offset < parent.size {
            let block_addr = self.get_block_for_offset(&parent, offset)?;
            self.read_block(block_addr, &mut buf)?;

            let mut pos = 0usize;
            let mut prev_pos: Option<usize> = None;
            let mut prev_rec_len: u16 = 0;

            while pos + DirEntry::HEADER_SIZE <= BLOCK_SIZE {
                let entry = match DirEntry::read_from_bytes(&buf, pos) {
                    Some(e) => e,
                    None => break,
                };

                if !entry.is_deleted()
                    && entry.name_len as usize == name.len()
                    && &entry.name[..name.len()] == name
                {
                    // Found it — mark as deleted
                    if let Some(prev) = prev_pos {
                        // Merge with previous entry by extending its rec_len
                        let new_rec_len = prev_rec_len + entry.rec_len;
                        DirEntry::write_rec_len(&mut buf, prev, new_rec_len);
                    } else {
                        // First entry — just zero the inode
                        DirEntry::write_inode(&mut buf, pos, 0);
                    }

                    self.write_block(block_addr, &buf)?;

                    parent.mtime = self.current_time();
                    parent.ctime = self.current_time();
                    self.write_inode(parent_ino, &parent, sb)?;
                    return Ok(());
                }

                prev_pos = Some(pos);
                prev_rec_len = entry.rec_len;
                pos += entry.rec_len as usize;
            }

            offset += BLOCK_SIZE as u64;
        }

        Err(IoError::NotFound)
    }

    /// Initialize a directory block with . and .. entries
    pub fn init_directory_block(
        &self,
        block: BlockAddr,
        self_ino: u64,
        parent_ino: u64,
    ) -> FsResult<()> {
        let mut buf = [0u8; BLOCK_SIZE];

        // "." entry
        let dot_size = DirEntry::entry_size(1);
        let mut dot = DirEntry::new(self_ino, b".", file_type::DIRECTORY);
        dot.rec_len = dot_size as u16;
        dot.write_to_bytes(&mut buf, 0);

        // ".." entry — gets rest of block
        let dotdot_size = BLOCK_SIZE - dot_size;
        let mut dotdot = DirEntry::new(parent_ino, b"..", file_type::DIRECTORY);
        dotdot.rec_len = dotdot_size as u16;
        dotdot.write_to_bytes(&mut buf, dot_size);

        self.write_block(block, &buf)
    }

    /// Check if directory is empty (only . and ..)
    pub fn is_dir_empty(&self, ino: u64, sb: &Superblock) -> FsResult<bool> {
        let inode = self.read_inode(ino, sb)?;
        let mut offset = 0u64;
        let mut buf = [0u8; BLOCK_SIZE];
        let mut count = 0;

        while offset < inode.size {
            let block_addr = self.get_block_for_offset(&inode, offset)?;
            self.read_block(block_addr, &mut buf)?;

            let mut pos = 0usize;
            while pos + DirEntry::HEADER_SIZE <= BLOCK_SIZE {
                let entry = match DirEntry::read_from_bytes(&buf, pos) {
                    Some(e) => e,
                    None => break,
                };

                if !entry.is_deleted() {
                    let name = entry.name_slice();
                    if name != b"." && name != b".." {
                        return Ok(false); // Found a real entry
                    }
                    count += 1;
                }

                pos += entry.rec_len as usize;
            }

            offset += BLOCK_SIZE as u64;
        }

        Ok(count <= 2) // Only . and .. (or less if corrupted)
    }

    // ========================================================================
    // HELPERS
    // ========================================================================

    /// Find a slot in a directory block that can fit `needed_size` bytes
    fn find_dirent_slot(&self, buf: &[u8; BLOCK_SIZE], needed_size: usize) -> Option<usize> {
        let mut pos = 0usize;

        while pos + DirEntry::HEADER_SIZE <= BLOCK_SIZE {
            let entry = match DirEntry::read_from_bytes(buf, pos) {
                Some(e) => e,
                None => {
                    // End of entries — check remaining space
                    let remaining = BLOCK_SIZE - pos;
                    if remaining >= needed_size {
                        return Some(pos);
                    }
                    return None;
                }
            };

            let actual_size = if entry.is_deleted() {
                0
            } else {
                DirEntry::entry_size(entry.name_len as usize)
            };

            let slack = entry.rec_len as usize - actual_size;
            if slack >= needed_size {
                return Some(pos);
            }

            pos += entry.rec_len as usize;
        }

        None
    }

    /// Insert a directory entry, splitting existing entry if needed
    fn insert_dirent_at(
        &self,
        buf: &mut [u8; BLOCK_SIZE],
        pos: usize,
        new_entry: &DirEntry,
        _needed_size: usize,
    ) {
        let existing = DirEntry::read_from_bytes(buf, pos);

        match existing {
            None => {
                // Empty slot — just write with rec_len filling to end of block
                let mut entry = new_entry.clone();
                entry.rec_len = (BLOCK_SIZE - pos) as u16;
                entry.write_to_bytes(buf, pos);
            }
            Some(ex) if ex.is_deleted() => {
                // Deleted slot — reuse with same rec_len
                let mut entry = new_entry.clone();
                entry.rec_len = ex.rec_len;
                entry.write_to_bytes(buf, pos);
            }
            Some(ex) => {
                // Split existing entry
                let existing_actual = DirEntry::entry_size(ex.name_len as usize);
                let old_rec_len = ex.rec_len;

                // Shrink existing entry's rec_len
                DirEntry::write_rec_len(buf, pos, existing_actual as u16);

                // Write new entry after it
                let new_pos = pos + existing_actual;
                let new_rec_len = old_rec_len - existing_actual as u16;
                let mut entry = new_entry.clone();
                entry.rec_len = new_rec_len;
                entry.write_to_bytes(buf, new_pos);
            }
        }
    }
}
