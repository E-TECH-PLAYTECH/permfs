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
                let entry = unsafe {
                    &*(buf.as_ptr().add(pos) as *const DirEntry)
                };

                if entry.rec_len == 0 {
                    break; // End of entries in this block
                }

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
        let new_block = self.alloc_block(Some(sb.volume_id))
            .map_err(|_| IoError::IoFailed)?;

        // Initialize new directory block
        buf.fill(0);
        let entry = DirEntry::new(child_ino, name, file_type);
        let entry_bytes = unsafe {
            core::slice::from_raw_parts(
                &entry as *const DirEntry as *const u8,
                DirEntry::HEADER_SIZE + name.len(),
            )
        };
        buf[..entry_bytes.len()].copy_from_slice(entry_bytes);

        // Set rec_len to fill rest of block (last entry convention)
        let rec_len_offset = 8; // offset of rec_len in DirEntry
        let fill_len = (BLOCK_SIZE - DirEntry::entry_size(name.len())) as u16 
                       + DirEntry::entry_size(name.len()) as u16;
        buf[rec_len_offset..rec_len_offset + 2].copy_from_slice(&fill_len.to_le_bytes());

        self.write_block(new_block, &buf)?;

        // Update inode to point to new block
        self.set_block_for_offset(&mut parent, parent.size, new_block, sb)?;
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

            while pos + DirEntry::HEADER_SIZE <= BLOCK_SIZE {
                let entry = unsafe {
                    &*(buf.as_ptr().add(pos) as *const DirEntry)
                };

                if entry.rec_len == 0 {
                    break;
                }

                if !entry.is_deleted() 
                    && entry.name_len as usize == name.len()
                    && &entry.name[..name.len()] == name 
                {
                    // Found it — mark as deleted
                    if let Some(prev) = prev_pos {
                        // Merge with previous entry
                        let prev_entry = unsafe {
                            &mut *(buf.as_mut_ptr().add(prev) as *mut DirEntry)
                        };
                        prev_entry.rec_len += entry.rec_len;
                    } else {
                        // First entry — just zero the inode
                        let entry_mut = unsafe {
                            &mut *(buf.as_mut_ptr().add(pos) as *mut DirEntry)
                        };
                        entry_mut.inode = 0;
                    }

                    self.write_block(block_addr, &buf)?;

                    parent.mtime = self.current_time();
                    parent.ctime = self.current_time();
                    self.write_inode(parent_ino, &parent, sb)?;
                    return Ok(());
                }

                prev_pos = Some(pos);
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
        let dot = DirEntry::new(self_ino, b".", file_type::DIRECTORY);
        let dot_size = DirEntry::entry_size(1);

        // ".." entry — gets rest of block
        let dotdot = DirEntry::new(parent_ino, b"..", file_type::DIRECTORY);

        // Write "."
        let dot_bytes = unsafe {
            core::slice::from_raw_parts(&dot as *const _ as *const u8, dot_size)
        };
        buf[..dot_size].copy_from_slice(dot_bytes);
        // Patch rec_len for "."
        buf[8..10].copy_from_slice(&(dot_size as u16).to_le_bytes());

        // Write ".." at offset dot_size
        let dotdot_size = BLOCK_SIZE - dot_size;
        buf[dot_size..dot_size + DirEntry::HEADER_SIZE + 2].copy_from_slice(unsafe {
            core::slice::from_raw_parts(&dotdot as *const _ as *const u8, DirEntry::HEADER_SIZE + 2)
        });
        // Patch rec_len for ".." to fill rest of block
        buf[dot_size + 8..dot_size + 10].copy_from_slice(&(dotdot_size as u16).to_le_bytes());

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
                let entry = unsafe {
                    &*(buf.as_ptr().add(pos) as *const DirEntry)
                };

                if entry.rec_len == 0 {
                    break;
                }

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
            let entry = unsafe {
                &*(buf.as_ptr().add(pos) as *const DirEntry)
            };

            if entry.rec_len == 0 {
                // End of entries — check remaining space
                let remaining = BLOCK_SIZE - pos;
                if remaining >= needed_size {
                    return Some(pos);
                }
                return None;
            }

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
        needed_size: usize,
    ) {
        let existing = unsafe {
            &mut *(buf.as_mut_ptr().add(pos) as *mut DirEntry)
        };

        if existing.rec_len == 0 || existing.is_deleted() {
            // Empty slot — just write
            let entry_bytes = unsafe {
                core::slice::from_raw_parts(
                    new_entry as *const _ as *const u8,
                    DirEntry::HEADER_SIZE + new_entry.name_len as usize,
                )
            };
            buf[pos..pos + entry_bytes.len()].copy_from_slice(entry_bytes);

            // Set rec_len to fill to end of block or existing rec_len
            let rec_len = if existing.rec_len == 0 {
                (BLOCK_SIZE - pos) as u16
            } else {
                existing.rec_len
            };
            buf[pos + 8..pos + 10].copy_from_slice(&rec_len.to_le_bytes());
        } else {
            // Split existing entry
            let existing_actual = DirEntry::entry_size(existing.name_len as usize);
            let old_rec_len = existing.rec_len;

            // Shrink existing entry
            existing.rec_len = existing_actual as u16;

            // Write new entry after it
            let new_pos = pos + existing_actual;
            let entry_bytes = unsafe {
                core::slice::from_raw_parts(
                    new_entry as *const _ as *const u8,
                    DirEntry::HEADER_SIZE + new_entry.name_len as usize,
                )
            };
            buf[new_pos..new_pos + entry_bytes.len()].copy_from_slice(entry_bytes);

            // New entry gets remaining space
            let new_rec_len = old_rec_len - existing_actual as u16;
            buf[new_pos + 8..new_pos + 10].copy_from_slice(&new_rec_len.to_le_bytes());
        }
    }
}
