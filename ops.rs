// PermFS Extended Operations — rename, link, symlink, readlink

use crate::dir::file_type;
use crate::*;

const INLINE_SYMLINK_MAX: usize = INODE_DIRECT_BLOCKS * core::mem::size_of::<BlockAddr>();

impl<B: BlockDevice, T: ClusterTransport> PermFs<B, T> {
    /// Create a hard link
    pub fn link_impl(
        &self,
        ino: u64,
        new_parent: u64,
        new_name: &[u8],
        sb: &Superblock,
    ) -> FsResult<()> {
        let mut inode = self.read_inode(ino, sb)?;
        if inode.is_dir() {
            return Err(IoError::PermissionDenied);
        }

        self.add_dirent(new_parent, new_name, ino, file_type::REGULAR, sb)?;

        inode.nlink += 1;
        inode.ctime = self.current_time();
        self.write_inode(ino, &inode, sb)?;

        Ok(())
    }

    /// Create a symbolic link
    pub fn symlink_impl(
        &self,
        parent: u64,
        name: &[u8],
        target: &[u8],
        sb: &Superblock,
    ) -> FsResult<u64> {
        if target.is_empty() || target.len() > BLOCK_SIZE {
            return Err(IoError::InvalidAddress);
        }

        let ino = self.alloc_inode(sb)?;
        let now = self.current_time();

        let mut inode = Inode {
            mode: 0o120777,
            uid: 0,
            gid: 0,
            flags: 0,
            size: target.len() as u64,
            blocks: 0,
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
            nlink: 1,
            generation: 0,
            direct: [BlockAddr::NULL; INODE_DIRECT_BLOCKS],
            indirect: [BlockAddr::NULL; INODE_INDIRECT_LEVELS],
            extent_root: BlockAddr::NULL,
            xattr_block: BlockAddr::NULL,
            checksum: 0,
        };

        if target.len() <= INLINE_SYMLINK_MAX {
            let ptr = inode.direct.as_mut_ptr() as *mut u8;
            unsafe {
                core::ptr::copy_nonoverlapping(target.as_ptr(), ptr, target.len());
            }
        } else {
            let block = self
                .alloc_block(Some(sb.volume_id))
                .map_err(|_| IoError::IoFailed)?;
            let mut buf = [0u8; BLOCK_SIZE];
            buf[..target.len()].copy_from_slice(target);
            self.write_block(block, &buf)?;
            inode.direct[0] = block;
            inode.blocks = 1;
        }

        self.write_inode(ino, &inode, sb)?;
        self.add_dirent(parent, name, ino, file_type::SYMLINK, sb)?;

        Ok(ino)
    }

    /// Read symbolic link target
    pub fn readlink_impl(&self, ino: u64, buf: &mut [u8], sb: &Superblock) -> FsResult<usize> {
        let inode = self.read_inode(ino, sb)?;
        if !inode.is_symlink() {
            return Err(IoError::InvalidAddress);
        }

        let len = core::cmp::min(inode.size as usize, buf.len());

        if inode.size as usize <= INLINE_SYMLINK_MAX {
            let ptr = inode.direct.as_ptr() as *const u8;
            unsafe {
                core::ptr::copy_nonoverlapping(ptr, buf.as_mut_ptr(), len);
            }
        } else {
            let mut block_buf = [0u8; BLOCK_SIZE];
            self.read_block(inode.direct[0], &mut block_buf)?;
            buf[..len].copy_from_slice(&block_buf[..len]);
        }

        Ok(len)
    }

    /// Rename a file or directory
    pub fn rename_impl(
        &self,
        old_parent: u64,
        old_name: &[u8],
        new_parent: u64,
        new_name: &[u8],
        sb: &Superblock,
    ) -> FsResult<()> {
        let old_parent_inode = self.read_inode(old_parent, sb)?;
        let ino = self.find_dirent(&old_parent_inode, old_name)?;
        let inode = self.read_inode(ino, sb)?;

        let file_type = if inode.is_dir() {
            file_type::DIRECTORY
        } else if inode.is_symlink() {
            file_type::SYMLINK
        } else {
            file_type::REGULAR
        };

        let new_parent_inode = self.read_inode(new_parent, sb)?;
        if let Ok(existing_ino) = self.find_dirent(&new_parent_inode, new_name) {
            let existing = self.read_inode(existing_ino, sb)?;

            if existing.is_dir() != inode.is_dir() {
                return Err(IoError::PermissionDenied);
            }

            if existing.is_dir() && !self.is_dir_empty(existing_ino, sb)? {
                return Err(IoError::PermissionDenied);
            }

            self.remove_dirent(new_parent, new_name, sb)?;

            let mut existing = existing;
            existing.nlink -= 1;
            if existing.nlink == 0 {
                self.free_inode_blocks(&existing)?;
                self.free_inode(existing_ino, sb)?;
            } else {
                self.write_inode(existing_ino, &existing, sb)?;
            }
        }

        self.add_dirent(new_parent, new_name, ino, file_type, sb)?;
        self.remove_dirent(old_parent, old_name, sb)?;

        if inode.is_dir() && old_parent != new_parent {
            self.update_dotdot(ino, new_parent, sb)?;

            let mut old_p = self.read_inode(old_parent, sb)?;
            let mut new_p = self.read_inode(new_parent, sb)?;
            old_p.nlink -= 1;
            new_p.nlink += 1;
            self.write_inode(old_parent, &old_p, sb)?;
            self.write_inode(new_parent, &new_p, sb)?;
        }

        let mut inode = inode;
        inode.ctime = self.current_time();
        self.write_inode(ino, &inode, sb)?;

        Ok(())
    }

    fn update_dotdot(&self, dir_ino: u64, new_parent: u64, sb: &Superblock) -> FsResult<()> {
        let inode = self.read_inode(dir_ino, sb)?;
        let block_addr = self.get_block_for_offset(&inode, 0)?;
        let mut buf = [0u8; BLOCK_SIZE];
        self.read_block(block_addr, &mut buf)?;

        let dot_rec_len = u16::from_le_bytes([buf[8], buf[9]]) as usize;
        let dotdot_offset = dot_rec_len;
        buf[dotdot_offset..dotdot_offset + 8].copy_from_slice(&new_parent.to_le_bytes());

        self.write_block(block_addr, &buf)
    }

    /// Get extended attribute
    #[cfg(feature = "std")]
    pub fn getxattr(
        &self,
        ino: u64,
        name: &[u8],
        buf: &mut [u8],
        sb: &Superblock,
    ) -> FsResult<usize> {
        self.getxattr_impl(ino, name, buf, sb)
    }

    /// Get extended attribute (no-std stub)
    #[cfg(not(feature = "std"))]
    pub fn getxattr(
        &self,
        _ino: u64,
        _name: &[u8],
        _buf: &mut [u8],
        _sb: &Superblock,
    ) -> FsResult<usize> {
        Err(IoError::NotFound)
    }

    /// Set extended attribute
    #[cfg(feature = "std")]
    pub fn setxattr(
        &self,
        ino: u64,
        name: &[u8],
        value: &[u8],
        flags: u32,
        sb: &Superblock,
    ) -> FsResult<()> {
        self.setxattr_impl(ino, name, value, flags, sb)
    }

    /// Set extended attribute (no-std stub)
    #[cfg(not(feature = "std"))]
    pub fn setxattr(
        &self,
        _ino: u64,
        _name: &[u8],
        _value: &[u8],
        _flags: u32,
        _sb: &Superblock,
    ) -> FsResult<()> {
        Err(IoError::IoFailed)
    }

    /// List extended attributes
    #[cfg(feature = "std")]
    pub fn listxattr(&self, ino: u64, buf: &mut [u8], sb: &Superblock) -> FsResult<usize> {
        self.listxattr_impl(ino, buf, sb)
    }

    /// List extended attributes (no-std stub)
    #[cfg(not(feature = "std"))]
    pub fn listxattr(&self, _ino: u64, _buf: &mut [u8], _sb: &Superblock) -> FsResult<usize> {
        Ok(0)
    }

    /// Remove extended attribute
    #[cfg(feature = "std")]
    pub fn removexattr(&self, ino: u64, name: &[u8], sb: &Superblock) -> FsResult<()> {
        self.removexattr_impl(ino, name, sb)
    }

    /// Remove extended attribute (no-std stub)
    #[cfg(not(feature = "std"))]
    pub fn removexattr(&self, _ino: u64, _name: &[u8], _sb: &Superblock) -> FsResult<()> {
        Err(IoError::NotFound)
    }
}
