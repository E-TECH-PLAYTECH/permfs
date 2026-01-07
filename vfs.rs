// PermFS VFS Layer — POSIX-like operations

#![cfg(feature = "std")]

use crate::*;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct OpenFlags: u32 {
        const READ      = 0x0001;
        const WRITE     = 0x0002;
        const APPEND    = 0x0004;
        const CREATE    = 0x0008;
        const TRUNCATE  = 0x0010;
        const EXCLUSIVE = 0x0020;
        const DIRECTORY = 0x0040;
        const NOFOLLOW  = 0x0080;
    }
}

#[repr(C)]
pub struct FileHandle {
    pub inode_num: u64,
    pub position: u64,
    pub flags: OpenFlags,
    pub ref_count: AtomicU32,
}

#[repr(i32)]
#[derive(Clone, Copy)]
pub enum SeekWhence {
    Set = 0,
    Cur = 1,
    End = 2,
}

#[repr(C)]
pub struct SetAttr {
    pub valid: u32,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub atime: u64,
    pub mtime: u64,
}

#[repr(C)]
pub struct StatFs {
    pub total_blocks: u64,
    pub free_blocks: u64,
    pub total_inodes: u64,
    pub free_inodes: u64,
    pub block_size: u32,
    pub max_name_len: u32,
}

pub trait VfsOperations {
    fn lookup(&self, parent: u64, name: &[u8]) -> FsResult<u64>;
    fn create(&self, parent: u64, name: &[u8], mode: u32) -> FsResult<u64>;
    fn mkdir(&self, parent: u64, name: &[u8], mode: u32) -> FsResult<u64>;
    fn unlink(&self, parent: u64, name: &[u8]) -> FsResult<()>;
    fn rmdir(&self, parent: u64, name: &[u8]) -> FsResult<()>;
    fn rename(
        &self,
        old_parent: u64,
        old_name: &[u8],
        new_parent: u64,
        new_name: &[u8],
    ) -> FsResult<()>;
    fn link(&self, ino: u64, new_parent: u64, new_name: &[u8]) -> FsResult<()>;
    fn symlink(&self, parent: u64, name: &[u8], target: &[u8]) -> FsResult<u64>;
    fn readlink(&self, ino: u64, buf: &mut [u8]) -> FsResult<usize>;
    fn open(&self, ino: u64, flags: OpenFlags) -> FsResult<FileHandle>;
    fn read(&self, handle: &FileHandle, buf: &mut [u8]) -> FsResult<usize>;
    fn write(&self, handle: &mut FileHandle, buf: &[u8]) -> FsResult<usize>;
    fn seek(&self, handle: &mut FileHandle, offset: i64, whence: SeekWhence) -> FsResult<u64>;
    fn fsync(&self, handle: &FileHandle) -> FsResult<()>;
    fn close(&self, handle: FileHandle) -> FsResult<()>;
    fn readdir(
        &self,
        ino: u64,
        offset: u64,
        callback: &mut dyn FnMut(&DirEntry) -> bool,
    ) -> FsResult<()>;
    fn getattr(&self, ino: u64) -> FsResult<Inode>;
    fn setattr(&self, ino: u64, attr: &SetAttr) -> FsResult<Inode>;
    fn truncate(&self, ino: u64, size: u64) -> FsResult<()>;
    fn statfs(&self) -> FsResult<StatFs>;
    fn sync(&self) -> FsResult<()>;
}

impl<B: BlockDevice, T: ClusterTransport> VfsOperations for PermFs<B, T> {
    fn lookup(&self, parent: u64, name: &[u8]) -> FsResult<u64> {
        let sb = self.read_superblock()?;
        let parent_inode = self.read_inode(parent, &sb)?;
        if !parent_inode.is_dir() {
            return Err(IoError::NotFound);
        }
        self.find_dirent(&parent_inode, name)
    }

    fn create(&self, parent: u64, name: &[u8], mode: u32) -> FsResult<u64> {
        let sb = self.read_superblock()?;
        let ino = self.alloc_inode(&sb)?;
        let now = self.current_time();

        let inode = Inode {
            mode: mode | 0o100000,
            uid: 0,
            gid: 0,
            flags: 0,
            size: 0,
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

        self.write_inode(ino, &inode, &sb)?;
        self.add_dirent(parent, name, ino, 1, &sb)?;
        Ok(ino)
    }

    fn mkdir(&self, parent: u64, name: &[u8], mode: u32) -> FsResult<u64> {
        let sb = self.read_superblock()?;
        let ino = self.alloc_inode(&sb)?;
        let now = self.current_time();

        let dir_block = self
            .alloc_block(Some(sb.volume_id))
            .map_err(|_| IoError::IoFailed)?;
        let mut inode = Inode {
            mode: mode | 0o040000,
            uid: 0,
            gid: 0,
            flags: 0,
            size: BLOCK_SIZE as u64,
            blocks: 1,
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
            nlink: 2,
            generation: 0,
            direct: [BlockAddr::NULL; INODE_DIRECT_BLOCKS],
            indirect: [BlockAddr::NULL; INODE_INDIRECT_LEVELS],
            extent_root: BlockAddr::NULL,
            xattr_block: BlockAddr::NULL,
            checksum: 0,
        };
        inode.direct[0] = dir_block;

        self.init_directory_block(dir_block, ino, parent)?;
        self.write_inode(ino, &inode, &sb)?;
        self.add_dirent(parent, name, ino, 2, &sb)?;

        let mut parent_inode = self.read_inode(parent, &sb)?;
        parent_inode.nlink += 1;
        self.write_inode(parent, &parent_inode, &sb)?;

        Ok(ino)
    }

    fn unlink(&self, parent: u64, name: &[u8]) -> FsResult<()> {
        let sb = self.read_superblock()?;
        let ino = self.lookup(parent, name)?;
        let mut inode = self.read_inode(ino, &sb)?;

        if inode.is_dir() {
            return Err(IoError::PermissionDenied);
        }

        inode.nlink -= 1;
        inode.ctime = self.current_time();

        if inode.nlink == 0 {
            self.free_inode_blocks(&inode)?;
            self.free_inode(ino, &sb)?;
        } else {
            self.write_inode(ino, &inode, &sb)?;
        }

        self.remove_dirent(parent, name, &sb)
    }

    fn rmdir(&self, parent: u64, name: &[u8]) -> FsResult<()> {
        let sb = self.read_superblock()?;
        let ino = self.lookup(parent, name)?;
        let inode = self.read_inode(ino, &sb)?;

        if !inode.is_dir() {
            return Err(IoError::PermissionDenied);
        }

        if !self.is_dir_empty(ino, &sb)? {
            return Err(IoError::PermissionDenied);
        }

        self.free_inode_blocks(&inode)?;
        self.free_inode(ino, &sb)?;
        self.remove_dirent(parent, name, &sb)?;

        let mut parent_inode = self.read_inode(parent, &sb)?;
        parent_inode.nlink -= 1;
        self.write_inode(parent, &parent_inode, &sb)?;

        Ok(())
    }

    fn open(&self, ino: u64, flags: OpenFlags) -> FsResult<FileHandle> {
        let sb = self.read_superblock()?;
        let inode = self.read_inode(ino, &sb)?;

        if flags.contains(OpenFlags::DIRECTORY) && !inode.is_dir() {
            return Err(IoError::NotFound);
        }

        Ok(FileHandle {
            inode_num: ino,
            position: 0,
            flags,
            ref_count: AtomicU32::new(1),
        })
    }

    fn read(&self, handle: &FileHandle, buf: &mut [u8]) -> FsResult<usize> {
        let sb = self.read_superblock()?;
        let inode = self.read_inode(handle.inode_num, &sb)?;
        self.read_file(&inode, handle.position, buf)
    }

    fn write(&self, handle: &mut FileHandle, buf: &[u8]) -> FsResult<usize> {
        let sb = self.read_superblock()?;
        let mut inode = self.read_inode(handle.inode_num, &sb)?;

        let pos = if handle.flags.contains(OpenFlags::APPEND) {
            inode.size
        } else {
            handle.position
        };

        let written = self.write_file(&mut inode, pos, buf, &sb)?;
        handle.position = pos + written as u64;

        self.write_inode(handle.inode_num, &inode, &sb)?;
        Ok(written)
    }

    fn seek(&self, handle: &mut FileHandle, offset: i64, whence: SeekWhence) -> FsResult<u64> {
        let sb = self.read_superblock()?;
        let inode = self.read_inode(handle.inode_num, &sb)?;

        let new_pos = match whence {
            SeekWhence::Set => offset as u64,
            SeekWhence::Cur => (handle.position as i64 + offset) as u64,
            SeekWhence::End => (inode.size as i64 + offset) as u64,
        };

        handle.position = new_pos;
        Ok(new_pos)
    }

    fn fsync(&self, _handle: &FileHandle) -> FsResult<()> {
        self.local_device.sync()
    }

    fn close(&self, handle: FileHandle) -> FsResult<()> {
        handle.ref_count.fetch_sub(1, Ordering::AcqRel);
        Ok(())
    }

    fn readdir(
        &self,
        ino: u64,
        offset: u64,
        callback: &mut dyn FnMut(&DirEntry) -> bool,
    ) -> FsResult<()> {
        let sb = self.read_superblock()?;
        let inode = self.read_inode(ino, &sb)?;

        if !inode.is_dir() {
            return Err(IoError::NotFound);
        }

        let mut pos = offset;
        while pos < inode.size {
            let block_addr = self.get_block_for_offset(&inode, pos)?;
            let mut buf = [0u8; BLOCK_SIZE];
            self.read_block(block_addr, &mut buf)?;

            let mut block_pos = (pos % BLOCK_SIZE as u64) as usize;
            while block_pos + DirEntry::HEADER_SIZE <= BLOCK_SIZE {
                let entry: &DirEntry =
                    unsafe { &*(buf.as_ptr().add(block_pos) as *const DirEntry) };

                if entry.rec_len == 0 {
                    break;
                }

                if entry.inode != 0 && !callback(entry) {
                    return Ok(());
                }

                block_pos += entry.rec_len as usize;
            }

            pos = (pos / BLOCK_SIZE as u64 + 1) * BLOCK_SIZE as u64;
        }

        Ok(())
    }

    fn getattr(&self, ino: u64) -> FsResult<Inode> {
        let sb = self.read_superblock()?;
        self.read_inode(ino, &sb)
    }

    fn setattr(&self, ino: u64, attr: &SetAttr) -> FsResult<Inode> {
        let sb = self.read_superblock()?;
        let mut inode = self.read_inode(ino, &sb)?;

        if attr.valid & 0x01 != 0 {
            inode.mode = attr.mode;
        }
        if attr.valid & 0x02 != 0 {
            inode.uid = attr.uid;
        }
        if attr.valid & 0x04 != 0 {
            inode.gid = attr.gid;
        }
        if attr.valid & 0x08 != 0 {
            self.truncate_internal(&mut inode, attr.size, &sb)?;
        }
        if attr.valid & 0x10 != 0 {
            inode.atime = attr.atime;
        }
        if attr.valid & 0x20 != 0 {
            inode.mtime = attr.mtime;
        }

        inode.ctime = self.current_time();
        self.write_inode(ino, &inode, &sb)?;
        Ok(inode)
    }

    fn truncate(&self, ino: u64, size: u64) -> FsResult<()> {
        let sb = self.read_superblock()?;
        let mut inode = self.read_inode(ino, &sb)?;
        self.truncate_internal(&mut inode, size, &sb)?;
        self.write_inode(ino, &inode, &sb)
    }

    fn statfs(&self) -> FsResult<StatFs> {
        let sb = self.read_superblock()?;
        Ok(StatFs {
            total_blocks: sb.total_blocks,
            free_blocks: sb.free_blocks.load(Ordering::Relaxed),
            total_inodes: sb.total_inodes,
            free_inodes: sb.free_inodes.load(Ordering::Relaxed),
            block_size: BLOCK_SIZE as u32,
            max_name_len: MAX_FILENAME_LEN as u32,
        })
    }

    fn sync(&self) -> FsResult<()> {
        self.local_device.sync()
    }

    fn rename(
        &self,
        old_parent: u64,
        old_name: &[u8],
        new_parent: u64,
        new_name: &[u8],
    ) -> FsResult<()> {
        let sb = self.read_superblock()?;
        self.rename_impl(old_parent, old_name, new_parent, new_name, &sb)
    }

    fn link(&self, ino: u64, new_parent: u64, new_name: &[u8]) -> FsResult<()> {
        let sb = self.read_superblock()?;
        self.link_impl(ino, new_parent, new_name, &sb)
    }

    fn symlink(&self, parent: u64, name: &[u8], target: &[u8]) -> FsResult<u64> {
        let sb = self.read_superblock()?;
        self.symlink_impl(parent, name, target, &sb)
    }

    fn readlink(&self, ino: u64, buf: &mut [u8]) -> FsResult<usize> {
        let sb = self.read_superblock()?;
        self.readlink_impl(ino, buf, &sb)
    }
}

impl<B: BlockDevice, T: ClusterTransport> PermFs<B, T> {
    fn read_superblock(&self) -> FsResult<Superblock> {
        let mut buf = [0u8; BLOCK_SIZE];
        let sb_addr = BlockAddr::new(self.node_id, 0, 0, 0);
        self.read_block(sb_addr, &mut buf)?;

        
        self.mount(self.node_id, 0)
    }
}
