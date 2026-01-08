// PermFS FUSE Adapter — Userspace filesystem via fuser

#![cfg(feature = "fuse")]

use crate::locking::{FileLock, LockResult, LockTable, LockType};
use crate::sync::{Arc, Mutex, RwLock};
use crate::vfs::OpenFlags;
use crate::*;
use fuser::{
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory,
    ReplyEmpty, ReplyEntry, ReplyLock, ReplyOpen, ReplyStatfs, ReplyWrite, ReplyXattr, Request,
    TimeOrNow,
};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const TTL: Duration = Duration::from_secs(1);

// FUSE uses inode 1 for root (FUSE_ROOT_ID), PermFS uses inode 0
// FUSE inode 0 is invalid/unused, so we offset by 1:
//   FUSE 1 <-> PermFS 0 (root)
//   FUSE 2 <-> PermFS 1
//   FUSE 3 <-> PermFS 2
//   etc.
#[inline]
fn fuse_to_permfs_ino(ino: u64) -> u64 {
    ino.saturating_sub(1)
}

#[inline]
fn permfs_to_fuse_ino(ino: u64) -> u64 {
    ino + 1
}

fn inode_to_attr(ino: u64, inode: &Inode) -> FileAttr {
    FileAttr {
        ino,
        size: inode.size,
        blocks: inode.blocks,
        atime: time_from_ns(inode.atime),
        mtime: time_from_ns(inode.mtime),
        ctime: time_from_ns(inode.ctime),
        crtime: time_from_ns(inode.crtime),
        kind: mode_to_kind(inode.mode),
        perm: (inode.mode & 0o7777) as u16,
        nlink: inode.nlink,
        uid: inode.uid,
        gid: inode.gid,
        rdev: 0,
        blksize: BLOCK_SIZE as u32,
        flags: inode.flags,
    }
}

fn time_from_ns(ns: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_nanos(ns)
}

fn time_to_ns(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos() as u64
}

fn mode_to_kind(mode: u32) -> FileType {
    match mode & 0o170000 {
        0o040000 => FileType::Directory,
        0o100000 => FileType::RegularFile,
        0o120000 => FileType::Symlink,
        0o060000 => FileType::BlockDevice,
        0o020000 => FileType::CharDevice,
        0o010000 => FileType::NamedPipe,
        0o140000 => FileType::Socket,
        _ => FileType::RegularFile,
    }
}

struct OpenFile {
    ino: u64,
    _flags: OpenFlags,
}

pub struct FuseFs<B: BlockDevice, T: ClusterTransport> {
    fs: Arc<PermFs<B, T>>,
    superblock: RwLock<Superblock>,
    open_files: Mutex<HashMap<u64, OpenFile>>,
    next_fh: Mutex<u64>,
    lock_table: LockTable,
}

impl<B: BlockDevice + 'static, T: ClusterTransport + 'static> FuseFs<B, T> {
    pub fn new(fs: Arc<PermFs<B, T>>, sb: Superblock) -> Self {
        Self {
            fs,
            superblock: RwLock::new(sb),
            open_files: Mutex::new(HashMap::new()),
            next_fh: Mutex::new(1),
            lock_table: LockTable::new(),
        }
    }

    fn sb(&self) -> Superblock {
        let sb = self.superblock.read().unwrap();
        Superblock {
            magic: sb.magic,
            version: sb.version,
            block_size: sb.block_size,
            total_blocks: sb.total_blocks,
            free_blocks: core::sync::atomic::AtomicU64::new(
                sb.free_blocks.load(core::sync::atomic::Ordering::Relaxed),
            ),
            total_inodes: sb.total_inodes,
            free_inodes: core::sync::atomic::AtomicU64::new(
                sb.free_inodes.load(core::sync::atomic::Ordering::Relaxed),
            ),
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
            root_inode: sb.root_inode,
            checksum: sb.checksum,
        }
    }

    fn alloc_fh(&self) -> u64 {
        let mut next = self.next_fh.lock().unwrap();
        let fh = *next;
        *next += 1;
        fh
    }

    pub fn mount(self, mountpoint: &std::path::Path) -> std::io::Result<()> {
        let options = vec![
            MountOption::FSName("permfs".to_string()),
            MountOption::AutoUnmount,
            MountOption::DefaultPermissions,
        ];
        fuser::mount2(self, mountpoint, &options)
    }
}

impl<B: BlockDevice + 'static, T: ClusterTransport + 'static> Filesystem for FuseFs<B, T> {
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let name = name.to_string_lossy();
        let sb = self.sb();
        let parent = fuse_to_permfs_ino(parent);

        let parent_inode = match self.fs.read_inode(parent, &sb) {
            Ok(i) => i,
            Err(_) => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let ino = match self.fs.find_dirent(&parent_inode, name.as_bytes()) {
            Ok(i) => i,
            Err(_) => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let inode = match self.fs.read_inode(ino, &sb) {
            Ok(i) => i,
            Err(_) => {
                reply.error(libc::EIO);
                return;
            }
        };

        reply.entry(&TTL, &inode_to_attr(permfs_to_fuse_ino(ino), &inode), 0);
    }

    fn getattr(&mut self, _req: &Request, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        let sb = self.sb();
        let permfs_ino = fuse_to_permfs_ino(ino);
        match self.fs.read_inode(permfs_ino, &sb) {
            Ok(inode) => reply.attr(&TTL, &inode_to_attr(ino, &inode)),
            Err(_) => reply.error(libc::ENOENT),
        }
    }

    fn setattr(
        &mut self,
        _req: &Request,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        let sb = self.sb();
        let permfs_ino = fuse_to_permfs_ino(ino);
        let mut inode = match self.fs.read_inode(permfs_ino, &sb) {
            Ok(i) => i,
            Err(_) => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        if let Some(m) = mode {
            inode.mode = (inode.mode & 0o170000) | (m & 0o7777);
        }
        if let Some(u) = uid {
            inode.uid = u;
        }
        if let Some(g) = gid {
            inode.gid = g;
        }
        if let Some(s) = size {
            if let Err(_) = self.fs.truncate_internal(&mut inode, s, &sb) {
                reply.error(libc::EIO);
                return;
            }
        }
        if let Some(a) = atime {
            inode.atime = match a {
                TimeOrNow::SpecificTime(t) => time_to_ns(t),
                TimeOrNow::Now => self.fs.current_time(),
            };
        }
        if let Some(m) = mtime {
            inode.mtime = match m {
                TimeOrNow::SpecificTime(t) => time_to_ns(t),
                TimeOrNow::Now => self.fs.current_time(),
            };
        }

        inode.ctime = self.fs.current_time();
        if let Err(_) = self.fs.write_inode(permfs_ino, &inode, &sb) {
            reply.error(libc::EIO);
            return;
        }

        reply.attr(&TTL, &inode_to_attr(ino, &inode));
    }

    fn mkdir(
        &mut self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let sb = self.sb();
        let name = name.to_string_lossy();
        let parent = fuse_to_permfs_ino(parent);
        let uid = req.uid();
        let gid = req.gid();

        let ino = match self.fs.alloc_inode(&sb) {
            Ok(i) => i,
            Err(_) => {
                reply.error(libc::ENOSPC);
                return;
            }
        };

        let dir_block = match self.fs.alloc_block(Some(sb.volume_id)) {
            Ok(b) => b,
            Err(_) => {
                reply.error(libc::ENOSPC);
                return;
            }
        };

        let now = self.fs.current_time();
        let mut inode = Inode {
            mode: 0o040000 | (mode & 0o7777),
            uid,
            gid,
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

        if self
            .fs
            .init_directory_block(dir_block, ino, parent)
            .is_err()
            || self.fs.write_inode(ino, &inode, &sb).is_err()
            || self
                .fs
                .add_dirent(parent, name.as_bytes(), ino, 2, &sb)
                .is_err()
        {
            reply.error(libc::EIO);
            return;
        }

        let mut parent_inode = match self.fs.read_inode(parent, &sb) {
            Ok(i) => i,
            Err(_) => {
                reply.error(libc::EIO);
                return;
            }
        };
        parent_inode.nlink += 1;
        let _ = self.fs.write_inode(parent, &parent_inode, &sb);

        reply.entry(&TTL, &inode_to_attr(permfs_to_fuse_ino(ino), &inode), 0);
    }

    fn mknod(
        &mut self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        _rdev: u32,
        reply: ReplyEntry,
    ) {
        let sb = self.sb();
        let name = name.to_string_lossy();
        let parent = fuse_to_permfs_ino(parent);
        let uid = req.uid();
        let gid = req.gid();

        let ino = match self.fs.alloc_inode(&sb) {
            Ok(i) => i,
            Err(_) => {
                reply.error(libc::ENOSPC);
                return;
            }
        };

        let now = self.fs.current_time();
        let inode = Inode {
            mode,
            uid,
            gid,
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

        if self.fs.write_inode(ino, &inode, &sb).is_err()
            || self
                .fs
                .add_dirent(parent, name.as_bytes(), ino, 1, &sb)
                .is_err()
        {
            reply.error(libc::EIO);
            return;
        }

        reply.entry(&TTL, &inode_to_attr(permfs_to_fuse_ino(ino), &inode), 0);
    }

    fn create(
        &mut self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let sb = self.sb();
        let name = name.to_string_lossy();
        let parent = fuse_to_permfs_ino(parent);
        let uid = req.uid();
        let gid = req.gid();

        let ino = match self.fs.alloc_inode(&sb) {
            Ok(i) => i,
            Err(_) => {
                reply.error(libc::ENOSPC);
                return;
            }
        };

        let now = self.fs.current_time();
        let inode = Inode {
            mode: 0o100000 | (mode & 0o7777),
            uid,
            gid,
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

        if self.fs.write_inode(ino, &inode, &sb).is_err()
            || self
                .fs
                .add_dirent(parent, name.as_bytes(), ino, 1, &sb)
                .is_err()
        {
            reply.error(libc::EIO);
            return;
        }

        let fh = self.alloc_fh();
        self.open_files.lock().unwrap().insert(
            fh,
            OpenFile {
                ino,
                _flags: OpenFlags::READ | OpenFlags::WRITE,
            },
        );

        reply.created(&TTL, &inode_to_attr(permfs_to_fuse_ino(ino), &inode), 0, fh, 0);
    }

    fn unlink(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let sb = self.sb();
        let name = name.to_string_lossy();
        let parent = fuse_to_permfs_ino(parent);

        let parent_inode = match self.fs.read_inode(parent, &sb) {
            Ok(i) => i,
            Err(_) => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let ino = match self.fs.find_dirent(&parent_inode, name.as_bytes()) {
            Ok(i) => i,
            Err(_) => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let mut inode = match self.fs.read_inode(ino, &sb) {
            Ok(i) => i,
            Err(_) => {
                reply.error(libc::EIO);
                return;
            }
        };

        if inode.is_dir() {
            reply.error(libc::EISDIR);
            return;
        }

        if let Err(_) = self.fs.remove_dirent(parent, name.as_bytes(), &sb) {
            reply.error(libc::EIO);
            return;
        }

        inode.nlink -= 1;
        inode.ctime = self.fs.current_time();

        if inode.nlink == 0 {
            let _ = self.fs.free_inode_blocks(&inode);
            let _ = self.fs.free_inode(ino, &sb);
        } else {
            let _ = self.fs.write_inode(ino, &inode, &sb);
        }

        reply.ok();
    }

    fn rmdir(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let sb = self.sb();
        let name = name.to_string_lossy();
        let parent = fuse_to_permfs_ino(parent);

        let parent_inode = match self.fs.read_inode(parent, &sb) {
            Ok(i) => i,
            Err(_) => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let ino = match self.fs.find_dirent(&parent_inode, name.as_bytes()) {
            Ok(i) => i,
            Err(_) => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let inode = match self.fs.read_inode(ino, &sb) {
            Ok(i) => i,
            Err(_) => {
                reply.error(libc::EIO);
                return;
            }
        };

        if !inode.is_dir() {
            reply.error(libc::ENOTDIR);
            return;
        }

        match self.fs.is_dir_empty(ino, &sb) {
            Ok(true) => {}
            Ok(false) => {
                reply.error(libc::ENOTEMPTY);
                return;
            }
            Err(_) => {
                reply.error(libc::EIO);
                return;
            }
        }

        let _ = self.fs.remove_dirent(parent, name.as_bytes(), &sb);
        let _ = self.fs.free_inode_blocks(&inode);
        let _ = self.fs.free_inode(ino, &sb);

        let mut parent_inode = match self.fs.read_inode(parent, &sb) {
            Ok(i) => i,
            Err(_) => {
                reply.ok();
                return;
            }
        };
        parent_inode.nlink -= 1;
        let _ = self.fs.write_inode(parent, &parent_inode, &sb);

        reply.ok();
    }

    fn open(&mut self, _req: &Request, ino: u64, flags: i32, reply: ReplyOpen) {
        let sb = self.sb();
        let permfs_ino = fuse_to_permfs_ino(ino);
        if self.fs.read_inode(permfs_ino, &sb).is_err() {
            reply.error(libc::ENOENT);
            return;
        }

        let fh = self.alloc_fh();
        let open_flags = OpenFlags::from_bits_truncate(flags as u32);

        self.open_files.lock().unwrap().insert(
            fh,
            OpenFile {
                ino: permfs_ino,
                _flags: open_flags,
            },
        );

        reply.opened(fh, 0);
    }

    fn read(
        &mut self,
        _req: &Request,
        _ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock: Option<u64>,
        reply: ReplyData,
    ) {
        let sb = self.sb();

        let file_ino = {
            let files = self.open_files.lock().unwrap();
            match files.get(&fh) {
                Some(f) => f.ino,
                None => {
                    reply.error(libc::EBADF);
                    return;
                }
            }
        };

        let inode = match self.fs.read_inode(file_ino, &sb) {
            Ok(i) => i,
            Err(_) => {
                reply.error(libc::EIO);
                return;
            }
        };

        let mut buf = vec![0u8; size as usize];
        match self.fs.read_file(&inode, offset as u64, &mut buf) {
            Ok(read) => {
                buf.truncate(read);
                reply.data(&buf);
            }
            Err(_) => reply.error(libc::EIO),
        }
    }

    fn write(
        &mut self,
        _req: &Request,
        _ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock: Option<u64>,
        reply: ReplyWrite,
    ) {
        let sb = self.sb();

        let file_ino = {
            let files = self.open_files.lock().unwrap();
            match files.get(&fh) {
                Some(f) => f.ino,
                None => {
                    reply.error(libc::EBADF);
                    return;
                }
            }
        };

        let mut inode = match self.fs.read_inode(file_ino, &sb) {
            Ok(i) => i,
            Err(_) => {
                reply.error(libc::EIO);
                return;
            }
        };

        match self.fs.write_file(&mut inode, offset as u64, data, &sb) {
            Ok(written) => {
                if let Err(_) = self.fs.write_inode(file_ino, &inode, &sb) {
                    reply.error(libc::EIO);
                    return;
                }
                reply.written(written as u32);
            }
            Err(_) => reply.error(libc::EIO),
        }
    }

    fn flush(&mut self, _req: &Request, ino: u64, _fh: u64, lock_owner: u64, reply: ReplyEmpty) {
        let ino = fuse_to_permfs_ino(ino);

        // Release all locks held by this owner on this inode
        self.lock_table.release_owner(ino, lock_owner);

        // Sync the device on flush
        match self.fs.local_device.sync() {
            Ok(_) => reply.ok(),
            Err(_) => reply.error(libc::EIO),
        }
    }

    fn fsync(&mut self, _req: &Request, _ino: u64, _fh: u64, _datasync: bool, reply: ReplyEmpty) {
        match self.fs.local_device.sync() {
            Ok(_) => reply.ok(),
            Err(_) => reply.error(libc::EIO),
        }
    }

    fn release(
        &mut self,
        _req: &Request,
        _ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        self.open_files.lock().unwrap().remove(&fh);
        reply.ok();
    }

    fn readdir(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let sb = self.sb();
        let permfs_ino = fuse_to_permfs_ino(ino);

        let inode = match self.fs.read_inode(permfs_ino, &sb) {
            Ok(i) => i,
            Err(_) => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        if !inode.is_dir() {
            reply.error(libc::ENOTDIR);
            return;
        }

        let mut entries = Vec::new();
        let mut buf = [0u8; BLOCK_SIZE];
        let mut block_offset = 0u64;

        while block_offset < inode.size {
            let block_addr = match self.fs.get_block_for_offset(&inode, block_offset) {
                Ok(a) => a,
                Err(_) => break,
            };

            if self.fs.read_block(block_addr, &mut buf).is_err() {
                break;
            }

            let mut pos = 0usize;
            while pos + 12 <= BLOCK_SIZE {
                let entry_ino = u64::from_le_bytes(buf[pos..pos + 8].try_into().unwrap());
                let rec_len = u16::from_le_bytes(buf[pos + 8..pos + 10].try_into().unwrap());
                let name_len = buf[pos + 10] as usize;
                let file_type = buf[pos + 11];

                if rec_len == 0 {
                    break;
                }

                if entry_ino != 0 {
                    let name = std::str::from_utf8(&buf[pos + 12..pos + 12 + name_len])
                        .unwrap_or("")
                        .to_string();
                    let kind = match file_type {
                        2 => FileType::Directory,
                        7 => FileType::Symlink,
                        _ => FileType::RegularFile,
                    };
                    entries.push((entry_ino, kind, name));
                }

                pos += rec_len as usize;
            }

            block_offset += BLOCK_SIZE as u64;
        }

        for (i, (entry_ino, kind, name)) in entries.iter().enumerate().skip(offset as usize) {
            if reply.add(permfs_to_fuse_ino(*entry_ino), (i + 1) as i64, *kind, name) {
                break;
            }
        }

        reply.ok();
    }

    fn statfs(&mut self, _req: &Request, _ino: u64, reply: ReplyStatfs) {
        let sb = self.sb();
        reply.statfs(
            sb.total_blocks,
            sb.free_blocks.load(core::sync::atomic::Ordering::Relaxed),
            sb.free_blocks.load(core::sync::atomic::Ordering::Relaxed),
            sb.total_inodes,
            sb.free_inodes.load(core::sync::atomic::Ordering::Relaxed),
            BLOCK_SIZE as u32,
            MAX_FILENAME_LEN as u32,
            BLOCK_SIZE as u32,
        );
    }

    fn symlink(
        &mut self,
        _req: &Request,
        parent: u64,
        link_name: &OsStr,
        target: &std::path::Path,
        reply: ReplyEntry,
    ) {
        let sb = self.sb();
        let parent = fuse_to_permfs_ino(parent);
        let link_name = link_name.to_string_lossy();
        let target = target.to_string_lossy();

        match self.fs.symlink_impl(parent, link_name.as_bytes(), target.as_bytes(), &sb) {
            Ok(ino) => {
                match self.fs.read_inode(ino, &sb) {
                    Ok(inode) => {
                        reply.entry(&TTL, &inode_to_attr(permfs_to_fuse_ino(ino), &inode), 0);
                    }
                    Err(_) => reply.error(libc::EIO),
                }
            }
            Err(IoError::NoSpace) => reply.error(libc::ENOSPC),
            Err(IoError::NotFound) => reply.error(libc::ENOENT),
            Err(_) => reply.error(libc::EIO),
        }
    }

    fn readlink(&mut self, _req: &Request, ino: u64, reply: ReplyData) {
        let sb = self.sb();
        let ino = fuse_to_permfs_ino(ino);

        let mut buf = [0u8; 4096];
        match self.fs.readlink_impl(ino, &mut buf, &sb) {
            Ok(len) => reply.data(&buf[..len]),
            Err(IoError::InvalidAddress) => reply.error(libc::EINVAL),
            Err(IoError::NotFound) => reply.error(libc::ENOENT),
            Err(_) => reply.error(libc::EIO),
        }
    }

    fn link(
        &mut self,
        _req: &Request,
        ino: u64,
        newparent: u64,
        newname: &OsStr,
        reply: ReplyEntry,
    ) {
        let sb = self.sb();
        let ino = fuse_to_permfs_ino(ino);
        let newparent = fuse_to_permfs_ino(newparent);
        let newname = newname.to_string_lossy();

        match self.fs.link_impl(ino, newparent, newname.as_bytes(), &sb) {
            Ok(()) => {
                match self.fs.read_inode(ino, &sb) {
                    Ok(inode) => {
                        reply.entry(&TTL, &inode_to_attr(permfs_to_fuse_ino(ino), &inode), 0);
                    }
                    Err(_) => reply.error(libc::EIO),
                }
            }
            Err(IoError::NotFound) => reply.error(libc::ENOENT),
            Err(IoError::NoSpace) => reply.error(libc::ENOSPC),
            Err(_) => reply.error(libc::EIO),
        }
    }

    fn rename(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        _flags: u32,
        reply: ReplyEmpty,
    ) {
        use std::os::unix::ffi::OsStrExt;
        let sb = self.sb();
        let parent = fuse_to_permfs_ino(parent);
        let newparent = fuse_to_permfs_ino(newparent);

        match self.fs.rename_impl(parent, name.as_bytes(), newparent, newname.as_bytes(), &sb) {
            Ok(()) => reply.ok(),
            Err(IoError::NotFound) => reply.error(libc::ENOENT),
            Err(IoError::DirectoryNotEmpty) => reply.error(libc::ENOTEMPTY),
            Err(_) => reply.error(libc::EIO),
        }
    }

    fn access(&mut self, req: &Request, ino: u64, mask: i32, reply: ReplyEmpty) {
        let sb = self.sb();
        let ino = fuse_to_permfs_ino(ino);

        let inode = match self.fs.read_inode(ino, &sb) {
            Ok(i) => i,
            Err(_) => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        // F_OK (existence check)
        if mask == libc::F_OK {
            reply.ok();
            return;
        }

        let uid = req.uid();
        let gid = req.gid();
        let mode = inode.mode;

        // Root can access anything (for read/write; execute still needs x bit)
        if uid == 0 {
            if mask & libc::X_OK != 0 {
                // Root can execute if any execute bit is set
                if mode & 0o111 != 0 {
                    reply.ok();
                } else {
                    reply.error(libc::EACCES);
                }
            } else {
                reply.ok();
            }
            return;
        }

        let (shift, _) = if uid == inode.uid {
            (6, "owner")
        } else if gid == inode.gid {
            (3, "group")
        } else {
            (0, "other")
        };

        let perms = (mode >> shift) & 0o7;
        let mut granted = true;

        if mask & libc::R_OK != 0 && perms & 0o4 == 0 {
            granted = false;
        }
        if mask & libc::W_OK != 0 && perms & 0o2 == 0 {
            granted = false;
        }
        if mask & libc::X_OK != 0 && perms & 0o1 == 0 {
            granted = false;
        }

        if granted {
            reply.ok();
        } else {
            reply.error(libc::EACCES);
        }
    }

    fn getlk(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        lock_owner: u64,
        start: u64,
        end: u64,
        typ: i32,
        pid: u32,
        reply: ReplyLock,
    ) {
        let ino = fuse_to_permfs_ino(ino);
        let lock_type = match LockType::from_libc(typ) {
            Some(t) => t,
            None => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        // Calculate length from start/end (end is exclusive, 0 means EOF)
        let len = if end == 0 || end == u64::MAX {
            0 // To EOF
        } else {
            end.saturating_sub(start)
        };

        let proposed = FileLock::new(lock_owner, start, len, lock_type);

        match self.lock_table.test_lock(ino, &proposed) {
            Some(conflict) => {
                // Return the conflicting lock
                let end = if conflict.len == 0 { 0 } else { conflict.start + conflict.len };
                reply.locked(
                    conflict.start,
                    end,
                    conflict.lock_type.to_libc(),
                    pid,
                );
            }
            None => {
                // No conflict - return unlock to indicate lock would succeed
                reply.locked(0, 0, libc::F_UNLCK as i32, 0);
            }
        }
    }

    fn setlk(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        lock_owner: u64,
        start: u64,
        end: u64,
        typ: i32,
        _pid: u32,
        block: bool,
        reply: ReplyEmpty,
    ) {
        let ino = fuse_to_permfs_ino(ino);
        let lock_type = match LockType::from_libc(typ) {
            Some(t) => t,
            None => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        // Calculate length from start/end
        let len = if end == 0 || end == u64::MAX {
            0 // To EOF
        } else {
            end.saturating_sub(start)
        };

        let lock = FileLock::new(lock_owner, start, len, lock_type);

        match self.lock_table.try_lock(ino, lock) {
            LockResult::Acquired | LockResult::Released => {
                reply.ok();
            }
            LockResult::WouldBlock(_) => {
                if block {
                    // For blocking locks, we'd need async support
                    // For now, just return EAGAIN and let the caller retry
                    reply.error(libc::EAGAIN);
                } else {
                    reply.error(libc::EAGAIN);
                }
            }
        }
    }

    fn getxattr(
        &mut self,
        _req: &Request,
        ino: u64,
        name: &OsStr,
        size: u32,
        reply: ReplyXattr,
    ) {
        let sb = self.sb();
        let ino = fuse_to_permfs_ino(ino);
        let name = name.to_string_lossy();

        if size == 0 {
            // Size query
            match self.fs.getxattr(ino, name.as_bytes(), &mut [], &sb) {
                Ok(len) => reply.size(len as u32),
                Err(IoError::NotFound) => reply.error(libc::ENODATA),
                Err(_) => reply.error(libc::EIO),
            }
        } else {
            let mut buf = vec![0u8; size as usize];
            match self.fs.getxattr(ino, name.as_bytes(), &mut buf, &sb) {
                Ok(len) => reply.data(&buf[..len]),
                Err(IoError::NotFound) => reply.error(libc::ENODATA),
                Err(IoError::InvalidAddress) => reply.error(libc::ERANGE),
                Err(_) => reply.error(libc::EIO),
            }
        }
    }

    fn setxattr(
        &mut self,
        _req: &Request,
        ino: u64,
        name: &OsStr,
        value: &[u8],
        flags: i32,
        _position: u32,
        reply: ReplyEmpty,
    ) {
        let sb = self.sb();
        let ino = fuse_to_permfs_ino(ino);
        let name = name.to_string_lossy();

        match self.fs.setxattr(ino, name.as_bytes(), value, flags as u32, &sb) {
            Ok(()) => reply.ok(),
            Err(IoError::NotFound) => reply.error(libc::ENODATA),
            Err(IoError::AlreadyExists) => reply.error(libc::EEXIST),
            Err(IoError::NoSpace) => reply.error(libc::ENOSPC),
            Err(IoError::InvalidAddress) => reply.error(libc::EINVAL),
            Err(_) => reply.error(libc::EIO),
        }
    }

    fn listxattr(&mut self, _req: &Request, ino: u64, size: u32, reply: ReplyXattr) {
        let sb = self.sb();
        let ino = fuse_to_permfs_ino(ino);

        if size == 0 {
            // Size query
            match self.fs.listxattr(ino, &mut [], &sb) {
                Ok(len) => reply.size(len as u32),
                Err(_) => reply.error(libc::EIO),
            }
        } else {
            let mut buf = vec![0u8; size as usize];
            match self.fs.listxattr(ino, &mut buf, &sb) {
                Ok(len) => reply.data(&buf[..len]),
                Err(IoError::InvalidAddress) => reply.error(libc::ERANGE),
                Err(_) => reply.error(libc::EIO),
            }
        }
    }

    fn removexattr(&mut self, _req: &Request, ino: u64, name: &OsStr, reply: ReplyEmpty) {
        let sb = self.sb();
        let ino = fuse_to_permfs_ino(ino);
        let name = name.to_string_lossy();

        match self.fs.removexattr(ino, name.as_bytes(), &sb) {
            Ok(()) => reply.ok(),
            Err(IoError::NotFound) => reply.error(libc::ENODATA),
            Err(_) => reply.error(libc::EIO),
        }
    }
}
