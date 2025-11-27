// PermFS Mock Block Device — In-memory storage for testing

#![cfg(feature = "std")]

use crate::*;
use std::collections::HashMap;
use std::sync::RwLock;
use core::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

pub struct MemoryBlockDevice {
    blocks: RwLock<HashMap<BlockAddr, [u8; BLOCK_SIZE]>>,
    node_id: u64,
    volume_id: u32,
}

impl MemoryBlockDevice {
    pub fn new(node_id: u64, volume_id: u32) -> Self {
        Self {
            blocks: RwLock::new(HashMap::new()),
            node_id,
            volume_id,
        }
    }

    pub fn block_count(&self) -> usize {
        self.blocks.read().unwrap().len()
    }
}

impl BlockDevice for MemoryBlockDevice {
    fn read_block(&self, addr: BlockAddr, buf: &mut [u8; BLOCK_SIZE]) -> FsResult<()> {
        let blocks = self.blocks.read().unwrap();
        if let Some(data) = blocks.get(&addr) {
            buf.copy_from_slice(data);
        } else {
            buf.fill(0);
        }
        Ok(())
    }

    fn write_block(&self, addr: BlockAddr, buf: &[u8; BLOCK_SIZE]) -> FsResult<()> {
        let mut blocks = self.blocks.write().unwrap();
        blocks.insert(addr, *buf);
        Ok(())
    }

    fn sync(&self) -> FsResult<()> {
        Ok(())
    }

    fn trim(&self, addr: BlockAddr) -> FsResult<()> {
        let mut blocks = self.blocks.write().unwrap();
        blocks.remove(&addr);
        Ok(())
    }
}

pub struct NullTransport;

impl ClusterTransport for NullTransport {
    fn read_remote(&self, _node: u64, _addr: BlockAddr, _buf: &mut [u8; BLOCK_SIZE]) -> FsResult<()> {
        Err(IoError::NetworkTimeout)
    }

    fn write_remote(&self, _node: u64, _addr: BlockAddr, _buf: &[u8; BLOCK_SIZE]) -> FsResult<()> {
        Err(IoError::NetworkTimeout)
    }

    fn alloc_remote(&self, _node: u64, _volume: u32) -> Result<BlockAddr, AllocError> {
        Err(AllocError::RemoteNodeDown)
    }

    fn free_remote(&self, _node: u64, _addr: BlockAddr) -> Result<(), AllocError> {
        Err(AllocError::RemoteNodeDown)
    }
}

pub struct TestFsBuilder {
    node_id: u64,
    volume_id: u32,
    total_blocks: u64,
}

impl Default for TestFsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TestFsBuilder {
    pub fn new() -> Self {
        Self {
            node_id: 1,
            volume_id: 0,
            total_blocks: 10000,
        }
    }

    pub fn node_id(mut self, id: u64) -> Self {
        self.node_id = id;
        self
    }

    pub fn volume_id(mut self, id: u32) -> Self {
        self.volume_id = id;
        self
    }

    pub fn total_blocks(mut self, blocks: u64) -> Self {
        self.total_blocks = blocks;
        self
    }

    pub fn build(self) -> Result<(Arc<TestFs>, Superblock), IoError> {
        let device = MemoryBlockDevice::new(self.node_id, self.volume_id);
        let transport = NullTransport;

        let fs = PermFs::new(self.node_id, device, transport);

        let params = crate::mkfs::MkfsParams {
            node_id: self.node_id,
            volume_id: self.volume_id,
            total_blocks: self.total_blocks,
            inode_ratio: 16384,
            journal_blocks: 128,
            volume_name: [0; 64],
            uuid: [0; 16],
        };

        let result = fs.mkfs(&params)?;
        Ok((Arc::new(fs), result.superblock))
    }
}

pub type TestFs = PermFs<MemoryBlockDevice, NullTransport>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mkfs_and_mount() {
        let (fs, sb) = TestFsBuilder::new()
            .total_blocks(1000)
            .build()
            .expect("mkfs failed");

        assert_eq!(sb.magic, SUPERBLOCK_MAGIC);
        assert_eq!(sb.total_blocks, 1000);
        assert!(sb.free_blocks.load(Ordering::Relaxed) > 0);
    }

    #[test]
    fn test_root_directory() {
        let (fs, sb) = TestFsBuilder::new().build().expect("mkfs failed");
        let root = fs.read_inode(0, &sb).expect("read root inode");
        assert!(root.is_dir());
        assert_eq!(root.nlink, 2);
    }

    #[test]
    fn test_create_file() {
        let (fs, sb) = TestFsBuilder::new().build().expect("mkfs failed");

        let ino = fs.alloc_inode(&sb).expect("alloc inode");
        assert!(ino > 0);

        let inode = Inode {
            mode: 0o100644,
            uid: 1000, gid: 1000, flags: 0,
            size: 0, blocks: 0,
            atime: 0, mtime: 0, ctime: 0, crtime: 0,
            nlink: 1, generation: 0,
            direct: [BlockAddr::NULL; INODE_DIRECT_BLOCKS],
            indirect: [BlockAddr::NULL; INODE_INDIRECT_LEVELS],
            extent_root: BlockAddr::NULL,
            xattr_block: BlockAddr::NULL,
            checksum: 0,
        };

        fs.write_inode(ino, &inode, &sb).expect("write inode");
        fs.add_dirent(0, b"testfile", ino, 1, &sb).expect("add dirent");

        let root = fs.read_inode(0, &sb).expect("read root");
        let found = fs.find_dirent(&root, b"testfile").expect("find dirent");
        assert_eq!(found, ino);
    }

    #[test]
    fn test_write_and_read() {
        let (fs, sb) = TestFsBuilder::new().build().expect("mkfs failed");

        let ino = fs.alloc_inode(&sb).expect("alloc inode");
        let mut inode = Inode {
            mode: 0o100644,
            uid: 0, gid: 0, flags: 0,
            size: 0, blocks: 0,
            atime: 0, mtime: 0, ctime: 0, crtime: 0,
            nlink: 1, generation: 0,
            direct: [BlockAddr::NULL; INODE_DIRECT_BLOCKS],
            indirect: [BlockAddr::NULL; INODE_INDIRECT_LEVELS],
            extent_root: BlockAddr::NULL,
            xattr_block: BlockAddr::NULL,
            checksum: 0,
        };

        let data = b"Hello, PermFS! This is a test of the write functionality.";
        let written = fs.write_file(&mut inode, 0, data, &sb).expect("write file");
        assert_eq!(written, data.len());
        assert_eq!(inode.size, data.len() as u64);

        fs.write_inode(ino, &inode, &sb).expect("save inode");

        let inode = fs.read_inode(ino, &sb).expect("read inode");
        let mut buf = vec![0u8; 100];
        let read = fs.read_file(&inode, 0, &mut buf).expect("read file");
        assert_eq!(read, data.len());
        assert_eq!(&buf[..read], data);
    }

    #[test]
    fn test_large_file() {
        let (fs, sb) = TestFsBuilder::new()
            .total_blocks(5000)
            .build()
            .expect("mkfs failed");

        let ino = fs.alloc_inode(&sb).expect("alloc inode");
        let mut inode = Inode {
            mode: 0o100644,
            uid: 0, gid: 0, flags: 0,
            size: 0, blocks: 0,
            atime: 0, mtime: 0, ctime: 0, crtime: 0,
            nlink: 1, generation: 0,
            direct: [BlockAddr::NULL; INODE_DIRECT_BLOCKS],
            indirect: [BlockAddr::NULL; INODE_INDIRECT_LEVELS],
            extent_root: BlockAddr::NULL,
            xattr_block: BlockAddr::NULL,
            checksum: 0,
        };

        let chunk = vec![0xABu8; BLOCK_SIZE];
        for i in 0..25 {
            let offset = i * BLOCK_SIZE;
            fs.write_file(&mut inode, offset as u64, &chunk, &sb).expect("write chunk");
        }

        assert_eq!(inode.size, 25 * BLOCK_SIZE as u64);
        assert!(inode.blocks >= 25);

        if inode.blocks > INODE_DIRECT_BLOCKS as u64 {
            assert!(!inode.indirect[0].is_null());
        }

        let mut buf = vec![0u8; BLOCK_SIZE];
        let read = fs.read_file(&inode, 20 * BLOCK_SIZE as u64, &mut buf).expect("read");
        assert_eq!(read, BLOCK_SIZE);
        assert!(buf.iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn test_mkdir_and_rmdir() {
        let (fs, sb) = TestFsBuilder::new().build().expect("mkfs failed");

        let ino = fs.alloc_inode(&sb).expect("alloc inode");
        let dir_block = fs.alloc_block(Some(sb.volume_id)).expect("alloc block");

        let mut inode = Inode {
            mode: 0o040755,
            uid: 0, gid: 0, flags: 0,
            size: BLOCK_SIZE as u64,
            blocks: 1,
            atime: 0, mtime: 0, ctime: 0, crtime: 0,
            nlink: 2,
            generation: 0,
            direct: [BlockAddr::NULL; INODE_DIRECT_BLOCKS],
            indirect: [BlockAddr::NULL; INODE_INDIRECT_LEVELS],
            extent_root: BlockAddr::NULL,
            xattr_block: BlockAddr::NULL,
            checksum: 0,
        };
        inode.direct[0] = dir_block;

        fs.init_directory_block(dir_block, ino, 0).expect("init dir");
        fs.write_inode(ino, &inode, &sb).expect("write inode");
        fs.add_dirent(0, b"subdir", ino, 2, &sb).expect("add dirent");

        assert!(fs.is_dir_empty(ino, &sb).expect("is_dir_empty"));

        fs.remove_dirent(0, b"subdir", &sb).expect("remove dirent");

        let root = fs.read_inode(0, &sb).expect("read root");
        assert!(fs.find_dirent(&root, b"subdir").is_err());
    }
}
