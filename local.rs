// PermFS Local Backends — in-memory/file block devices and in-process transport

use crate::sync::RwLock;
use crate::*;
use std::collections::HashMap;
use std::sync::Arc;

// ============================================================================//
// MEMORY BLOCK DEVICE
// ============================================================================//

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
        if addr.node_id() != self.node_id || addr.volume_id() != self.volume_id {
            return Err(IoError::InvalidAddress);
        }

        let blocks = self.blocks.read().unwrap();
        if let Some(data) = blocks.get(&addr) {
            buf.copy_from_slice(data);
        } else {
            buf.fill(0);
        }
        Ok(())
    }

    fn write_block(&self, addr: BlockAddr, buf: &[u8; BLOCK_SIZE]) -> FsResult<()> {
        if addr.node_id() != self.node_id || addr.volume_id() != self.volume_id {
            return Err(IoError::InvalidAddress);
        }

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

// ============================================================================//
// IN-PROCESS TRANSPORT
// ============================================================================//

/// In-process transport that routes cluster calls to registered node endpoints.
#[derive(Clone, Default)]
pub struct InProcessTransport {
    endpoints: Arc<RwLock<HashMap<u64, LocalEndpoint>>>,
}

type ReadFn = Arc<dyn Fn(BlockAddr, &mut [u8; BLOCK_SIZE]) -> FsResult<()> + Send + Sync>;
type WriteFn = Arc<dyn Fn(BlockAddr, &[u8; BLOCK_SIZE]) -> FsResult<()> + Send + Sync>;
type AllocFn = Arc<dyn Fn(u32) -> Result<BlockAddr, AllocError> + Send + Sync>;
type FreeFn = Arc<dyn Fn(BlockAddr) -> Result<(), AllocError> + Send + Sync>;

struct LocalEndpoint {
    read: ReadFn,
    write: WriteFn,
    alloc: AllocFn,
    free: FreeFn,
}

impl InProcessTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a node endpoint to satisfy remote calls.
    pub fn register<B: BlockDevice + 'static, T: ClusterTransport + 'static>(
        &self,
        node_id: u64,
        fs: Arc<PermFs<B, T>>,
    ) {
        let read = {
            let fs = fs.clone();
            Arc::new(move |addr: BlockAddr, buf: &mut [u8; BLOCK_SIZE]| {
                fs.local_device.read_block(addr, buf)
            })
        };
        let write = {
            let fs = fs.clone();
            Arc::new(move |addr: BlockAddr, buf: &[u8; BLOCK_SIZE]| {
                fs.local_device.write_block(addr, buf)
            })
        };
        let alloc = {
            let fs = fs.clone();
            Arc::new(move |volume: u32| {
                let idx = volume as usize;
                fs.volumes
                    .get(idx)
                    .and_then(|v| v.as_ref())
                    .ok_or(AllocError::WrongVolume)?
                    .alloc_block()
            })
        };
        let free = {
            let fs = fs.clone();
            Arc::new(move |addr: BlockAddr| {
                let idx = addr.volume_id() as usize;
                fs.volumes
                    .get(idx)
                    .and_then(|v| v.as_ref())
                    .ok_or(AllocError::WrongVolume)?
                    .free_block(addr)
            })
        };

        self.endpoints.write().unwrap().insert(
            node_id,
            LocalEndpoint {
                read,
                write,
                alloc,
                free,
            },
        );
    }
}

impl ClusterTransport for InProcessTransport {
    fn read_remote(&self, node: u64, addr: BlockAddr, buf: &mut [u8; BLOCK_SIZE]) -> FsResult<()> {
        (self
            .endpoints
            .read()
            .unwrap()
            .get(&node)
            .ok_or(IoError::NetworkTimeout)?
            .read)(addr, buf)
    }

    fn write_remote(&self, node: u64, addr: BlockAddr, buf: &[u8; BLOCK_SIZE]) -> FsResult<()> {
        (self
            .endpoints
            .read()
            .unwrap()
            .get(&node)
            .ok_or(IoError::NetworkTimeout)?
            .write)(addr, buf)
    }

    fn alloc_remote(&self, node: u64, volume: u32) -> Result<BlockAddr, AllocError> {
        (self
            .endpoints
            .read()
            .unwrap()
            .get(&node)
            .ok_or(AllocError::NetworkError)?
            .alloc)(volume)
    }

    fn free_remote(&self, node: u64, addr: BlockAddr) -> Result<(), AllocError> {
        (self
            .endpoints
            .read()
            .unwrap()
            .get(&node)
            .ok_or(AllocError::NetworkError)?
            .free)(addr)
    }
}

// ============================================================================//
// BUILDERS
// ============================================================================//

pub struct MemoryFsBuilder {
    node_id: u64,
    volume_id: u32,
    total_blocks: u64,
}

impl Default for MemoryFsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryFsBuilder {
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

    pub fn build(self) -> Result<(Arc<MemoryFs>, Superblock), IoError> {
        use crate::{ShardAllocator, VolumeAllocator};

        let transport = InProcessTransport::new();
        let device = MemoryBlockDevice::new(self.node_id, self.volume_id);

        let mut fs = PermFs::new(self.node_id, device, transport.clone());

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

        // Set up the block allocator
        let mut volume = VolumeAllocator::new(self.node_id, self.volume_id);
        let shard = ShardAllocator::new(0, self.total_blocks);
        // Mark metadata blocks + root directory block as used
        // data_start is where the root directory block is allocated
        shard.mark_used_range(0, result.data_start + 1);
        volume.add_shard(shard).map_err(|_| IoError::IoFailed)?;
        fs.register_volume(self.volume_id, volume).map_err(|_| IoError::IoFailed)?;

        let fs = Arc::new(fs);
        transport.register(self.node_id, fs.clone());

        Ok((fs, result.superblock))
    }
}

pub type MemoryFs = PermFs<MemoryBlockDevice, InProcessTransport>;

/// Disk-backed builder for a "real" node using FileBlockDevice.
pub struct DiskFsBuilder {
    node_id: u64,
    volume_id: u32,
    total_blocks: u64,
    image_path: std::path::PathBuf,
}

impl DiskFsBuilder {
    pub fn new<P: Into<std::path::PathBuf>>(image_path: P) -> Self {
        Self {
            node_id: 1,
            volume_id: 0,
            total_blocks: 10000,
            image_path: image_path.into(),
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

    pub fn build(self) -> Result<(Arc<DiskFs>, Superblock), IoError> {
        use crate::file_device::FileBlockDevice;
        use crate::{ShardAllocator, VolumeAllocator};

        // Create fresh image file (truncates if exists)
        let device = FileBlockDevice::create(
            &self.image_path,
            self.node_id,
            self.volume_id,
            self.total_blocks,
        )
        .map_err(|_| IoError::IoFailed)?;

        let transport = InProcessTransport::new();
        let mut fs = PermFs::new(self.node_id, device, transport.clone());

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

        // Set up the block allocator
        let mut volume = VolumeAllocator::new(self.node_id, self.volume_id);
        let shard = ShardAllocator::new(0, self.total_blocks);
        // Mark metadata blocks + root directory block as used
        // data_start is where the root directory block is allocated
        shard.mark_used_range(0, result.data_start + 1);
        volume.add_shard(shard).map_err(|_| IoError::IoFailed)?;
        fs.register_volume(self.volume_id, volume).map_err(|_| IoError::IoFailed)?;

        let fs = Arc::new(fs);
        transport.register(self.node_id, fs.clone());

        Ok((fs, result.superblock))
    }

    pub fn open_existing(self) -> Result<(Arc<DiskFs>, Superblock), IoError> {
        use crate::file_device::FileBlockDevice;
        use crate::{ShardAllocator, VolumeAllocator};

        // Open existing image without truncating
        let device = FileBlockDevice::open_existing(
            &self.image_path,
            self.node_id,
            self.volume_id,
        )
        .map_err(|_| IoError::IoFailed)?;

        let total_blocks = device.total_blocks();

        let transport = InProcessTransport::new();
        let mut fs = PermFs::new(self.node_id, device, transport.clone());
        let sb = fs.mount(self.node_id, self.volume_id)?;

        // Perform journal recovery before normal operation
        let recovery_stats = fs.recover_journal(&sb)?;
        if recovery_stats.recovery_needed {
            eprintln!(
                "PermFS: Recovered {} transactions from journal",
                recovery_stats.transactions_replayed
            );
        }

        // Set up the block allocator
        // Calculate data_start: journal_start + journal_blocks
        // We hardcode journal_blocks = 128 to match the build() method
        // TODO: In a full implementation, read the block bitmap from disk
        let journal_blocks = 128u64;
        let data_start = sb.journal_start.block_offset() + journal_blocks;
        let mut volume = VolumeAllocator::new(self.node_id, self.volume_id);
        let shard = ShardAllocator::new(0, total_blocks);
        // Mark metadata + root directory block as used
        shard.mark_used_range(0, data_start + 1);
        volume.add_shard(shard).map_err(|_| IoError::IoFailed)?;
        fs.register_volume(self.volume_id, volume).map_err(|_| IoError::IoFailed)?;

        let fs = Arc::new(fs);
        transport.register(self.node_id, fs.clone());

        Ok((fs, sb))
    }
}

pub type DiskFs = PermFs<crate::file_device::FileBlockDevice, InProcessTransport>;

// ============================================================================//
// TESTS
// ============================================================================//

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mkfs_and_mount() {
        let (_fs, sb) = MemoryFsBuilder::new()
            .total_blocks(1000)
            .build()
            .expect("mkfs failed");

        assert_eq!(sb.magic, SUPERBLOCK_MAGIC);
        assert_eq!(sb.total_blocks, 1000);
        assert!(sb.free_blocks.load(core::sync::atomic::Ordering::Relaxed) > 0);
    }

    #[test]
    fn test_root_directory() {
        let (fs, sb) = MemoryFsBuilder::new().build().expect("mkfs failed");
        let root = fs.read_inode(0, &sb).expect("read root inode");
        assert!(root.is_dir());
        assert_eq!(root.nlink, 2);
    }

    #[test]
    fn test_create_file() {
        let (fs, sb) = MemoryFsBuilder::new().build().expect("mkfs failed");

        let ino = fs.alloc_inode(&sb).expect("alloc inode");
        assert!(ino > 0);

        let inode = Inode {
            mode: 0o100644,
            uid: 1000,
            gid: 1000,
            flags: 0,
            size: 0,
            blocks: 0,
            atime: 0,
            mtime: 0,
            ctime: 0,
            crtime: 0,
            nlink: 1,
            generation: 0,
            direct: [BlockAddr::NULL; INODE_DIRECT_BLOCKS],
            indirect: [BlockAddr::NULL; INODE_INDIRECT_LEVELS],
            extent_root: BlockAddr::NULL,
            xattr_block: BlockAddr::NULL,
            checksum: 0,
        };

        fs.write_inode(ino, &inode, &sb).expect("write inode");
        fs.add_dirent(0, b"testfile", ino, 1, &sb)
            .expect("add dirent");

        let root = fs.read_inode(0, &sb).expect("read root");
        let found = fs.find_dirent(&root, b"testfile").expect("find dirent");
        assert_eq!(found, ino);
    }

    #[test]
    fn test_write_and_read() {
        let (fs, sb) = MemoryFsBuilder::new().build().expect("mkfs failed");

        let ino = fs.alloc_inode(&sb).expect("alloc inode");
        let mut inode = Inode {
            mode: 0o100644,
            uid: 0,
            gid: 0,
            flags: 0,
            size: 0,
            blocks: 0,
            atime: 0,
            mtime: 0,
            ctime: 0,
            crtime: 0,
            nlink: 1,
            generation: 0,
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
        let (fs, sb) = MemoryFsBuilder::new()
            .total_blocks(5000)
            .build()
            .expect("mkfs failed");

        let ino = fs.alloc_inode(&sb).expect("alloc inode");
        let mut inode = Inode {
            mode: 0o100644,
            uid: 0,
            gid: 0,
            flags: 0,
            size: 0,
            blocks: 0,
            atime: 0,
            mtime: 0,
            ctime: 0,
            crtime: 0,
            nlink: 1,
            generation: 0,
            direct: [BlockAddr::NULL; INODE_DIRECT_BLOCKS],
            indirect: [BlockAddr::NULL; INODE_INDIRECT_LEVELS],
            extent_root: BlockAddr::NULL,
            xattr_block: BlockAddr::NULL,
            checksum: 0,
        };

        let chunk = vec![0xCDu8; BLOCK_SIZE];
        for i in 0..20 {
            fs.write_file(&mut inode, (i * BLOCK_SIZE) as u64, &chunk, &sb)
                .expect("write");
        }

        fs.write_inode(ino, &inode, &sb).expect("save inode");

        let inode = fs.read_inode(ino, &sb).expect("read inode");
        let mut buf = vec![0u8; BLOCK_SIZE];
        let read = fs
            .read_file(&inode, 10 * BLOCK_SIZE as u64, &mut buf)
            .expect("read");
        assert_eq!(read, BLOCK_SIZE);
        assert!(buf.iter().all(|&b| b == 0xCD));
    }

    #[test]
    fn test_symlink() {
        let (fs, sb) = MemoryFsBuilder::new().build().expect("mkfs failed");

        let ino = fs
            .symlink_impl(0, b"link", b"/hello.txt", &sb)
            .expect("symlink");
        let inode = fs.read_inode(ino, &sb).expect("read");
        assert!(inode.is_symlink());

        let mut buf = vec![0u8; 256];
        let len = fs.readlink_impl(ino, &mut buf, &sb).expect("readlink");
        assert_eq!(&buf[..len], b"/hello.txt");
    }
}
