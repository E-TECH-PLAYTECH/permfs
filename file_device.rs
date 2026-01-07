// PermFS File-backed Block Device — simple persistent backend using a sparse file

use crate::{BlockAddr, BlockDevice, FsResult, IoError, BLOCK_SIZE};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::RwLock;

/// Persistent block device backed by a single sparse file.
/// One instance serves a single (node_id, volume_id) pair.
#[derive(Clone)]
pub struct FileBlockDevice {
    file: Arc<RwLock<File>>,
    total_blocks: u64,
    node_id: u64,
    volume_id: u32,
}

impl FileBlockDevice {
    /// Create a new block image at `path` sized for `total_blocks`.
    /// WARNING: This truncates any existing file!
    pub fn create<P: AsRef<Path>>(
        path: P,
        node_id: u64,
        volume_id: u32,
        total_blocks: u64,
    ) -> std::io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .open(path)?;

        let target_len = total_blocks.saturating_mul(BLOCK_SIZE as u64);
        file.set_len(target_len)?;

        Ok(Self {
            file: Arc::new(RwLock::new(file)),
            total_blocks,
            node_id,
            volume_id,
        })
    }

    /// Open an existing block image at `path` without truncating.
    pub fn open_existing<P: AsRef<Path>>(
        path: P,
        node_id: u64,
        volume_id: u32,
    ) -> std::io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)?;

        let len = file.metadata()?.len();
        let total_blocks = len / BLOCK_SIZE as u64;

        Ok(Self {
            file: Arc::new(RwLock::new(file)),
            total_blocks,
            node_id,
            volume_id,
        })
    }

    /// Create or open a block image. Creates new file if it doesn't exist,
    /// otherwise opens existing without truncating.
    pub fn open_or_create<P: AsRef<Path>>(
        path: P,
        node_id: u64,
        volume_id: u32,
        total_blocks: u64,
    ) -> std::io::Result<Self> {
        let p = path.as_ref();
        if p.exists() {
            Self::open_existing(p, node_id, volume_id)
        } else {
            Self::create(p, node_id, volume_id, total_blocks)
        }
    }

    pub fn total_blocks(&self) -> u64 {
        self.total_blocks
    }

    #[inline]
    fn validate_addr(&self, addr: BlockAddr) -> FsResult<u64> {
        if addr.node_id() != self.node_id || addr.volume_id() != self.volume_id {
            return Err(IoError::InvalidAddress);
        }

        let offset = addr.block_offset();
        if offset >= self.total_blocks {
            return Err(IoError::InvalidAddress);
        }

        Ok(offset)
    }

    #[inline]
    fn seek_offset(&self, file: &mut File, block_offset: u64) -> std::io::Result<()> {
        let byte_off = block_offset.saturating_mul(BLOCK_SIZE as u64);
        file.seek(SeekFrom::Start(byte_off))?;
        Ok(())
    }
}

impl BlockDevice for FileBlockDevice {
    fn read_block(&self, addr: BlockAddr, buf: &mut [u8; BLOCK_SIZE]) -> FsResult<()> {
        let offset = self.validate_addr(addr)?;

        let mut file = self.file.write().unwrap();
        self.seek_offset(&mut file, offset)
            .map_err(|_| IoError::IoFailed)?;
        file.read_exact(buf).map_err(|_| IoError::IoFailed)?;
        Ok(())
    }

    fn write_block(&self, addr: BlockAddr, buf: &[u8; BLOCK_SIZE]) -> FsResult<()> {
        let offset = self.validate_addr(addr)?;

        let mut file = self.file.write().unwrap();
        self.seek_offset(&mut file, offset)
            .map_err(|_| IoError::IoFailed)?;
        file.write_all(buf).map_err(|_| IoError::IoFailed)?;
        Ok(())
    }

    fn sync(&self) -> FsResult<()> {
        self.file
            .read()
            .unwrap()
            .sync_all()
            .map_err(|_| IoError::IoFailed)?;
        Ok(())
    }

    fn trim(&self, addr: BlockAddr) -> FsResult<()> {
        let offset = self.validate_addr(addr)?;

        let mut file = self.file.write().unwrap();
        self.seek_offset(&mut file, offset)
            .map_err(|_| IoError::IoFailed)?;
        let zero = [0u8; BLOCK_SIZE];
        file.write_all(&zero).map_err(|_| IoError::IoFailed)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BlockAddr;
    use tempfile::tempdir;

    #[test]
    fn file_device_roundtrip() {
        let dir = tempdir().unwrap();
        let img = dir.path().join("blk.img");
        let device = FileBlockDevice::open_or_create(&img, 7, 0, 16).unwrap();

        let addr = BlockAddr::new(7, 0, 0, 3);
        let mut data = [0xABu8; BLOCK_SIZE];
        data[0] = 0x42;

        device.write_block(addr, &data).unwrap();

        let mut out = [0u8; BLOCK_SIZE];
        device.read_block(addr, &mut out).unwrap();
        assert_eq!(out[0], 0x42);
        assert_eq!(out[1], 0xAB);

        device.trim(addr).unwrap();
        let mut zero = [0u8; BLOCK_SIZE];
        device.read_block(addr, &mut zero).unwrap();
        assert!(zero.iter().all(|b| *b == 0));
    }

    #[test]
    fn rejects_wrong_node_or_volume() {
        let dir = tempdir().unwrap();
        let img = dir.path().join("blk.img");
        let device = FileBlockDevice::open_or_create(&img, 1, 2, 8).unwrap();

        let mut buf = [0u8; BLOCK_SIZE];
        let bad_node = BlockAddr::new(3, 2, 0, 0);
        assert!(matches!(
            device.read_block(bad_node, &mut buf),
            Err(IoError::InvalidAddress)
        ));

        let bad_vol = BlockAddr::new(1, 3, 0, 0);
        assert!(matches!(
            device.read_block(bad_vol, &mut buf),
            Err(IoError::InvalidAddress)
        ));
    }
}
