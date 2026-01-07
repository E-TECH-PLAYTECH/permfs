//! OS-backed block device implementation.
//!
//! This module wires the crate's `BlockDevice` abstraction to a host block
//! device or regular file using synchronous I/O primitives. It enforces 4 KiB
//! alignment, performs lightweight retries, and exposes optional checksum
//! verification hooks.

#![cfg(feature = "std")]

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::io::{ErrorKind, Result as IoResult};
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::panic_support::{register_panic_quiesce, PanicQuiesce, PanicQuiesceResult};
use crate::sync::Arc;
use crate::{BlockAddr, BlockDevice, FsResult, IoError, BLOCK_SIZE};

/// Hook signature used to validate buffers before/after I/O.
pub type ChecksumHook = dyn Fn(&[u8; BLOCK_SIZE]) -> FsResult<()> + Send + Sync + 'static;

/// Configuration parameters for the OS block device binding.
#[derive(Clone)]
pub struct BlockDeviceParams {
    pub node_id: u64,
    pub volume_id: u32,
    pub shard_id: u16,
    pub queue_depth: usize,
    pub verify_read: Option<Arc<ChecksumHook>>,
    pub verify_write: Option<Arc<ChecksumHook>>,
}

impl BlockDeviceParams {
    pub fn new(node_id: u64, volume_id: u32, shard_id: u16) -> Self {
        Self {
            node_id,
            volume_id,
            shard_id,
            queue_depth: 32,
            verify_read: None,
            verify_write: None,
        }
    }

    pub fn with_queue_depth(mut self, depth: usize) -> Self {
        self.queue_depth = depth.max(1);
        self
    }

    pub fn with_read_verifier(mut self, hook: Arc<ChecksumHook>) -> Self {
        self.verify_read = Some(hook);
        self
    }

    pub fn with_write_verifier(mut self, hook: Arc<ChecksumHook>) -> Self {
        self.verify_write = Some(hook);
        self
    }
}

/// Internal abstraction to allow mocking the backing I/O primitive.
pub trait BlockBackend: Send + Sync {
    fn read_aligned(&self, offset: u64, buf: &mut [u8]) -> IoResult<()>;
    fn write_aligned(&self, offset: u64, buf: &[u8]) -> IoResult<()>;
    fn flush(&self) -> IoResult<()> {
        Ok(())
    }
    fn trim(&self, _offset: u64, _len: u64) -> IoResult<()> {
        Err(std::io::Error::new(
            ErrorKind::Unsupported,
            "discard unsupported",
        ))
    }
}

impl BlockBackend for std::fs::File {
    fn read_aligned(&self, offset: u64, buf: &mut [u8]) -> IoResult<()> {
        self.read_exact_at(buf, offset)
    }

    fn write_aligned(&self, offset: u64, buf: &[u8]) -> IoResult<()> {
        self.write_all_at(buf, offset)
    }

    fn flush(&self) -> IoResult<()> {
        self.sync_all()
    }

    fn trim(&self, _offset: u64, _len: u64) -> IoResult<()> {
        #[cfg(all(unix, feature = "block-discard"))]
        unsafe {
            use std::os::unix::io::AsRawFd;

            // On Linux, punch a hole to emulate discard. Fall back to zeroing if unsupported.
            let ret = libc::fallocate(
                self.as_raw_fd(),
                libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
                offset as i64,
                len as i64,
            );
            if ret == 0 {
                return Ok(());
            }
            let err = std::io::Error::last_os_error();
            if err.kind() != ErrorKind::Unsupported && err.raw_os_error() != Some(libc::EOPNOTSUPP)
            {
                return Err(err);
            }
        }

        Err(std::io::Error::new(
            ErrorKind::Unsupported,
            "discard unsupported",
        ))
    }
}

/// OS-backed implementation of the crate's [`BlockDevice`] trait.
pub struct OsBlockDevice<B: BlockBackend = std::fs::File> {
    backend: B,
    params: BlockDeviceParams,
    retries: usize,
    panic_frozen: AtomicBool,
    in_flight: AtomicUsize,
}

impl OsBlockDevice {
    /// Open a device or regular file path.
    pub fn open(path: impl AsRef<Path>, params: BlockDeviceParams) -> FsResult<Self> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(map_io_error)?;
        Ok(Self::from_backend(file, params))
    }
}

impl<B: BlockBackend + 'static> OsBlockDevice<B> {
    pub fn from_backend(backend: B, params: BlockDeviceParams) -> Self {
        Self {
            backend,
            params,
            retries: 3,
            panic_frozen: AtomicBool::new(false),
            in_flight: AtomicUsize::new(0),
        }
    }

    /// Leak the device reference and register it for panic quiesce handling.
    pub fn register_for_panic(self: &Arc<Self>) {
        let leaked: &'static Self = unsafe { &*Arc::into_raw(self.clone()) };
        register_panic_quiesce(Some(leaked));
    }

    fn validate_address(&self, addr: BlockAddr) -> FsResult<u64> {
        if addr.node_id() != self.params.node_id
            || addr.volume_id() != self.params.volume_id
            || addr.shard_id() != self.params.shard_id
        {
            return Err(IoError::InvalidAddress);
        }

        let byte_offset = addr.block_offset().saturating_mul(BLOCK_SIZE as u64);
        if byte_offset % (BLOCK_SIZE as u64) != 0 {
            return Err(IoError::InvalidAddress);
        }
        Ok(byte_offset)
    }

    fn retry_io<F>(&self, mut op: F) -> FsResult<()>
    where
        F: FnMut() -> IoResult<()>,
    {
        if self.panic_frozen.load(Ordering::Acquire) {
            return Err(IoError::IoFailed);
        }

        self.in_flight.fetch_add(1, Ordering::AcqRel);
        let attempts = self.retries.max(1);
        for attempt in 0..attempts {
            match op() {
                Ok(()) => {
                    self.in_flight.fetch_sub(1, Ordering::AcqRel);
                    return Ok(());
                }
                Err(err) if attempt + 1 < attempts => {
                    if err.kind() == ErrorKind::Interrupted {
                        continue;
                    }
                }
                Err(err) => {
                    self.in_flight.fetch_sub(1, Ordering::AcqRel);
                    return Err(map_io_error(err));
                }
            }
        }
        self.in_flight.fetch_sub(1, Ordering::AcqRel);
        Err(IoError::IoFailed)
    }

    fn verify_read(&self, buf: &[u8; BLOCK_SIZE]) -> FsResult<()> {
        if let Some(hook) = &self.params.verify_read {
            hook(buf)?;
        }
        Ok(())
    }

    fn verify_write(&self, buf: &[u8; BLOCK_SIZE]) -> FsResult<()> {
        if let Some(hook) = &self.params.verify_write {
            hook(buf)?;
        }
        Ok(())
    }

    fn zero_block(&self, byte_offset: u64) -> FsResult<()> {
        self.zero_range(byte_offset, 1)
    }

    fn zero_range(&self, byte_offset: u64, blocks: u64) -> FsResult<()> {
        let zeros = [0u8; BLOCK_SIZE];
        for blk in 0..blocks {
            let offset = byte_offset.saturating_add(blk * BLOCK_SIZE as u64);
            self.retry_io(|| self.backend.write_aligned(offset, &zeros))?;
        }
        Ok(())
    }
}

impl<B: BlockBackend + 'static> BlockDevice for OsBlockDevice<B> {
    fn read_block(&self, addr: BlockAddr, buf: &mut [u8; BLOCK_SIZE]) -> FsResult<()> {
        let offset = self.validate_address(addr)?;
        self.retry_io(|| self.backend.read_aligned(offset, buf))?;
        self.verify_read(buf)
    }

    fn write_block(&self, addr: BlockAddr, buf: &[u8; BLOCK_SIZE]) -> FsResult<()> {
        let offset = self.validate_address(addr)?;
        self.verify_write(buf)?;
        self.retry_io(|| self.backend.write_aligned(offset, buf))
    }

    fn sync(&self) -> FsResult<()> {
        if self.panic_frozen.load(Ordering::Acquire) {
            return Err(IoError::IoFailed);
        }

        self.in_flight.fetch_add(1, Ordering::AcqRel);
        let result = match self.backend.flush() {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == ErrorKind::Unsupported => Ok(()),
            Err(err) => Err(map_io_error(err)),
        };
        self.in_flight.fetch_sub(1, Ordering::AcqRel);
        result
    }

    fn trim(&self, addr: BlockAddr) -> FsResult<()> {
        self.trim_range(addr, 1)
    }

    fn trim_range(&self, addr: BlockAddr, len: u64) -> FsResult<()> {
        let offset = self.validate_address(addr)?;
        let byte_len = len.saturating_mul(BLOCK_SIZE as u64);
        if self.panic_frozen.load(Ordering::Acquire) {
            return Err(IoError::IoFailed);
        }

        self.in_flight.fetch_add(1, Ordering::AcqRel);
        let result = match self.backend.trim(offset, byte_len) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == ErrorKind::Unsupported => self
                .zero_range(offset, len)
                .or_else(|_| self.zero_block(offset)),
            Err(err) => Err(map_io_error(err)),
        };
        self.in_flight.fetch_sub(1, Ordering::AcqRel);
        result
    }

    fn queue_depth(&self) -> usize {
        self.params.queue_depth
    }
}

impl<B: BlockBackend> PanicQuiesce for OsBlockDevice<B> {
    fn panic_freeze(&self) -> PanicQuiesceResult {
        self.panic_frozen.store(true, Ordering::Release);
        let start = Instant::now();
        let mut drained = false;
        let mut flush_issued = false;
        let timeout = Duration::from_millis(50);

        loop {
            let in_flight = self.in_flight.load(Ordering::Acquire);
            if in_flight == 0 {
                drained = true;
                flush_issued = self.backend.flush().is_ok();
                return PanicQuiesceResult {
                    drained,
                    in_flight,
                    flush_issued,
                };
            }

            if start.elapsed() >= timeout {
                return PanicQuiesceResult {
                    drained,
                    in_flight,
                    flush_issued,
                };
            }

            std::thread::yield_now();
        }
    }
}

fn map_io_error(err: std::io::Error) -> IoError {
    match err.kind() {
        ErrorKind::NotFound => IoError::NotFound,
        ErrorKind::PermissionDenied => IoError::PermissionDenied,
        ErrorKind::TimedOut | ErrorKind::WouldBlock => IoError::NetworkTimeout,
        ErrorKind::InvalidData => IoError::Corrupted,
        ErrorKind::Interrupted => IoError::LockContention,
        _ => IoError::IoFailed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::fs::OpenOptions;
    use tempfile::tempdir;

    #[derive(Clone)]
    struct MockBackend {
        fail_writes: bool,
        storage: Arc<crate::sync::Mutex<Vec<u8>>>,
    }

    impl MockBackend {
        fn new(blocks: usize, fail_writes: bool) -> Self {
            Self {
                fail_writes,
                storage: Arc::new(crate::sync::Mutex::new(vec![0u8; blocks * BLOCK_SIZE])),
            }
        }
    }

    impl BlockBackend for MockBackend {
        fn read_aligned(&self, offset: u64, buf: &mut [u8]) -> IoResult<()> {
            let mut guard = self.storage.lock().unwrap();
            let off = offset as usize;
            buf.copy_from_slice(&guard[off..off + buf.len()]);
            Ok(())
        }

        fn write_aligned(&self, offset: u64, buf: &[u8]) -> IoResult<()> {
            if self.fail_writes {
                return Err(std::io::Error::new(ErrorKind::Other, "fail"));
            }
            let mut guard = self.storage.lock().unwrap();
            let off = offset as usize;
            guard[off..off + buf.len()].copy_from_slice(buf);
            Ok(())
        }

        fn trim(&self, offset: u64, len: u64) -> IoResult<()> {
            let mut guard = self.storage.lock().unwrap();
            let off = offset as usize;
            guard[off..off + len as usize].fill(0);
            Ok(())
        }
    }

    fn params() -> BlockDeviceParams {
        BlockDeviceParams::new(7, 3, 1).with_queue_depth(8)
    }

    fn addr(offset: u64) -> BlockAddr {
        BlockAddr::new(7, 3, 1, offset)
    }

    #[test]
    fn rejects_mismatched_address() {
        let backend = MockBackend::new(4, false);
        let device = OsBlockDevice::from_backend(backend, params());
        let bad_addr = BlockAddr::new(1, 1, 1, 0);
        let mut buf = [0u8; BLOCK_SIZE];
        let err = device.read_block(bad_addr, &mut buf).unwrap_err();
        assert_eq!(err, IoError::InvalidAddress);
    }

    #[test]
    fn read_write_roundtrip_with_hooks() {
        let backend = MockBackend::new(4, false);
        let read_calls = Arc::new(AtomicUsize::new(0));
        let write_calls = Arc::new(AtomicUsize::new(0));

        let params = params()
            .with_read_verifier({
                let read_calls = read_calls.clone();
                Arc::new(move |_| {
                    read_calls.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                })
            })
            .with_write_verifier({
                let write_calls = write_calls.clone();
                Arc::new(move |_| {
                    write_calls.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                })
            });

        let device = OsBlockDevice::from_backend(backend, params);

        let mut write_buf = [0u8; BLOCK_SIZE];
        write_buf[..4].copy_from_slice(b"test");
        device.write_block(addr(0), &write_buf).expect("write");

        let mut read_buf = [0u8; BLOCK_SIZE];
        device.read_block(addr(0), &mut read_buf).expect("read");
        assert_eq!(&read_buf[..4], b"test");
        assert_eq!(read_calls.load(Ordering::SeqCst), 1);
        assert_eq!(write_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn sync_flushes_to_disk() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("device.bin");
        {
            let file = OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            file.set_len((BLOCK_SIZE * 2) as u64).unwrap();
            let device = OsBlockDevice::from_backend(file, params());

            let mut buf = [0u8; BLOCK_SIZE];
            buf[..3].copy_from_slice(b"abc");
            device.write_block(addr(1), &buf).unwrap();
            device.sync().unwrap();
        }

        let mut reopen = OpenOptions::new().read(true).open(&path).unwrap();
        let mut verify = [0u8; BLOCK_SIZE];
        reopen
            .read_exact_at(&mut verify, BLOCK_SIZE as u64)
            .unwrap();
        assert_eq!(&verify[..3], b"abc");
    }

    #[test]
    fn trim_zeroes_block() {
        let backend = MockBackend::new(2, false);
        let device = OsBlockDevice::from_backend(backend.clone(), params());

        let mut buf = [0xFFu8; BLOCK_SIZE];
        device.write_block(addr(0), &buf).unwrap();
        device.trim(addr(0)).unwrap();

        let mut verify = [0u8; BLOCK_SIZE];
        backend
            .read_aligned(0, &mut verify)
            .expect("read after trim");
        assert_eq!(verify, [0u8; BLOCK_SIZE]);
    }

    #[test]
    fn propagates_backend_error() {
        let backend = MockBackend::new(1, true);
        let device = OsBlockDevice::from_backend(backend, params());
        let buf = [0u8; BLOCK_SIZE];
        let err = device.write_block(addr(0), &buf).unwrap_err();
        assert_eq!(err, IoError::IoFailed);
    }
}
