use permfs::file_device::FileBlockDevice;
use permfs::journal::{Journal, JournalHeader, TxState, MAX_TRANSACTION_BLOCKS};
use permfs::{BlockAddr, BlockDevice, BLOCK_SIZE};
use tempfile::tempdir;

fn journal_block_addr(first: BlockAddr, block_count: u64, seq: u64, offset: u64) -> BlockAddr {
    let journal_offset = ((seq * (MAX_TRANSACTION_BLOCKS as u64 + 2)) + offset) % block_count;
    let mut addr = first;
    addr.limbs[0] += journal_offset;
    addr
}

#[test]
fn journal_recovers_committed_tx() {
    let dir = tempdir().unwrap();
    let img = dir.path().join("journal.img");
    let device = FileBlockDevice::open_or_create(&img, 1, 0, 1024).unwrap();

    let header = JournalHeader {
        magic: permfs::journal::JOURNAL_MAGIC,
        version: 1,
        state: TxState::Running,
        head_seq: 1,
        tail_seq: 1,
        first_block: BlockAddr::new(1, 0, 0, 100),
        block_count: 32,
        max_transaction: MAX_TRANSACTION_BLOCKS as u32,
        checksum: 0,
    };

    let journal = Journal::new(device.clone(), header);
    let mut tx = journal.begin();

    // destination block to replay into
    let dest = BlockAddr::new(1, 0, 0, 5);
    let mut payload = [0u8; BLOCK_SIZE];
    payload[..11].copy_from_slice(b"journal_wal");
    tx.write(dest, &payload).unwrap();

    // Commit (descriptor + data + commit) but do not checkpoint.
    journal.commit(&mut tx).unwrap();

    // Simulate persisted header advancing head_seq
    let crash_header = JournalHeader {
        head_seq: tx.sequence() + 1,
        tail_seq: tx.sequence(),
        ..header
    };
    let replay = Journal::new(device.clone(), crash_header);
    let recovered = replay.recover().unwrap();
    assert_eq!(recovered, vec![tx.sequence()]);

    // Data should have been replayed to destination block.
    let mut out = [0u8; BLOCK_SIZE];
    device.read_block(dest, &mut out).unwrap();
    assert_eq!(&out[..11], b"journal_wal");
}

#[test]
fn journal_skips_missing_commit() {
    let dir = tempdir().unwrap();
    let img = dir.path().join("journal_missing_commit.img");
    let device = FileBlockDevice::open_or_create(&img, 1, 0, 1024).unwrap();

    let header = JournalHeader {
        magic: permfs::journal::JOURNAL_MAGIC,
        version: 1,
        state: TxState::Running,
        head_seq: 1,
        tail_seq: 1,
        first_block: BlockAddr::new(1, 0, 0, 200),
        block_count: 32,
        max_transaction: MAX_TRANSACTION_BLOCKS as u32,
        checksum: 0,
    };

    let journal = Journal::new(device.clone(), header);
    let mut tx = journal.begin();
    let dest = BlockAddr::new(1, 0, 0, 8);
    let payload = [0xAAu8; BLOCK_SIZE];
    tx.write(dest, &payload).unwrap();

    // Write descriptor and data blocks via commit, then corrupt commit record.
    journal.commit(&mut tx).unwrap();
    let commit_addr = journal_block_addr(
        header.first_block,
        header.block_count,
        tx.sequence(),
        1 + tx.block_count() as u64,
    );
    let zero = [0u8; BLOCK_SIZE];
    device.write_block(commit_addr, &zero).unwrap();

    let crash_header = JournalHeader {
        head_seq: tx.sequence() + 1,
        tail_seq: tx.sequence(),
        ..header
    };
    let replay = Journal::new(device.clone(), crash_header);
    let recovered = replay.recover().unwrap();
    assert!(recovered.is_empty());

    // Destination block should remain zeroed (not replayed)
    let mut out = [0u8; BLOCK_SIZE];
    device.read_block(dest, &mut out).unwrap();
    assert_ne!(out[0], 0xAA);
    assert!(out.iter().all(|b| *b == 0));
}

/// Test that journal recovery works during mount
#[test]
fn recovery_on_mount() {
    use std::path::PathBuf;

    let img = PathBuf::from("/tmp/permfs_journal_recovery.img");
    let _ = std::fs::remove_file(&img);

    let node_id = 1u64;
    let volume_id = 0u32;

    // Create fresh filesystem
    let device = FileBlockDevice::create(&img, node_id, volume_id, 10000).unwrap();

    // Set up journal header pointing to journal area (after superblock + inode table)
    // For simplicity, use fixed offsets matching DiskFsBuilder
    let journal_start = BlockAddr::new(node_id, volume_id, 0, 300);
    let header = JournalHeader {
        magic: permfs::journal::JOURNAL_MAGIC,
        version: 1,
        state: TxState::Running,
        head_seq: 1,
        tail_seq: 1,
        first_block: BlockAddr::new(node_id, volume_id, 0, 301),
        block_count: 64,
        max_transaction: MAX_TRANSACTION_BLOCKS as u32,
        checksum: 0,
    };

    // Write journal header
    let mut header_buf = [0u8; BLOCK_SIZE];
    header.serialize(&mut header_buf);
    device.write_block(journal_start, &header_buf).unwrap();

    // Create journal and commit a transaction
    let journal = Journal::new(device.clone(), header);
    let mut tx = journal.begin();

    // Write test data to a specific block
    let dest_block = BlockAddr::new(node_id, volume_id, 0, 500);
    let mut payload = [0u8; BLOCK_SIZE];
    payload[..16].copy_from_slice(b"recovery_test!!\0");
    tx.write(dest_block, &payload).unwrap();

    // Commit but don't checkpoint (simulating crash after commit)
    journal.commit(&mut tx).unwrap();

    // Update header to reflect uncommitted transaction
    let crash_header = JournalHeader {
        head_seq: tx.sequence() + 1,
        tail_seq: tx.sequence(),
        ..header
    };
    let mut crash_header_buf = [0u8; BLOCK_SIZE];
    crash_header.serialize(&mut crash_header_buf);
    device.write_block(journal_start, &crash_header_buf).unwrap();
    device.sync().unwrap();

    // Verify destination block is still empty (not checkpointed)
    let mut check_buf = [0u8; BLOCK_SIZE];
    device.read_block(dest_block, &mut check_buf).unwrap();
    assert_ne!(&check_buf[..16], b"recovery_test!!\0", "Data should not be at destination yet");

    // Now simulate reopening - create a fresh device to same file
    drop(device);

    // Re-open using the lower-level journal recovery
    let device2 = FileBlockDevice::open_existing(&img, node_id, volume_id).unwrap();

    // Read journal header
    let mut header_buf2 = [0u8; BLOCK_SIZE];
    device2.read_block(journal_start, &mut header_buf2).unwrap();
    let header2 = JournalHeader::deserialize(&header_buf2);

    // Perform recovery
    let journal2 = Journal::new(device2.clone(), header2);
    let recovered = journal2.recover().unwrap();

    assert!(!recovered.is_empty(), "Should have recovered at least one transaction");
    assert_eq!(recovered.len(), 1);

    // Verify data was replayed to destination
    let mut out = [0u8; BLOCK_SIZE];
    device2.read_block(dest_block, &mut out).unwrap();
    assert_eq!(&out[..16], b"recovery_test!!\0", "Data should be recovered");
}

#[cfg(feature = "network")]
#[test]
fn tcp_transport_roundtrip() {
    use permfs::local::MemoryBlockDevice;
    use permfs::transport::{RequestHandler, TcpServer, TcpTransport};
    use permfs::{AllocError, IoError};
    use std::net::{SocketAddr, TcpStream};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::thread;

    // Simple in-memory handler with tracked allocations.
    #[derive(Clone)]
    struct MemHandler {
        device: MemoryBlockDevice,
        next: Arc<AtomicU64>,
    }
    impl RequestHandler for MemHandler {
        fn handle_read(&self, addr: BlockAddr) -> Result<[u8; BLOCK_SIZE], IoError> {
            let mut buf = [0u8; BLOCK_SIZE];
            self.device.read_block(addr, &mut buf)?;
            Ok(buf)
        }
        fn handle_write(&self, addr: BlockAddr, data: &[u8; BLOCK_SIZE]) -> Result<(), IoError> {
            self.device.write_block(addr, data)
        }
        fn handle_alloc(&self, _volume: u32) -> Result<BlockAddr, AllocError> {
            let off = self.next.fetch_add(1, Ordering::Relaxed);
            Ok(BlockAddr::new(1, 0, 0, off))
        }
        fn handle_free(&self, _addr: BlockAddr) -> Result<(), AllocError> {
            Ok(())
        }
    }

    let handler = Arc::new(MemHandler {
        device: MemoryBlockDevice::new(1, 0),
        next: Arc::new(AtomicU64::new(0)),
    });

    let addr: SocketAddr = "127.0.0.1:18743".parse().unwrap();
    let server = Arc::new(TcpServer::bind(1, addr).expect("bind"));
    let server_run = server.clone();
    let handler_run = handler.clone();
    let handle = thread::spawn(move || {
        server_run.run(handler_run);
    });

    // Client transport
    let transport = TcpTransport::new(2);
    transport.registry().register(1, addr);

    // Allocate, write, and read back.
    let block = transport.alloc_remote(1, 0).expect("alloc");
    let mut data = [0u8; BLOCK_SIZE];
    data[..4].copy_from_slice(b"PING");
    transport.write_remote(1, block, &data).expect("write");

    let mut out = [0u8; BLOCK_SIZE];
    transport.read_remote(1, block, &mut out).expect("read");
    assert_eq!(&out[..4], b"PING");

    // Stop server: set flag then connect once to unblock accept loop.
    server.stop();
    let _ = TcpStream::connect(addr);
    let _ = handle.join();
}
