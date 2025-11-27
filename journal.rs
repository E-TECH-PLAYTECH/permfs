// PermFS Journal — Write-ahead logging for crash consistency

use crate::*;
use core::sync::atomic::Ordering;

pub const JOURNAL_MAGIC: u64 = 0x5045524D_4A524E4C; // "PERMJRNL"
pub const MAX_TRANSACTION_BLOCKS: usize = 64;

#[repr(u32)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TxState {
    Invalid = 0,
    Running = 1,
    Committed = 2,
    Checkpointed = 3,
}

/// Journal superblock
#[repr(C)]
#[derive(Clone, Copy)]
pub struct JournalHeader {
    pub magic: u64,
    pub version: u32,
    pub state: TxState,
    pub head_seq: u64,
    pub tail_seq: u64,
    pub first_block: BlockAddr,
    pub block_count: u64,
    pub max_transaction: u32,
    pub checksum: u64,
}

impl JournalHeader {
    pub const SIZE: usize = 96;

    pub fn serialize(&self, buf: &mut [u8; BLOCK_SIZE]) {
        buf.fill(0);
        buf[0..8].copy_from_slice(&self.magic.to_le_bytes());
        buf[8..12].copy_from_slice(&self.version.to_le_bytes());
        buf[12..16].copy_from_slice(&(self.state as u32).to_le_bytes());
        buf[16..24].copy_from_slice(&self.head_seq.to_le_bytes());
        buf[24..32].copy_from_slice(&self.tail_seq.to_le_bytes());
        buf[32..64].copy_from_slice(&self.first_block.to_bytes());
        buf[64..72].copy_from_slice(&self.block_count.to_le_bytes());
        buf[72..76].copy_from_slice(&self.max_transaction.to_le_bytes());
        buf[76..84].copy_from_slice(&self.checksum.to_le_bytes());
    }

    pub fn deserialize(buf: &[u8; BLOCK_SIZE]) -> Self {
        Self {
            magic: u64::from_le_bytes(buf[0..8].try_into().unwrap()),
            version: u32::from_le_bytes(buf[8..12].try_into().unwrap()),
            state: match u32::from_le_bytes(buf[12..16].try_into().unwrap()) {
                1 => TxState::Running,
                2 => TxState::Committed,
                3 => TxState::Checkpointed,
                _ => TxState::Invalid,
            },
            head_seq: u64::from_le_bytes(buf[16..24].try_into().unwrap()),
            tail_seq: u64::from_le_bytes(buf[24..32].try_into().unwrap()),
            first_block: BlockAddr::from_bytes(buf[32..64].try_into().unwrap()),
            block_count: u64::from_le_bytes(buf[64..72].try_into().unwrap()),
            max_transaction: u32::from_le_bytes(buf[72..76].try_into().unwrap()),
            checksum: u64::from_le_bytes(buf[76..84].try_into().unwrap()),
        }
    }
}

/// Transaction descriptor
#[repr(C)]
pub struct TxDescriptor {
    pub magic: u64,
    pub seq: u64,
    pub state: TxState,
    pub block_count: u32,
    pub timestamp: u64,
    pub checksum: u64,
}

impl TxDescriptor {
    pub const SIZE: usize = 40;

    pub fn serialize(&self, buf: &mut [u8]) {
        buf[0..8].copy_from_slice(&self.magic.to_le_bytes());
        buf[8..16].copy_from_slice(&self.seq.to_le_bytes());
        buf[16..20].copy_from_slice(&(self.state as u32).to_le_bytes());
        buf[20..24].copy_from_slice(&self.block_count.to_le_bytes());
        buf[24..32].copy_from_slice(&self.timestamp.to_le_bytes());
        buf[32..40].copy_from_slice(&self.checksum.to_le_bytes());
    }

    pub fn deserialize(buf: &[u8]) -> Self {
        Self {
            magic: u64::from_le_bytes(buf[0..8].try_into().unwrap()),
            seq: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
            state: match u32::from_le_bytes(buf[16..20].try_into().unwrap()) {
                1 => TxState::Running,
                2 => TxState::Committed,
                3 => TxState::Checkpointed,
                _ => TxState::Invalid,
            },
            block_count: u32::from_le_bytes(buf[20..24].try_into().unwrap()),
            timestamp: u64::from_le_bytes(buf[24..32].try_into().unwrap()),
            checksum: u64::from_le_bytes(buf[32..40].try_into().unwrap()),
        }
    }
}

/// Commit record
#[repr(C)]
pub struct TxCommit {
    pub magic: u64,
    pub seq: u64,
    pub checksum: u64,
}

impl TxCommit {
    pub const SIZE: usize = 24;

    pub fn serialize(&self, buf: &mut [u8]) {
        buf[0..8].copy_from_slice(&self.magic.to_le_bytes());
        buf[8..16].copy_from_slice(&self.seq.to_le_bytes());
        buf[16..24].copy_from_slice(&self.checksum.to_le_bytes());
    }

    pub fn deserialize(buf: &[u8]) -> Self {
        Self {
            magic: u64::from_le_bytes(buf[0..8].try_into().unwrap()),
            seq: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
            checksum: u64::from_le_bytes(buf[16..24].try_into().unwrap()),
        }
    }
}

#[derive(Debug)]
pub enum JournalError {
    TransactionFull,
    InvalidState,
    JournalFull,
    CorruptedEntry,
    ChecksumMismatch,
    IoError(IoError),
}

impl From<IoError> for JournalError {
    fn from(e: IoError) -> Self { JournalError::IoError(e) }
}

/// In-memory transaction builder
pub struct Transaction {
    seq: u64,
    blocks: Vec<(BlockAddr, [u8; BLOCK_SIZE])>,
    state: TxState,
}

impl Transaction {
    pub fn new(seq: u64) -> Self {
        Self {
            seq,
            blocks: Vec::with_capacity(MAX_TRANSACTION_BLOCKS),
            state: TxState::Running,
        }
    }

    pub fn write(&mut self, addr: BlockAddr, data: &[u8; BLOCK_SIZE]) -> Result<(), JournalError> {
        if self.blocks.len() >= MAX_TRANSACTION_BLOCKS {
            return Err(JournalError::TransactionFull);
        }
        if self.state != TxState::Running {
            return Err(JournalError::InvalidState);
        }
        self.blocks.push((addr, *data));
        Ok(())
    }

    pub fn block_count(&self) -> usize { self.blocks.len() }
    pub fn sequence(&self) -> u64 { self.seq }
}

/// Journal manager
#[cfg(feature = "std")]
pub struct Journal<B: BlockDevice> {
    header: JournalHeader,
    current_seq: AtomicU64,
    device: B,
}

#[cfg(feature = "std")]
impl<B: BlockDevice> Journal<B> {
    pub fn new(device: B, header: JournalHeader) -> Self {
        Self {
            current_seq: AtomicU64::new(header.head_seq),
            header,
            device,
        }
    }

    pub fn begin(&self) -> Transaction {
        let seq = self.current_seq.fetch_add(1, Ordering::SeqCst);
        Transaction::new(seq)
    }

    pub fn commit(&self, tx: &mut Transaction) -> Result<(), JournalError> {
        if tx.blocks.is_empty() {
            return Ok(());
        }

        let desc_addr = self.journal_block_addr(tx.seq, 0);
        let mut desc_buf = [0u8; BLOCK_SIZE];

        let mut checksum_data = Vec::new();
        for (addr, _) in &tx.blocks {
            checksum_data.extend_from_slice(&addr.to_bytes());
        }
        let desc_checksum = crate::checksum::crc32c(&checksum_data) as u64;

        let descriptor = TxDescriptor {
            magic: JOURNAL_MAGIC,
            seq: tx.seq,
            state: TxState::Running,
            block_count: tx.blocks.len() as u32,
            timestamp: crate::time::SystemClock::new().now_ns(),
            checksum: desc_checksum,
        };

        descriptor.serialize(&mut desc_buf[..TxDescriptor::SIZE]);

        // Write block addresses after descriptor
        let mut offset = TxDescriptor::SIZE;
        for (addr, _) in &tx.blocks {
            desc_buf[offset..offset + 32].copy_from_slice(&addr.to_bytes());
            offset += 32;
        }

        self.device.write_block(desc_addr, &desc_buf)?;

        // Write data blocks
        for (i, (_, data)) in tx.blocks.iter().enumerate() {
            let data_addr = self.journal_block_addr(tx.seq, 1 + i as u64);
            self.device.write_block(data_addr, data)?;
        }

        // Write commit record
        let commit_addr = self.journal_block_addr(tx.seq, 1 + tx.blocks.len() as u64);
        let mut commit_buf = [0u8; BLOCK_SIZE];

        let mut all_data = Vec::new();
        for (_, data) in &tx.blocks {
            all_data.extend_from_slice(data);
        }
        let commit_checksum = crate::checksum::crc32c(&all_data) as u64;

        let commit = TxCommit {
            magic: JOURNAL_MAGIC,
            seq: tx.seq,
            checksum: commit_checksum,
        };
        commit.serialize(&mut commit_buf[..TxCommit::SIZE]);

        self.device.sync()?;
        self.device.write_block(commit_addr, &commit_buf)?;
        self.device.sync()?;

        tx.state = TxState::Committed;
        Ok(())
    }

    pub fn checkpoint(&self, tx: &Transaction) -> Result<(), JournalError> {
        if tx.state != TxState::Committed {
            return Err(JournalError::InvalidState);
        }

        for (dest_addr, data) in &tx.blocks {
            self.device.write_block(*dest_addr, data)?;
        }

        self.device.sync()?;
        Ok(())
    }

    pub fn recover(&self) -> Result<Vec<u64>, JournalError> {
        let mut recovered = Vec::new();
        let mut seq = self.header.tail_seq;

        while seq < self.header.head_seq {
            if self.try_replay_tx(seq)? {
                recovered.push(seq);
            }
            seq += 1;
        }

        Ok(recovered)
    }

    fn try_replay_tx(&self, seq: u64) -> Result<bool, JournalError> {
        let desc_addr = self.journal_block_addr(seq, 0);
        let mut buf = [0u8; BLOCK_SIZE];
        self.device.read_block(desc_addr, &mut buf)?;

        let desc = TxDescriptor::deserialize(&buf[..TxDescriptor::SIZE]);
        if desc.magic != JOURNAL_MAGIC || desc.seq != seq {
            return Ok(false);
        }

        // Verify commit exists
        let commit_addr = self.journal_block_addr(seq, 1 + desc.block_count as u64);
        self.device.read_block(commit_addr, &mut buf)?;

        let commit = TxCommit::deserialize(&buf[..TxCommit::SIZE]);
        if commit.magic != JOURNAL_MAGIC || commit.seq != seq {
            return Ok(false);
        }

        // Read addresses
        self.device.read_block(desc_addr, &mut buf)?;
        let mut addrs = Vec::new();
        let mut offset = TxDescriptor::SIZE;
        for _ in 0..desc.block_count {
            let addr = BlockAddr::from_bytes(buf[offset..offset + 32].try_into().unwrap());
            addrs.push(addr);
            offset += 32;
        }

        // Replay data
        for (i, addr) in addrs.iter().enumerate() {
            let data_addr = self.journal_block_addr(seq, 1 + i as u64);
            let mut data_buf = [0u8; BLOCK_SIZE];
            self.device.read_block(data_addr, &mut data_buf)?;
            self.device.write_block(*addr, &data_buf)?;
        }

        self.device.sync()?;
        Ok(true)
    }

    fn journal_block_addr(&self, seq: u64, offset: u64) -> BlockAddr {
        let journal_offset = ((seq * (MAX_TRANSACTION_BLOCKS as u64 + 2)) + offset) 
            % self.header.block_count;
        let mut addr = self.header.first_block;
        addr.limbs[0] += journal_offset;
        addr
    }
}
