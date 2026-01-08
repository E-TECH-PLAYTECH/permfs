// PermFS Encryption — At-rest block encryption

#![cfg(feature = "encryption")]

use crate::{BlockAddr, BlockDevice, ClusterTransport, FsResult, IoError, Inode, PermFs, BLOCK_SIZE};
use aes::Aes256;
use aes::cipher::KeyInit;
use xts_mode::{Xts128, get_tweak_default};

/// Encryption algorithm identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EncryptionAlgorithm {
    /// No encryption
    None = 0,
    /// AES-256-XTS (recommended for disk encryption)
    Aes256Xts = 1,
}

impl EncryptionAlgorithm {
    /// Convert from u8
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::None),
            1 => Some(Self::Aes256Xts),
            _ => None,
        }
    }
}

impl Default for EncryptionAlgorithm {
    fn default() -> Self {
        Self::None
    }
}

/// Encryption error
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionError {
    /// Invalid key length
    InvalidKeyLength,
    /// Encryption failed
    EncryptionFailed,
    /// Decryption failed
    DecryptionFailed,
    /// Invalid data length
    InvalidDataLength,
    /// Key derivation failed
    KeyDerivationFailed,
    /// Invalid passphrase
    InvalidPassphrase,
    /// No key available
    NoKey,
}

impl From<EncryptionError> for IoError {
    fn from(_: EncryptionError) -> Self {
        IoError::PermissionDenied
    }
}

// ============================================================================
// Key derivation
// ============================================================================

/// Number of PBKDF2 iterations (higher = more secure but slower)
pub const DEFAULT_PBKDF2_ITERATIONS: u32 = 100_000;

/// Salt length in bytes
pub const SALT_LENGTH: usize = 32;

/// Derived key length for AES-256-XTS (two 256-bit keys)
pub const XTS_KEY_LENGTH: usize = 64;

/// Derive a key from a passphrase using PBKDF2-HMAC-SHA256
pub fn derive_key(
    passphrase: &[u8],
    salt: &[u8; SALT_LENGTH],
    iterations: u32,
    output: &mut [u8],
) -> Result<(), EncryptionError> {
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(passphrase, salt, iterations, output);
    Ok(())
}

/// Generate a random salt
pub fn generate_salt() -> [u8; SALT_LENGTH] {
    use rand::RngCore;
    let mut salt = [0u8; SALT_LENGTH];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// Generate a random data encryption key
pub fn generate_dek() -> [u8; XTS_KEY_LENGTH] {
    use rand::RngCore;
    let mut key = [0u8; XTS_KEY_LENGTH];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

// ============================================================================
// Key slot management (LUKS-style)
// ============================================================================

/// Maximum number of key slots
pub const MAX_KEY_SLOTS: usize = 8;

/// A key slot stores an encrypted copy of the master key
#[derive(Debug, Clone)]
pub struct KeySlot {
    /// Whether this slot is active
    pub active: bool,
    /// Salt for key derivation
    pub salt: [u8; SALT_LENGTH],
    /// PBKDF2 iterations
    pub iterations: u32,
    /// Encrypted master key (wrapped DEK)
    pub encrypted_key: [u8; XTS_KEY_LENGTH],
    /// Authentication tag / checksum
    pub key_checksum: [u8; 32],
}

impl Default for KeySlot {
    fn default() -> Self {
        Self {
            active: false,
            salt: [0u8; SALT_LENGTH],
            iterations: DEFAULT_PBKDF2_ITERATIONS,
            encrypted_key: [0u8; XTS_KEY_LENGTH],
            key_checksum: [0u8; 32],
        }
    }
}

impl KeySlot {
    /// Size of a serialized key slot
    pub const SIZE: usize = 1 + SALT_LENGTH + 4 + XTS_KEY_LENGTH + 32; // 161 bytes

    /// Serialize to bytes
    pub fn serialize(&self, buf: &mut [u8]) {
        buf[0] = if self.active { 1 } else { 0 };
        buf[1..33].copy_from_slice(&self.salt);
        buf[33..37].copy_from_slice(&self.iterations.to_le_bytes());
        buf[37..101].copy_from_slice(&self.encrypted_key);
        buf[101..133].copy_from_slice(&self.key_checksum);
    }

    /// Deserialize from bytes
    pub fn deserialize(buf: &[u8]) -> Self {
        let mut slot = Self::default();
        slot.active = buf[0] != 0;
        slot.salt.copy_from_slice(&buf[1..33]);
        slot.iterations = u32::from_le_bytes([buf[33], buf[34], buf[35], buf[36]]);
        slot.encrypted_key.copy_from_slice(&buf[37..101]);
        slot.key_checksum.copy_from_slice(&buf[101..133]);
        slot
    }

    /// Create a new key slot from a passphrase and master key
    pub fn create(passphrase: &[u8], master_key: &[u8; XTS_KEY_LENGTH]) -> Result<Self, EncryptionError> {
        let salt = generate_salt();
        let iterations = DEFAULT_PBKDF2_ITERATIONS;

        // Derive wrapping key from passphrase
        let mut wrapping_key = [0u8; XTS_KEY_LENGTH];
        derive_key(passphrase, &salt, iterations, &mut wrapping_key)?;

        // XOR master key with wrapping key (simple key wrapping)
        let mut encrypted_key = [0u8; XTS_KEY_LENGTH];
        for i in 0..XTS_KEY_LENGTH {
            encrypted_key[i] = master_key[i] ^ wrapping_key[i];
        }

        // Compute checksum of master key for verification
        let key_checksum = compute_key_checksum(master_key);

        Ok(Self {
            active: true,
            salt,
            iterations,
            encrypted_key,
            key_checksum,
        })
    }

    /// Unwrap the master key using a passphrase
    pub fn unwrap(&self, passphrase: &[u8]) -> Result<[u8; XTS_KEY_LENGTH], EncryptionError> {
        if !self.active {
            return Err(EncryptionError::NoKey);
        }

        // Derive wrapping key from passphrase
        let mut wrapping_key = [0u8; XTS_KEY_LENGTH];
        derive_key(passphrase, &self.salt, self.iterations, &mut wrapping_key)?;

        // XOR to recover master key
        let mut master_key = [0u8; XTS_KEY_LENGTH];
        for i in 0..XTS_KEY_LENGTH {
            master_key[i] = self.encrypted_key[i] ^ wrapping_key[i];
        }

        // Verify checksum
        let checksum = compute_key_checksum(&master_key);
        if checksum != self.key_checksum {
            return Err(EncryptionError::InvalidPassphrase);
        }

        Ok(master_key)
    }
}

/// Compute a checksum of a key for verification
fn compute_key_checksum(key: &[u8]) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(b"PERMFS_KEY_CHECK");
    hasher.update(key);
    let result = hasher.finalize();
    let mut checksum = [0u8; 32];
    checksum.copy_from_slice(&result);
    checksum
}

// ============================================================================
// Encryption header (stored at start of encrypted volume)
// ============================================================================

/// Magic number for encrypted volumes
pub const ENCRYPTION_MAGIC: u64 = 0x454E4352_59505446; // "ENCRYPTF"

/// Encryption header version
pub const ENCRYPTION_VERSION: u16 = 1;

/// Encryption header stored on disk
#[derive(Debug, Clone)]
pub struct EncryptionHeader {
    /// Magic number
    pub magic: u64,
    /// Version
    pub version: u16,
    /// Encryption algorithm
    pub algorithm: u8,
    /// Flags
    pub flags: u8,
    /// Number of active key slots
    pub key_slot_count: u8,
    /// Reserved
    pub reserved: [u8; 3],
    /// Master key checksum (for quick verification)
    pub master_checksum: [u8; 32],
    /// Key slots
    pub key_slots: [KeySlot; MAX_KEY_SLOTS],
}

impl Default for EncryptionHeader {
    fn default() -> Self {
        Self {
            magic: ENCRYPTION_MAGIC,
            version: ENCRYPTION_VERSION,
            algorithm: EncryptionAlgorithm::Aes256Xts as u8,
            flags: 0,
            key_slot_count: 0,
            reserved: [0; 3],
            master_checksum: [0; 32],
            key_slots: std::array::from_fn(|_| KeySlot::default()),
        }
    }
}

impl EncryptionHeader {
    /// Size of the header (fits in one block)
    pub const SIZE: usize = 8 + 2 + 1 + 1 + 1 + 3 + 32 + (KeySlot::SIZE * MAX_KEY_SLOTS);

    /// Create a new encryption header with a master key and initial passphrase
    pub fn create(
        algorithm: EncryptionAlgorithm,
        master_key: &[u8; XTS_KEY_LENGTH],
        passphrase: &[u8],
    ) -> Result<Self, EncryptionError> {
        let mut header = Self {
            magic: ENCRYPTION_MAGIC,
            version: ENCRYPTION_VERSION,
            algorithm: algorithm as u8,
            flags: 0,
            key_slot_count: 1,
            reserved: [0; 3],
            master_checksum: compute_key_checksum(master_key),
            key_slots: std::array::from_fn(|_| KeySlot::default()),
        };

        // Create first key slot
        header.key_slots[0] = KeySlot::create(passphrase, master_key)?;

        Ok(header)
    }

    /// Add a new key slot with a passphrase
    pub fn add_key_slot(
        &mut self,
        master_key: &[u8; XTS_KEY_LENGTH],
        passphrase: &[u8],
    ) -> Result<usize, EncryptionError> {
        // Find empty slot
        for (i, slot) in self.key_slots.iter_mut().enumerate() {
            if !slot.active {
                *slot = KeySlot::create(passphrase, master_key)?;
                self.key_slot_count += 1;
                return Ok(i);
            }
        }
        Err(EncryptionError::NoKey) // No empty slots
    }

    /// Remove a key slot
    pub fn remove_key_slot(&mut self, index: usize) -> Result<(), EncryptionError> {
        if index >= MAX_KEY_SLOTS || !self.key_slots[index].active {
            return Err(EncryptionError::NoKey);
        }
        if self.key_slot_count <= 1 {
            return Err(EncryptionError::NoKey); // Can't remove last slot
        }
        self.key_slots[index] = KeySlot::default();
        self.key_slot_count -= 1;
        Ok(())
    }

    /// Try to unlock with a passphrase (tries all slots)
    pub fn unlock(&self, passphrase: &[u8]) -> Result<[u8; XTS_KEY_LENGTH], EncryptionError> {
        for slot in &self.key_slots {
            if slot.active {
                if let Ok(key) = slot.unwrap(passphrase) {
                    // Verify against master checksum
                    if compute_key_checksum(&key) == self.master_checksum {
                        return Ok(key);
                    }
                }
            }
        }
        Err(EncryptionError::InvalidPassphrase)
    }

    /// Serialize to bytes
    pub fn serialize(&self, buf: &mut [u8]) {
        buf[0..8].copy_from_slice(&self.magic.to_le_bytes());
        buf[8..10].copy_from_slice(&self.version.to_le_bytes());
        buf[10] = self.algorithm;
        buf[11] = self.flags;
        buf[12] = self.key_slot_count;
        buf[13..16].copy_from_slice(&self.reserved);
        buf[16..48].copy_from_slice(&self.master_checksum);

        let mut offset = 48;
        for slot in &self.key_slots {
            slot.serialize(&mut buf[offset..offset + KeySlot::SIZE]);
            offset += KeySlot::SIZE;
        }
    }

    /// Deserialize from bytes
    pub fn deserialize(buf: &[u8]) -> Option<Self> {
        let magic = u64::from_le_bytes(buf[0..8].try_into().ok()?);
        if magic != ENCRYPTION_MAGIC {
            return None;
        }

        let mut header = Self {
            magic,
            version: u16::from_le_bytes(buf[8..10].try_into().ok()?),
            algorithm: buf[10],
            flags: buf[11],
            key_slot_count: buf[12],
            reserved: [buf[13], buf[14], buf[15]],
            master_checksum: buf[16..48].try_into().ok()?,
            key_slots: std::array::from_fn(|_| KeySlot::default()),
        };

        let mut offset = 48;
        for i in 0..MAX_KEY_SLOTS {
            header.key_slots[i] = KeySlot::deserialize(&buf[offset..offset + KeySlot::SIZE]);
            offset += KeySlot::SIZE;
        }

        Some(header)
    }
}

// ============================================================================
// Encryption engine trait
// ============================================================================

/// Encryption engine trait
pub trait EncryptionEngine: Send + Sync {
    /// Encrypt a block in place
    fn encrypt_block(&self, block_num: u64, data: &mut [u8; BLOCK_SIZE]);

    /// Decrypt a block in place
    fn decrypt_block(&self, block_num: u64, data: &mut [u8; BLOCK_SIZE]);

    /// Get the algorithm
    fn algorithm(&self) -> EncryptionAlgorithm;
}

// ============================================================================
// No-op encryption (passthrough)
// ============================================================================

/// No-op encryption engine (passthrough)
#[derive(Debug, Clone, Default)]
pub struct NoEncryption;

impl EncryptionEngine for NoEncryption {
    fn encrypt_block(&self, _block_num: u64, _data: &mut [u8; BLOCK_SIZE]) {
        // No-op
    }

    fn decrypt_block(&self, _block_num: u64, _data: &mut [u8; BLOCK_SIZE]) {
        // No-op
    }

    fn algorithm(&self) -> EncryptionAlgorithm {
        EncryptionAlgorithm::None
    }
}

// ============================================================================
// AES-256-XTS encryption
// ============================================================================

/// AES-256-XTS encryption engine
pub struct Aes256XtsEngine {
    /// XTS cipher instance
    cipher: Xts128<Aes256>,
}

impl Aes256XtsEngine {
    /// Create a new AES-256-XTS engine with a 64-byte key (two 256-bit keys)
    pub fn new(key: &[u8; XTS_KEY_LENGTH]) -> Self {
        let cipher = Xts128::<Aes256>::new(
            Aes256::new_from_slice(&key[0..32]).unwrap(),
            Aes256::new_from_slice(&key[32..64]).unwrap(),
        );
        Self { cipher }
    }

    /// Create from a master key derived from passphrase
    pub fn from_passphrase(
        passphrase: &[u8],
        salt: &[u8; SALT_LENGTH],
        iterations: u32,
    ) -> Result<Self, EncryptionError> {
        let mut key = [0u8; XTS_KEY_LENGTH];
        derive_key(passphrase, salt, iterations, &mut key)?;
        Ok(Self::new(&key))
    }
}

impl EncryptionEngine for Aes256XtsEngine {
    fn encrypt_block(&self, block_num: u64, data: &mut [u8; BLOCK_SIZE]) {
        // Use block number as tweak for XTS mode
        let tweak = get_tweak_default(block_num as u128);
        self.cipher.encrypt_sector(data, tweak);
    }

    fn decrypt_block(&self, block_num: u64, data: &mut [u8; BLOCK_SIZE]) {
        let tweak = get_tweak_default(block_num as u128);
        self.cipher.decrypt_sector(data, tweak);
    }

    fn algorithm(&self) -> EncryptionAlgorithm {
        EncryptionAlgorithm::Aes256Xts
    }
}

// ============================================================================
// Inode encryption flags
// ============================================================================

/// Inode flag indicating file is encrypted
pub const INODE_FLAG_ENCRYPTED: u32 = 0x0004;

/// Inode flag indicating file should NOT be encrypted (explicit disable)
pub const INODE_FLAG_NOENCRYPT: u32 = 0x0008;

/// Check if an inode has encryption enabled
pub fn is_encryption_enabled(inode: &Inode) -> bool {
    (inode.flags & INODE_FLAG_ENCRYPTED) != 0 && (inode.flags & INODE_FLAG_NOENCRYPT) == 0
}

/// Set encryption flag on inode
pub fn enable_encryption(inode: &mut Inode) {
    inode.flags |= INODE_FLAG_ENCRYPTED;
    inode.flags &= !INODE_FLAG_NOENCRYPT;
}

/// Clear encryption flag on inode
pub fn disable_encryption(inode: &mut Inode) {
    inode.flags &= !INODE_FLAG_ENCRYPTED;
    inode.flags |= INODE_FLAG_NOENCRYPT;
}

// ============================================================================
// Encryption context
// ============================================================================

/// Encryption context holding the active engine
pub struct EncryptionContext {
    /// The encryption engine
    engine: Box<dyn EncryptionEngine>,
    /// Whether encryption is enabled
    enabled: bool,
}

impl EncryptionContext {
    /// Create a new encryption context with AES-256-XTS
    pub fn new_aes256xts(key: &[u8; XTS_KEY_LENGTH]) -> Self {
        Self {
            engine: Box::new(Aes256XtsEngine::new(key)),
            enabled: true,
        }
    }

    /// Create a disabled encryption context
    pub fn disabled() -> Self {
        Self {
            engine: Box::new(NoEncryption),
            enabled: false,
        }
    }

    /// Create from passphrase and salt
    pub fn from_passphrase(
        passphrase: &[u8],
        salt: &[u8; SALT_LENGTH],
        iterations: u32,
    ) -> Result<Self, EncryptionError> {
        let engine = Aes256XtsEngine::from_passphrase(passphrase, salt, iterations)?;
        Ok(Self {
            engine: Box::new(engine),
            enabled: true,
        })
    }

    /// Check if encryption is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Encrypt a block
    pub fn encrypt_block(&self, block_num: u64, data: &mut [u8; BLOCK_SIZE]) {
        if self.enabled {
            self.engine.encrypt_block(block_num, data);
        }
    }

    /// Decrypt a block
    pub fn decrypt_block(&self, block_num: u64, data: &mut [u8; BLOCK_SIZE]) {
        if self.enabled {
            self.engine.decrypt_block(block_num, data);
        }
    }

    /// Get the algorithm
    pub fn algorithm(&self) -> EncryptionAlgorithm {
        self.engine.algorithm()
    }
}

impl Default for EncryptionContext {
    fn default() -> Self {
        Self::disabled()
    }
}

// ============================================================================
// PermFs integration
// ============================================================================

impl<B: BlockDevice, T: ClusterTransport> PermFs<B, T> {
    /// Write a block with encryption
    pub fn write_block_encrypted(
        &self,
        addr: BlockAddr,
        data: &[u8; BLOCK_SIZE],
        ctx: &EncryptionContext,
    ) -> FsResult<()> {
        let mut encrypted = *data;
        let block_num = addr.block_offset();
        ctx.encrypt_block(block_num, &mut encrypted);
        self.local_device.write_block(addr, &encrypted)
    }

    /// Read a block with decryption
    pub fn read_block_decrypted(
        &self,
        addr: BlockAddr,
        buf: &mut [u8; BLOCK_SIZE],
        ctx: &EncryptionContext,
    ) -> FsResult<()> {
        self.local_device.read_block(addr, buf)?;
        let block_num = addr.block_offset();
        ctx.decrypt_block(block_num, buf);
        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation() {
        let passphrase = b"test_password_123";
        let salt = generate_salt();
        let mut key1 = [0u8; XTS_KEY_LENGTH];
        let mut key2 = [0u8; XTS_KEY_LENGTH];

        derive_key(passphrase, &salt, 1000, &mut key1).unwrap();
        derive_key(passphrase, &salt, 1000, &mut key2).unwrap();

        // Same input should produce same output
        assert_eq!(key1, key2);

        // Different salt should produce different output
        let salt2 = generate_salt();
        let mut key3 = [0u8; XTS_KEY_LENGTH];
        derive_key(passphrase, &salt2, 1000, &mut key3).unwrap();
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_key_slot_roundtrip() {
        let master_key = generate_dek();
        let passphrase = b"my_secret_passphrase";

        let slot = KeySlot::create(passphrase, &master_key).unwrap();
        assert!(slot.active);

        // Unwrap with correct passphrase
        let recovered = slot.unwrap(passphrase).unwrap();
        assert_eq!(recovered, master_key);

        // Wrong passphrase should fail
        let wrong = slot.unwrap(b"wrong_password");
        assert!(wrong.is_err());
    }

    #[test]
    fn test_key_slot_serialization() {
        let master_key = generate_dek();
        let slot = KeySlot::create(b"password", &master_key).unwrap();

        let mut buf = [0u8; KeySlot::SIZE];
        slot.serialize(&mut buf);

        let restored = KeySlot::deserialize(&buf);
        assert_eq!(restored.active, slot.active);
        assert_eq!(restored.salt, slot.salt);
        assert_eq!(restored.iterations, slot.iterations);
        assert_eq!(restored.encrypted_key, slot.encrypted_key);
        assert_eq!(restored.key_checksum, slot.key_checksum);
    }

    #[test]
    fn test_encryption_header() {
        let master_key = generate_dek();
        let passphrase = b"volume_password";

        let header = EncryptionHeader::create(
            EncryptionAlgorithm::Aes256Xts,
            &master_key,
            passphrase,
        ).unwrap();

        assert_eq!(header.magic, ENCRYPTION_MAGIC);
        assert_eq!(header.key_slot_count, 1);

        // Unlock with correct passphrase
        let recovered = header.unlock(passphrase).unwrap();
        assert_eq!(recovered, master_key);

        // Wrong passphrase should fail
        assert!(header.unlock(b"wrong").is_err());
    }

    #[test]
    fn test_encryption_header_serialization() {
        let master_key = generate_dek();
        let header = EncryptionHeader::create(
            EncryptionAlgorithm::Aes256Xts,
            &master_key,
            b"password",
        ).unwrap();

        let mut buf = [0u8; BLOCK_SIZE];
        header.serialize(&mut buf);

        let restored = EncryptionHeader::deserialize(&buf).unwrap();
        assert_eq!(restored.magic, header.magic);
        assert_eq!(restored.version, header.version);
        assert_eq!(restored.algorithm, header.algorithm);
        assert_eq!(restored.key_slot_count, header.key_slot_count);
    }

    #[test]
    fn test_multiple_key_slots() {
        let master_key = generate_dek();
        let mut header = EncryptionHeader::create(
            EncryptionAlgorithm::Aes256Xts,
            &master_key,
            b"password1",
        ).unwrap();

        // Add second key slot
        header.add_key_slot(&master_key, b"password2").unwrap();
        assert_eq!(header.key_slot_count, 2);

        // Both passwords should work
        assert_eq!(header.unlock(b"password1").unwrap(), master_key);
        assert_eq!(header.unlock(b"password2").unwrap(), master_key);

        // Remove first slot
        header.remove_key_slot(0).unwrap();
        assert_eq!(header.key_slot_count, 1);

        // Only second password should work now
        assert!(header.unlock(b"password1").is_err());
        assert_eq!(header.unlock(b"password2").unwrap(), master_key);
    }

    #[test]
    fn test_aes256xts_encrypt_decrypt() {
        let key = generate_dek();
        let engine = Aes256XtsEngine::new(&key);

        let original = [0x42u8; BLOCK_SIZE];
        let mut data = original;

        // Encrypt
        engine.encrypt_block(0, &mut data);
        assert_ne!(data, original);

        // Decrypt
        engine.decrypt_block(0, &mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn test_aes256xts_different_blocks() {
        let key = generate_dek();
        let engine = Aes256XtsEngine::new(&key);

        let original = [0x42u8; BLOCK_SIZE];

        let mut block0 = original;
        let mut block1 = original;

        engine.encrypt_block(0, &mut block0);
        engine.encrypt_block(1, &mut block1);

        // Same plaintext, different block numbers = different ciphertext
        assert_ne!(block0, block1);

        // Both should decrypt correctly
        engine.decrypt_block(0, &mut block0);
        engine.decrypt_block(1, &mut block1);
        assert_eq!(block0, original);
        assert_eq!(block1, original);
    }

    #[test]
    fn test_encryption_context() {
        let key = generate_dek();
        let ctx = EncryptionContext::new_aes256xts(&key);

        assert!(ctx.is_enabled());
        assert_eq!(ctx.algorithm(), EncryptionAlgorithm::Aes256Xts);

        let original = [0x55u8; BLOCK_SIZE];
        let mut data = original;

        ctx.encrypt_block(42, &mut data);
        assert_ne!(data, original);

        ctx.decrypt_block(42, &mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn test_encryption_context_disabled() {
        let ctx = EncryptionContext::disabled();

        assert!(!ctx.is_enabled());

        let original = [0x55u8; BLOCK_SIZE];
        let mut data = original;

        // Should be no-op when disabled
        ctx.encrypt_block(0, &mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn test_inode_encryption_flags() {
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
            direct: [BlockAddr::NULL; crate::INODE_DIRECT_BLOCKS],
            indirect: [BlockAddr::NULL; crate::INODE_INDIRECT_LEVELS],
            extent_root: BlockAddr::NULL,
            xattr_block: BlockAddr::NULL,
            checksum: 0,
        };

        assert!(!is_encryption_enabled(&inode));

        enable_encryption(&mut inode);
        assert!(is_encryption_enabled(&inode));

        disable_encryption(&mut inode);
        assert!(!is_encryption_enabled(&inode));
    }

    #[test]
    fn test_no_encryption_engine() {
        let engine = NoEncryption;

        let original = [0xAAu8; BLOCK_SIZE];
        let mut data = original;

        engine.encrypt_block(0, &mut data);
        assert_eq!(data, original); // No change

        engine.decrypt_block(0, &mut data);
        assert_eq!(data, original); // No change
    }
}
