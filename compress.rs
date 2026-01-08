// PermFS Compression — Transparent block compression

#![cfg(feature = "compression")]

use crate::{BlockAddr, BlockDevice, ClusterTransport, FsResult, IoError, Inode, PermFs, BLOCK_SIZE};

/// Compression algorithm identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CompressionAlgorithm {
    /// No compression
    None = 0,
    /// LZ4 fast compression
    Lz4 = 1,
    /// Reserved for future: Zstd
    Zstd = 2,
    /// Reserved for future: Gzip
    Gzip = 3,
}

impl CompressionAlgorithm {
    /// Convert from u8
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::None),
            1 => Some(Self::Lz4),
            2 => Some(Self::Zstd),
            3 => Some(Self::Gzip),
            _ => None,
        }
    }
}

impl Default for CompressionAlgorithm {
    fn default() -> Self {
        Self::None
    }
}

/// Result of a compression operation
#[derive(Debug, Clone)]
pub struct CompressionResult {
    /// Compressed data
    pub data: Vec<u8>,
    /// Original uncompressed size
    pub original_size: usize,
    /// Whether compression was applied (false if data was incompressible)
    pub compressed: bool,
    /// Algorithm used
    pub algorithm: CompressionAlgorithm,
}

/// Compression engine trait
pub trait CompressionEngine: Send + Sync {
    /// Compress data, returns compressed bytes or original if incompressible
    fn compress(&self, data: &[u8]) -> CompressionResult;

    /// Decompress data back to original size
    fn decompress(&self, data: &[u8], original_size: usize) -> Result<Vec<u8>, CompressionError>;

    /// Get the algorithm identifier
    fn algorithm(&self) -> CompressionAlgorithm;

    /// Minimum compression ratio to consider data compressible (e.g., 0.9 = 90%)
    fn min_ratio(&self) -> f32 {
        0.9
    }
}

/// Compression error
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionError {
    /// Decompression failed
    DecompressionFailed,
    /// Invalid compressed data
    InvalidData,
    /// Output buffer too small
    BufferTooSmall,
    /// Unsupported algorithm
    UnsupportedAlgorithm,
}

impl From<CompressionError> for IoError {
    fn from(_: CompressionError) -> Self {
        IoError::Corrupted
    }
}

// ============================================================================
// No-op compression (passthrough)
// ============================================================================

/// No-op compression engine (passthrough)
#[derive(Debug, Clone, Default)]
pub struct NoCompression;

impl CompressionEngine for NoCompression {
    fn compress(&self, data: &[u8]) -> CompressionResult {
        CompressionResult {
            data: data.to_vec(),
            original_size: data.len(),
            compressed: false,
            algorithm: CompressionAlgorithm::None,
        }
    }

    fn decompress(&self, data: &[u8], _original_size: usize) -> Result<Vec<u8>, CompressionError> {
        Ok(data.to_vec())
    }

    fn algorithm(&self) -> CompressionAlgorithm {
        CompressionAlgorithm::None
    }
}

// ============================================================================
// LZ4 compression
// ============================================================================

/// LZ4 compression engine
#[derive(Debug, Clone)]
pub struct Lz4Compression {
    /// Minimum compression ratio (default 0.9 = 90%)
    min_ratio: f32,
}

impl Default for Lz4Compression {
    fn default() -> Self {
        Self { min_ratio: 0.9 }
    }
}

impl Lz4Compression {
    /// Create with custom minimum compression ratio
    pub fn with_min_ratio(min_ratio: f32) -> Self {
        Self { min_ratio }
    }

    /// Check if data appears to be already compressed (heuristic)
    fn is_likely_compressed(data: &[u8]) -> bool {
        if data.len() < 4 {
            return false;
        }

        // Check for common compressed file magic bytes
        let magic = &data[0..4];

        // PNG
        if magic == [0x89, 0x50, 0x4E, 0x47] {
            return true;
        }
        // JPEG
        if magic[0..2] == [0xFF, 0xD8] {
            return true;
        }
        // GIF
        if magic[0..3] == [0x47, 0x49, 0x46] {
            return true;
        }
        // ZIP/DOCX/XLSX/JAR
        if magic == [0x50, 0x4B, 0x03, 0x04] {
            return true;
        }
        // GZIP
        if magic[0..2] == [0x1F, 0x8B] {
            return true;
        }
        // ZSTD
        if magic == [0x28, 0xB5, 0x2F, 0xFD] {
            return true;
        }
        // XZ
        if data.len() >= 6 && data[0..6] == [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00] {
            return true;
        }
        // BZIP2
        if magic[0..2] == [0x42, 0x5A] {
            return true;
        }
        // 7z
        if data.len() >= 6 && data[0..6] == [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C] {
            return true;
        }
        // RAR
        if magic == [0x52, 0x61, 0x72, 0x21] {
            return true;
        }
        // MP4/MOV
        if data.len() >= 8 && &data[4..8] == b"ftyp" {
            return true;
        }
        // WebM/MKV
        if magic == [0x1A, 0x45, 0xDF, 0xA3] {
            return true;
        }
        // MP3
        if magic[0..2] == [0xFF, 0xFB] || magic[0..3] == [0x49, 0x44, 0x33] {
            return true;
        }
        // FLAC
        if magic == [0x66, 0x4C, 0x61, 0x43] {
            return true;
        }
        // OGG
        if magic == [0x4F, 0x67, 0x67, 0x53] {
            return true;
        }

        false
    }
}

impl CompressionEngine for Lz4Compression {
    fn compress(&self, data: &[u8]) -> CompressionResult {
        // Skip if data is likely already compressed
        if Self::is_likely_compressed(data) {
            return CompressionResult {
                data: data.to_vec(),
                original_size: data.len(),
                compressed: false,
                algorithm: CompressionAlgorithm::None,
            };
        }

        // Compress using LZ4
        let compressed = lz4_flex::compress_prepend_size(data);

        // Check compression ratio
        let ratio = compressed.len() as f32 / data.len() as f32;
        if ratio >= self.min_ratio {
            // Not worth compressing
            return CompressionResult {
                data: data.to_vec(),
                original_size: data.len(),
                compressed: false,
                algorithm: CompressionAlgorithm::None,
            };
        }

        CompressionResult {
            data: compressed,
            original_size: data.len(),
            compressed: true,
            algorithm: CompressionAlgorithm::Lz4,
        }
    }

    fn decompress(&self, data: &[u8], _original_size: usize) -> Result<Vec<u8>, CompressionError> {
        lz4_flex::decompress_size_prepended(data)
            .map_err(|_| CompressionError::DecompressionFailed)
    }

    fn algorithm(&self) -> CompressionAlgorithm {
        CompressionAlgorithm::Lz4
    }

    fn min_ratio(&self) -> f32 {
        self.min_ratio
    }
}

// ============================================================================
// Compressed block header
// ============================================================================

/// Header prepended to compressed blocks on disk
#[derive(Debug, Clone, Copy)]
pub struct CompressedBlockHeader {
    /// Magic number for validation
    pub magic: u32,
    /// Compression algorithm
    pub algorithm: u8,
    /// Flags (reserved)
    pub flags: u8,
    /// Original uncompressed size
    pub original_size: u16,
    /// Compressed size (not including header)
    pub compressed_size: u16,
    /// Checksum of compressed data
    pub checksum: u16,
}

/// Magic number for compressed blocks
pub const COMPRESSED_BLOCK_MAGIC: u32 = 0x434D5052; // "CMPR"

/// Size of the compressed block header
pub const COMPRESSED_HEADER_SIZE: usize = 12;

impl CompressedBlockHeader {
    /// Create a new header
    pub fn new(algorithm: CompressionAlgorithm, original_size: usize, compressed_size: usize) -> Self {
        Self {
            magic: COMPRESSED_BLOCK_MAGIC,
            algorithm: algorithm as u8,
            flags: 0,
            original_size: original_size as u16,
            compressed_size: compressed_size as u16,
            checksum: 0,
        }
    }

    /// Serialize to bytes
    pub fn serialize(&self, buf: &mut [u8]) {
        buf[0..4].copy_from_slice(&self.magic.to_le_bytes());
        buf[4] = self.algorithm;
        buf[5] = self.flags;
        buf[6..8].copy_from_slice(&self.original_size.to_le_bytes());
        buf[8..10].copy_from_slice(&self.compressed_size.to_le_bytes());
        buf[10..12].copy_from_slice(&self.checksum.to_le_bytes());
    }

    /// Deserialize from bytes
    pub fn deserialize(buf: &[u8]) -> Option<Self> {
        if buf.len() < COMPRESSED_HEADER_SIZE {
            return None;
        }

        let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if magic != COMPRESSED_BLOCK_MAGIC {
            return None;
        }

        Some(Self {
            magic,
            algorithm: buf[4],
            flags: buf[5],
            original_size: u16::from_le_bytes([buf[6], buf[7]]),
            compressed_size: u16::from_le_bytes([buf[8], buf[9]]),
            checksum: u16::from_le_bytes([buf[10], buf[11]]),
        })
    }

    /// Check if a block is compressed by looking for magic
    pub fn is_compressed_block(buf: &[u8]) -> bool {
        if buf.len() < 4 {
            return false;
        }
        let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        magic == COMPRESSED_BLOCK_MAGIC
    }
}

// ============================================================================
// Inode compression flags
// ============================================================================

/// Inode flag indicating file should be compressed
pub const INODE_FLAG_COMPRESSED: u32 = 0x0001;

/// Inode flag indicating file should NOT be compressed (explicit disable)
pub const INODE_FLAG_NOCOMPRESS: u32 = 0x0002;

/// Check if an inode has compression enabled
pub fn is_compression_enabled(inode: &Inode) -> bool {
    (inode.flags & INODE_FLAG_COMPRESSED) != 0 && (inode.flags & INODE_FLAG_NOCOMPRESS) == 0
}

/// Set compression flag on inode
pub fn enable_compression(inode: &mut Inode) {
    inode.flags |= INODE_FLAG_COMPRESSED;
    inode.flags &= !INODE_FLAG_NOCOMPRESS;
}

/// Clear compression flag on inode
pub fn disable_compression(inode: &mut Inode) {
    inode.flags &= !INODE_FLAG_COMPRESSED;
    inode.flags |= INODE_FLAG_NOCOMPRESS;
}

// ============================================================================
// Compression context for PermFs
// ============================================================================

/// Compression context holding the active engine
pub struct CompressionContext {
    /// The compression engine to use
    engine: Box<dyn CompressionEngine>,
    /// Whether compression is enabled globally
    enabled: bool,
}

impl CompressionContext {
    /// Create a new compression context with LZ4
    pub fn new_lz4() -> Self {
        Self {
            engine: Box::new(Lz4Compression::default()),
            enabled: true,
        }
    }

    /// Create a disabled compression context
    pub fn disabled() -> Self {
        Self {
            engine: Box::new(NoCompression),
            enabled: false,
        }
    }

    /// Create with a custom engine
    pub fn with_engine(engine: Box<dyn CompressionEngine>) -> Self {
        Self {
            engine,
            enabled: true,
        }
    }

    /// Check if compression is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable compression
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable compression
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Compress a block if beneficial
    pub fn compress_block(&self, data: &[u8; BLOCK_SIZE]) -> CompressedBlock {
        if !self.enabled {
            return CompressedBlock::Uncompressed(*data);
        }

        let result = self.engine.compress(data);

        if !result.compressed {
            return CompressedBlock::Uncompressed(*data);
        }

        // Check if compressed data + header fits in a block
        if result.data.len() + COMPRESSED_HEADER_SIZE > BLOCK_SIZE {
            return CompressedBlock::Uncompressed(*data);
        }

        // Build compressed block with header
        let mut block = [0u8; BLOCK_SIZE];
        let header = CompressedBlockHeader::new(
            result.algorithm,
            BLOCK_SIZE,
            result.data.len(),
        );
        header.serialize(&mut block[0..COMPRESSED_HEADER_SIZE]);
        block[COMPRESSED_HEADER_SIZE..COMPRESSED_HEADER_SIZE + result.data.len()]
            .copy_from_slice(&result.data);

        CompressedBlock::Compressed(block)
    }

    /// Decompress a block if it's compressed
    pub fn decompress_block(&self, data: &[u8; BLOCK_SIZE]) -> Result<[u8; BLOCK_SIZE], CompressionError> {
        // Check if block has compression header
        if let Some(header) = CompressedBlockHeader::deserialize(data) {
            let algorithm = CompressionAlgorithm::from_u8(header.algorithm)
                .ok_or(CompressionError::UnsupportedAlgorithm)?;

            if algorithm == CompressionAlgorithm::None {
                // Stored uncompressed
                let mut result = [0u8; BLOCK_SIZE];
                result.copy_from_slice(data);
                return Ok(result);
            }

            // Extract compressed data
            let compressed_start = COMPRESSED_HEADER_SIZE;
            let compressed_end = compressed_start + header.compressed_size as usize;
            if compressed_end > BLOCK_SIZE {
                return Err(CompressionError::InvalidData);
            }

            let compressed = &data[compressed_start..compressed_end];

            // Decompress
            let decompressed = self.engine.decompress(compressed, header.original_size as usize)?;

            if decompressed.len() != BLOCK_SIZE {
                return Err(CompressionError::InvalidData);
            }

            let mut result = [0u8; BLOCK_SIZE];
            result.copy_from_slice(&decompressed);
            Ok(result)
        } else {
            // Not compressed, return as-is
            let mut result = [0u8; BLOCK_SIZE];
            result.copy_from_slice(data);
            Ok(result)
        }
    }

    /// Get compression statistics for a block
    pub fn get_stats(&self, data: &[u8; BLOCK_SIZE]) -> CompressionStats {
        if !self.enabled {
            return CompressionStats {
                original_size: BLOCK_SIZE,
                compressed_size: BLOCK_SIZE,
                ratio: 1.0,
                algorithm: CompressionAlgorithm::None,
                would_compress: false,
            };
        }

        let result = self.engine.compress(data);

        CompressionStats {
            original_size: BLOCK_SIZE,
            compressed_size: if result.compressed {
                result.data.len() + COMPRESSED_HEADER_SIZE
            } else {
                BLOCK_SIZE
            },
            ratio: if result.compressed {
                (result.data.len() + COMPRESSED_HEADER_SIZE) as f32 / BLOCK_SIZE as f32
            } else {
                1.0
            },
            algorithm: result.algorithm,
            would_compress: result.compressed,
        }
    }
}

impl Default for CompressionContext {
    fn default() -> Self {
        Self::disabled()
    }
}

/// Result of compression (either compressed or uncompressed block)
#[derive(Debug)]
pub enum CompressedBlock {
    /// Block was compressed
    Compressed([u8; BLOCK_SIZE]),
    /// Block was not compressed (incompressible or compression disabled)
    Uncompressed([u8; BLOCK_SIZE]),
}

impl CompressedBlock {
    /// Get the block data regardless of compression state
    pub fn data(&self) -> &[u8; BLOCK_SIZE] {
        match self {
            CompressedBlock::Compressed(data) => data,
            CompressedBlock::Uncompressed(data) => data,
        }
    }

    /// Check if block was compressed
    pub fn is_compressed(&self) -> bool {
        matches!(self, CompressedBlock::Compressed(_))
    }
}

/// Statistics about compression
#[derive(Debug, Clone)]
pub struct CompressionStats {
    /// Original uncompressed size
    pub original_size: usize,
    /// Compressed size (including header)
    pub compressed_size: usize,
    /// Compression ratio (compressed/original)
    pub ratio: f32,
    /// Algorithm used
    pub algorithm: CompressionAlgorithm,
    /// Whether the data would be compressed
    pub would_compress: bool,
}

// ============================================================================
// PermFs integration
// ============================================================================

impl<B: BlockDevice, T: ClusterTransport> PermFs<B, T> {
    /// Write a block with optional compression
    pub fn write_block_compressed(
        &self,
        addr: BlockAddr,
        data: &[u8; BLOCK_SIZE],
        ctx: &CompressionContext,
    ) -> FsResult<bool> {
        let compressed = ctx.compress_block(data);
        self.local_device.write_block(addr, compressed.data())?;
        Ok(compressed.is_compressed())
    }

    /// Read a block with automatic decompression
    pub fn read_block_decompressed(
        &self,
        addr: BlockAddr,
        buf: &mut [u8; BLOCK_SIZE],
        ctx: &CompressionContext,
    ) -> FsResult<()> {
        let mut raw = [0u8; BLOCK_SIZE];
        self.local_device.read_block(addr, &mut raw)?;

        let decompressed = ctx.decompress_block(&raw)?;
        buf.copy_from_slice(&decompressed);
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
    fn test_lz4_compression_basic() {
        let engine = Lz4Compression::default();

        // Highly compressible data
        let data = vec![0u8; 1024];
        let result = engine.compress(&data);

        assert!(result.compressed);
        assert!(result.data.len() < data.len());
        assert_eq!(result.original_size, 1024);

        // Decompress
        let decompressed = engine.decompress(&result.data, result.original_size).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_lz4_incompressible() {
        let engine = Lz4Compression::default();

        // Random data is incompressible
        let data: Vec<u8> = (0..1024).map(|i| (i * 17 + 31) as u8).collect();
        let result = engine.compress(&data);

        // May or may not compress depending on data
        if result.compressed {
            let decompressed = engine.decompress(&result.data, result.original_size).unwrap();
            assert_eq!(decompressed, data);
        }
    }

    #[test]
    fn test_compression_context_block() {
        let ctx = CompressionContext::new_lz4();

        // Create a compressible block (all zeros)
        let mut data = [0u8; BLOCK_SIZE];
        data[0..4].copy_from_slice(b"TEST");

        let compressed = ctx.compress_block(&data);
        assert!(compressed.is_compressed());

        // Decompress
        let decompressed = ctx.decompress_block(compressed.data()).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_compression_context_disabled() {
        let ctx = CompressionContext::disabled();

        let data = [0u8; BLOCK_SIZE];
        let compressed = ctx.compress_block(&data);

        // Should not compress when disabled
        assert!(!compressed.is_compressed());
    }

    #[test]
    fn test_compressed_block_header() {
        let header = CompressedBlockHeader::new(CompressionAlgorithm::Lz4, BLOCK_SIZE, 512);

        let mut buf = [0u8; COMPRESSED_HEADER_SIZE];
        header.serialize(&mut buf);

        let restored = CompressedBlockHeader::deserialize(&buf).unwrap();
        assert_eq!(restored.magic, COMPRESSED_BLOCK_MAGIC);
        assert_eq!(restored.algorithm, CompressionAlgorithm::Lz4 as u8);
        assert_eq!(restored.original_size, BLOCK_SIZE as u16);
        assert_eq!(restored.compressed_size, 512);
    }

    #[test]
    fn test_is_compressed_block() {
        let mut buf = [0u8; BLOCK_SIZE];

        // Not compressed
        assert!(!CompressedBlockHeader::is_compressed_block(&buf));

        // Add compression magic
        buf[0..4].copy_from_slice(&COMPRESSED_BLOCK_MAGIC.to_le_bytes());
        assert!(CompressedBlockHeader::is_compressed_block(&buf));
    }

    #[test]
    fn test_skip_already_compressed() {
        let engine = Lz4Compression::default();

        // PNG magic
        let mut png_data = vec![0x89, 0x50, 0x4E, 0x47];
        png_data.extend(vec![0u8; 1020]);
        let result = engine.compress(&png_data);
        assert!(!result.compressed);

        // JPEG magic
        let mut jpeg_data = vec![0xFF, 0xD8, 0xFF, 0xE0];
        jpeg_data.extend(vec![0u8; 1020]);
        let result = engine.compress(&jpeg_data);
        assert!(!result.compressed);

        // GZIP magic
        let mut gzip_data = vec![0x1F, 0x8B, 0x08, 0x00];
        gzip_data.extend(vec![0u8; 1020]);
        let result = engine.compress(&gzip_data);
        assert!(!result.compressed);
    }

    #[test]
    fn test_inode_compression_flags() {
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

        assert!(!is_compression_enabled(&inode));

        enable_compression(&mut inode);
        assert!(is_compression_enabled(&inode));

        disable_compression(&mut inode);
        assert!(!is_compression_enabled(&inode));
    }

    #[test]
    fn test_compression_stats() {
        let ctx = CompressionContext::new_lz4();

        // Compressible data
        let data = [0u8; BLOCK_SIZE];
        let stats = ctx.get_stats(&data);

        assert_eq!(stats.original_size, BLOCK_SIZE);
        assert!(stats.would_compress);
        assert!(stats.ratio < 1.0);
    }

    #[test]
    fn test_no_compression_engine() {
        let engine = NoCompression;

        let data = vec![0u8; 1024];
        let result = engine.compress(&data);

        assert!(!result.compressed);
        assert_eq!(result.data, data);

        let decompressed = engine.decompress(&result.data, result.original_size).unwrap();
        assert_eq!(decompressed, data);
    }
}
