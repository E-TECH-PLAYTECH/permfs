// PermFS Checksum — CRC32C implementation for data integrity

use crate::{Inode, Superblock, BLOCK_SIZE};

/// CRC32C polynomial (Castagnoli)
const CRC32C_POLY: u32 = 0x82F63B78;

/// Precomputed CRC32C lookup table
static CRC32C_TABLE: [u32; 256] = generate_crc32c_table();

const fn generate_crc32c_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ CRC32C_POLY;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

/// Compute CRC32C checksum of data
#[inline]
pub fn crc32c(data: &[u8]) -> u32 {
    crc32c_update(0xFFFFFFFF, data) ^ 0xFFFFFFFF
}

/// Update running CRC32C with additional data
#[inline]
pub fn crc32c_update(mut crc: u32, data: &[u8]) -> u32 {
    // Try hardware acceleration first
    #[cfg(all(target_arch = "x86_64", target_feature = "sse4.2"))]
    {
        return crc32c_hw(crc, data);
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "crc"))]
    {
        return crc32c_arm(crc, data);
    }

    // Software fallback
    for &byte in data {
        crc = CRC32C_TABLE[((crc ^ byte as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc
}

/// x86_64 hardware CRC32C using SSE4.2
#[cfg(all(target_arch = "x86_64", target_feature = "sse4.2"))]
fn crc32c_hw(mut crc: u32, data: &[u8]) -> u32 {
    use core::arch::x86_64::_mm_crc32_u64;

    let mut crc64 = crc as u64;
    let mut chunks = data.chunks_exact(8);

    for chunk in chunks.by_ref() {
        let val = u64::from_le_bytes(chunk.try_into().unwrap());
        crc64 = unsafe { _mm_crc32_u64(crc64, val) };
    }

    let remainder = chunks.remainder();
    let mut crc32 = crc64 as u32;

    for &byte in remainder {
        crc32 = CRC32C_TABLE[((crc32 ^ byte as u32) & 0xFF) as usize] ^ (crc32 >> 8);
    }

    crc32
}

/// ARM64 hardware CRC32C
#[cfg(all(target_arch = "aarch64", target_feature = "crc"))]
fn crc32c_arm(mut crc: u32, data: &[u8]) -> u32 {
    use core::arch::aarch64::__crc32cd;

    let mut chunks = data.chunks_exact(8);

    for chunk in chunks.by_ref() {
        let val = u64::from_le_bytes(chunk.try_into().unwrap());
        crc = unsafe { __crc32cd(crc, val) };
    }

    let remainder = chunks.remainder();
    for &byte in remainder {
        crc = CRC32C_TABLE[((crc ^ byte as u32) & 0xFF) as usize] ^ (crc >> 8);
    }

    crc
}

/// Verify checksum matches computed value
#[inline]
pub fn verify_checksum(data: &[u8], expected: u32) -> bool {
    crc32c(data) == expected
}

/// Compute checksum for an inode (excluding the checksum field itself)
pub fn compute_inode_checksum(inode: &Inode) -> u64 {
    // Create a copy with checksum zeroed
    let mut temp = *inode;
    temp.checksum = 0;

    let bytes = unsafe {
        core::slice::from_raw_parts(
            &temp as *const Inode as *const u8,
            core::mem::size_of::<Inode>(),
        )
    };

    crc32c(bytes) as u64
}

/// Compute checksum for superblock (excluding the checksum field itself)
pub fn compute_superblock_checksum(sb: &Superblock) -> u64 {
    // We need to serialize without the checksum field
    // The checksum is at the end, so we compute CRC of everything before it
    let size_without_checksum = core::mem::size_of::<Superblock>() - core::mem::size_of::<u64>();

    let bytes = unsafe {
        core::slice::from_raw_parts(sb as *const Superblock as *const u8, size_without_checksum)
    };

    crc32c(bytes) as u64
}

/// Compute checksum for a data block
#[inline]
pub fn compute_block_checksum(block: &[u8; BLOCK_SIZE]) -> u32 {
    crc32c(block)
}

/// Verify a data block's integrity against an expected checksum
#[inline]
pub fn verify_block_checksum(block: &[u8; BLOCK_SIZE], expected: u32) -> bool {
    compute_block_checksum(block) == expected
}

/// xxHash64 - faster non-cryptographic hash for very large data
pub fn xxhash64(data: &[u8]) -> u64 {
    const PRIME64_1: u64 = 0x9E3779B185EBCA87;
    const PRIME64_2: u64 = 0xC2B2AE3D27D4EB4F;
    const PRIME64_3: u64 = 0x165667B19E3779F9;
    const PRIME64_4: u64 = 0x85EBCA77C2B2AE63;
    const PRIME64_5: u64 = 0x27D4EB2F165667C5;

    let seed: u64 = 0;
    let len = data.len();

    let mut h64: u64;
    let mut ptr = data.as_ptr();

    if len >= 32 {
        let mut v1 = seed.wrapping_add(PRIME64_1).wrapping_add(PRIME64_2);
        let mut v2 = seed.wrapping_add(PRIME64_2);
        let mut v3 = seed;
        let mut v4 = seed.wrapping_sub(PRIME64_1);

        let end = unsafe { ptr.add(len - 32) };

        while ptr as usize <= end as usize {
            let k1 = unsafe { core::ptr::read_unaligned(ptr as *const u64).to_le() };
            v1 = v1.wrapping_add(k1.wrapping_mul(PRIME64_2));
            v1 = v1.rotate_left(31).wrapping_mul(PRIME64_1);
            ptr = unsafe { ptr.add(8) };

            let k2 = unsafe { core::ptr::read_unaligned(ptr as *const u64).to_le() };
            v2 = v2.wrapping_add(k2.wrapping_mul(PRIME64_2));
            v2 = v2.rotate_left(31).wrapping_mul(PRIME64_1);
            ptr = unsafe { ptr.add(8) };

            let k3 = unsafe { core::ptr::read_unaligned(ptr as *const u64).to_le() };
            v3 = v3.wrapping_add(k3.wrapping_mul(PRIME64_2));
            v3 = v3.rotate_left(31).wrapping_mul(PRIME64_1);
            ptr = unsafe { ptr.add(8) };

            let k4 = unsafe { core::ptr::read_unaligned(ptr as *const u64).to_le() };
            v4 = v4.wrapping_add(k4.wrapping_mul(PRIME64_2));
            v4 = v4.rotate_left(31).wrapping_mul(PRIME64_1);
            ptr = unsafe { ptr.add(8) };
        }

        h64 = v1
            .rotate_left(1)
            .wrapping_add(v2.rotate_left(7))
            .wrapping_add(v3.rotate_left(12))
            .wrapping_add(v4.rotate_left(18));

        fn merge_round(mut acc: u64, val: u64) -> u64 {
            let val = val.wrapping_mul(PRIME64_2);
            let val = val.rotate_left(31).wrapping_mul(PRIME64_1);
            acc ^= val;
            acc.wrapping_mul(PRIME64_1).wrapping_add(PRIME64_4)
        }

        h64 = merge_round(h64, v1);
        h64 = merge_round(h64, v2);
        h64 = merge_round(h64, v3);
        h64 = merge_round(h64, v4);
    } else {
        h64 = seed.wrapping_add(PRIME64_5);
    }

    h64 = h64.wrapping_add(len as u64);

    // Process remaining bytes
    let remaining = len - (ptr as usize - data.as_ptr() as usize);
    let end = unsafe { ptr.add(remaining) };

    // Process 8-byte chunks
    while (end as usize - ptr as usize) >= 8 {
        let k = unsafe { core::ptr::read_unaligned(ptr as *const u64).to_le() };
        let k = k
            .wrapping_mul(PRIME64_2)
            .rotate_left(31)
            .wrapping_mul(PRIME64_1);
        h64 ^= k;
        h64 = h64
            .rotate_left(27)
            .wrapping_mul(PRIME64_1)
            .wrapping_add(PRIME64_4);
        ptr = unsafe { ptr.add(8) };
    }

    // Process 4-byte chunk
    if (end as usize - ptr as usize) >= 4 {
        let k = unsafe { core::ptr::read_unaligned(ptr as *const u32).to_le() } as u64;
        h64 ^= k.wrapping_mul(PRIME64_1);
        h64 = h64
            .rotate_left(23)
            .wrapping_mul(PRIME64_2)
            .wrapping_add(PRIME64_3);
        ptr = unsafe { ptr.add(4) };
    }

    // Process remaining bytes
    while ptr != end {
        let k = unsafe { *ptr } as u64;
        h64 ^= k.wrapping_mul(PRIME64_5);
        h64 = h64.rotate_left(11).wrapping_mul(PRIME64_1);
        ptr = unsafe { ptr.add(1) };
    }

    // Final mix
    h64 ^= h64 >> 33;
    h64 = h64.wrapping_mul(PRIME64_2);
    h64 ^= h64 >> 29;
    h64 = h64.wrapping_mul(PRIME64_3);
    h64 ^= h64 >> 32;

    h64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32c_empty() {
        let crc = crc32c(&[]);
        assert_eq!(crc, 0);
    }

    #[test]
    fn test_crc32c_known_values() {
        // Known test vectors for CRC32C
        assert_eq!(crc32c(b"123456789"), 0xE3069283);
    }

    #[test]
    fn test_crc32c_consistency() {
        let data = b"Hello, PermFS! This is test data for checksum verification.";
        let crc1 = crc32c(data);
        let crc2 = crc32c(data);
        assert_eq!(crc1, crc2);
    }

    #[test]
    fn test_crc32c_different_data() {
        let crc1 = crc32c(b"Hello");
        let crc2 = crc32c(b"World");
        assert_ne!(crc1, crc2);
    }

    #[test]
    fn test_verify_checksum() {
        let data = b"Test data for verification";
        let crc = crc32c(data);
        assert!(verify_checksum(data, crc));
        assert!(!verify_checksum(data, crc ^ 1));
    }

    #[test]
    fn test_xxhash64_consistency() {
        let data = b"Hello, PermFS!";
        let h1 = xxhash64(data);
        let h2 = xxhash64(data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_xxhash64_different_data() {
        let h1 = xxhash64(b"Hello");
        let h2 = xxhash64(b"World");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_block_checksum() {
        let mut block = [0u8; BLOCK_SIZE];
        block[0] = 0xDE;
        block[1] = 0xAD;
        block[4095] = 0xBE;

        let crc = compute_block_checksum(&block);
        assert!(verify_block_checksum(&block, crc));

        block[100] = 0xFF;
        assert!(!verify_block_checksum(&block, crc));
    }
}
