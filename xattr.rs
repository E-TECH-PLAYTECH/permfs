// PermFS Extended Attributes — xattr support for metadata, ACLs, security contexts

#![cfg(feature = "std")]

use crate::{BlockAddr, BlockDevice, ClusterTransport, FsResult, IoError, PermFs, Superblock, BLOCK_SIZE};

/// Maximum length of an xattr name (including namespace prefix)
pub const XATTR_NAME_MAX: usize = 255;

/// Maximum length of an xattr value
pub const XATTR_VALUE_MAX: usize = 65535;

/// Size of the xattr block header
const XATTR_HEADER_SIZE: usize = 36; // next block (32) + count (2) + padding (2)

/// Xattr entry header size: name_len (1) + value_len (2) + padding (1)
const XATTR_ENTRY_HEADER: usize = 4;

/// Xattr block header stored at the start of each xattr block
#[derive(Debug, Clone, Copy)]
struct XattrBlockHeader {
    /// Next xattr block in chain (for overflow)
    next: BlockAddr,
    /// Number of entries in this block
    count: u16,
}

impl XattrBlockHeader {
    fn read_from(buf: &[u8]) -> Self {
        let mut next_bytes = [0u8; 32];
        next_bytes.copy_from_slice(&buf[0..32]);
        let next = BlockAddr::from_bytes(&next_bytes);
        let count = u16::from_le_bytes([buf[32], buf[33]]);
        Self { next, count }
    }

    fn write_to(&self, buf: &mut [u8]) {
        let next_bytes = self.next.to_bytes();
        buf[0..32].copy_from_slice(&next_bytes);
        buf[32..34].copy_from_slice(&self.count.to_le_bytes());
        buf[34..36].fill(0); // padding
    }
}

/// An xattr entry within a block
#[derive(Debug, Clone)]
pub struct XattrEntry {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

impl XattrEntry {
    /// Calculate the size this entry takes in the block
    pub fn size(&self) -> usize {
        XATTR_ENTRY_HEADER + self.name.len() + self.value.len()
    }

    /// Read an entry from a buffer at the given offset
    fn read_from(buf: &[u8], offset: usize) -> Option<(Self, usize)> {
        if offset + XATTR_ENTRY_HEADER > buf.len() {
            return None;
        }

        let name_len = buf[offset] as usize;
        let value_len = u16::from_le_bytes([buf[offset + 1], buf[offset + 2]]) as usize;

        if name_len == 0 {
            return None; // End marker or invalid
        }

        let total_size = XATTR_ENTRY_HEADER + name_len + value_len;
        if offset + total_size > buf.len() {
            return None;
        }

        let name_start = offset + XATTR_ENTRY_HEADER;
        let value_start = name_start + name_len;

        Some((
            Self {
                name: buf[name_start..name_start + name_len].to_vec(),
                value: buf[value_start..value_start + value_len].to_vec(),
            },
            total_size,
        ))
    }

    /// Write an entry to a buffer at the given offset
    fn write_to(&self, buf: &mut [u8], offset: usize) -> usize {
        buf[offset] = self.name.len() as u8;
        buf[offset + 1..offset + 3].copy_from_slice(&(self.value.len() as u16).to_le_bytes());
        buf[offset + 3] = 0; // padding

        let name_start = offset + XATTR_ENTRY_HEADER;
        buf[name_start..name_start + self.name.len()].copy_from_slice(&self.name);

        let value_start = name_start + self.name.len();
        buf[value_start..value_start + self.value.len()].copy_from_slice(&self.value);

        self.size()
    }
}

/// Flags for setxattr
pub mod xattr_flags {
    /// Create the attribute if it doesn't exist (default behavior)
    pub const XATTR_CREATE: u32 = 0x1;
    /// Replace only if attribute exists
    pub const XATTR_REPLACE: u32 = 0x2;
}

impl<B: BlockDevice, T: ClusterTransport> PermFs<B, T> {
    /// Get an extended attribute value
    pub fn getxattr_impl(
        &self,
        ino: u64,
        name: &[u8],
        buf: &mut [u8],
        sb: &Superblock,
    ) -> FsResult<usize> {
        if name.is_empty() || name.len() > XATTR_NAME_MAX {
            return Err(IoError::InvalidAddress);
        }

        let inode = self.read_inode(ino, sb)?;
        if inode.xattr_block.is_null() {
            return Err(IoError::NotFound);
        }

        let mut block_addr = inode.xattr_block;
        let mut block_buf = [0u8; BLOCK_SIZE];

        while !block_addr.is_null() {
            self.read_block(block_addr, &mut block_buf)?;
            let header = XattrBlockHeader::read_from(&block_buf);

            let mut offset = XATTR_HEADER_SIZE;
            for _ in 0..header.count {
                if let Some((entry, size)) = XattrEntry::read_from(&block_buf, offset) {
                    if entry.name == name {
                        // Found it
                        if buf.is_empty() {
                            // Size query
                            return Ok(entry.value.len());
                        }
                        if buf.len() < entry.value.len() {
                            return Err(IoError::InvalidAddress); // ERANGE
                        }
                        buf[..entry.value.len()].copy_from_slice(&entry.value);
                        return Ok(entry.value.len());
                    }
                    offset += size;
                } else {
                    break;
                }
            }

            block_addr = header.next;
        }

        Err(IoError::NotFound)
    }

    /// Set an extended attribute
    pub fn setxattr_impl(
        &self,
        ino: u64,
        name: &[u8],
        value: &[u8],
        flags: u32,
        sb: &Superblock,
    ) -> FsResult<()> {
        if name.is_empty() || name.len() > XATTR_NAME_MAX {
            return Err(IoError::InvalidAddress);
        }
        if value.len() > XATTR_VALUE_MAX {
            return Err(IoError::InvalidAddress);
        }

        let mut inode = self.read_inode(ino, sb)?;
        let new_entry = XattrEntry {
            name: name.to_vec(),
            value: value.to_vec(),
        };
        let entry_size = new_entry.size();

        // Check if we need to allocate a new xattr block
        if inode.xattr_block.is_null() {
            if flags & xattr_flags::XATTR_REPLACE != 0 {
                return Err(IoError::NotFound);
            }

            // Allocate new block
            let block_addr = self.alloc_block(Some(sb.volume_id))
                .map_err(|_| IoError::NoSpace)?;
            let mut block_buf = [0u8; BLOCK_SIZE];

            let header = XattrBlockHeader {
                next: BlockAddr::NULL,
                count: 1,
            };
            header.write_to(&mut block_buf);
            new_entry.write_to(&mut block_buf, XATTR_HEADER_SIZE);

            self.write_block(block_addr, &block_buf)?;

            inode.xattr_block = block_addr;
            self.write_inode(ino, &inode, sb)?;
            return Ok(());
        }

        // Search existing blocks for the attribute
        let mut block_addr = inode.xattr_block;
        let mut block_buf = [0u8; BLOCK_SIZE];

        while !block_addr.is_null() {
            self.read_block(block_addr, &mut block_buf)?;
            let mut header = XattrBlockHeader::read_from(&block_buf);

            let mut offset = XATTR_HEADER_SIZE;
            let mut found_offset = None;
            let mut found_size = 0;

            for _ in 0..header.count {
                if let Some((entry, size)) = XattrEntry::read_from(&block_buf, offset) {
                    if entry.name == name {
                        found_offset = Some(offset);
                        found_size = size;
                        break;
                    }
                    offset += size;
                } else {
                    break;
                }
            }

            if let Some(old_offset) = found_offset {
                // Found existing entry
                if flags & xattr_flags::XATTR_CREATE != 0 {
                    return Err(IoError::AlreadyExists);
                }

                // Remove old entry and add new one
                block_buf.copy_within(old_offset + found_size..BLOCK_SIZE, old_offset);
                block_buf[BLOCK_SIZE - found_size..].fill(0);
                header.count -= 1;

                // Calculate free space
                let mut used = XATTR_HEADER_SIZE;
                let mut temp_offset = XATTR_HEADER_SIZE;
                for _ in 0..header.count {
                    if let Some((_, size)) = XattrEntry::read_from(&block_buf, temp_offset) {
                        used += size;
                        temp_offset += size;
                    } else {
                        break;
                    }
                }

                if used + entry_size <= BLOCK_SIZE {
                    // Fits in this block
                    new_entry.write_to(&mut block_buf, used);
                    header.count += 1;
                    header.write_to(&mut block_buf);
                    self.write_block(block_addr, &block_buf)?;
                    return Ok(());
                } else {
                    // Need to add to a different block - save this one and continue
                    header.write_to(&mut block_buf);
                    self.write_block(block_addr, &block_buf)?;
                    // Fall through to add new entry logic
                }
            }

            // Check if entry fits in current block
            let mut used = XATTR_HEADER_SIZE;
            let mut temp_offset = XATTR_HEADER_SIZE;
            for _ in 0..header.count {
                if let Some((_, size)) = XattrEntry::read_from(&block_buf, temp_offset) {
                    used += size;
                    temp_offset += size;
                } else {
                    break;
                }
            }

            if found_offset.is_none() && used + entry_size <= BLOCK_SIZE {
                if flags & xattr_flags::XATTR_REPLACE != 0 {
                    // Continue searching other blocks
                    block_addr = header.next;
                    continue;
                }

                // Add new entry here
                new_entry.write_to(&mut block_buf, used);
                header.count += 1;
                header.write_to(&mut block_buf);
                self.write_block(block_addr, &block_buf)?;
                return Ok(());
            }

            if header.next.is_null() && found_offset.is_none() {
                if flags & xattr_flags::XATTR_REPLACE != 0 {
                    return Err(IoError::NotFound);
                }

                // Allocate new block in chain
                let new_block = self.alloc_block(Some(sb.volume_id))
                    .map_err(|_| IoError::NoSpace)?;
                let mut new_buf = [0u8; BLOCK_SIZE];

                let new_header = XattrBlockHeader {
                    next: BlockAddr::NULL,
                    count: 1,
                };
                new_header.write_to(&mut new_buf);
                new_entry.write_to(&mut new_buf, XATTR_HEADER_SIZE);
                self.write_block(new_block, &new_buf)?;

                // Update chain
                header.next = new_block;
                header.write_to(&mut block_buf);
                self.write_block(block_addr, &block_buf)?;
                return Ok(());
            }

            block_addr = header.next;
        }

        if flags & xattr_flags::XATTR_REPLACE != 0 {
            return Err(IoError::NotFound);
        }

        Err(IoError::IoFailed)
    }

    /// List all extended attribute names
    pub fn listxattr_impl(&self, ino: u64, buf: &mut [u8], sb: &Superblock) -> FsResult<usize> {
        let inode = self.read_inode(ino, sb)?;
        if inode.xattr_block.is_null() {
            return Ok(0);
        }

        let mut block_addr = inode.xattr_block;
        let mut block_buf = [0u8; BLOCK_SIZE];
        let mut total_size = 0usize;
        let mut write_offset = 0usize;

        while !block_addr.is_null() {
            self.read_block(block_addr, &mut block_buf)?;
            let header = XattrBlockHeader::read_from(&block_buf);

            let mut offset = XATTR_HEADER_SIZE;
            for _ in 0..header.count {
                if let Some((entry, size)) = XattrEntry::read_from(&block_buf, offset) {
                    let name_with_null = entry.name.len() + 1;
                    total_size += name_with_null;

                    if !buf.is_empty() {
                        if write_offset + name_with_null > buf.len() {
                            return Err(IoError::InvalidAddress); // ERANGE
                        }
                        buf[write_offset..write_offset + entry.name.len()]
                            .copy_from_slice(&entry.name);
                        buf[write_offset + entry.name.len()] = 0;
                        write_offset += name_with_null;
                    }

                    offset += size;
                } else {
                    break;
                }
            }

            block_addr = header.next;
        }

        Ok(total_size)
    }

    /// Remove an extended attribute
    pub fn removexattr_impl(&self, ino: u64, name: &[u8], sb: &Superblock) -> FsResult<()> {
        if name.is_empty() || name.len() > XATTR_NAME_MAX {
            return Err(IoError::InvalidAddress);
        }

        let inode = self.read_inode(ino, sb)?;
        if inode.xattr_block.is_null() {
            return Err(IoError::NotFound);
        }

        let mut block_addr = inode.xattr_block;
        let mut block_buf = [0u8; BLOCK_SIZE];

        while !block_addr.is_null() {
            self.read_block(block_addr, &mut block_buf)?;
            let mut header = XattrBlockHeader::read_from(&block_buf);

            let mut offset = XATTR_HEADER_SIZE;
            let mut found = false;
            let mut remove_offset = 0;
            let mut remove_size = 0;

            for _ in 0..header.count {
                if let Some((entry, size)) = XattrEntry::read_from(&block_buf, offset) {
                    if entry.name == name {
                        found = true;
                        remove_offset = offset;
                        remove_size = size;
                        break;
                    }
                    offset += size;
                } else {
                    break;
                }
            }

            if found {
                // Remove the entry by shifting remaining data
                let remaining_start = remove_offset + remove_size;
                block_buf.copy_within(remaining_start..BLOCK_SIZE, remove_offset);
                block_buf[BLOCK_SIZE - remove_size..].fill(0);

                header.count -= 1;
                header.write_to(&mut block_buf);
                self.write_block(block_addr, &block_buf)?;

                // TODO: If block is now empty and not the first block,
                // could unlink it from the chain and free it
                return Ok(());
            }

            block_addr = header.next;
        }

        Err(IoError::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::TestFsBuilder;

    #[test]
    fn test_xattr_basic() {
        let (fs, sb) = TestFsBuilder::new().build().expect("mkfs failed");

        // Set an xattr on root
        let name = b"user.test";
        let value = b"hello world";

        fs.setxattr_impl(0, name, value, 0, &sb).expect("setxattr");

        // Get it back
        let mut buf = [0u8; 64];
        let len = fs.getxattr_impl(0, name, &mut buf, &sb).expect("getxattr");
        assert_eq!(len, value.len());
        assert_eq!(&buf[..len], value);
    }

    #[test]
    fn test_xattr_size_query() {
        let (fs, sb) = TestFsBuilder::new().build().expect("mkfs failed");

        let name = b"user.test";
        let value = b"test value";
        fs.setxattr_impl(0, name, value, 0, &sb).expect("setxattr");

        // Size query with empty buffer
        let len = fs.getxattr_impl(0, name, &mut [], &sb).expect("size query");
        assert_eq!(len, value.len());
    }

    #[test]
    fn test_xattr_not_found() {
        let (fs, sb) = TestFsBuilder::new().build().expect("mkfs failed");

        let mut buf = [0u8; 64];
        let result = fs.getxattr_impl(0, b"user.nonexistent", &mut buf, &sb);
        assert!(matches!(result, Err(IoError::NotFound)));
    }

    #[test]
    fn test_xattr_list() {
        let (fs, sb) = TestFsBuilder::new().build().expect("mkfs failed");

        fs.setxattr_impl(0, b"user.one", b"1", 0, &sb).expect("set one");
        fs.setxattr_impl(0, b"user.two", b"2", 0, &sb).expect("set two");
        fs.setxattr_impl(0, b"user.three", b"3", 0, &sb).expect("set three");

        // Get total size
        let size = fs.listxattr_impl(0, &mut [], &sb).expect("list size");

        // Get actual list
        let mut buf = vec![0u8; size];
        let len = fs.listxattr_impl(0, &mut buf, &sb).expect("list");
        assert_eq!(len, size);

        // Parse the null-separated list
        let names: Vec<&[u8]> = buf.split(|&b| b == 0).filter(|s| !s.is_empty()).collect();
        assert_eq!(names.len(), 3);
        assert!(names.contains(&b"user.one".as_slice()));
        assert!(names.contains(&b"user.two".as_slice()));
        assert!(names.contains(&b"user.three".as_slice()));
    }

    #[test]
    fn test_xattr_remove() {
        let (fs, sb) = TestFsBuilder::new().build().expect("mkfs failed");

        fs.setxattr_impl(0, b"user.test", b"value", 0, &sb).expect("set");

        // Verify it exists
        let mut buf = [0u8; 64];
        assert!(fs.getxattr_impl(0, b"user.test", &mut buf, &sb).is_ok());

        // Remove it
        fs.removexattr_impl(0, b"user.test", &sb).expect("remove");

        // Verify it's gone
        assert!(matches!(
            fs.getxattr_impl(0, b"user.test", &mut buf, &sb),
            Err(IoError::NotFound)
        ));
    }

    #[test]
    fn test_xattr_replace() {
        let (fs, sb) = TestFsBuilder::new().build().expect("mkfs failed");

        // Set initial value
        fs.setxattr_impl(0, b"user.test", b"initial", 0, &sb).expect("set initial");

        // Replace with new value
        fs.setxattr_impl(0, b"user.test", b"replaced", 0, &sb).expect("replace");

        // Verify new value
        let mut buf = [0u8; 64];
        let len = fs.getxattr_impl(0, b"user.test", &mut buf, &sb).expect("get");
        assert_eq!(&buf[..len], b"replaced");
    }

    #[test]
    fn test_xattr_flags() {
        let (fs, sb) = TestFsBuilder::new().build().expect("mkfs failed");

        // XATTR_REPLACE on non-existent should fail
        let result = fs.setxattr_impl(0, b"user.new", b"value", xattr_flags::XATTR_REPLACE, &sb);
        assert!(matches!(result, Err(IoError::NotFound)));

        // Create it first
        fs.setxattr_impl(0, b"user.new", b"value", 0, &sb).expect("create");

        // XATTR_CREATE on existing should fail
        let result = fs.setxattr_impl(0, b"user.new", b"value2", xattr_flags::XATTR_CREATE, &sb);
        assert!(matches!(result, Err(IoError::AlreadyExists)));

        // XATTR_REPLACE on existing should work
        fs.setxattr_impl(0, b"user.new", b"updated", xattr_flags::XATTR_REPLACE, &sb)
            .expect("replace");

        let mut buf = [0u8; 64];
        let len = fs.getxattr_impl(0, b"user.new", &mut buf, &sb).expect("get");
        assert_eq!(&buf[..len], b"updated");
    }
}
