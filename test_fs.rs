// PermFS Example — Standalone test binary

use permfs::mock::{TestFs, TestFsBuilder};
use permfs::*;
use std::sync::Arc;

fn main() {
    println!("PermFS Test Suite");
    println!("==================\n");

    let (fs, sb) = TestFsBuilder::new()
        .node_id(1)
        .volume_id(0)
        .total_blocks(10000)
        .build()
        .expect("Failed to create filesystem");

    println!("Created filesystem:");
    println!("  Total blocks: {}", sb.total_blocks);
    println!(
        "  Free blocks:  {}",
        sb.free_blocks.load(core::sync::atomic::Ordering::Relaxed)
    );
    println!("  Total inodes: {}", sb.total_inodes);
    println!(
        "  Free inodes:  {}",
        sb.free_inodes.load(core::sync::atomic::Ordering::Relaxed)
    );
    println!();

    test_file_operations(&fs, &sb);
    test_directory_operations(&fs, &sb);
    test_large_file(&fs, &sb);
    test_symlinks(&fs, &sb);

    println!("\nAll tests passed!");
}

fn test_file_operations(fs: &TestFs, sb: &Superblock) {
    println!("Testing file operations...");

    let ino = fs.alloc_inode(sb).expect("alloc inode");
    let mut inode = Inode {
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

    let content = b"Hello, PermFS! Testing write functionality.";
    let written = fs.write_file(&mut inode, 0, content, sb).expect("write");
    println!("  Written {} bytes", written);

    fs.write_inode(ino, &inode, sb).expect("save inode");
    fs.add_dirent(0, b"hello.txt", ino, 1, sb)
        .expect("add dirent");

    let root = fs.read_inode(0, sb).expect("read root");
    let found_ino = fs.find_dirent(&root, b"hello.txt").expect("find");
    assert_eq!(found_ino, ino);

    let inode = fs.read_inode(ino, sb).expect("read inode");
    let mut buf = vec![0u8; 100];
    let read = fs.read_file(&inode, 0, &mut buf).expect("read");
    assert_eq!(&buf[..read], content);
    println!(
        "  Read {} bytes: {:?}",
        read,
        String::from_utf8_lossy(&buf[..read])
    );
    println!("  ✓ File operations passed");
}

fn test_directory_operations(fs: &TestFs, sb: &Superblock) {
    println!("Testing directory operations...");

    let dir_ino = fs.alloc_inode(sb).expect("alloc inode");
    let dir_block = fs.alloc_block(Some(sb.volume_id)).expect("alloc block");

    let mut dir_inode = Inode {
        mode: 0o040755,
        uid: 1000,
        gid: 1000,
        flags: 0,
        size: BLOCK_SIZE as u64,
        blocks: 1,
        atime: 0,
        mtime: 0,
        ctime: 0,
        crtime: 0,
        nlink: 2,
        generation: 0,
        direct: [BlockAddr::NULL; INODE_DIRECT_BLOCKS],
        indirect: [BlockAddr::NULL; INODE_INDIRECT_LEVELS],
        extent_root: BlockAddr::NULL,
        xattr_block: BlockAddr::NULL,
        checksum: 0,
    };
    dir_inode.direct[0] = dir_block;

    fs.init_directory_block(dir_block, dir_ino, 0)
        .expect("init dir");
    fs.write_inode(dir_ino, &dir_inode, sb)
        .expect("write inode");
    fs.add_dirent(0, b"subdir", dir_ino, 2, sb)
        .expect("add dirent");
    println!("  Created /subdir");

    let file_ino = fs.alloc_inode(sb).expect("alloc inode");
    let mut file_inode = Inode {
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

    let content = b"File in subdirectory";
    fs.write_file(&mut file_inode, 0, content, sb)
        .expect("write");
    fs.write_inode(file_ino, &file_inode, sb).expect("save");
    fs.add_dirent(dir_ino, b"nested.txt", file_ino, 1, sb)
        .expect("add dirent");
    println!("  Created /subdir/nested.txt");

    let root = fs.read_inode(0, sb).expect("read root");
    let found_dir = fs.find_dirent(&root, b"subdir").expect("find subdir");
    assert_eq!(found_dir, dir_ino);

    let dir_inode = fs.read_inode(dir_ino, sb).expect("read dir");
    let found_file = fs
        .find_dirent(&dir_inode, b"nested.txt")
        .expect("find nested");
    assert_eq!(found_file, file_ino);

    println!("  ✓ Directory operations passed");
}

fn test_large_file(fs: &TestFs, sb: &Superblock) {
    println!("Testing large file (indirect blocks)...");

    let ino = fs.alloc_inode(sb).expect("alloc inode");
    let mut inode = Inode {
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

    let chunk = vec![0xDEu8; BLOCK_SIZE];
    for i in 0..16 {
        fs.write_file(&mut inode, (i * BLOCK_SIZE) as u64, &chunk, sb)
            .expect("write");
    }

    println!("  Written 64 KiB ({} blocks)", inode.blocks);
    println!(
        "  Direct blocks used: {}",
        inode.direct.iter().filter(|b| !b.is_null()).count()
    );
    println!(
        "  Indirect block allocated: {}",
        !inode.indirect[0].is_null()
    );

    fs.write_inode(ino, &inode, sb).expect("save");
    fs.add_dirent(0, b"large.bin", ino, 1, sb)
        .expect("add dirent");

    let inode = fs.read_inode(ino, sb).expect("read");
    let mut buf = vec![0u8; BLOCK_SIZE];
    let read = fs
        .read_file(&inode, 14 * BLOCK_SIZE as u64, &mut buf)
        .expect("read");
    assert_eq!(read, BLOCK_SIZE);
    assert!(buf.iter().all(|&b| b == 0xDE));

    println!("  ✓ Large file operations passed");
}

fn test_symlinks(fs: &TestFs, sb: &Superblock) {
    println!("Testing symbolic links...");

    let ino = fs
        .symlink_impl(0, b"link", b"/hello.txt", sb)
        .expect("symlink");
    println!("  Created symlink /link -> /hello.txt");

    let inode = fs.read_inode(ino, sb).expect("read");
    assert!(inode.is_symlink());

    let mut buf = vec![0u8; 256];
    let len = fs.readlink_impl(ino, &mut buf, sb).expect("readlink");
    assert_eq!(&buf[..len], b"/hello.txt");
    println!(
        "  Read symlink target: {:?}",
        String::from_utf8_lossy(&buf[..len])
    );

    println!("  ✓ Symlink operations passed");
}
