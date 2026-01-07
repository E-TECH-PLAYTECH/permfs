use permfs::local::{DiskFs, DiskFsBuilder};
use permfs::{BlockAddr, Inode, INODE_DIRECT_BLOCKS, INODE_INDIRECT_LEVELS};
use std::path::PathBuf;

fn sample_inode() -> Inode {
    Inode {
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
    }
}

#[test]
fn remount_persists_data() {
    let img = PathBuf::from("/tmp/permfs_persist.img");
    let _ = std::fs::remove_file(&img);

    // Create and write data
    let (fs, mut sb) = DiskFsBuilder::new(&img)
        .node_id(1)
        .volume_id(0)
        .total_blocks(20_000)
        .build()
        .expect("mkfs");

    let ino = fs.alloc_inode(&sb).expect("alloc inode");
    let mut inode = sample_inode();
    let content = b"persist me across remount";
    fs.write_file(&mut inode, 0, content, &sb).expect("write");
    fs.write_inode(ino, &inode, &sb).expect("write inode");
    fs.add_dirent(0, b"persist.txt", ino, 1, &sb)
        .expect("dirent");

    // Unmount to flush superblock state
    fs.unmount(&mut sb).expect("unmount");
    drop(fs);

    // Remount from existing image
    let (fs2, sb2) = DiskFsBuilder::new(&img)
        .node_id(1)
        .volume_id(0)
        .total_blocks(20_000)
        .open_existing()
        .expect("mount");

    let root = fs2.read_inode(0, &sb2).expect("read root");
    let found = fs2.find_dirent(&root, b"persist.txt").expect("find entry");
    assert_eq!(found, ino);

    let inode2 = fs2.read_inode(ino, &sb2).expect("read inode");
    let mut buf = vec![0u8; 64];
    let read = fs2.read_file(&inode2, 0, &mut buf).expect("read back");
    assert_eq!(&buf[..read], content);
}
