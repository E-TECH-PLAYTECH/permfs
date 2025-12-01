// PermFS FUSE Mount Example
// Run with: cargo run --example fuse_mount --features fuse -- /path/to/mountpoint

#[cfg(feature = "fuse")]
fn main() {
    use permfs::fuse::FuseFs;
    use permfs::mock::TestFsBuilder;
    use std::path::Path;
    use std::sync::Arc;

    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <mountpoint>", args[0]);
        std::process::exit(1);
    }

    let mountpoint = Path::new(&args[1]);
    if !mountpoint.exists() {
        eprintln!("Mountpoint does not exist: {}", mountpoint.display());
        std::process::exit(1);
    }

    println!("Creating PermFS filesystem...");
    let (fs, sb) = TestFsBuilder::new()
        .node_id(1)
        .volume_id(0)
        .total_blocks(100000) // ~400 MiB
        .build()
        .expect("Failed to create filesystem");

    println!("Filesystem created:");
    println!("  Total blocks: {}", sb.total_blocks);
    println!(
        "  Free blocks:  {}",
        sb.free_blocks.load(std::sync::atomic::Ordering::Relaxed)
    );

    println!("Mounting at {}...", mountpoint.display());
    let fuse_fs = FuseFs::new(Arc::new(fs), sb);

    // Handle Ctrl+C for clean unmount
    ctrlc::set_handler(move || {
        println!("\nUnmounting...");
        std::process::exit(0);
    })
    .expect("Error setting Ctrl+C handler");

    if let Err(e) = fuse_fs.mount(mountpoint) {
        eprintln!("Mount failed: {}", e);
        std::process::exit(1);
    }
}

#[cfg(not(feature = "fuse"))]
fn main() {
    eprintln!("This example requires the 'fuse' feature.");
    eprintln!("Run with: cargo run --example fuse_mount --features fuse");
    std::process::exit(1);
}
