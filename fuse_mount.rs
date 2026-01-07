// PermFS FUSE Mount Example
// Run with: cargo run --example fuse_mount --features fuse -- <mountpoint> [image_path] [--format]
// If image_path is provided, mounts existing disk image
// Use --format to create/reformat the image before mounting

#[cfg(feature = "fuse")]
fn main() {
    use permfs::fuse::FuseFs;
    use permfs::local::{DiskFsBuilder, MemoryFsBuilder};
    use std::path::Path;

    let args: Vec<String> = std::env::args().collect();

    let format_flag = args.iter().any(|a| a == "--format");
    let args_filtered: Vec<&String> = args.iter().filter(|a| *a != "--format").collect();

    if args_filtered.len() < 2 || args_filtered.len() > 3 {
        eprintln!("Usage: {} <mountpoint> [image_path] [--format]", args[0]);
        eprintln!("  If image_path is provided, mounts existing disk image");
        eprintln!("  Use --format to create/reformat the image before mounting");
        eprintln!("  Without image_path, creates an in-memory filesystem");
        std::process::exit(1);
    }

    let mountpoint = Path::new(args_filtered[1]);
    if !mountpoint.exists() {
        eprintln!("Mountpoint does not exist: {}", mountpoint.display());
        std::process::exit(1);
    }

    // Handle Ctrl+C for clean unmount
    ctrlc::set_handler(move || {
        println!("\nUnmounting...");
        std::process::exit(0);
    })
    .expect("Error setting Ctrl+C handler");

    if args_filtered.len() == 3 {
        // Mount disk image
        let image_path = Path::new(args_filtered[2]);

        if format_flag {
            println!("Formatting new PermFS image: {}", image_path.display());
            let (fs, sb) = DiskFsBuilder::new(image_path)
                .node_id(1)
                .volume_id(0)
                .total_blocks(100000) // ~400 MiB
                .build()
                .expect("Failed to format filesystem");

            println!("Filesystem formatted:");
            println!("  Total blocks: {}", sb.total_blocks);
            println!(
                "  Free blocks:  {}",
                sb.free_blocks.load(std::sync::atomic::Ordering::Relaxed)
            );

            println!("Mounting at {}...", mountpoint.display());
            let fuse_fs = FuseFs::new(fs, sb);
            if let Err(e) = fuse_fs.mount(mountpoint) {
                eprintln!("Mount failed: {}", e);
                std::process::exit(1);
            }
        } else {
            if !image_path.exists() {
                eprintln!("Image file does not exist: {}", image_path.display());
                eprintln!("Use --format to create a new image");
                std::process::exit(1);
            }

            println!("Opening existing PermFS image: {}", image_path.display());
            let (fs, sb) = DiskFsBuilder::new(image_path)
                .node_id(1)
                .volume_id(0)
                .total_blocks(100000)
                .open_existing()
                .expect("Failed to open filesystem");

            println!("Filesystem opened:");
            println!("  Total blocks: {}", sb.total_blocks);
            println!(
                "  Free blocks:  {}",
                sb.free_blocks.load(std::sync::atomic::Ordering::Relaxed)
            );

            println!("Mounting at {}...", mountpoint.display());
            let fuse_fs = FuseFs::new(fs, sb);
            if let Err(e) = fuse_fs.mount(mountpoint) {
                eprintln!("Mount failed: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        // Create in-memory filesystem
        println!("Creating in-memory PermFS filesystem...");
        let (fs, sb) = MemoryFsBuilder::new()
            .node_id(1)
            .volume_id(0)
            .total_blocks(100000)
            .build()
            .expect("Failed to create filesystem");

        println!("Filesystem created:");
        println!("  Total blocks: {}", sb.total_blocks);
        println!(
            "  Free blocks:  {}",
            sb.free_blocks.load(std::sync::atomic::Ordering::Relaxed)
        );

        println!("Mounting at {}...", mountpoint.display());
        let fuse_fs = FuseFs::new(fs, sb);
        if let Err(e) = fuse_fs.mount(mountpoint) {
            eprintln!("Mount failed: {}", e);
            std::process::exit(1);
        }
    }
}

#[cfg(not(feature = "fuse"))]
fn main() {
    eprintln!("This example requires the 'fuse' feature.");
    eprintln!("Run with: cargo run --example fuse_mount --features fuse");
    std::process::exit(1);
}
