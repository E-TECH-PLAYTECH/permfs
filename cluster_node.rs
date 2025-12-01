// PermFS Cluster Node Example
// Run with: cargo run --example cluster_node --features network

#[cfg(feature = "network")]
fn main() {
    use permfs::mock::MemoryBlockDevice;
    use permfs::transport::{RequestHandler, TcpServer, TcpTransport};
    use permfs::{AllocError, BlockAddr, BlockDevice, IoError, BLOCK_SIZE};
    use std::net::SocketAddr;
    use std::sync::Arc;

    struct LocalHandler {
        device: MemoryBlockDevice,
    }

    impl RequestHandler for LocalHandler {
        fn handle_read(&self, addr: BlockAddr) -> Result<[u8; BLOCK_SIZE], IoError> {
            let mut buf = [0u8; BLOCK_SIZE];
            self.device.read_block(addr, &mut buf)?;
            Ok(buf)
        }

        fn handle_write(&self, addr: BlockAddr, data: &[u8; BLOCK_SIZE]) -> Result<(), IoError> {
            self.device.write_block(addr, data)
        }

        fn handle_alloc(&self, _volume: u32) -> Result<BlockAddr, AllocError> {
            // Simple allocation - just use incrementing addresses
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let offset = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(BlockAddr::new(1, 0, 0, offset))
        }

        fn handle_free(&self, _addr: BlockAddr) -> Result<(), AllocError> {
            Ok(())
        }
    }

    let args: Vec<String> = std::env::args().collect();
    let bind_addr: SocketAddr = args
        .get(1)
        .map(|s| s.parse().expect("Invalid address"))
        .unwrap_or_else(|| "127.0.0.1:7432".parse().unwrap());

    println!("Starting PermFS cluster node...");
    println!("Listening on {}", bind_addr);

    let handler = Arc::new(LocalHandler {
        device: MemoryBlockDevice::new(1, 0),
    });

    let server = TcpServer::bind(1, bind_addr).expect("Failed to bind");

    ctrlc::set_handler(move || {
        println!("\nShutting down...");
        std::process::exit(0);
    })
    .expect("Error setting Ctrl+C handler");

    println!("Server running. Press Ctrl+C to stop.");
    server.run(handler);
}

#[cfg(not(feature = "network"))]
fn main() {
    eprintln!("This example requires the 'network' feature.");
    eprintln!("Run with: cargo run --example cluster_node --features network");
    std::process::exit(1);
}
