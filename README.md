# PermFS — Permutation-addressed Distributed Filesystem

A production-ready `no_std` compatible distributed filesystem protocol using 256-bit global block addressing and lock-free allocation.

## Features

- **256-bit Block Addressing**: Global unique addressing across unlimited cluster nodes
- **Lock-free Shard Allocator**: ~4-12 cycles per allocation with bitmap-based allocation
- **Crash Consistency**: Full write-ahead journal with commit/checkpoint/recovery
- **Extent Trees**: B+ tree extent mapping for efficient large file handling
- **Distributed Lock Manager**: Lease-based locking with timeout and renewal
- **FUSE Integration**: Userspace mounting via `fuser` crate
- **TCP Transport**: Full network protocol for cluster communication
- **Checksum Verification**: CRC32C with hardware acceleration support

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        VFS Layer (vfs.rs)                       │
│              POSIX-like: open/read/write/mkdir/etc              │
├─────────────────────────────────────────────────────────────────┤
│                     Core FS (lib.rs, dir.rs)                    │
│         Inode ops, directory entries, block mapping             │
├─────────────────────────────────────────────────────────────────┤
│   Write Path (write.rs)  │  Journal (journal.rs)  │  mkfs.rs   │
│   Allocation, truncate   │  WAL, crash recovery   │  Format    │
├─────────────────────────────────────────────────────────────────┤
│        Extent Tree       │        DLM (dlm.rs)                  │
│   B+ tree block mapping  │   Distributed locking                │
├─────────────────────────────────────────────────────────────────┤
│                    Block Layer (lib.rs)                         │
│         Local BlockDevice  ←→  ClusterTransport                 │
├─────────────────────────────────────────────────────────────────┤
│                Transport Layer (transport.rs)                   │
│       TCP/connection pooling/retry/node registry                │
└─────────────────────────────────────────────────────────────────┘
```

## 256-bit Block Addressing

```
BlockAddr Layout (32 bytes):
┌────────────────┬────────────────┬────────────────┬────────────────┐
│   limbs[0]     │   limbs[1]     │   limbs[2]     │   limbs[3]     │
│  block_offset  │ shard|volume   │    node_id     │   reserved     │
│     64 bits    │   16|32 bits   │    64 bits     │    64 bits     │
└────────────────┴────────────────┴────────────────┴────────────────┘
```

## Module Summary

| Module | Purpose |
|--------|---------|
| `lib.rs` | Core types, `BlockAddr`, `Inode`, shard allocator |
| `time.rs` | Clock abstraction (TSC for no_std, SystemTime for std) |
| `checksum.rs` | CRC32C + xxHash64 with hardware acceleration |
| `dir.rs` | Directory operations, `DirEntry` management |
| `write.rs` | Write path, inode allocation, truncate |
| `journal.rs` | WAL transactions, crash recovery |
| `mkfs.rs` | Format, layout calculation, mount/unmount |
| `ops.rs` | Extended ops: rename, link, symlink |
| `extent.rs` | B+ tree extent mapping |
| `dlm.rs` | Distributed lock manager with leases |
| `transport.rs` | TCP transport, connection pooling |
| `vfs.rs` | POSIX VFS trait and implementation |
| `fuse.rs` | Userspace FUSE adapter |
| `mock.rs` | In-memory block device for testing |

## Building

```bash
# Default (with std)
cargo build

# no_std kernel mode
cargo build --no-default-features --features kernel

# With FUSE support
cargo build --features fuse

# With network transport
cargo build --features network

# Full production build
cargo build --release --features "fuse,network"
```

## Usage

### Creating a Filesystem

```rust
use permfs::mock::TestFsBuilder;

let (fs, sb) = TestFsBuilder::new()
    .node_id(1)
    .volume_id(0)
    .total_blocks(10000)  // ~40 MiB
    .build()
    .expect("mkfs failed");
```

### File Operations

```rust
// Create and write file
let ino = fs.alloc_inode(&sb)?;
let mut inode = Inode { /* ... */ };
fs.write_file(&mut inode, 0, b"Hello, PermFS!", &sb)?;
fs.write_inode(ino, &inode, &sb)?;
fs.add_dirent(0, b"hello.txt", ino, 1, &sb)?;

// Read back
let inode = fs.read_inode(ino, &sb)?;
let mut buf = vec![0u8; 100];
let n = fs.read_file(&inode, 0, &mut buf)?;
```

### FUSE Mount

```rust
use permfs::fuse::FuseFs;
use std::path::Path;

let fuse_fs = FuseFs::new(Arc::new(fs), sb);
fuse_fs.mount(Path::new("/mnt/permfs"))?;
```

### Distributed Lock Manager

```rust
use permfs::dlm::{DistributedLockManager, LockRequest, LockId, LockMode};

let dlm = DistributedLockManager::new(node_id);
let request = LockRequest::new(LockId::Inode(42), LockMode::Exclusive, node_id);
let grant = dlm.acquire(&request)?;
// ... do work ...
dlm.release(&grant)?;
```

### Network Transport

```rust
use permfs::transport::{NodeAuthConfig, SharedSecret, TcpTransport, TcpServer};

// Client
let transport = TcpTransport::new(local_node_id);
transport.registry().register(
    remote_node_id,
    "192.168.1.10:7432".parse()?,
    NodeAuthConfig::new(SharedSecret::new(1, b"shared-cluster-secret".to_vec())),
);

// Server
let registry = transport.registry().clone();
let server = TcpServer::bind(local_node_id, "0.0.0.0:7432".parse()?, registry)?;
server.run(handler);
```
Use `NodeAuthConfig::with_rollover` to accept both the current and next shared secret during rotations.

## Testing

```bash
cargo test

# Run example
cargo run --example test_fs

# Validate `no_std` + `alloc` build used by the `kernel` feature
cargo +nightly check -Zbuild-std=core,alloc --no-default-features --features kernel
```

## Filesystem Layout

```
Block 0:          Superblock
Block 1..N:       Inode bitmap
Block N+1..M:     Block bitmap
Block M+1..K:     Inode table
Block K+1..J:     Journal
Block J+1..:      Data blocks
```

## Inode Block Mapping

- 12 direct block pointers (48 KiB)
- Single indirect (4 MiB)
- Double indirect (16 GiB)
- Triple indirect (~4 TiB)
- Alternative: Extent tree (B+ tree for contiguous ranges)

## Cluster Protocol

Binary protocol with:
- Read/Write/Alloc/Free block operations
- Connection pooling with idle timeout
- Automatic retry with exponential backoff
- Node health tracking and failover

## Configuration

Environment variables:
- `PERMFS_NODE_ID`: Local node identifier
- `PERMFS_BIND_ADDR`: Server bind address (default: 0.0.0.0:7432)
- `PERMFS_LEASE_DURATION_MS`: Lock lease duration (default: 30000)

## Performance Notes

- Lock-free allocator uses atomic CAS operations
- CRC32C hardware acceleration on x86_64 (SSE4.2) and AArch64
- Connection pooling reduces TCP handshake overhead
- Extent trees reduce metadata overhead for large files

## License

Apache-2.0
