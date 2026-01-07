# PermFS Operations & Usage Guide

This document distills how to build, test, and run PermFS in practical environments (macOS with macFUSE, APFS volumes, and the included TCP example). It is written to be executable as-is—no TODOs or placeholders.

## 1) What PermFS Is
- Distributed filesystem with 256-bit global block addresses and lock-free shard allocator.
- Crash-safe write-ahead journal with recovery.
- Extent trees plus direct/indirect pointers for efficient file layout.
- Distributed lock manager (leases + fencing).
- Pluggable block devices (`BlockDevice` trait) and transports (`ClusterTransport` trait).
- Userspace mounting via FUSE (`fuser` crate) and a reference TCP transport.

## 2) Build, Lint, Test
Use the included CI helper:
```bash
tools/ci.sh
```
It runs fmt, clippy (all targets/features), checks the fuse/network feature matrix, unit tests, and optionally the examples (gate with `RUN_EXAMPLE_*` env vars).

Targeted commands:
```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo check --features fuse
cargo check --features network
cargo check --features "fuse,network"
cargo test
```

### Integration Coverage
- `tests/integration_persistence.rs`: mkfs → write → unmount → remount from the same image → verify data.
- `tests/integration_journal_network.rs`:
  - Replays committed journal transactions after a simulated crash.
  - Skips replay when the commit record is missing.
  - (With `network` feature) Round-trips the TCP protocol against an in-process handler.

## 3) Disk-backed Smoke Test
```bash
cargo run --example test_fs
```
Creates a sparse image, writes files (including large/indirect and symlinks), and verifies reads.

## 4) FUSE on macOS (APFS, macFUSE)
Prereqs (already installed per runbook): `pkgconf`, `macfuse` (kernel extension approved in System Settings → Privacy & Security), reboot if prompted.

### Create an APFS target volume (safe, isolated)
> **Warning:** double-check disk identifiers; replacing the wrong one can destroy data. Always run `diskutil list` first.
1. List disks: `diskutil list`
2. Identify an APFS container (e.g., `disk3s2`); create a dedicated volume:
   ```bash
   sudo diskutil apfs addVolume disk3s2 APFS permfs-lab
   ```
   This mounts at `/Volumes/permfs-lab`.
3. Own it: `sudo chown $(whoami) /Volumes/permfs-lab`
4. Prepare mount/data dirs:
   ```bash
   mkdir -p /Volumes/permfs-lab/permfs /Volumes/permfs-lab/permfs_mount
   ```

### Mount PermFS via FUSE
```bash
RUN_EXAMPLE_FUSE=1 cargo run --example fuse_mount --features fuse \
  /Volumes/permfs-lab/permfs_mount \
  /Volumes/permfs-lab/permfs/permfs_test.img
```
- The example creates/initializes the image, then mounts it at `/Volumes/permfs-lab/permfs_mount`.
- Do **not** mount on a path that is itself already a FUSE mount; macFUSE rejects nested mounts.

### Unmount
```bash
umount /Volumes/permfs-lab/permfs_mount  # or: diskutil unmount /Volumes/permfs-lab/permfs_mount
```

## 5) TCP Transport Example (loopback lab)
```bash
RUN_EXAMPLE_CLUSTER=1 cargo run --example cluster_node --features network \
  127.0.0.1:8743 /tmp/permfs_cluster.img 50000
```
Start multiple nodes on different ports; register peers through the `NodeRegistry` API before issuing remote ops.

## 6) Designing for OS Integration
- The abstraction layers (`BlockDevice`, `ClusterTransport`, `VfsOperations`) are used everywhere, not just FUSE. They let you swap:
  - Block I/O backend (file-backed, raw block device, RAM, NVMe driver, object store).
  - Transport (TCP, in-process, kernel IPC, RDMA).
- For a new OS:
  - Provide a `BlockDevice` that wraps your kernel block driver (requires `no_std`, allocator, and panic handlers; see `STATUS.md` for gaps).
  - Provide a `ClusterTransport` over your kernel messaging stack.
  - Reuse the journal, extent, allocator, and DLM logic unchanged.
  - Keep tests: re-run the integration suite atop your backend to ensure parity.
- This swap does **not** remove functionality; it relocates I/O and threading primitives to your environment.

## 7) Distribution & Offline Use
- Cargo registry access is required the first time. For offline installs when network is available, vendor dependencies:
  ```bash
  cargo vendor --locked vendor > .cargo/config.toml
  ```
  (Network is currently unreachable in this environment; run the above when online. Do **not** commit an empty `vendor/`.)
- Ship artifacts with the `vendor/` directory and `.cargo/config.toml` pointing to it for reproducible builds without external fetches.

## 8) Troubleshooting
- **macFUSE mount errors**
  - `Operation not permitted` or `mount_macfuse: ... not available`: ensure the mountpoint is on APFS, not a FUSE mount; approve the kernel extension; retry after reboot.
  - `is itself on a macFUSE volume`: move the mountpoint to a real APFS path (see steps above).
- **Stale images**: remove old images (`rm /tmp/permfs_*.img`) before reruns.
- **Port in use** (cluster example): switch to another port, e.g., `127.0.0.1:8744`.
- **Offline builds fail**: vendor dependencies when you have connectivity, then rebuild with the generated `.cargo/config.toml`.

## 9) Safe Ops Checklist
- Always know the target disk/volume before running `diskutil apfs addVolume`.
- Keep test images under `/tmp` or a dedicated APFS volume.
- Unmount FUSE targets before removing images.
- Run `tools/ci.sh` before distributing binaries or images.

