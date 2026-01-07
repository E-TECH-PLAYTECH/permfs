# PermFS Status & Runbook

## What Works
- Core library builds and tests pass: `cargo test` (32/32 green).
- Linting passes: `cargo clippy --all-targets --all-features -D warnings`.
- Feature checks pass for std builds: `cargo check`, and with `--features fuse`, `--features network`, `--features "fuse,network"`.
- Example `test_fs` runs clean on disk-backed image and exercises create/read/write/large file/symlink paths.

## Requirements
- Rust toolchain with `rustfmt` and `clippy` components.
- For FUSE: `pkgconf` and `macfuse` (on macOS) installed; allow kernel extension and reboot if prompted.
- Network example: needs permission to bind TCP (defaults to 127.0.0.1:8743 in `tools/ci.sh`).

## Known Scope Limits
- `--no-default-features` / pure `no_std` is not wired: would need a global allocator and panic handler, plus allocator/mutex replacements.
- Examples are best-effort in `tools/ci.sh`: cluster node may still fail if the port is blocked; FUSE mount needs an existing mountpoint directory and macFUSE loaded.

## Quick Commands
- Format: `cargo fmt --all -- --check`
- Lint: `cargo clippy --all-targets --all-features -- -D warnings`
- Tests: `cargo test`
- Feature checks (std): `cargo check --features fuse`, `--features network`, `--features "fuse,network"`
- Full local CI: `tools/ci.sh` (creates `/tmp/permfs_ci_mount`, runs examples)
- Run disk-backed example: `cargo run --example test_fs`
- FUSE example: `mkdir -p /tmp/permfs_ci_mount && cargo run --example fuse_mount --features fuse /tmp/permfs_ci_mount /tmp/permfs_ci.img`
- Cluster node example: `cargo run --example cluster_node --features network 127.0.0.1:8743 /tmp/permfs_cluster.img 50000`

## Implementation Notes
- Superblock now records block/inode bitmap starts/counts and data start; mkfs marks the root data block as used and builds a live `VolumeAllocator` from on-disk bitmaps.
- Block allocator state is behind an `RwLock` for std builds; allocator updates propagate on mount/mkfs.
- File-backed device zeroes/truncates images on create and validates node/volume/offset.
- FUSE adapter clones superblock fields added for allocator metadata; examples point to disk-backed builders.
- In-process transport uses clarified type aliases; network transport header uses `repr(C)` to avoid misalignment.

## Troubleshooting
- FUSE missing pkg-config/lib: install `brew install pkgconf --cask macfuse` and approve kernel extension.
- Cluster example bind errors: use a different port (e.g., `127.0.0.1:8744`) or run with sufficient privileges.
- Stale images: delete `/tmp/permfs_*.img` before reruns if needed.
