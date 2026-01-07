#!/usr/bin/env bash
set -euo pipefail

# PermFS local CI runner
# Runs formatting, lint, feature matrix checks, and example smoke tests.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

cmd() {
  echo "> $*"
  "$@"
}

# Ensure rustfmt/clippy available
if ! cargo fmt --version >/dev/null 2>&1; then
  echo "rustfmt not found (install with: rustup component add rustfmt)" >&2
  exit 1
fi
if ! cargo clippy --version >/dev/null 2>&1; then
  echo "clippy not found (install with: rustup component add clippy)" >&2
  exit 1
fi

# Format check
cmd cargo fmt --all -- --check

# Base check + clippy
cmd cargo check
cmd cargo clippy --all-targets --all-features -- -D warnings

# Feature matrix checks (std-oriented)
cmd cargo check --features fuse
cmd cargo check --features network
cmd cargo check --features "fuse,network"

# Tests (std only)
cmd cargo test

# Example smoke runs (opt-in via env flags)
TMP_IMG="/tmp/permfs_ci.img"
TMP_MOUNT="/tmp/permfs_ci_mount"
rm -f "$TMP_IMG" /tmp/permfs_cluster.img
mkdir -p "$TMP_MOUNT"

if [ "${RUN_EXAMPLE_TEST_FS:-1}" = "1" ]; then
  cmd cargo run --example test_fs || true
else
  echo "Skipping test_fs example (set RUN_EXAMPLE_TEST_FS=1 to run)"
fi

if [ "${RUN_EXAMPLE_FUSE:-0}" = "1" ]; then
  cmd cargo run --example fuse_mount --features fuse "$TMP_MOUNT" "$TMP_IMG" || true
else
  echo "Skipping fuse_mount example (set RUN_EXAMPLE_FUSE=1 to run; requires FUSE/mount perms)"
fi

if [ "${RUN_EXAMPLE_CLUSTER:-0}" = "1" ]; then
  cmd cargo run --example cluster_node --features network 127.0.0.1:8743 /tmp/permfs_cluster.img 50000 || true
else
  echo "Skipping cluster_node example (set RUN_EXAMPLE_CLUSTER=1 to run; requires bind perms)"
fi

echo "CI script finished."
