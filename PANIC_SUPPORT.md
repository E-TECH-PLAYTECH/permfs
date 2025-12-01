# PermFS Panic Support Prototype

This document outlines a production-ready panic strategy that fits the prototype block driver and allocator designs previously outlined for PermFS. It assumes an environment that can run in `no_std` with an optional `alloc`-backed heap, and it is structured to be hardware-friendly (DMA-aware) and observability-first.

## Goals
- **Fail fast, log first:** Capture actionable state (location, thread/task identifiers if available, allocator/driver health) before halting or rebooting.
- **Deterministic policy:** Use a configurable strategy (halt vs. reboot) with an unambiguous default of halt/spin to avoid reboot loops.
- **Zero-allocation execution:** Panic handling must run without heap allocations and tolerate partially initialized drivers/allocators.
- **Driver/allocator cooperation:** Freeze new I/O, attempt best-effort flush of durable state, and emit breadcrumbs that help reconstruct allocator and journal state postmortem.

## Architecture
1. **Panic hooks API** (already present in `os_porting.rs`):
   - `install_panic_hooks(logger, halt, reboot, strategy)` installs platform callbacks for logging and termination.
   - `PanicStrategy` enumerates `Halt` and `Reboot`, defaulting to `Halt`.
   - Logging uses a fixed-size `PanicLineBuffer` to avoid allocations.

2. **Driver-aware panic fence:**
   - Expose a `panic_freeze()` on the block-driver wrapper that stops new submissions, drains in-flight operations with a bounded wait, and optionally issues a cache flush/FUA barrier if the transport supports it.
   - If draining times out, mark outstanding operations as lost and surface that in the panic log to avoid assuming durability.

3. **Allocator breadcrumbs:**
   - Add `allocator::panic_report()` that snapshots per-shard free/used counters, last journaled epoch, and double-free guard stats into a small struct stored in `.bss`/`.data` for postmortem reads.
   - Provide an emergency single-producer log ring (fixed-size) to record the last N allocator events (alloc/free failures, hint collisions) without heap usage; expose a `drain_for_panic()` method to format into the panic log.

4. **Panic logging pipeline:**
   - Compose a panic message that includes the panic `PanicInfo`, driver freeze result, allocator snapshot, and time source (monotonic ns from `PlatformClock`).
   - Default logger writes to a serial/console callback; if unavailable, panic handler still spins to avoid silent failure.
   - Ensure the panic handler uses only atomic loads/stores and bounded loops—no blocking locks.

5. **Termination policy:**
   - Strategy is chosen at hook installation; `Reboot` invokes the reboot handler, else spins forever. If the reboot handler returns (should be `-> !`), fall back to spinning.

6. **Integration path:**
   - Platform code installs hooks during early boot: logger (serial/UART), halt (e.g., disable interrupts + `hlt`/`wfi`), reboot (e.g., watchdog or reset register), and optional monotonic timer.
   - The block driver and allocator expose their panic helpers behind feature flags so they are available in kernel/no_std builds without pulling `std`.

## Implementation sketch (no_std friendly)
- **Driver freeze API** (new):
  ```rust
  pub trait PanicQuiesce {
      /// Stop taking new I/O and attempt to flush/drain in-flight work.
      fn panic_freeze(&self) -> PanicQuiesceResult;
  }
  
  pub struct PanicQuiesceResult {
      pub drained: bool,
      pub in_flight: usize,
      pub flush_issued: bool,
  }
  ```
  The hardware-backed `BlockDevice` wrapper implements this by rejecting new submissions, waiting for completions up to a bounded deadline, issuing a flush if supported, and returning the result for logging.

- **Allocator snapshot API** (new):
  ```rust
  pub struct AllocatorPanicReport {
      pub epoch: u64,
      pub shards_total: u32,
      pub shards_with_pressure: u32,
      pub free_blocks: u64,
      pub last_errors: &'static [AllocatorEvent],
  }
  
  pub fn allocator_panic_report() -> AllocatorPanicReport;
  ```
  The report reads atomics only; it must never block or allocate. `last_errors` points at the fixed ring buffer described above.

- **Panic handler flow:**
  1. Build `PanicLineBuffer` with `PanicInfo` and timestamp.
  2. Call `panic_freeze()` on the driver (if registered) and append the result.
  3. Pull `allocator_panic_report()` and append counters plus recent events.
  4. Emit via logger hook; ignore secondary errors.
  5. Follow `PanicStrategy` (reboot or halt/spin).

## Testing strategy
- **Unit tests:**
  - Validate that `panic_freeze()` returns within the bounded deadline and properly reports in-flight counts when forced timeouts occur (mock driver).
  - Ensure allocator breadcrumb ring survives concurrent writes and can be drained without allocation.
  - Confirm the panic handler path remains allocation-free by running under `no_std` test harness or with `panic = "abort"` and instrumentation that panics from early boot contexts.

- **Integration tests:**
  - Induce panics during journal commit and allocator pressure in the in-memory `MemoryBlockDevice` to verify breadcrumbs show correct shard pressure and the driver freeze result shows zero in-flight ops.
  - On hardware, inject panics while I/O is in flight and verify flush/FUA or discard commands are issued as expected (using device tracing or logic analyzer where applicable).

## Operational guidance
- Install hooks as early as possible (before mounting) so panics during driver/allocator init are captured.
- Keep log output short to avoid overrunning slow serial consoles; prefer structured, machine-parseable lines.
- Tie reboot hooks to a hardware watchdog or platform reset register that cannot fail silently.
- Periodically exercise the panic path in staging (fault injection) to ensure quiesce/flush logic remains correct as drivers evolve.
