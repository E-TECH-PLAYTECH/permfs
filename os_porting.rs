//! OS porting glue for no_std environments.
//! Provides panic wiring, allocator bridging, and monotonic clock adapters.

#![cfg_attr(not(feature = "std"), allow(dead_code))]

#[cfg(not(feature = "std"))]
use core::fmt::{self, Write};
#[cfg(not(feature = "std"))]
use core::sync::atomic::{AtomicPtr, AtomicU8};
use core::sync::atomic::{AtomicUsize, Ordering};

/// Panic strategy to follow after logging the panic details.
#[cfg(not(feature = "std"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PanicStrategy {
    /// Halt execution (spin forever) after logging.
    Halt = 0,
    /// Invoke the configured reboot handler after logging.
    Reboot = 1,
}

#[cfg(not(feature = "std"))]
struct PanicHooks {
    logger: AtomicPtr<()>,
    halt: AtomicPtr<()>,
    reboot: AtomicPtr<()>,
    strategy: AtomicU8,
}

#[cfg(not(feature = "std"))]
static PANIC_HOOKS: PanicHooks = PanicHooks {
    logger: AtomicPtr::new(core::ptr::null_mut()),
    halt: AtomicPtr::new(core::ptr::null_mut()),
    reboot: AtomicPtr::new(core::ptr::null_mut()),
    strategy: AtomicU8::new(PanicStrategy::Halt as u8),
};

/// Install platform-specific panic hooks.
///
/// The hooks are function pointers so they remain FFI-friendly for kernels and hypervisors
/// that cannot use trait objects. Pass `None` to keep the default for any handler.
#[cfg(not(feature = "std"))]
pub fn install_panic_hooks(
    logger: Option<fn(&str)>,
    halt: Option<fn() -> !>,
    reboot: Option<fn() -> !>,
    strategy: PanicStrategy,
) {
    if let Some(log_fn) = logger {
        PANIC_HOOKS
            .logger
            .store(log_fn as *mut (), Ordering::Release);
    }

    if let Some(halt_fn) = halt {
        PANIC_HOOKS
            .halt
            .store(halt_fn as *mut (), Ordering::Release);
    }

    if let Some(reboot_fn) = reboot {
        PANIC_HOOKS
            .reboot
            .store(reboot_fn as *mut (), Ordering::Release);
    }

    PANIC_HOOKS
        .strategy
        .store(strategy as u8, Ordering::Release);
}

#[cfg(not(feature = "std"))]
fn with_logger<F: FnOnce(fn(&str))>(f: F) {
    let ptr = PANIC_HOOKS.logger.load(Ordering::Acquire);
    if !ptr.is_null() {
        // SAFETY: pointer comes from install_panic_hooks
        let logger: fn(&str) = unsafe { core::mem::transmute(ptr) };
        f(logger);
    }
}

#[cfg(not(feature = "std"))]
fn panic_buffer(info: &core::panic::PanicInfo<'_>) -> PanicLineBuffer {
    let mut buf = PanicLineBuffer::new();
    let _ = write!(buf, "PermFS panic: {info}");
    buf
}

/// Fixed-size stack buffer that implements `fmt::Write` without heap allocation.
#[cfg(not(feature = "std"))]
struct PanicLineBuffer {
    buf: [u8; 384],
    len: usize,
}

#[cfg(not(feature = "std"))]
impl PanicLineBuffer {
    const fn new() -> Self {
        Self {
            buf: [0; 384],
            len: 0,
        }
    }

    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("<panic>")
    }
}

#[cfg(not(feature = "std"))]
impl Write for PanicLineBuffer {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let bytes = s.as_bytes();
        let remaining = self.buf.len().saturating_sub(self.len);
        let to_copy = remaining.min(bytes.len());
        self.buf[self.len..self.len + to_copy].copy_from_slice(&bytes[..to_copy]);
        self.len += to_copy;
        Ok(())
    }
}

#[cfg(not(feature = "std"))]
fn halt_or_spin() -> ! {
    let halt_ptr = PANIC_HOOKS.halt.load(Ordering::Acquire);
    if !halt_ptr.is_null() {
        let halt_fn: fn() -> ! = unsafe { core::mem::transmute(halt_ptr) };
        halt_fn();
    }

    loop {
        core::hint::spin_loop();
    }
}

#[cfg(not(feature = "std"))]
fn reboot_or_halt() -> ! {
    let reboot_ptr = PANIC_HOOKS.reboot.load(Ordering::Acquire);
    if !reboot_ptr.is_null() {
        let reboot_fn: fn() -> ! = unsafe { core::mem::transmute(reboot_ptr) };
        reboot_fn();
    }

    halt_or_spin()
}

/// Panic handler for `no_std` targets.
#[cfg(not(feature = "std"))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    let buf = panic_buffer(info);
    with_logger(|logger| logger(buf.as_str()));

    let strategy = PANIC_HOOKS.strategy.load(Ordering::Acquire);
    match strategy {
        x if x == PanicStrategy::Reboot as u8 => reboot_or_halt(),
        _ => halt_or_spin(),
    }
}

/// Trait for platform allocators to bridge into `#[global_allocator]`.
pub trait PlatformAllocator: Send + Sync {
    /// Allocate a block matching the provided layout.
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8;
    /// Deallocate a block allocated by this allocator.
    unsafe fn dealloc(&self, ptr: *mut u8, layout: core::alloc::Layout);
}

#[cfg(all(not(feature = "std"), feature = "alloc"))]
struct AllocatorRegistry {
    platform: AtomicPtr<()>,
    fallback_cursor: AtomicUsize,
}

#[cfg(all(not(feature = "std"), feature = "alloc"))]
static ALLOCATOR: AllocatorRegistry = AllocatorRegistry {
    platform: AtomicPtr::new(core::ptr::null_mut()),
    fallback_cursor: AtomicUsize::new(0),
};

/// Install a platform allocator. This will be used by the `#[global_allocator]` bridge.
#[cfg(all(not(feature = "std"), feature = "alloc"))]
pub fn install_platform_allocator(allocator: &'static dyn PlatformAllocator) {
    ALLOCATOR
        .platform
        .store(allocator as *const _ as *mut (), Ordering::Release);
}

#[cfg(all(not(feature = "std"), feature = "alloc"))]
const FALLBACK_HEAP_SIZE: usize = 1024 * 1024; // 1 MiB for early boot needs.

#[cfg(all(not(feature = "std"), feature = "alloc"))]
#[repr(align(16))]
struct FallbackHeap([u8; FALLBACK_HEAP_SIZE]);

#[cfg(all(not(feature = "std"), feature = "alloc"))]
static mut FALLBACK_HEAP: FallbackHeap = FallbackHeap([0; FALLBACK_HEAP_SIZE]);

#[inline]
fn align_up(value: usize, align: usize) -> Option<usize> {
    if align == 0 {
        return Some(value);
    }
    let mask = align - 1;
    value.checked_add(mask).map(|sum| sum & !mask)
}

#[cfg(all(not(feature = "std"), feature = "alloc"))]
unsafe fn fallback_alloc(layout: core::alloc::Layout) -> *mut u8 {
    let align = layout.align();
    let allocation_start = match ALLOCATOR.fallback_cursor.fetch_update(
        Ordering::AcqRel,
        Ordering::Acquire,
        |cursor| {
            let aligned = align_up(cursor, align)?;
            let new_cursor = aligned.checked_add(layout.size())?;
            if new_cursor > FALLBACK_HEAP_SIZE {
                None
            } else {
                Some(new_cursor)
            }
        },
    ) {
        Ok(previous) => align_up(previous, align).unwrap_or(previous),
        Err(_) => return core::ptr::null_mut(),
    };

    unsafe { FALLBACK_HEAP.0.as_mut_ptr().add(allocation_start) }
}

#[cfg(all(not(feature = "std"), feature = "alloc"))]
unsafe fn fallback_dealloc(_ptr: *mut u8, _layout: core::alloc::Layout) {
    // The fallback is a bump allocator; deallocation is a no-op.
}

#[cfg(all(not(feature = "std"), feature = "alloc"))]
fn platform_allocator() -> Option<&'static dyn PlatformAllocator> {
    let ptr = ALLOCATOR.platform.load(Ordering::Acquire);
    if ptr.is_null() {
        None
    } else {
        // SAFETY: pointer installed via install_platform_allocator
        Some(unsafe { &*(ptr as *const dyn PlatformAllocator) })
    }
}

/// Global allocator bridge that delegates to a platform allocator when present
/// and falls back to a fixed bump allocator otherwise.
#[cfg(all(not(feature = "std"), feature = "alloc"))]
pub struct GlobalAllocatorBridge;

#[cfg(all(not(feature = "std"), feature = "alloc"))]
unsafe impl core::alloc::GlobalAlloc for GlobalAllocatorBridge {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        if let Some(allocator) = platform_allocator() {
            allocator.alloc(layout)
        } else {
            fallback_alloc(layout)
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: core::alloc::Layout) {
        if let Some(allocator) = platform_allocator() {
            allocator.dealloc(ptr, layout)
        } else {
            fallback_dealloc(ptr, layout)
        }
    }
}

#[cfg(all(not(feature = "std"), feature = "alloc"))]
#[global_allocator]
static GLOBAL_ALLOCATOR: GlobalAllocatorBridge = GlobalAllocatorBridge;

/// Fixed-size allocator that can be embedded by platform code.
/// Useful when the host wants an owned allocator separate from the global one.
pub struct FixedRegionAllocator<const N: usize> {
    region: core::cell::UnsafeCell<[u8; N]>,
    cursor: core::sync::atomic::AtomicUsize,
}

unsafe impl<const N: usize> Sync for FixedRegionAllocator<N> {}

impl<const N: usize> FixedRegionAllocator<N> {
    pub const fn new() -> Self {
        Self {
            region: core::cell::UnsafeCell::new([0; N]),
            cursor: core::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn bump_alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        let align = layout.align();
        let allocation_start =
            match self
                .cursor
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |cursor| {
                    let aligned = align_up(cursor, align)?;
                    let new_cursor = aligned.checked_add(layout.size())?;
                    if new_cursor > N {
                        None
                    } else {
                        Some(new_cursor)
                    }
                }) {
                Ok(previous) => align_up(previous, align).unwrap_or(previous),
                Err(_) => return core::ptr::null_mut(),
            };

        // SAFETY: the region is private to this allocator
        unsafe { (*self.region.get()).as_mut_ptr().add(allocation_start) }
    }
}

unsafe impl<const N: usize> core::alloc::GlobalAlloc for FixedRegionAllocator<N> {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        self.bump_alloc(layout)
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: core::alloc::Layout) {
        // Intentional no-op; the allocator is bump-only.
    }
}

/// Monotonic time source registration for `no_std` builds.
#[cfg(not(feature = "std"))]
static MONOTONIC_TIME_SOURCE: AtomicUsize = AtomicUsize::new(0);

/// Register a monotonic timer function that returns nanoseconds since boot or another monotonic epoch.
#[cfg(not(feature = "std"))]
pub fn install_monotonic_timer(reader: fn() -> u64) {
    MONOTONIC_TIME_SOURCE.store(reader as usize, Ordering::Release);
}

#[cfg(not(feature = "std"))]
pub(crate) fn monotonic_now_ns() -> Option<u64> {
    let ptr = MONOTONIC_TIME_SOURCE.load(Ordering::Acquire);
    if ptr == 0 {
        None
    } else {
        let f: fn() -> u64 = unsafe { core::mem::transmute(ptr) };
        Some(f())
    }
}

/// Clock adapter that reads directly from the registered monotonic timer.
pub struct PlatformClock;

impl crate::time::Clock for PlatformClock {
    fn now_ns(&self) -> u64 {
        #[cfg(not(feature = "std"))]
        {
            if let Some(ns) = monotonic_now_ns() {
                return ns;
            }
        }

        // Fallback to SystemClock when std is available or the platform timer is unset.
        crate::time::SystemClock::new().now_ns()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_region_allocator_aligns() {
        const SIZE: usize = 1024;
        static ALLOCATOR: FixedRegionAllocator<SIZE> = FixedRegionAllocator::new();

        unsafe {
            let ptr_a = ALLOCATOR.alloc(core::alloc::Layout::from_size_align(8, 8).unwrap());
            assert!(!ptr_a.is_null());
            let ptr_b = ALLOCATOR.alloc(core::alloc::Layout::from_size_align(16, 16).unwrap());
            assert!(!ptr_b.is_null());
            assert_eq!(ptr_b as usize % 16, 0);
            ALLOCATOR.dealloc(ptr_a, core::alloc::Layout::from_size_align(8, 8).unwrap());
            ALLOCATOR.dealloc(ptr_b, core::alloc::Layout::from_size_align(16, 16).unwrap());
        }
    }
}
