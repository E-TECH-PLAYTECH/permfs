// PermFS Time — Clock source abstraction for std and no_std environments

/// Clock trait for time abstraction
pub trait Clock: Send + Sync {
    /// Get current time in nanoseconds since Unix epoch
    fn now_ns(&self) -> u64;

    /// Get current time in seconds since Unix epoch
    fn now_secs(&self) -> u64 {
        self.now_ns() / 1_000_000_000
    }

    /// Get current time in milliseconds since Unix epoch
    fn now_ms(&self) -> u64 {
        self.now_ns() / 1_000_000
    }
}

/// System clock implementation
pub struct SystemClock {
    #[cfg(not(feature = "std"))]
    base_tsc: u64,
    #[cfg(not(feature = "std"))]
    tsc_freq_hz: u64,
}

impl SystemClock {
    pub fn new() -> Self {
        #[cfg(feature = "std")]
        {
            Self {}
        }

        #[cfg(not(feature = "std"))]
        {
            // For no_std, we'll use TSC or a provided base time
            Self {
                base_tsc: Self::read_tsc(),
                tsc_freq_hz: Self::estimate_tsc_freq(),
            }
        }
    }

    #[cfg(not(feature = "std"))]
    #[inline]
    fn read_tsc() -> u64 {
        #[cfg(target_arch = "x86_64")]
        {
            let lo: u32;
            let hi: u32;
            unsafe {
                core::arch::asm!(
                    "rdtsc",
                    out("eax") lo,
                    out("edx") hi,
                    options(nostack, nomem, preserves_flags)
                );
            }
            ((hi as u64) << 32) | (lo as u64)
        }

        #[cfg(target_arch = "x86")]
        {
            let lo: u32;
            let hi: u32;
            unsafe {
                core::arch::asm!(
                    "rdtsc",
                    out("eax") lo,
                    out("edx") hi,
                    options(nostack, nomem, preserves_flags)
                );
            }
            ((hi as u64) << 32) | (lo as u64)
        }

        #[cfg(target_arch = "aarch64")]
        {
            let cnt: u64;
            unsafe {
                core::arch::asm!(
                    "mrs {}, cntvct_el0",
                    out(reg) cnt,
                    options(nostack, nomem, preserves_flags)
                );
            }
            cnt
        }

        #[cfg(not(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64")))]
        {
            // Fallback: return 0, caller should provide clock
            0
        }
    }

    #[cfg(not(feature = "std"))]
    fn estimate_tsc_freq() -> u64 {
        // Default assumption: 2.5 GHz
        // In a real kernel module, this would be calibrated
        2_500_000_000
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now_ns(&self) -> u64 {
        #[cfg(feature = "std")]
        {
            use std::time::{SystemTime, UNIX_EPOCH};
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0)
        }

        #[cfg(not(feature = "std"))]
        {
            if let Some(ns) = crate::os_porting::monotonic_now_ns() {
                return ns;
            }

            let current_tsc = Self::read_tsc();
            let elapsed_ticks = current_tsc.saturating_sub(self.base_tsc);
            // Convert TSC ticks to nanoseconds
            // ns = ticks * 1_000_000_000 / freq
            // To avoid overflow: ns = ticks / (freq / 1_000_000_000)
            // But freq >> 1B typically, so: ns = ticks * 1000 / (freq / 1_000_000)
            let freq_mhz = self.tsc_freq_hz / 1_000_000;
            if freq_mhz > 0 {
                elapsed_ticks * 1000 / freq_mhz
            } else {
                0
            }
        }
    }
}

/// Monotonic clock - guaranteed never to go backwards
#[cfg(feature = "std")]
pub struct MonotonicClock {
    start: std::time::Instant,
    epoch_offset_ns: u64,
}

#[cfg(feature = "std")]
impl MonotonicClock {
    pub fn new() -> Self {
        use std::time::{Instant, SystemTime, UNIX_EPOCH};
        let epoch_offset_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        Self {
            start: Instant::now(),
            epoch_offset_ns,
        }
    }
}

#[cfg(feature = "std")]
impl Default for MonotonicClock {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "std")]
impl Clock for MonotonicClock {
    fn now_ns(&self) -> u64 {
        let elapsed = self.start.elapsed().as_nanos() as u64;
        self.epoch_offset_ns.saturating_add(elapsed)
    }
}

/// A clock that can be manually set (useful for testing)
pub struct ManualClock {
    current_ns: core::sync::atomic::AtomicU64,
}

impl ManualClock {
    pub fn new(initial_ns: u64) -> Self {
        Self {
            current_ns: core::sync::atomic::AtomicU64::new(initial_ns),
        }
    }

    pub fn set(&self, ns: u64) {
        self.current_ns
            .store(ns, core::sync::atomic::Ordering::SeqCst);
    }

    pub fn advance(&self, ns: u64) {
        self.current_ns
            .fetch_add(ns, core::sync::atomic::Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now_ns(&self) -> u64 {
        self.current_ns.load(core::sync::atomic::Ordering::SeqCst)
    }
}

/// Convert nanoseconds to a (secs, nsecs) tuple
pub fn ns_to_timespec(ns: u64) -> (u64, u32) {
    let secs = ns / 1_000_000_000;
    let nsecs = (ns % 1_000_000_000) as u32;
    (secs, nsecs)
}

/// Convert (secs, nsecs) to nanoseconds
pub fn timespec_to_ns(secs: u64, nsecs: u32) -> u64 {
    secs.saturating_mul(1_000_000_000)
        .saturating_add(nsecs as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_clock() {
        let clock = SystemClock::new();
        let t1 = clock.now_ns();
        // Small busy wait
        for _ in 0..10000 {
            core::hint::spin_loop();
        }
        let t2 = clock.now_ns();
        assert!(t2 >= t1, "Time should not go backwards");
    }

    #[test]
    fn test_manual_clock() {
        let clock = ManualClock::new(1000);
        assert_eq!(clock.now_ns(), 1000);
        clock.advance(500);
        assert_eq!(clock.now_ns(), 1500);
        clock.set(2000);
        assert_eq!(clock.now_ns(), 2000);
    }

    #[test]
    fn test_timespec_conversion() {
        let ns = 1_500_000_123u64;
        let (secs, nsecs) = ns_to_timespec(ns);
        assert_eq!(secs, 1);
        assert_eq!(nsecs, 500_000_123);
        assert_eq!(timespec_to_ns(secs, nsecs), ns);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_monotonic_clock() {
        let clock = MonotonicClock::new();
        let t1 = clock.now_ns();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let t2 = clock.now_ns();
        assert!(t2 > t1, "Monotonic clock should advance");
        assert!(t2 - t1 >= 10_000_000, "At least 10ms should have passed");
    }
}
