//! Synchronization primitives that work in both `std` and `no_std + alloc` builds.
//! When the standard library is available we defer to its locking primitives (or
//! `parking_lot` when the `network` feature is enabled). In `no_std` builds we
//! provide lightweight spin-based locks backed by atomics.


#[cfg(feature = "alloc")]
pub use alloc::sync::Arc;

#[cfg(all(feature = "std", feature = "network"))]
pub type Mutex<T> = parking_lot::Mutex<T>;
#[cfg(all(feature = "std", feature = "network"))]
pub type RwLock<T> = parking_lot::RwLock<T>;
#[cfg(all(feature = "std", feature = "network"))]
pub use parking_lot::{MutexGuard, RwLockReadGuard, RwLockWriteGuard};

#[cfg(all(feature = "std", not(feature = "network")))]
pub type Mutex<T> = std::sync::Mutex<T>;
#[cfg(all(feature = "std", not(feature = "network")))]
pub type RwLock<T> = std::sync::RwLock<T>;
#[cfg(all(feature = "std", not(feature = "network")))]
pub use std::sync::{MutexGuard, RwLockReadGuard, RwLockWriteGuard};

#[cfg(not(feature = "std"))]
pub struct Mutex<T: ?Sized> {
    locked: AtomicBool,
    value: UnsafeCell<T>,
}

#[cfg(not(feature = "std"))]
unsafe impl<T: ?Sized + Send> Send for Mutex<T> {}
#[cfg(not(feature = "std"))]
unsafe impl<T: ?Sized + Send> Sync for Mutex<T> {}

#[cfg(not(feature = "std"))]
impl<T> Mutex<T> {
    pub const fn new(value: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            value: UnsafeCell::new(value),
        }
    }

    pub fn lock(&self) -> MutexGuard<'_, T> {
        while self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            spin_loop();
        }
        MutexGuard { mutex: self }
    }
}

#[cfg(not(feature = "std"))]
pub struct MutexGuard<'a, T: ?Sized + 'a> {
    mutex: &'a Mutex<T>,
}

#[cfg(not(feature = "std"))]
impl<'a, T: ?Sized> Drop for MutexGuard<'a, T> {
    fn drop(&mut self) {
        self.mutex.locked.store(false, Ordering::Release);
    }
}

#[cfg(not(feature = "std"))]
impl<'a, T: ?Sized> core::ops::Deref for MutexGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.mutex.value.get() }
    }
}

#[cfg(not(feature = "std"))]
impl<'a, T: ?Sized> core::ops::DerefMut for MutexGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.mutex.value.get() }
    }
}

#[cfg(not(feature = "std"))]
pub struct RwLock<T: ?Sized> {
    reader_count: AtomicUsize,
    writer: AtomicBool,
    value: UnsafeCell<T>,
}

#[cfg(not(feature = "std"))]
unsafe impl<T: ?Sized + Send> Send for RwLock<T> {}
#[cfg(not(feature = "std"))]
unsafe impl<T: ?Sized + Send + Sync> Sync for RwLock<T> {}

#[cfg(not(feature = "std"))]
impl<T> RwLock<T> {
    pub const fn new(value: T) -> Self {
        Self {
            reader_count: AtomicUsize::new(0),
            writer: AtomicBool::new(false),
            value: UnsafeCell::new(value),
        }
    }

    pub fn read(&self) -> RwLockReadGuard<'_, T> {
        loop {
            while self.writer.load(Ordering::Acquire) {
                spin_loop();
            }
            let prev = self.reader_count.fetch_add(1, Ordering::Acquire);
            if !self.writer.load(Ordering::Acquire) {
                return RwLockReadGuard { lock: self };
            }
            self.reader_count.store(prev, Ordering::Release);
        }
    }

    pub fn write(&self) -> RwLockWriteGuard<'_, T> {
        while self
            .writer
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            spin_loop();
        }

        while self.reader_count.load(Ordering::Acquire) != 0 {
            spin_loop();
        }

        RwLockWriteGuard { lock: self }
    }
}

#[cfg(not(feature = "std"))]
pub struct RwLockReadGuard<'a, T: ?Sized + 'a> {
    lock: &'a RwLock<T>,
}

#[cfg(not(feature = "std"))]
impl<'a, T: ?Sized> Drop for RwLockReadGuard<'a, T> {
    fn drop(&mut self) {
        self.lock.reader_count.fetch_sub(1, Ordering::Release);
    }
}

#[cfg(not(feature = "std"))]
impl<'a, T: ?Sized> core::ops::Deref for RwLockReadGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.value.get() }
    }
}

#[cfg(not(feature = "std"))]
pub struct RwLockWriteGuard<'a, T: ?Sized + 'a> {
    lock: &'a RwLock<T>,
}

#[cfg(not(feature = "std"))]
impl<'a, T: ?Sized> Drop for RwLockWriteGuard<'a, T> {
    fn drop(&mut self) {
        self.lock.writer.store(false, Ordering::Release);
    }
}

#[cfg(not(feature = "std"))]
impl<'a, T: ?Sized> core::ops::Deref for RwLockWriteGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.value.get() }
    }
}

#[cfg(not(feature = "std"))]
impl<'a, T: ?Sized> core::ops::DerefMut for RwLockWriteGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.lock.value.get() }
    }
}
