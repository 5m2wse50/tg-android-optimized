//! Wait-free single-producer/single-consumer ring buffer for audio frames.

use core::sync::atomic::{AtomicU64, Ordering};

#[repr(C, align(64))]
pub struct RingSlot<T> {
    pub seq: AtomicU64,
    pub data: std::mem::MaybeUninit<T>,
}

pub const CAP: usize = 1 << 12;

pub struct SpScRing<T> {
    buf: Box<[RingSlot<T>]>,
    head: AtomicU64,
    tail: AtomicU64,
}

impl<T> SpScRing<T> {
    pub fn new() -> Self {
        // Initialize slots with sequence numbers 0 (empty) and MaybeUninit.
        let mut v = Vec::with_capacity(CAP);
        for _ in 0..CAP {
            v.push(RingSlot {
                seq: AtomicU64::new(0),
                data: std::mem::MaybeUninit::uninit(),
            });
        }
        Self {
            buf: v.into_boxed_slice(),
            head: AtomicU64::new(0),
            tail: AtomicU64::new(0),
        }
    }

    /// Producer side (audio capture thread).
    pub fn push(&self, v: T) -> bool {
        let t = self.tail.load(Ordering::Relaxed);
        let n = t.wrapping_add(1);
        if n.wrapping_sub(self.head.load(Ordering::Acquire)) > CAP as u64 {
            return false;
        }
        let slot = &self.buf[(t % CAP as u64) as usize];
        slot.data.write(v);
        slot.seq.store(n, Ordering::Release);
        self.tail.store(n, Ordering::Release);
        true
    }

    /// Consumer side (playout / encoder thread).
    pub fn try_pop(&self) -> Option<T> {
        let h = self.head.load(Ordering::Acquire);
        let cur = h.wrapping_add(1);
        let slot = &self.buf[(h % CAP as u64) as usize];
        if slot.seq.load(Ordering::Acquire) == cur {
            let v = unsafe { slot.data.assume_init_read() };
            self.head.store(cur, Ordering::Release);
            Some(v)
        } else {
            None
        }
    }
}

impl<T> Drop for SpScRing<T> {
    fn drop(&mut self) {
        // Drain remaining items to drop them.
        while self.try_pop().is_some() {}
    }
}