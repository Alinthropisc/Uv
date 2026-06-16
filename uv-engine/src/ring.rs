// Lock-free ring buffer — masscan rte-ring.c / DPDK style.
// Single-producer single-consumer (SPSC) ring for raw packet TX/RX queues.
// Uses power-of-2 size and atomic head/tail for wait-free operation.

use std::sync::atomic::{AtomicUsize, Ordering};

/// SPSC lock-free ring buffer.
pub struct Ring<T> {
    buf: Vec<Option<T>>,
    mask: usize,
    head: AtomicUsize, // producer writes here
    tail: AtomicUsize, // consumer reads here
}

impl<T: Send> Ring<T> {
    /// Create a ring of capacity rounded up to the next power of 2.
    pub fn new(capacity: usize) -> Self {
        let cap = capacity.next_power_of_two();
        let mut buf = Vec::with_capacity(cap);
        for _ in 0..cap {
            buf.push(None);
        }
        Self {
            buf,
            mask: cap - 1,
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
        }
    }

    /// Try to push an item. Returns `Err(item)` if the ring is full.
    pub fn push(&self, item: T) -> Result<(), T> {
        let head = self.head.load(Ordering::Relaxed);
        let next_head = head.wrapping_add(1);
        if next_head & self.mask == self.tail.load(Ordering::Acquire) & self.mask
            && next_head != self.tail.load(Ordering::Acquire)
        {
            // Full — but check more carefully
            if (head.wrapping_sub(self.tail.load(Ordering::Acquire))) >= self.mask {
                return Err(item);
            }
        }
        // Safety: single producer — only we write to buf[head & mask]
        let slot = unsafe { &mut *(self.buf.as_ptr().add(head & self.mask) as *mut Option<T>) };
        *slot = Some(item);
        self.head.store(next_head, Ordering::Release);
        Ok(())
    }

    /// Try to pop an item. Returns `None` if the ring is empty.
    pub fn pop(&self) -> Option<T> {
        let tail = self.tail.load(Ordering::Relaxed);
        if tail == self.head.load(Ordering::Acquire) {
            return None; // empty
        }
        let slot = unsafe { &mut *(self.buf.as_ptr().add(tail & self.mask) as *mut Option<T>) };
        let item = slot.take();
        self.tail.store(tail.wrapping_add(1), Ordering::Release);
        item
    }

    /// Returns the number of items currently in the ring.
    pub fn len(&self) -> usize {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Relaxed);
        head.wrapping_sub(tail) & (self.mask * 2 + 1)
    }

    pub fn is_empty(&self) -> bool {
        self.head.load(Ordering::Relaxed) == self.tail.load(Ordering::Relaxed)
    }

    pub fn capacity(&self) -> usize {
        self.mask + 1
    }
}

unsafe impl<T: Send> Sync for Ring<T> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_pop() {
        let ring: Ring<u32> = Ring::new(8);
        assert!(ring.push(1).is_ok());
        assert!(ring.push(2).is_ok());
        assert_eq!(ring.pop(), Some(1));
        assert_eq!(ring.pop(), Some(2));
        assert_eq!(ring.pop(), None);
    }

    #[test]
    fn capacity_power_of_two() {
        let ring: Ring<u8> = Ring::new(5);
        assert_eq!(ring.capacity(), 8);
    }
}
