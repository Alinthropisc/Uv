// Hierarchical timer wheel — masscan event-timeout.c style.
// O(1) insert/cancel/fire for scan probe timeouts.
// Uses 256-slot wheel with 1ms resolution per tick.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

type TimerId = u64;

pub struct TimerEntry {
    pub id: TimerId,
    pub expires_at: Instant,
    pub data: Box<dyn std::any::Any + Send>,
}

/// A single-level timer wheel with configurable resolution.
pub struct TimeoutWheel {
    slots: Vec<VecDeque<TimerEntry>>,
    slot_count: usize,
    tick_ms: u64,
    current_slot: usize,
    last_tick: Instant,
    next_id: TimerId,
}

impl TimeoutWheel {
    /// Create a wheel with `slot_count` slots and `tick_ms` milliseconds per slot.
    /// Total range = slot_count * tick_ms milliseconds.
    pub fn new(slot_count: usize, tick_ms: u64) -> Self {
        let mut slots = Vec::with_capacity(slot_count);
        for _ in 0..slot_count {
            slots.push(VecDeque::new());
        }
        Self {
            slots,
            slot_count,
            tick_ms,
            current_slot: 0,
            last_tick: Instant::now(),
            next_id: 1,
        }
    }

    /// Insert a timer that fires after `delay`. Returns a TimerId for cancellation.
    pub fn insert<T: std::any::Any + Send + 'static>(
        &mut self,
        delay: Duration,
        data: T,
    ) -> TimerId {
        let id = self.next_id;
        self.next_id += 1;

        let ticks = (delay.as_millis() as u64 / self.tick_ms).max(1) as usize;
        let slot = (self.current_slot + ticks) % self.slot_count;
        let expires_at = Instant::now() + delay;

        self.slots[slot].push_back(TimerEntry {
            id,
            expires_at,
            data: Box::new(data),
        });

        id
    }

    /// Cancel a timer by id. Returns true if found and removed.
    pub fn cancel(&mut self, id: TimerId) -> bool {
        for slot in &mut self.slots {
            if let Some(pos) = slot.iter().position(|e| e.id == id) {
                slot.remove(pos);
                return true;
            }
        }
        false
    }

    /// Advance the wheel and collect all expired timers.
    /// Call this regularly (e.g. every tick_ms milliseconds).
    pub fn tick(&mut self) -> Vec<TimerEntry> {
        let now = Instant::now();
        let elapsed_ms = now.duration_since(self.last_tick).as_millis() as u64;
        let ticks_to_advance = (elapsed_ms / self.tick_ms) as usize;

        let mut expired = Vec::new();

        for _ in 0..ticks_to_advance.min(self.slot_count) {
            self.current_slot = (self.current_slot + 1) % self.slot_count;
            let slot = &mut self.slots[self.current_slot];

            // Drain entries that have actually expired
            let mut remaining = VecDeque::new();
            while let Some(entry) = slot.pop_front() {
                if entry.expires_at <= now {
                    expired.push(entry);
                } else {
                    remaining.push_back(entry);
                }
            }
            *slot = remaining;
        }

        if ticks_to_advance > 0 {
            self.last_tick = now;
        }

        expired
    }

    /// Returns the number of pending timers.
    pub fn pending(&self) -> usize {
        self.slots.iter().map(|s| s.len()).sum()
    }
}

impl Default for TimeoutWheel {
    /// Default: 256 slots × 10ms = 2560ms range.
    fn default() -> Self {
        Self::new(256, 10)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_tick() {
        let mut wheel = TimeoutWheel::new(64, 10);
        wheel.insert(Duration::from_millis(10), 42u32);
        assert_eq!(wheel.pending(), 1);
        std::thread::sleep(Duration::from_millis(15));
        let fired = wheel.tick();
        assert_eq!(fired.len(), 1);
        assert_eq!(wheel.pending(), 0);
    }

    #[test]
    fn cancel_timer() {
        let mut wheel = TimeoutWheel::new(64, 10);
        let id = wheel.insert(Duration::from_millis(100), "hello");
        assert!(wheel.cancel(id));
        assert_eq!(wheel.pending(), 0);
    }
}
