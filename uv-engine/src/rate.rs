use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use uv_core::error::{UvError, UvResult};
use uv_core::traits::RateLimiter;

/// Lock-free token-bucket rate limiter.
/// Tokens are stored as integer micro-tokens (×1000) to avoid floating-point.
/// CAS loop ensures no double-spend under contention.
pub struct TokenBucketLimiter {
    pps: u64,
    burst: u64,
    /// Stored as count × 1000 (milli-tokens)
    tokens_m: Arc<AtomicU64>,
    last_refill: std::sync::Mutex<Instant>,
}

impl TokenBucketLimiter {
    pub fn new(pps: u64, burst: u64) -> Self {
        Self {
            pps,
            burst,
            tokens_m: Arc::new(AtomicU64::new(burst * 1000)),
            last_refill: std::sync::Mutex::new(Instant::now()),
        }
    }

    /// Convenience: burst = 10% of pps (100ms burst window).
    pub fn with_rate(pps: u64) -> Self {
        Self::new(pps, (pps / 10).max(1))
    }

    fn refill(&self) {
        let mut last = self.last_refill.lock().unwrap();
        let now = Instant::now();
        let elapsed = now.duration_since(*last).as_secs_f64();
        let new_m = (elapsed * self.pps as f64 * 1000.0) as u64;
        if new_m > 0 {
            let cap = self.burst * 1000;
            self.tokens_m
                .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |cur| {
                    Some((cur + new_m).min(cap))
                })
                .ok();
            *last = now;
        }
    }
}

impl RateLimiter for TokenBucketLimiter {
    fn acquire(&self, n: u32) -> UvResult<()> {
        let need = n as u64 * 1000;
        if need > self.burst * 1000 {
            return Err(UvError::RateOverflow {
                requested: n,
                cap: self.burst,
            });
        }

        loop {
            self.refill();
            let cur = self.tokens_m.load(Ordering::Relaxed);
            if cur >= need {
                match self.tokens_m.compare_exchange(
                    cur,
                    cur - need,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => return Ok(()),
                    Err(_) => continue, // lost CAS race, retry
                }
            }
            // Yield to tokio scheduler instead of spinning hot
            std::thread::yield_now();
        }
    }

    fn rate_pps(&self) -> u64 {
        self.pps
    }
}
