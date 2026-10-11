// Adaptive rate throttler — masscan main-throttle.c style.
// Monitors packet loss signals and adjusts the scan rate dynamically.
// Strategy: if loss detected → halve rate; if clean for N seconds → slowly increase.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Adaptive throttle state — shared between scanner and monitor.
pub struct Throttle {
    /// Current rate in packets/sec.
    rate_pps: Arc<AtomicU64>,
    /// Packets sent counter (incremented by scanner).
    sent: Arc<AtomicU64>,
    /// Packets received/confirmed counter (incremented by receiver).
    recv: Arc<AtomicU64>,
    /// Maximum allowed rate.
    max_rate: u64,
    /// Minimum floor rate.
    min_rate: u64,
}

impl Throttle {
    pub fn new(initial_rate: u64, max_rate: u64, min_rate: u64) -> Self {
        Self {
            rate_pps: Arc::new(AtomicU64::new(initial_rate)),
            sent: Arc::new(AtomicU64::new(0)),
            recv: Arc::new(AtomicU64::new(0)),
            max_rate,
            min_rate,
        }
    }

    /// Current rate (read by rate limiter).
    pub fn current_rate(&self) -> u64 {
        self.rate_pps.load(Ordering::Relaxed)
    }

    /// Record a sent packet.
    pub fn on_sent(&self) {
        self.sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a received response.
    pub fn on_recv(&self) {
        self.recv.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns shared rate handle (for rate limiter to read).
    pub fn rate_handle(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.rate_pps)
    }

    /// Spawn a background task that adjusts rate every `interval`.
    /// Loss ratio = (sent - recv) / sent over the window.
    /// If loss > threshold → reduce rate; otherwise → slowly ramp up.
    pub fn spawn_monitor(self: Arc<Self>, interval: Duration) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut last_sent = 0u64;
            let mut last_recv = 0u64;
            let mut last_time = Instant::now();
            let mut consecutive_clean = 0u32;

            loop {
                tokio::time::sleep(interval).await;

                let now_sent = self.sent.load(Ordering::Relaxed);
                let now_recv = self.recv.load(Ordering::Relaxed);
                let elapsed = last_time.elapsed().as_secs_f64();

                let delta_sent = now_sent.saturating_sub(last_sent);
                let delta_recv = now_recv.saturating_sub(last_recv);

                if delta_sent > 100 {
                    let loss_ratio = if delta_sent > 0 {
                        1.0 - (delta_recv as f64 / delta_sent as f64)
                    } else {
                        0.0
                    };

                    let current = self.rate_pps.load(Ordering::Relaxed);

                    if loss_ratio > 0.05 {
                        // >5% loss — halve rate (AIMD: multiplicative decrease)
                        consecutive_clean = 0;
                        let new_rate = (current / 2).max(self.min_rate);
                        self.rate_pps.store(new_rate, Ordering::Relaxed);
                        tracing::warn!(
                            loss_pct = format!("{:.1}", loss_ratio * 100.0),
                            old_rate = current,
                            new_rate,
                            "throttle: reducing rate due to packet loss"
                        );
                    } else {
                        // No significant loss — slowly increase (AIMD: additive increase)
                        consecutive_clean += 1;
                        if consecutive_clean >= 3 {
                            // Increase by 10% every 3 clean windows
                            let new_rate = (current + current / 10).min(self.max_rate);
                            if new_rate > current {
                                self.rate_pps.store(new_rate, Ordering::Relaxed);
                                tracing::debug!(
                                    new_rate,
                                    "throttle: increasing rate (clean window)"
                                );
                            }
                            consecutive_clean = 0;
                        }
                    }
                }

                last_sent = now_sent;
                last_recv = now_recv;
                last_time = Instant::now();
                let _ = elapsed; // suppress unused warning
            }
        })
    }
}

impl Default for Throttle {
    fn default() -> Self {
        Self::new(1000, 1_000_000, 10)
    }
}
