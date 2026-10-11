// Live progress reporter — masscan main-status.c style.
// Prints rate/s, percent done, ETA to stderr at a fixed interval.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::time::interval;
use tracing::info;

pub struct ScanStatus {
    total: u64,
    done: Arc<AtomicU64>,
    start: Instant,
}

impl ScanStatus {
    pub fn new(total: u64) -> (Self, Arc<AtomicU64>) {
        let done = Arc::new(AtomicU64::new(0));
        let status = Self {
            total,
            done: Arc::clone(&done),
            start: Instant::now(),
        };
        (status, done)
    }

    /// Spawn a background task that prints progress every `interval_secs` seconds.
    /// Returns a handle; dropping or aborting it stops reporting.
    pub fn spawn(self, interval_secs: u64) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut tick = interval(Duration::from_secs(interval_secs));
            tick.tick().await; // skip immediate first tick
            loop {
                tick.tick().await;
                let done = self.done.load(Ordering::Relaxed);
                let elapsed = self.start.elapsed().as_secs_f64();
                let rate = if elapsed > 0.0 {
                    done as f64 / elapsed
                } else {
                    0.0
                };
                let pct = if self.total > 0 {
                    done as f64 / self.total as f64 * 100.0
                } else {
                    0.0
                };
                let remaining = self.total.saturating_sub(done);
                let eta_secs = if rate > 0.0 {
                    (remaining as f64 / rate) as u64
                } else {
                    0
                };
                let eta_str = fmt_eta(eta_secs);

                // Print to stderr (same as masscan --status)
                eprint!(
                    "\r\x1b[KRate: {:.0} p/s  Done: {}/{} ({:.1}%)  ETA: {}",
                    rate, done, self.total, pct, eta_str
                );

                info!(
                    rate = rate as u64,
                    done,
                    total = self.total,
                    pct = format!("{:.1}", pct),
                    eta = eta_str,
                    "scan progress"
                );

                if done >= self.total {
                    eprintln!(); // newline after scan done
                    break;
                }
            }
        })
    }
}

fn fmt_eta(secs: u64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m{}s", secs / 60, secs % 60)
    } else {
        format!("{}h{}m", secs / 3600, (secs % 3600) / 60)
    }
}
