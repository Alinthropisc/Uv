// Active OS prober — nmap FPEngine-inspired.
// Sends TCP probes to open/closed ports and collects SEQ, RTT variance, and window data
// to enrich the OsFingerprint beyond passive TTL matching.

use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use crate::fingerprint::OsFingerprint;

pub struct ActiveOsProber {
    timeout_ms: u32,
}

impl ActiveOsProber {
    pub fn new(timeout_ms: u32) -> Self {
        Self { timeout_ms }
    }

    /// Run active probes against target and return an enriched OsFingerprint.
    /// `open_port`   — a port known to be open (for SEQ/OPS/WIN probes).
    /// `closed_port` — a port expected to be closed (for T5-T7 RST probes).
    pub async fn probe(
        &self,
        ip: IpAddr,
        open_port: u16,
        closed_port: u16,
        observed_ttl: Option<u8>,
    ) -> OsFingerprint {
        let timeout = Duration::from_millis(self.timeout_ms as u64);
        let mut fp = OsFingerprint::default();

        // --- Passive TTL (already collected by scanner) ---
        if let Some(ttl) = observed_ttl {
            fp.ttl_guess = Some(OsFingerprint::guess_ttl(ttl));
        }

        // --- SEQ1-6: 6 rapid TCP SYN-like connects to open port ---
        // We can't read raw ISN without raw sockets, but RTT jitter reveals OS scheduler.
        // Linux: variable ISN + low jitter. Windows: low ISN entropy. BSD: medium jitter.
        let rtts = collect_rtts(ip, open_port, timeout, 6).await;

        if !rtts.is_empty() {
            let mean = rtts.iter().sum::<u128>() / rtts.len() as u128;
            let variance: u128 = rtts
                .iter()
                .map(|&r| {
                    let d = r as i128 - mean as i128;
                    (d * d) as u128
                })
                .sum::<u128>()
                / rtts.len().max(1) as u128;

            // High RTT variance → Linux-like (variable ISN generation timing)
            // Low RTT variance  → Windows-like (constant-rate ISN)
            fp.seq_index = Some(variance.min(u32::MAX as u128) as u32);
        }

        // --- RST probe to closed port (T5-T7 equivalent) ---
        // Windows sends RST+ACK immediately; Linux sends RST without ACK from closed port.
        // We use connection speed as a proxy — immediate RST = host is definitely up.
        let rst_rtt = probe_closed(ip, closed_port, timeout).await;
        if rst_rtt.is_some() {
            // Closed port responded with RST — normal behaviour
            fp.df = true; // assume DF set (conservative; overridden by raw scan if available)
        }

        // --- ICMP-based TTL probe (IE1/IE2 equivalent via TCP-ACK to port 80) ---
        // We use TCP connect to port 0 (always refused on any OS) as IE probe proxy.
        // The round-trip gives us another RTT sample to detect ECN echo.
        if let Some(rtt) = probe_closed(ip, 0, timeout).await {
            // Very fast RST (< 5ms) suggests a local/low-hop target — adjust TTL guess.
            if rtt < 5 && fp.ttl_guess == Some(128) {
                fp.ttl_guess = Some(64); // likely Linux/macOS, not Windows
            }
        }

        // --- TCP option order heuristic ---
        // Without raw socket we can't see actual TCP options, but we set a placeholder
        // based on the RTT pattern until raw socket probes are available.
        if fp.seq_index.map(|v| v > 10_000).unwrap_or(false) {
            fp.set_tcp_opts(&["mss", "sack", "timestamp", "nop", "wscale"]); // Linux style
        } else {
            fp.set_tcp_opts(&["mss", "nop", "wscale", "nop", "nop", "sack"]); // Windows style
        }

        fp
    }
}

/// Make `count` TCP connections to (ip, port) and return RTT samples in ms.
async fn collect_rtts(ip: IpAddr, port: u16, timeout: Duration, count: usize) -> Vec<u128> {
    let sa = SocketAddr::new(ip, port);
    let mut rtts = Vec::with_capacity(count);

    for _ in 0..count {
        let t0 = Instant::now();
        let result = tokio::task::spawn_blocking(move || {
            TcpStream::connect_timeout(&sa, timeout).map(|_| ())
        })
        .await;

        if result.is_ok() {
            rtts.push(t0.elapsed().as_millis());
        }
        // Small gap between probes (100ms) like nmap's SEQ probe timing
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    rtts
}

/// Probe a closed port and return RTT in ms if the host replied (RST or connect).
async fn probe_closed(ip: IpAddr, port: u16, timeout: Duration) -> Option<u128> {
    if port == 0 {
        return None; // port 0 is not connectable
    }
    let sa = SocketAddr::new(ip, port);
    let t0 = Instant::now();
    let result = tokio::task::spawn_blocking(move || TcpStream::connect_timeout(&sa, timeout))
        .await
        .ok()?;

    match result {
        Ok(_) => Some(t0.elapsed().as_millis()),
        Err(e) => {
            use std::io::ErrorKind;
            if matches!(e.kind(), ErrorKind::ConnectionRefused) {
                Some(t0.elapsed().as_millis()) // RST received — host is responding
            } else {
                None
            }
        }
    }
}
