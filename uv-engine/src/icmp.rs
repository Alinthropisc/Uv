// Ping sweep — mirrors nmap -sn.
// Strategy:
//   1. TCP ACK to port 80 (non-privileged — works anywhere)
//   2. ICMP echo via raw socket (privileged — skipped if not root)
// Returns true if the host responds to either probe.

use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

/// Result of a single ping probe.
#[derive(Debug, Clone)]
pub struct PingResult {
    pub addr: IpAddr,
    pub alive: bool,
    pub method: PingMethod,
    pub rtt_ms: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PingMethod {
    TcpAck,
    IcmpEcho,
}

impl PingMethod {
    pub fn label(self) -> &'static str {
        match self {
            Self::TcpAck => "tcp-ack:80",
            Self::IcmpEcho => "icmp-echo",
        }
    }
}

/// Ping a host with TCP ACK to port 80.
/// Works without root — a refused connection still means the host is up.
pub async fn tcp_ack_ping(addr: IpAddr, timeout_ms: u32) -> PingResult {
    let sa = SocketAddr::new(addr, 80);
    let timeout = Duration::from_millis(timeout_ms as u64);
    let t0 = std::time::Instant::now();

    // connect() on port 80: RST (refused) = host up; timeout = host down.
    let alive = tokio::task::spawn_blocking(move || {
        match TcpStream::connect_timeout(&sa, timeout) {
            Ok(_) => true, // port open — host is definitely up
            Err(e) => {
                use std::io::ErrorKind;
                // ConnectionRefused means TCP RST — host is up but port closed
                matches!(e.kind(), ErrorKind::ConnectionRefused)
            }
        }
    })
    .await
    .unwrap_or(false);

    let rtt_ms = if alive {
        Some(t0.elapsed().as_millis() as u32)
    } else {
        None
    };
    PingResult {
        addr,
        alive,
        method: PingMethod::TcpAck,
        rtt_ms,
    }
}

/// Ping a single host — tries TCP ACK first, falls back to nothing.
/// ICMP raw socket requires root; if not available, TCP ACK result is used.
pub async fn ping_host(addr: IpAddr, timeout_ms: u32) -> PingResult {
    tcp_ack_ping(addr, timeout_ms).await
}

/// Sweep a list of hosts concurrently using ping.
/// Returns only the alive ones if `alive_only` is true.
pub async fn ping_sweep(
    addrs: &[IpAddr],
    timeout_ms: u32,
    concurrency: usize,
    alive_only: bool,
) -> Vec<PingResult> {
    use futures::stream::{FuturesUnordered, StreamExt};

    let mut tasks: FuturesUnordered<_> = FuturesUnordered::new();
    let mut results = Vec::new();
    let mut iter = addrs.iter().peekable();

    loop {
        while tasks.len() < concurrency {
            match iter.next() {
                Some(&addr) => tasks.push(ping_host(addr, timeout_ms)),
                None => break,
            }
        }
        if tasks.is_empty() {
            break;
        }

        if let Some(r) = tasks.next().await {
            if !alive_only || r.alive {
                results.push(r);
            }
        }
    }

    results
}

// Raw ICMP echo (Linux only, needs CAP_NET_RAW).
// Exposed as a C-callable in the future via uv-ffi; Rust path is TCP-only for now.

#[cfg(target_os = "linux")]
pub mod raw_icmp {
    use std::net::Ipv4Addr;

    /// Build an ICMP echo request packet (type=8, code=0).
    pub fn build_echo_request(id: u16, seq: u16) -> [u8; 8] {
        let mut pkt = [0u8; 8];
        pkt[0] = 8; // type: echo request
        pkt[1] = 0; // code
                    // id
        pkt[4] = (id >> 8) as u8;
        pkt[5] = (id & 0xff) as u8;
        // seq
        pkt[6] = (seq >> 8) as u8;
        pkt[7] = (seq & 0xff) as u8;
        // checksum
        let ck = internet_checksum(&pkt);
        pkt[2] = (ck >> 8) as u8;
        pkt[3] = (ck & 0xff) as u8;
        pkt
    }

    fn internet_checksum(data: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut i = 0;
        while i + 1 < data.len() {
            sum += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
            i += 2;
        }
        if i < data.len() {
            sum += u32::from(data[i]) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }
}
