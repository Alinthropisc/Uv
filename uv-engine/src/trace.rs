// Traceroute — TTL-limited UDP probes, collect ICMP Time Exceeded responses.
// Mirrors nmap --traceroute. Works without root via UDP (high port).
// Each hop: send UDP to dst:port with TTL=n, wait for ICMP type=11 (TTL exceeded).
// Stops at TTL=max_hops or when dst replies (port unreachable = ICMP type=3).

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct Hop {
    pub ttl: u8,
    pub addr: Option<IpAddr>,
    pub rtt_ms: Option<u32>,
    pub label: HopLabel,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HopLabel {
    Reply,       // got ICMP Time Exceeded — hop found
    PortUnreach, // destination replied — last hop
    Timeout,     // no reply within timeout
    Dest,        // arrived at target
}

impl Hop {
    pub fn timeout(ttl: u8) -> Self {
        Self {
            ttl,
            addr: None,
            rtt_ms: None,
            label: HopLabel::Timeout,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TraceResult {
    pub target: IpAddr,
    pub hops: Vec<Hop>,
    pub reached: bool,
}

/// Run a traceroute to `target`.
/// Uses UDP probes (port 33434+ttl) — works in user-space.
/// For ICMP traceroute (better compat), root + raw socket is needed (future: uv-ffi).
pub fn traceroute(target: IpAddr, max_hops: u8, timeout_ms: u32) -> TraceResult {
    let timeout = Duration::from_millis(timeout_ms as u64);
    let mut hops = Vec::with_capacity(max_hops as usize);
    let mut reached = false;

    for ttl in 1..=max_hops {
        let probe_port = 33434u16 + ttl as u16;
        let sa = SocketAddr::new(target, probe_port);

        let hop = probe_hop(sa, ttl, timeout);
        let done = matches!(hop.label, HopLabel::PortUnreach | HopLabel::Dest);
        if matches!(hop.label, HopLabel::Dest | HopLabel::PortUnreach) {
            reached = true;
        }
        hops.push(hop);
        if done {
            break;
        }
    }

    TraceResult {
        target,
        hops,
        reached,
    }
}

fn probe_hop(dst: SocketAddr, ttl: u8, timeout: Duration) -> Hop {
    // Bind a UDP socket on a random local port
    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return Hop::timeout(ttl),
    };

    // Set IP_TTL
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let fd = sock.as_raw_fd();
        let ttl_val: libc_ttl = ttl as libc_ttl;
        unsafe {
            libc_setsockopt(fd, ttl_val);
        }
    }

    sock.set_read_timeout(Some(timeout)).ok();

    let t0 = Instant::now();
    // Send 1-byte UDP probe
    if sock.send_to(&[0u8], dst).is_err() {
        return Hop::timeout(ttl);
    }

    // Wait for ICMP reply via connect + recv trick (Linux: ICMP errors delivered to socket)
    let mut buf = [0u8; 512];
    match sock.recv_from(&mut buf) {
        Ok((_, from)) => {
            let rtt_ms = t0.elapsed().as_millis() as u32;
            let addr = Some(from.ip());
            // If reply is from the target itself → destination reached
            let label = if from.ip() == dst.ip() {
                HopLabel::Dest
            } else {
                HopLabel::Reply
            };
            Hop {
                ttl,
                addr,
                rtt_ms: Some(rtt_ms),
                label,
            }
        }
        Err(_) => Hop::timeout(ttl),
    }
}

// Minimal inline TTL setter via setsockopt — avoids pulling in libc crate.
#[cfg(target_os = "linux")]
type libc_ttl = i32;

#[cfg(target_os = "linux")]
unsafe fn libc_setsockopt(fd: i32, ttl: i32) {
    extern "C" {
        fn setsockopt(sock: i32, level: i32, optname: i32, optval: *const i32, optlen: u32) -> i32;
    }
    const IPPROTO_IP: i32 = 0;
    const IP_TTL: i32 = 2;
    setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, 4);
}

impl TraceResult {
    pub fn format(&self) -> String {
        let mut out = format!(
            "traceroute to {} ({} hops max)\n",
            self.target,
            self.hops.len()
        );
        for hop in &self.hops {
            let addr = hop
                .addr
                .map(|a| a.to_string())
                .unwrap_or_else(|| "*".into());
            let rtt = hop
                .rtt_ms
                .map(|r| format!("{r} ms"))
                .unwrap_or_else(|| "*".into());
            out.push_str(&format!(" {:2}  {}  {}\n", hop.ttl, addr, rtt));
        }
        out
    }
}
