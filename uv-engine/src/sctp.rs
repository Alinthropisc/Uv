// SCTP scanner — mirrors nmap -sY (INIT) and -sZ (COOKIE-ECHO).
// Uses raw sockets (AF_INET/SOCK_RAW/IPPROTO_SCTP) — requires root.
//
// INIT scan logic:
//   Send SCTP INIT chunk → INIT-ACK = open, ABORT = closed, no reply = filtered.
// COOKIE-ECHO scan:
//   Send SCTP COOKIE-ECHO with zeroed cookie → ABORT indicates open (port exists,
//   server rejects bad cookie), silence = filtered, ICMP unreachable = closed.
//
// Both modes never complete the 4-way SCTP handshake — stealthy.

use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;
use tracing::debug;
use uv_core::error::{UvError, UvResult};
use uv_core::traits::Scanner;
use uv_core::types::port::{Port, PortState};
use uv_core::types::protocol::Protocol;
use uv_core::types::result::ProbeResult;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SctpMode {
    Init,
    CookieEcho,
}

pub struct SctpScanner {
    mode: SctpMode,
    timeout_ms: u32,
}

impl SctpScanner {
    pub fn new(mode: SctpMode, timeout_ms: u32) -> Self {
        Self { mode, timeout_ms }
    }

    pub fn init(timeout_ms: u32) -> Self {
        Self::new(SctpMode::Init, timeout_ms)
    }

    pub fn cookie_echo(timeout_ms: u32) -> Self {
        Self::new(SctpMode::CookieEcho, timeout_ms)
    }
}

#[async_trait]
impl Scanner for SctpScanner {
    fn protocol(&self) -> Protocol {
        Protocol::Sctp
    }

    async fn scan(&self, target: IpAddr, ports: &[Port]) -> UvResult<Vec<ProbeResult>> {
        // Raw SCTP requires AF_INET/SOCK_RAW — must run as root.
        // We probe each port sequentially (SCTP is not a TCP-connect workaround).
        if !is_root() {
            return Err(UvError::Permission(
                "SCTP scan requires root (raw socket)".into(),
            ));
        }

        let mut results = Vec::with_capacity(ports.len());
        let timeout = Duration::from_millis(self.timeout_ms as u64);

        for &port in ports {
            let state = match self.mode {
                SctpMode::Init => probe_sctp_init(target, port, timeout).await,
                SctpMode::CookieEcho => probe_sctp_cookie_echo(target, port, timeout).await,
            };
            results.push(ProbeResult {
                port,
                state,
                proto: Protocol::Sctp,
                rtt: None,
                ttl: None,
                service: None,
            });
        }

        Ok(results)
    }
}

/// Send an SCTP INIT chunk and classify the response.
async fn probe_sctp_init(target: IpAddr, port: Port, timeout: Duration) -> PortState {
    // We build a minimal raw SCTP INIT packet.
    // SCTP common header (12 bytes) + INIT chunk (20 bytes minimum).
    let src_port: u16 = ephemeral_port();
    let dst_port: u16 = port.0;
    let vtag: u32 = 0; // verification tag = 0 for INIT
    let checksum: u32 = 0; // will compute CRC32c below

    let mut pkt = [0u8; 32];
    // Common header
    pkt[0..2].copy_from_slice(&src_port.to_be_bytes());
    pkt[2..4].copy_from_slice(&dst_port.to_be_bytes());
    pkt[4..8].copy_from_slice(&vtag.to_be_bytes());
    pkt[8..12].copy_from_slice(&checksum.to_be_bytes()); // placeholder

    // INIT chunk header: type=1, flags=0, length=20
    pkt[12] = 1; // chunk type: INIT
    pkt[13] = 0; // flags
    pkt[14..16].copy_from_slice(&20u16.to_be_bytes()); // length
                                                       // Initiate tag (random)
    pkt[16..20].copy_from_slice(&0xdeadbeef_u32.to_be_bytes());
    // Advertised receiver window (64K)
    pkt[20..24].copy_from_slice(&65535u32.to_be_bytes());
    // Outbound streams
    pkt[24..26].copy_from_slice(&1u16.to_be_bytes());
    // Inbound streams
    pkt[26..28].copy_from_slice(&1u16.to_be_bytes());
    // Initial TSN
    pkt[28..32].copy_from_slice(&1u32.to_be_bytes());

    // Compute CRC32c and patch
    let crc = crc32c(&pkt);
    pkt[8..12].copy_from_slice(&crc.to_be_bytes());

    // Raw socket send + timed receive — done in blocking thread to avoid async raw-socket complexity.
    let result =
        tokio::task::spawn_blocking(move || send_raw_sctp_and_recv(&pkt, target, timeout)).await;

    match result {
        Ok(Ok(response)) => classify_sctp_response(&response),
        Ok(Err(e)) => {
            debug!(%target, port = dst_port, err = %e, "SCTP INIT probe error");
            PortState::Filtered
        }
        Err(_) => PortState::Filtered,
    }
}

/// Send SCTP COOKIE-ECHO (zeroed cookie) — ABORT back means port exists (open).
async fn probe_sctp_cookie_echo(target: IpAddr, port: Port, timeout: Duration) -> PortState {
    let src_port: u16 = ephemeral_port();
    let dst_port: u16 = port.0;

    // SCTP common header + COOKIE-ECHO chunk (type=10) with 8-byte zeroed cookie
    let mut pkt = [0u8; 24];
    pkt[0..2].copy_from_slice(&src_port.to_be_bytes());
    pkt[2..4].copy_from_slice(&dst_port.to_be_bytes());
    // vtag = 0 (unknown at this point)
    pkt[12] = 10; // COOKIE-ECHO
    pkt[13] = 0;
    pkt[14..16].copy_from_slice(&12u16.to_be_bytes()); // 4 header + 8 cookie
                                                       // 8 zeroed cookie bytes at pkt[16..24]

    let crc = crc32c(&pkt);
    pkt[8..12].copy_from_slice(&crc.to_be_bytes());

    let result =
        tokio::task::spawn_blocking(move || send_raw_sctp_and_recv(&pkt, target, timeout)).await;

    match result {
        Ok(Ok(response)) => {
            // ABORT in response to COOKIE-ECHO means port is open (server exists but rejects bad cookie)
            if response.len() >= 13 && response[12] == 6 {
                PortState::Open
            } else {
                PortState::Filtered
            }
        }
        Ok(Err(_)) => PortState::Filtered,
        Err(_) => PortState::Filtered,
    }
}

/// Minimal CRC-32c (Castagnoli) for SCTP checksum.
fn crc32c(data: &[u8]) -> u32 {
    const POLY: u32 = 0x82F63B78;
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ POLY;
            } else {
                crc >>= 1;
            }
        }
    }
    crc ^ 0xFFFF_FFFF
}

fn ephemeral_port() -> u16 {
    // Pick a random-ish source port in ephemeral range.
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    32768 + (t % 28232) as u16
}

fn classify_sctp_response(pkt: &[u8]) -> PortState {
    // SCTP common header is 12 bytes, chunk type at byte 12.
    if pkt.len() < 13 {
        return PortState::Filtered;
    }
    match pkt[12] {
        1 => PortState::Open,   // INIT-ACK — port open
        6 => PortState::Closed, // ABORT — port closed
        _ => PortState::Filtered,
    }
}

/// Send raw SCTP packet and wait for a reply (blocking, for spawn_blocking).
/// Returns the IP payload of the received SCTP packet.
fn send_raw_sctp_and_recv(
    pkt: &[u8],
    target: IpAddr,
    timeout: Duration,
) -> Result<Vec<u8>, std::io::Error> {
    // AF_INET raw socket with IPPROTO_SCTP (132)
    let sock = unsafe {
        let fd = libc_socket(libc_af(target), libc::SOCK_RAW, 132);
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        fd
    };

    // Set receive timeout
    let tv = libc::timeval {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_usec: timeout.subsec_micros() as libc::suseconds_t,
    };
    unsafe {
        libc::setsockopt(
            sock,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }

    // Send
    let dst = sockaddr_for(target, pkt[2] as u16 | ((pkt[3] as u16) << 8));
    let sent = unsafe {
        libc::sendto(
            sock,
            pkt.as_ptr() as *const libc::c_void,
            pkt.len(),
            0,
            &dst as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if sent < 0 {
        unsafe { libc::close(sock) };
        return Err(std::io::Error::last_os_error());
    }

    // Recv
    let mut buf = vec![0u8; 1500];
    let n = unsafe { libc::recv(sock, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
    unsafe { libc::close(sock) };

    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    buf.truncate(n as usize);
    // Skip IP header (first byte & 0xf gives IHL in 32-bit words)
    let ihl = if buf.is_empty() {
        5
    } else {
        (buf[0] & 0x0f) as usize * 4
    };
    if buf.len() > ihl {
        Ok(buf[ihl..].to_vec())
    } else {
        Ok(buf)
    }
}

unsafe fn libc_socket(af: libc::c_int, kind: libc::c_int, proto: libc::c_int) -> libc::c_int {
    libc::socket(af, kind, proto)
}

fn libc_af(ip: IpAddr) -> libc::c_int {
    match ip {
        IpAddr::V4(_) => libc::AF_INET,
        IpAddr::V6(_) => libc::AF_INET6,
    }
}

fn sockaddr_for(ip: IpAddr, _port: u16) -> libc::sockaddr_in {
    let addr = match ip {
        IpAddr::V4(v4) => u32::from(v4).to_be(),
        IpAddr::V6(_) => 0, // IPv6 handled separately; simplified here
    };
    libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr { s_addr: addr },
        sin_zero: [0; 8],
    }
}

fn is_root() -> bool {
    unsafe { libc::getuid() == 0 }
}
