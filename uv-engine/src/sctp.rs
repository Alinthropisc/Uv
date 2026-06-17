// SCTP scanner — mirrors nmap -sY (INIT) and -sZ (COOKIE-ECHO).
// Uses raw sockets (AF_INET/SOCK_RAW/IPPROTO_SCTP) — requires root.

use std::net::IpAddr;
#[cfg(unix)]
use std::time::Duration;

use async_trait::async_trait;
#[cfg(unix)]
use tracing::debug;
use uv_core::error::{UvError, UvResult};
use uv_core::traits::Scanner;
#[cfg(unix)]
use uv_core::types::port::PortState;
use uv_core::types::port::Port;
use uv_core::types::protocol::Protocol;
use uv_core::types::result::ProbeResult;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SctpMode {
    Init,
    CookieEcho,
}

#[allow(dead_code)]
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
        #[cfg(not(unix))]
        {
            let _ = (target, ports);
            return Err(UvError::Unsupported(
                "SCTP scan requires Unix (raw sockets)".into(),
            ));
        }

        #[cfg(unix)]
        {
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
}

#[cfg(unix)]
async fn probe_sctp_init(target: IpAddr, port: Port, timeout: Duration) -> PortState {
    let src_port: u16 = ephemeral_port();
    let dst_port: u16 = port.0;
    let vtag: u32 = 0;
    let checksum: u32 = 0;

    let mut pkt = [0u8; 32];
    pkt[0..2].copy_from_slice(&src_port.to_be_bytes());
    pkt[2..4].copy_from_slice(&dst_port.to_be_bytes());
    pkt[4..8].copy_from_slice(&vtag.to_be_bytes());
    pkt[8..12].copy_from_slice(&checksum.to_be_bytes());
    pkt[12] = 1;
    pkt[13] = 0;
    pkt[14..16].copy_from_slice(&20u16.to_be_bytes());
    pkt[16..20].copy_from_slice(&0xdeadbeef_u32.to_be_bytes());
    pkt[20..24].copy_from_slice(&65535u32.to_be_bytes());
    pkt[24..26].copy_from_slice(&1u16.to_be_bytes());
    pkt[26..28].copy_from_slice(&1u16.to_be_bytes());
    pkt[28..32].copy_from_slice(&1u32.to_be_bytes());

    let crc = crc32c(&pkt);
    pkt[8..12].copy_from_slice(&crc.to_be_bytes());

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

#[cfg(unix)]
async fn probe_sctp_cookie_echo(target: IpAddr, port: Port, timeout: Duration) -> PortState {
    let src_port: u16 = ephemeral_port();
    let dst_port: u16 = port.0;

    let mut pkt = [0u8; 24];
    pkt[0..2].copy_from_slice(&src_port.to_be_bytes());
    pkt[2..4].copy_from_slice(&dst_port.to_be_bytes());
    pkt[12] = 10;
    pkt[13] = 0;
    pkt[14..16].copy_from_slice(&12u16.to_be_bytes());

    let crc = crc32c(&pkt);
    pkt[8..12].copy_from_slice(&crc.to_be_bytes());

    let result =
        tokio::task::spawn_blocking(move || send_raw_sctp_and_recv(&pkt, target, timeout)).await;

    match result {
        Ok(Ok(response)) => {
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

#[cfg(unix)]
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

#[cfg(unix)]
fn ephemeral_port() -> u16 {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    32768 + (t % 28232) as u16
}

#[cfg(unix)]
fn classify_sctp_response(pkt: &[u8]) -> PortState {
    if pkt.len() < 13 {
        return PortState::Filtered;
    }
    match pkt[12] {
        1 => PortState::Open,
        6 => PortState::Closed,
        _ => PortState::Filtered,
    }
}

#[cfg(unix)]
fn send_raw_sctp_and_recv(
    pkt: &[u8],
    target: IpAddr,
    timeout: Duration,
) -> Result<Vec<u8>, std::io::Error> {
    let sock = unsafe {
        let fd = libc_socket(libc_af(target), libc::SOCK_RAW, 132);
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        fd
    };

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

    let mut buf = vec![0u8; 1500];
    let n = unsafe { libc::recv(sock, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
    unsafe { libc::close(sock) };

    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    buf.truncate(n as usize);
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

#[cfg(unix)]
unsafe fn libc_socket(af: libc::c_int, kind: libc::c_int, proto: libc::c_int) -> libc::c_int {
    libc::socket(af, kind, proto)
}

#[cfg(unix)]
fn libc_af(ip: IpAddr) -> libc::c_int {
    match ip {
        IpAddr::V4(_) => libc::AF_INET,
        IpAddr::V6(_) => libc::AF_INET6,
    }
}

#[cfg(unix)]
fn sockaddr_for(ip: IpAddr, _port: u16) -> libc::sockaddr_in {
    let addr = match ip {
        IpAddr::V4(v4) => u32::from(v4).to_be(),
        IpAddr::V6(_) => 0,
    };
    let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    sa.sin_family = libc::AF_INET as libc::sa_family_t;
    sa.sin_port = 0;
    sa.sin_addr = libc::in_addr { s_addr: addr };
    sa
}

#[cfg(unix)]
fn is_root() -> bool {
    unsafe { libc::getuid() == 0 }
}

#[cfg(not(unix))]
fn is_root() -> bool {
    false
}
