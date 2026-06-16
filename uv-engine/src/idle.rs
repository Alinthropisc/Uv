// Idle scan (zombie scan) — nmap idle_scan.cc style.
// Uses a zombie host's IP ID sequence to infer open/closed ports on a target
// without sending any packets from the attacker's real IP.
//
// Algorithm:
//   1. Probe zombie → get IP ID (ipid1)
//   2. Spoof SYN to target as if from zombie (requires raw socket)
//   3. Probe zombie again → get IP ID (ipid2)
//   4. If ipid2 == ipid1 + 2 → target sent SYN-ACK to zombie (port OPEN)
//      If ipid2 == ipid1 + 1 → target sent RST to zombie (port CLOSED/FILTERED)

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use tracing::{debug, warn};
use uv_core::traits::Scanner;
use uv_core::types::port::{Port, PortState};
use uv_core::types::protocol::Protocol;
use uv_core::types::result::ProbeResult;
use uv_core::UvError;

pub struct IdleScanner {
    zombie: Ipv4Addr,
    zombie_port: u16,
    timeout_ms: u32,
}

impl IdleScanner {
    /// Create an idle scanner using `zombie` as the IP ID oracle.
    /// `zombie_port` is an open port on the zombie (to probe its IP ID counter).
    pub fn new(zombie: Ipv4Addr, zombie_port: u16, timeout_ms: u32) -> Self {
        Self {
            zombie,
            zombie_port,
            timeout_ms,
        }
    }
}

#[async_trait::async_trait]
impl Scanner for IdleScanner {
    async fn scan(&self, target: IpAddr, ports: &[Port]) -> Result<Vec<ProbeResult>, UvError> {
        let dst_ip = match target {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => return Err(UvError::Unsupported("Idle scan requires IPv4".into())),
        };

        let zombie = self.zombie;
        let zombie_port = self.zombie_port;
        let timeout_ms = self.timeout_ms;
        let ports_vec: Vec<Port> = ports.to_vec();

        tokio::task::spawn_blocking(move || {
            idle_scan_blocking(zombie, zombie_port, dst_ip, &ports_vec, timeout_ms)
        })
        .await
        .map_err(|e| {
            UvError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))
        })?
    }
}

fn idle_scan_blocking(
    zombie: Ipv4Addr,
    zombie_port: u16,
    target: Ipv4Addr,
    ports: &[Port],
    timeout_ms: u32,
) -> Result<Vec<ProbeResult>, UvError> {
    let timeout = Duration::from_millis(timeout_ms as u64);

    // Verify zombie has predictable (incremental) IP ID by sampling 3 times
    let id0 = probe_ipid(zombie, zombie_port, timeout)?;
    std::thread::sleep(Duration::from_millis(50));
    let id1 = probe_ipid(zombie, zombie_port, timeout)?;
    std::thread::sleep(Duration::from_millis(50));
    let id2 = probe_ipid(zombie, zombie_port, timeout)?;

    let delta01 = id1.wrapping_sub(id0);
    let delta12 = id2.wrapping_sub(id1);

    if delta01 > 3 || delta12 > 3 {
        warn!(%zombie, delta01, delta12, "zombie IP ID not predictable — idle scan unreliable");
    } else {
        debug!(%zombie, id0, id1, id2, "zombie IP ID is predictable");
    }

    let src_port = 45000u16;
    let mut results = Vec::with_capacity(ports.len());

    for &port in ports {
        // Step 1: get zombie IP ID baseline
        let ipid_before = probe_ipid(zombie, zombie_port, timeout)?;

        // Step 2: send spoofed SYN to target, appearing to come from zombie
        send_spoofed_syn(zombie, target, src_port, port.0)?;

        // Allow time for target to respond to zombie and zombie to reply
        std::thread::sleep(Duration::from_millis(100));

        // Step 3: probe zombie again
        let ipid_after = probe_ipid(zombie, zombie_port, timeout)?;

        let increment = ipid_after.wrapping_sub(ipid_before);

        // Step 4: classify
        let state = match increment {
            2 => PortState::Open,     // SYN-ACK from target → zombie replied RST → +2
            1 => PortState::Closed,   // RST from target → zombie silent → +1 (our probe only)
            _ => PortState::Filtered, // firewall dropped or flood
        };

        debug!(%target, port = port.0, ipid_before, ipid_after, increment, ?state, "idle scan result");

        let probe = match state {
            PortState::Open => ProbeResult::open(port, Protocol::Tcp, Duration::from_millis(100)),
            PortState::Closed => ProbeResult::closed(port, Protocol::Tcp),
            PortState::Filtered => ProbeResult::filtered(port, Protocol::Tcp),
        };
        results.push(probe);
    }

    Ok(results)
}

/// Send a TCP SYN to (target, dport) spoofed as coming from zombie:sport.
fn send_spoofed_syn(
    zombie: Ipv4Addr,
    target: Ipv4Addr,
    sport: u16,
    dport: u16,
) -> Result<(), UvError> {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW) };
    if sock < 0 {
        return Err(UvError::Io(std::io::Error::last_os_error()));
    }

    let one: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            sock,
            libc::IPPROTO_IP,
            libc::IP_HDRINCL,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }

    let pkt = build_spoofed_syn(zombie, target, sport, dport);
    let dst_addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: dport.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from(target).to_be(),
        },
        sin_zero: [0; 8],
    };

    unsafe {
        libc::sendto(
            sock,
            pkt.as_ptr() as *const libc::c_void,
            pkt.len(),
            0,
            &dst_addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        libc::close(sock);
    }
    Ok(())
}

/// Build a spoofed SYN packet: IP src = zombie, IP dst = target.
fn build_spoofed_syn(zombie: Ipv4Addr, target: Ipv4Addr, sport: u16, dport: u16) -> Vec<u8> {
    let mut pkt = vec![0u8; 40];
    pkt[0] = 0x45;
    pkt[3] = 40;
    pkt[6] = 0x40; // DF
    pkt[8] = 64; // TTL
    pkt[9] = 6; // TCP
    pkt[12..16].copy_from_slice(&zombie.octets()); // spoofed src
    pkt[16..20].copy_from_slice(&target.octets());
    pkt[20..22].copy_from_slice(&sport.to_be_bytes());
    pkt[22..24].copy_from_slice(&dport.to_be_bytes());
    pkt[24..28].copy_from_slice(&0xdeadbeefu32.to_be_bytes()); // seq
    pkt[32] = 0x50; // data offset
    pkt[33] = 0x02; // SYN
    pkt[34..36].copy_from_slice(&1024u16.to_be_bytes());
    let cksum = tcp_checksum(&zombie.octets(), &target.octets(), &pkt[20..]);
    pkt[36..38].copy_from_slice(&cksum.to_be_bytes());
    pkt
}

/// Probe zombie's IP ID by sending a SYN-ACK (elicits RST with IP ID) via TCP connect.
/// We use the IP ID from the RST packet the zombie sends back when we probe its open port.
fn probe_ipid(zombie: Ipv4Addr, zombie_port: u16, timeout: Duration) -> Result<u16, UvError> {
    // Open raw recv socket
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_TCP) };
    if sock < 0 {
        return Err(UvError::Io(std::io::Error::last_os_error()));
    }

    let tv = libc::timeval {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_usec: (timeout.subsec_millis() as libc::suseconds_t) * 1000,
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

    // Send SYN to zombie open port to elicit SYN-ACK (which contains IP ID)
    let probe_sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW) };
    let one: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            probe_sock,
            libc::IPPROTO_IP,
            libc::IP_HDRINCL,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }

    // Use local IP as source for our probe
    let local_ip = local_ip_for(zombie).unwrap_or(Ipv4Addr::UNSPECIFIED);
    let sport = 44444u16;
    let pkt = build_spoofed_syn(local_ip, zombie, sport, zombie_port);
    let dst_addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: zombie_port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from(zombie).to_be(),
        },
        sin_zero: [0; 8],
    };
    unsafe {
        libc::sendto(
            probe_sock,
            pkt.as_ptr() as *const libc::c_void,
            pkt.len(),
            0,
            &dst_addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        libc::close(probe_sock);
    }

    // Receive SYN-ACK from zombie and extract IP ID
    let mut buf = [0u8; 4096];
    let deadline = std::time::Instant::now() + timeout;
    let mut ipid = None;

    while std::time::Instant::now() < deadline {
        let n = unsafe { libc::recv(sock, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n <= 0 {
            break;
        }
        let pkt = &buf[..n as usize];
        if pkt.len() < 20 {
            continue;
        }
        let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
        if src != zombie {
            continue;
        }
        let ihl = (pkt[0] & 0x0f) as usize * 4;
        if pkt.len() < ihl + 20 {
            continue;
        }
        let tcp = &pkt[ihl..];
        let tcp_src = u16::from_be_bytes([tcp[0], tcp[1]]);
        if tcp_src != zombie_port {
            continue;
        }
        // IP ID is at bytes 4-5 of IP header
        let id = u16::from_be_bytes([pkt[4], pkt[5]]);
        ipid = Some(id);
        break;
    }

    unsafe {
        libc::close(sock);
    }

    ipid.ok_or_else(|| {
        UvError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("no response from zombie {}", zombie),
        ))
    })
}

fn local_ip_for(dst: Ipv4Addr) -> Option<Ipv4Addr> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect(SocketAddr::new(IpAddr::V4(dst), 80)).ok()?;
    match sock.local_addr().ok()? {
        SocketAddr::V4(v4) => Some(*v4.ip()),
        _ => None,
    }
}

fn tcp_checksum(src: &[u8; 4], dst: &[u8; 4], tcp: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    sum += u16::from_be_bytes([src[0], src[1]]) as u32;
    sum += u16::from_be_bytes([src[2], src[3]]) as u32;
    sum += u16::from_be_bytes([dst[0], dst[1]]) as u32;
    sum += u16::from_be_bytes([dst[2], dst[3]]) as u32;
    sum += 6u32;
    sum += tcp.len() as u32;
    let mut i = 0;
    while i + 1 < tcp.len() {
        sum += u16::from_be_bytes([tcp[i], tcp[i + 1]]) as u32;
        i += 2;
    }
    if i < tcp.len() {
        sum += (tcp[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
