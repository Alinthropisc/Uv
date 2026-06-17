// Raw SYN stealth scanner — masscan stack-tcp-core.c / templ-pkt.c style.
// Sends raw TCP SYN packets via raw IP socket, receives SYN-ACK (open) or RST (closed).
// Requires CAP_NET_RAW / root.

use std::net::{IpAddr, Ipv4Addr};
#[cfg(unix)]
use std::time::Duration;

use uv_core::traits::Scanner;
#[cfg(unix)]
use uv_core::types::port::PortState;
use uv_core::types::port::Port;
use uv_core::types::protocol::Protocol;
use uv_core::types::result::ProbeResult;
use uv_core::UvError;

#[allow(dead_code)]
pub struct SynStealthScanner {
    timeout_ms: u32,
    src_ip: Option<Ipv4Addr>,
    src_port: u16,
}

impl SynStealthScanner {
    pub fn new(timeout_ms: u32) -> Self {
        Self {
            timeout_ms,
            src_ip: None,
            src_port: 40000 + (std::process::id() as u16 % 10000),
        }
    }

    pub fn with_source(mut self, src_ip: Ipv4Addr, src_port: u16) -> Self {
        self.src_ip = Some(src_ip);
        self.src_port = src_port;
        self
    }
}

#[async_trait::async_trait]
impl Scanner for SynStealthScanner {
    fn protocol(&self) -> Protocol {
        Protocol::Tcp
    }

    async fn scan(&self, target: IpAddr, ports: &[Port]) -> Result<Vec<ProbeResult>, UvError> {
        #[cfg(not(unix))]
        {
            let _ = (target, ports);
            return Err(UvError::Unsupported(
                "SYN stealth scan requires Unix (raw sockets)".into(),
            ));
        }

        #[cfg(unix)]
        {
            let dst_ip = match target {
                IpAddr::V4(v4) => v4,
                IpAddr::V6(_) => {
                    return Err(UvError::Unsupported("SYN stealth requires IPv4".into()))
                }
            };

            let src_ip = self.src_ip.unwrap_or_else(|| {
                get_source_ip(dst_ip).unwrap_or(Ipv4Addr::UNSPECIFIED)
            });

            let timeout = Duration::from_millis(self.timeout_ms as u64);
            let src_port = self.src_port;
            let ports_vec: Vec<Port> = ports.to_vec();

            tokio::task::spawn_blocking(move || {
                syn_scan_blocking(src_ip, dst_ip, src_port, &ports_vec, timeout)
            })
            .await
            .map_err(|e| UvError::Io(std::io::Error::other(e.to_string())))?
        }
    }
}

#[cfg(unix)]
fn get_source_ip(dst: Ipv4Addr) -> Option<Ipv4Addr> {
    use std::net::{SocketAddr, UdpSocket};
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect(SocketAddr::new(IpAddr::V4(dst), 80)).ok()?;
    match sock.local_addr().ok()? {
        SocketAddr::V4(v4) => Some(*v4.ip()),
        _ => None,
    }
}

#[cfg(unix)]
fn syn_scan_blocking(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    ports: &[Port],
    timeout: Duration,
) -> Result<Vec<ProbeResult>, UvError> {
    use std::collections::HashMap;
    use tracing::{debug, warn};

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

    let recv_sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_TCP) };
    if recv_sock < 0 {
        unsafe { libc::close(sock) };
        return Err(UvError::Io(std::io::Error::last_os_error()));
    }

    let tv = libc::timeval {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_usec: 0,
    };
    unsafe {
        libc::setsockopt(
            recv_sock,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }

    let mut results: HashMap<u16, PortState> =
        ports.iter().map(|&p| (p.0, PortState::Filtered)).collect();

    for &port in ports {
        let pkt = build_syn_packet(src_ip, dst_ip, src_port, port.0);
        let mut dst_addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        dst_addr.sin_family = libc::AF_INET as libc::sa_family_t;
        dst_addr.sin_port = port.0.to_be();
        dst_addr.sin_addr = libc::in_addr {
            s_addr: u32::from(dst_ip).to_be(),
        };
        let ret = unsafe {
            libc::sendto(
                sock,
                pkt.as_ptr() as *const libc::c_void,
                pkt.len(),
                0,
                &dst_addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            warn!(
                "SYN sendto failed for port {}: {}",
                port.0,
                std::io::Error::last_os_error()
            );
        } else {
            debug!("SYN sent to {}:{}", dst_ip, port.0);
        }
    }

    let deadline = std::time::Instant::now() + timeout;
    let mut buf = [0u8; 4096];

    while std::time::Instant::now() < deadline {
        let n = unsafe {
            libc::recv(
                recv_sock,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
            )
        };
        if n <= 0 {
            break;
        }
        let pkt = &buf[..n as usize];
        if pkt.len() < 40 {
            continue;
        }
        let ihl = (pkt[0] & 0x0f) as usize * 4;
        if pkt.len() < ihl + 20 {
            continue;
        }
        let src_addr = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
        if src_addr != dst_ip {
            continue;
        }
        let tcp = &pkt[ihl..];
        let tcp_src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
        let tcp_dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
        let flags = tcp[13];
        if tcp_dst_port != src_port {
            continue;
        }
        let syn_ack = flags & 0x12 == 0x12;
        let rst = flags & 0x04 != 0;
        if syn_ack {
            results.insert(tcp_src_port, PortState::Open);
            let rst_pkt = build_rst_packet(
                src_ip,
                dst_ip,
                src_port,
                tcp_src_port,
                u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]) + 1,
            );
            let mut dst_addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            dst_addr.sin_family = libc::AF_INET as libc::sa_family_t;
            dst_addr.sin_port = tcp_src_port.to_be();
            dst_addr.sin_addr = libc::in_addr {
                s_addr: u32::from(dst_ip).to_be(),
            };
            unsafe {
                libc::sendto(
                    sock,
                    rst_pkt.as_ptr() as *const libc::c_void,
                    rst_pkt.len(),
                    0,
                    &dst_addr as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                );
            }
        } else if rst {
            results.insert(tcp_src_port, PortState::Closed);
        }
    }

    unsafe {
        libc::close(sock);
        libc::close(recv_sock);
    }

    let probe_results = results
        .into_iter()
        .map(|(port_num, state)| {
            let port = Port(port_num);
            match state {
                PortState::Open => ProbeResult::open(port, Protocol::Tcp, Duration::from_millis(1)),
                PortState::Closed => ProbeResult::closed(port, Protocol::Tcp),
                PortState::Filtered | PortState::OpenFiltered => {
                    ProbeResult::filtered(port, Protocol::Tcp)
                }
            }
        })
        .collect();

    Ok(probe_results)
}

#[cfg(unix)]
fn build_syn_packet(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16) -> Vec<u8> {
    let mut pkt = vec![0u8; 40];
    pkt[0] = 0x45;
    pkt[3] = 40;
    pkt[6] = 0x40;
    pkt[8] = 64;
    pkt[9] = 6;
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    pkt[20..22].copy_from_slice(&sport.to_be_bytes());
    pkt[22..24].copy_from_slice(&dport.to_be_bytes());
    let seq = pseudo_random_seq(src, dst, sport, dport);
    pkt[24..28].copy_from_slice(&seq.to_be_bytes());
    pkt[32] = 0x50;
    pkt[33] = 0x02;
    pkt[34..36].copy_from_slice(&1024u16.to_be_bytes());
    let cksum = tcp_checksum(&src.octets(), &dst.octets(), &pkt[20..]);
    pkt[36..38].copy_from_slice(&cksum.to_be_bytes());
    pkt
}

#[cfg(unix)]
fn build_rst_packet(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, seq: u32) -> Vec<u8> {
    let mut pkt = build_syn_packet(src, dst, sport, dport);
    pkt[24..28].copy_from_slice(&seq.to_be_bytes());
    pkt[33] = 0x04;
    let cksum = tcp_checksum(&src.octets(), &dst.octets(), &pkt[20..]);
    pkt[36..38].copy_from_slice(&cksum.to_be_bytes());
    pkt
}

#[cfg(unix)]
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

#[cfg(unix)]
fn pseudo_random_seq(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16) -> u32 {
    let mut h = 0x811c9dc5u32;
    for b in src.octets().iter().chain(dst.octets().iter()) {
        h ^= *b as u32;
        h = h.wrapping_mul(0x01000193);
    }
    h ^= sport as u32;
    h ^= (dport as u32) << 16;
    h
}
