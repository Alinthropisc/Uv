// ARP resolution — masscan stack-arpv4.c style.
// Resolves IPv4 addresses to MAC addresses on the local LAN via raw ARP requests.
// Requires CAP_NET_RAW. Falls back gracefully if interface unavailable.

use std::net::Ipv4Addr;
use std::time::Duration;

/// Result of an ARP lookup.
#[derive(Debug, Clone)]
pub struct ArpResult {
    pub ip: Ipv4Addr,
    pub mac: [u8; 6],
    pub vendor: Option<&'static str>,
}

impl ArpResult {
    pub fn mac_str(&self) -> String {
        crate::mac::format_mac(&self.mac)
    }
}

/// Resolve a local IPv4 address to its MAC via ARP.
/// Returns None if the host doesn't respond within `timeout_ms`.
pub async fn arp_resolve(target: Ipv4Addr, timeout_ms: u32) -> Option<ArpResult> {
    tokio::task::spawn_blocking(move || arp_blocking(target, timeout_ms))
        .await
        .ok()
        .flatten()
}

/// Resolve multiple IPs concurrently.
pub async fn arp_sweep(targets: &[Ipv4Addr], timeout_ms: u32) -> Vec<ArpResult> {
    use futures::stream::{FuturesUnordered, StreamExt};
    let mut tasks: FuturesUnordered<_> = targets
        .iter()
        .map(|&ip| arp_resolve(ip, timeout_ms))
        .collect();
    let mut results = Vec::new();
    while let Some(r) = tasks.next().await {
        if let Some(res) = r {
            results.push(res);
        }
    }
    results
}

fn arp_blocking(target: Ipv4Addr, timeout_ms: u32) -> Option<ArpResult> {
    let timeout = Duration::from_millis(timeout_ms as u64);

    // Open raw socket for ARP (ETH_P_ARP = 0x0806)
    let sock = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (0x0806u16).to_be() as libc::c_int,
        )
    };
    if sock < 0 {
        return None; // No permission or not Linux — silently skip
    }

    // Get interface index for binding (use first non-loopback interface)
    let ifindex = get_interface_index(sock)?;

    // Build ARP request
    let src_mac = get_interface_mac(sock, ifindex)?;
    let src_ip = get_source_ip(target)?;
    let pkt = build_arp_request(&src_mac, src_ip, target);

    // Bind to interface
    let sll = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_protocol: (0x0806u16).to_be(),
        sll_ifindex: ifindex,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 6,
        sll_addr: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0],
    };
    unsafe {
        libc::bind(
            sock,
            &sll as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        );
    }

    // Send ARP request
    unsafe {
        libc::send(sock, pkt.as_ptr() as *const libc::c_void, pkt.len(), 0);
    }

    // Set receive timeout
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

    // Receive ARP replies
    let mut buf = [0u8; 60];
    let deadline = std::time::Instant::now() + timeout;
    let mut found = None;

    while std::time::Instant::now() < deadline {
        let n = unsafe { libc::recv(sock, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n < 42 {
            break;
        }
        // Ethernet frame: dst(6) + src(6) + ethertype(2) = 14 bytes header
        // ARP packet starts at byte 14
        let arp = &buf[14..];
        // ARP reply: opcode=0x0002, sender_ip at offset 14
        if arp.len() >= 28 && arp[6] == 0x00 && arp[7] == 0x02 {
            let sender_ip = Ipv4Addr::new(arp[14], arp[15], arp[16], arp[17]);
            if sender_ip == target {
                let mut mac = [0u8; 6];
                mac.copy_from_slice(&arp[8..14]);
                let vendor = crate::mac::oui_vendor(&mac);
                found = Some(ArpResult {
                    ip: target,
                    mac,
                    vendor,
                });
                break;
            }
        }
    }

    unsafe {
        libc::close(sock);
    }
    found
}

/// Build a raw ARP request Ethernet frame.
fn build_arp_request(src_mac: &[u8; 6], src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> Vec<u8> {
    let mut pkt = vec![0u8; 42]; // 14 Ethernet + 28 ARP

    // Ethernet header
    pkt[0..6].copy_from_slice(&[0xff; 6]); // dst: broadcast
    pkt[6..12].copy_from_slice(src_mac); // src: our MAC
    pkt[12] = 0x08;
    pkt[13] = 0x06; // EtherType: ARP

    // ARP header
    pkt[14] = 0x00;
    pkt[15] = 0x01; // HTYPE: Ethernet
    pkt[16] = 0x08;
    pkt[17] = 0x00; // PTYPE: IPv4
    pkt[18] = 6; // HLEN
    pkt[19] = 4; // PLEN
    pkt[20] = 0x00;
    pkt[21] = 0x01; // OPER: request
    pkt[22..28].copy_from_slice(src_mac); // SHA: sender MAC
    pkt[28..32].copy_from_slice(&src_ip.octets()); // SPA: sender IP
                                                   // pkt[32..38] = 0 (target MAC unknown)
    pkt[38..42].copy_from_slice(&dst_ip.octets()); // TPA: target IP

    pkt
}

fn get_interface_index(sock: libc::c_int) -> Option<libc::c_int> {
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    // Try eth0, then ens33, then enp0s3
    for iface in &["eth0\0", "ens33\0", "enp0s3\0", "wlan0\0"] {
        let bytes = iface.as_bytes();
        ifr.ifr_name[..bytes.len()]
            .copy_from_slice(&bytes.iter().map(|&b| b as libc::c_char).collect::<Vec<_>>());
        let ret = unsafe { libc::ioctl(sock, libc::SIOCGIFINDEX, &mut ifr) };
        if ret == 0 {
            return Some(unsafe { ifr.ifr_ifru.ifru_ifindex });
        }
    }
    None
}

fn get_interface_mac(sock: libc::c_int, _ifindex: libc::c_int) -> Option<[u8; 6]> {
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    let name = b"eth0\0";
    ifr.ifr_name[..name.len()]
        .copy_from_slice(&name.iter().map(|&b| b as libc::c_char).collect::<Vec<_>>());
    let ret = unsafe { libc::ioctl(sock, libc::SIOCGIFHWADDR, &mut ifr) };
    if ret != 0 {
        return Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // fallback
    }
    let addr = unsafe { ifr.ifr_ifru.ifru_hwaddr.sa_data };
    Some([
        addr[0] as u8,
        addr[1] as u8,
        addr[2] as u8,
        addr[3] as u8,
        addr[4] as u8,
        addr[5] as u8,
    ])
}

fn get_source_ip(dst: Ipv4Addr) -> Option<Ipv4Addr> {
    use std::net::{SocketAddr, UdpSocket};
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect(SocketAddr::new(std::net::IpAddr::V4(dst), 80))
        .ok()?;
    match sock.local_addr().ok()? {
        SocketAddr::V4(v4) => Some(*v4.ip()),
        _ => None,
    }
}
