// Binary input — masscan in-binary.c style.
// Reads a saved .uvbin file and reconstructs a partial ScanResult for resume or merging.

use std::net::IpAddr;
use std::path::Path;

use uv_core::types::port::Port;
use uv_core::types::protocol::Protocol;
use uv_core::types::result::{HostResult, ProbeResult, ScanResult};

use crate::binary::{decode_binary, BinaryRecord};

/// Load a saved binary scan file and reconstruct a ScanResult.
pub fn load_binary<P: AsRef<Path>>(path: P) -> std::io::Result<ScanResult> {
    let data = std::fs::read(path)?;
    decode_to_scan(&data).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid uv binary format")
    })
}

/// Decode raw binary bytes into a ScanResult.
pub fn decode_to_scan(data: &[u8]) -> Option<ScanResult> {
    let records = decode_binary(data)?;

    // Group records by IP
    use std::collections::HashMap;
    let mut hosts: HashMap<IpAddr, HostResult> = HashMap::new();

    for rec in records {
        let (ip, port_num, proto_byte, ttl) = match rec {
            BinaryRecord::V4 {
                ip,
                port,
                proto,
                ttl,
            } => (IpAddr::V4(ip), port, proto, ttl),
            BinaryRecord::V6 {
                ip,
                port,
                proto,
                ttl,
            } => (IpAddr::V6(ip), port, proto, ttl),
        };

        let proto = match proto_byte {
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            132 => Protocol::Sctp,
            1 => Protocol::Icmp,
            _ => Protocol::Tcp,
        };

        let host = hosts.entry(ip).or_insert_with(|| HostResult::new(ip));
        let port = Port(port_num);
        let mut probe = ProbeResult::open(port, proto, std::time::Duration::from_millis(0));
        if ttl > 0 {
            probe = probe.with_ttl(ttl);
        }
        host.ports.push(probe);
    }

    // Extract duration from header (bytes 8..16)
    let duration_ms = if data.len() >= 16 {
        u64::from_le_bytes(data[8..16].try_into().unwrap_or([0; 8]))
    } else {
        0
    };

    let hosts_vec: Vec<HostResult> = hosts.into_values().collect();
    let total_probes = hosts_vec.iter().map(|h| h.ports.len() as u64).sum();

    Some(ScanResult {
        hosts: hosts_vec,
        duration_ms,
        total_probes,
        packets_sent: 0,
        packets_recv: 0,
    })
}

/// Merge two ScanResults (e.g. previous binary + new scan).
pub fn merge(base: ScanResult, extra: ScanResult) -> ScanResult {
    use std::collections::HashMap;
    let mut hosts: HashMap<IpAddr, HostResult> =
        base.hosts.into_iter().map(|h| (h.addr, h)).collect();

    for host in extra.hosts {
        let entry = hosts
            .entry(host.addr)
            .or_insert_with(|| HostResult::new(host.addr));
        for port in host.ports {
            let key = (port.port, port.proto);
            if !entry.ports.iter().any(|p| (p.port, p.proto) == key) {
                entry.ports.push(port);
            }
        }
    }

    let hosts_vec: Vec<HostResult> = hosts.into_values().collect();
    let total = hosts_vec.iter().map(|h| h.ports.len() as u64).sum();

    ScanResult {
        hosts: hosts_vec,
        duration_ms: base.duration_ms + extra.duration_ms,
        total_probes: total,
        packets_sent: 0,
        packets_recv: 0,
    }
}
