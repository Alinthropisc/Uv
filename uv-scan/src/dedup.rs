// Dedup filter — masscan main-dedup.c style.
// Removes duplicate (port, proto) entries per host and duplicate host records.

use std::collections::HashSet;
use uv_core::types::result::{HostResult, ScanResult};

/// Deduplicate a ScanResult in-place:
/// - Per host: remove duplicate (port, proto) ProbeResult entries, keep highest-state winner.
/// - Across hosts: merge duplicate IPs (keep first, append unique ports from duplicates).
pub fn dedup(result: &mut ScanResult) {
    // Per-host port dedup
    for host in &mut result.hosts {
        dedup_ports(host);
    }

    // Cross-host IP dedup — merge duplicate IPs
    let mut seen: HashSet<std::net::IpAddr> = HashSet::new();
    let mut merged: Vec<HostResult> = Vec::with_capacity(result.hosts.len());

    for host in std::mem::take(&mut result.hosts) {
        if seen.insert(host.addr) {
            merged.push(host);
        } else {
            // Merge ports into the existing entry
            if let Some(existing) = merged.iter_mut().find(|h| h.addr == host.addr) {
                for port in host.ports {
                    let key = (port.port, port.proto);
                    if !existing.ports.iter().any(|p| (p.port, p.proto) == key) {
                        existing.ports.push(port);
                    }
                }
                existing.vulns.extend(host.vulns);
                if existing.os_matches.is_empty() {
                    existing.os_matches = host.os_matches;
                }
                if existing.hostname.is_none() {
                    existing.hostname = host.hostname;
                }
            }
        }
    }

    result.hosts = merged;
}

fn dedup_ports(host: &mut HostResult) {
    use std::collections::HashMap;
    use uv_core::types::port::PortState;

    // Keep best state per (port, proto): Open > Filtered > Closed
    let mut best: HashMap<
        (
            uv_core::types::port::Port,
            uv_core::types::protocol::Protocol,
        ),
        usize,
    > = HashMap::new();

    let state_rank = |s: PortState| match s {
        PortState::Open => 2,
        PortState::Filtered => 1,
        PortState::Closed => 0,
    };

    for (i, p) in host.ports.iter().enumerate() {
        let key = (p.port, p.proto);
        let rank = state_rank(p.state);
        best.entry(key)
            .and_modify(|best_idx| {
                if rank > state_rank(host.ports[*best_idx].state) {
                    *best_idx = i;
                }
            })
            .or_insert(i);
    }

    let keep: HashSet<usize> = best.values().copied().collect();
    let mut i = 0;
    host.ports.retain(|_| {
        let keep_it = keep.contains(&i);
        i += 1;
        keep_it
    });
}
