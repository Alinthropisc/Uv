// RST filter — masscan misc-rstfilter.c style.
// Tracks outgoing SYN flows (src_ip, src_port, dst_ip, dst_port) so we can
// identify and discard RST packets that we ourselves caused (e.g. kernel auto-RST
// to SYN-ACKs we received for ports not in our listen table).
// Without this filter, raw-socket scanners see their own RSTs and misclassify ports.

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

/// A 4-tuple identifying a TCP flow we sent a SYN for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Flow {
    pub src_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_ip: Ipv4Addr,
    pub dst_port: u16,
}

/// Thread-safe RST filter — records sent SYN flows and filters incoming RSTs.
#[derive(Clone)]
pub struct RstFilter {
    flows: Arc<Mutex<HashSet<Flow>>>,
}

impl RstFilter {
    pub fn new() -> Self {
        Self {
            flows: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Record a sent SYN flow.
    pub fn add(&self, src_ip: Ipv4Addr, src_port: u16, dst_ip: Ipv4Addr, dst_port: u16) {
        let flow = Flow {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
        };
        if let Ok(mut set) = self.flows.lock() {
            set.insert(flow);
        }
    }

    /// Returns true if the RST packet came from a flow we initiated —
    /// i.e. we should KEEP this RST (it's a real closed-port response).
    /// Returns false if we should DISCARD it (RST for a flow we didn't send).
    pub fn is_our_flow(
        &self,
        src_ip: Ipv4Addr,
        src_port: u16,
        dst_ip: Ipv4Addr,
        dst_port: u16,
    ) -> bool {
        // The RST comes back with src/dst swapped relative to our SYN
        let flow = Flow {
            src_ip: dst_ip, // our source was the RST's destination
            src_port: dst_port,
            dst_ip: src_ip, // our destination was the RST's source
            dst_port: src_port,
        };
        self.flows
            .lock()
            .map(|s| s.contains(&flow))
            .unwrap_or(false)
    }

    /// Remove a flow once we've received its response (free memory).
    pub fn remove(&self, src_ip: Ipv4Addr, src_port: u16, dst_ip: Ipv4Addr, dst_port: u16) {
        let flow = Flow {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
        };
        if let Ok(mut set) = self.flows.lock() {
            set.remove(&flow);
        }
    }

    /// Discard all recorded flows (call after scan completes).
    pub fn clear(&self) {
        if let Ok(mut set) = self.flows.lock() {
            set.clear();
        }
    }

    pub fn len(&self) -> usize {
        self.flows.lock().map(|s| s.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for RstFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_filter() {
        let f = RstFilter::new();
        let src = Ipv4Addr::new(192, 168, 1, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 1);
        f.add(src, 12345, dst, 80);

        // RST comes back with swapped src/dst
        assert!(f.is_our_flow(dst, 80, src, 12345));
        // Random RST not in our flows
        assert!(!f.is_our_flow(dst, 443, src, 12345));
    }

    #[test]
    fn remove_flow() {
        let f = RstFilter::new();
        let src = Ipv4Addr::new(1, 2, 3, 4);
        let dst = Ipv4Addr::new(5, 6, 7, 8);
        f.add(src, 1000, dst, 22);
        f.remove(src, 1000, dst, 22);
        assert!(!f.is_our_flow(dst, 22, src, 1000));
    }
}
