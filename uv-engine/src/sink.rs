use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;
use uv_core::traits::ResultSink;
use uv_core::types::port::PortState;
use uv_core::types::result::{HostResult, ProbeResult, ScanResult};

pub struct MemorySink {
    hosts: HashMap<IpAddr, HostResult>,
    total_probes: u64,
    packets_sent: u64,
    packets_recv: u64,
    started: Instant,
}

impl MemorySink {
    pub fn new() -> Self {
        Self {
            hosts: HashMap::new(),
            total_probes: 0,
            packets_sent: 0,
            packets_recv: 0,
            started: Instant::now(),
        }
    }

    pub fn inc_sent(&mut self) {
        self.packets_sent += 1;
    }
    pub fn inc_recv(&mut self) {
        self.packets_recv += 1;
    }
}

impl Default for MemorySink {
    fn default() -> Self {
        Self::new()
    }
}

impl ResultSink for MemorySink {
    fn push(&mut self, result: ProbeResult, host: IpAddr) {
        self.total_probes += 1;
        if result.state == PortState::Open {
            self.packets_recv += 1;
        }
        self.hosts
            .entry(host)
            .or_insert_with(|| HostResult::new(host))
            .ports
            .push(result);
    }

    fn finalize(self) -> ScanResult {
        ScanResult {
            hosts: self.hosts.into_values().collect(),
            duration_ms: self.started.elapsed().as_millis() as u64,
            total_probes: self.total_probes,
            packets_sent: self.packets_sent,
            packets_recv: self.packets_recv,
        }
    }
}
