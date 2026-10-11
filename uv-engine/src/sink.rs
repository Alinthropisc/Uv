use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

use uv_core::traits::UvResultSink;
use uv_core::types::port::UvPortState;
use uv_core::types::result::{UvHostResult, UvProbeResult, UvScanResult};

pub struct UvMemorySink {
    hosts: HashMap<IpAddr, UvHostResult>,
    total_probes: u64,
    packets_sent: u64,
    packets_recv: u64,
    started: Instant,
}

impl UvMemorySink {
    pub fn uv_new() -> Self {
        Self {
            hosts: HashMap::new(),
            total_probes: 0,
            packets_sent: 0,
            packets_recv: 0,
            started: Instant::now(),
        }
    }

    pub fn uv_inc_sent(&mut self) {
        self.packets_sent += 1;
    }
    pub fn uv_inc_recv(&mut self) {
        self.packets_recv += 1;
    }
}

impl Default for UvMemorySink {
    fn default() -> Self {
        Self::uv_new()
    }
}

impl UvResultSink for UvMemorySink {
    fn uv_push(&mut self, result: UvProbeResult, host: IpAddr) {
        self.total_probes += 1;
        
        if result.state == UvPortState::Open {
            self.packets_recv += 1;
        }
        self.hosts.entry(host).or_insert_with(|| UvHostResult::uv_new(host)).ports.push(result);
    }

    fn uv_finalize(self) -> UvScanResult {
        UvScanResult {
            hosts: self.hosts.into_values().collect(),
            duration_ms: self.started.elapsed().as_millis() as u64,
            total_probes: self.total_probes,
            packets_sent: self.packets_sent,
            packets_recv: self.packets_recv,
        }
    }
}
