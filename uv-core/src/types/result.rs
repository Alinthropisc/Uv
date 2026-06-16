use super::banner::ServiceInfo;
use super::port::{Port, PortState};
use super::protocol::Protocol;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    pub port: Port,
    pub proto: Protocol,
    pub state: PortState,
    pub rtt: Option<Duration>,
    pub ttl: Option<u8>,
    pub service: Option<ServiceInfo>,
}

impl ProbeResult {
    pub fn open(port: Port, proto: Protocol, rtt: Duration) -> Self {
        Self {
            port,
            proto,
            state: PortState::Open,
            rtt: Some(rtt),
            ttl: None,
            service: None,
        }
    }

    pub fn closed(port: Port, proto: Protocol) -> Self {
        Self {
            port,
            proto,
            state: PortState::Closed,
            rtt: None,
            ttl: None,
            service: None,
        }
    }

    pub fn filtered(port: Port, proto: Protocol) -> Self {
        Self {
            port,
            proto,
            state: PortState::Filtered,
            rtt: None,
            ttl: None,
            service: None,
        }
    }

    pub fn with_service(mut self, svc: ServiceInfo) -> Self {
        self.service = Some(svc);
        self
    }

    pub fn with_ttl(mut self, ttl: u8) -> Self {
        self.ttl = Some(ttl);
        self
    }
}

/// Lightweight vuln finding — plain types only, no uv-vuln dep.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnEntry {
    pub check: String,
    pub severity: String,
    pub detail: String,
    pub cve: Option<String>,
}

/// Lightweight OS match — plain types only, no uv-os dep.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsEntry {
    pub name: String,
    pub accuracy: u8,
    pub os_class: String,
    pub cpe: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostResult {
    pub addr: IpAddr,
    pub hostname: Option<String>,
    pub ports: Vec<ProbeResult>,
    pub latency_ms: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vulns: Vec<VulnEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub os_matches: Vec<OsEntry>,
}

impl HostResult {
    pub fn new(addr: IpAddr) -> Self {
        Self {
            addr,
            hostname: None,
            ports: Vec::new(),
            latency_ms: None,
            vulns: Vec::new(),
            os_matches: Vec::new(),
        }
    }

    pub fn open_ports(&self) -> impl Iterator<Item = &ProbeResult> {
        self.ports.iter().filter(|p| p.state == PortState::Open)
    }

    pub fn has_vulns(&self) -> bool {
        !self.vulns.is_empty()
    }

    pub fn top_os(&self) -> Option<&OsEntry> {
        self.os_matches.first()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub hosts: Vec<HostResult>,
    pub duration_ms: u64,
    pub total_probes: u64,
    pub packets_sent: u64,
    pub packets_recv: u64,
}

impl ScanResult {
    pub fn new() -> Self {
        Self {
            hosts: Vec::new(),
            duration_ms: 0,
            total_probes: 0,
            packets_sent: 0,
            packets_recv: 0,
        }
    }

    pub fn open_count(&self) -> usize {
        self.hosts.iter().flat_map(|h| h.open_ports()).count()
    }

    pub fn vuln_count(&self) -> usize {
        self.hosts.iter().map(|h| h.vulns.len()).sum()
    }
}

impl Default for ScanResult {
    fn default() -> Self {
        Self::new()
    }
}
