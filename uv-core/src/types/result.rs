use std::net::IpAddr;
use std::time::Duration;
use serde::{Deserialize, Serialize};

use super::banner::UvServiceInfo;
use super::port::{UvPort, UvPortState};
use super::protocol::UvProtocol;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UvProbeResult {
    pub port: UvPort,
    pub proto: UvProtocol,
    pub state: UvPortState,
    pub rtt: Option<Duration>,
    pub ttl: Option<u8>,
    pub service: Option<UvServiceInfo>,
}

impl UvProbeResult {
    pub fn uv_open(port: UvPort, proto: UvProtocol, rtt: Duration) -> Self {
        Self {
            port,
            proto,
            state: UvPortState::Open,
            rtt: Some(rtt),
            ttl: None,
            service: None,
        }
    }

    pub fn uv_closed(port: UvPort, proto: UvProtocol) -> Self {
        Self {
            port,
            proto,
            state: UvPortState::Closed,
            rtt: None,
            ttl: None,
            service: None,
        }
    }

    pub fn uv_filtered(port: UvPort, proto: UvProtocol) -> Self {
        Self {
            port,
            proto,
            state: UvPortState::Filtered,
            rtt: None,
            ttl: None,
            service: None,
        }
    }

    pub fn uv_with_service(mut self, svc: UvServiceInfo) -> Self {
        self.service = Some(svc);
        self
    }

    pub fn uv_with_ttl(mut self, ttl: u8) -> Self {
        self.ttl = Some(ttl);
        self
    }
}

/// Lightweight vuln finding — plain types only, no uv-vuln dep.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UvVulnEntry {
    pub check: String,
    pub severity: String,
    pub detail: String,
    pub cve: Option<String>,
}

/// Lightweight OS match — plain types only, no uv-os dep.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UvOsEntry {
    pub name: String,
    pub accuracy: u8,
    pub os_class: String,
    pub cpe: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UvHostResult {
    pub addr: IpAddr,
    pub hostname: Option<String>,
    pub ports: Vec<UvProbeResult>,
    pub latency_ms: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vulns: Vec<UvVulnEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub os_matches: Vec<UvOsEntry>,
}

impl UvHostResult {
    pub fn uv_new(addr: IpAddr) -> Self {
        Self {
            addr,
            hostname: None,
            ports: Vec::new(),
            latency_ms: None,
            vulns: Vec::new(),
            os_matches: Vec::new(),
        }
    }

    pub fn uv_open_ports(&self) -> impl Iterator<Item = &UvProbeResult> {
        self.ports.iter().filter(|p| p.state == UvPortState::Open)
    }

    pub fn uv_has_vulns(&self) -> bool {
        !self.vulns.is_empty()
    }

    pub fn uv_top_os(&self) -> Option<&UvOsEntry> {
        self.os_matches.first()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UvScanResult {
    pub hosts: Vec<UvHostResult>,
    pub duration_ms: u64,
    pub total_probes: u64,
    pub packets_sent: u64,
    pub packets_recv: u64,
}

impl UvScanResult {
    pub fn uv_new() -> Self {
        Self {
            hosts: Vec::new(),
            duration_ms: 0,
            total_probes: 0,
            packets_sent: 0,
            packets_recv: 0,
        }
    }

    pub fn uv_open_count(&self) -> usize {
        self.hosts.iter().flat_map(|h| h.uv_open_ports()).count()
    }

    pub fn uv_vuln_count(&self) -> usize {
        self.hosts.iter().map(|h| h.vulns.len()).sum()
    }
}

impl Default for UvScanResult {
    fn default() -> Self {
        
        Self::uv_new()
    }
}