// ScanJob — Builder pattern for composing a scan configuration.

use std::net::IpAddr;
use uv_core::exclude::{IpExcludeList, PortExcludeList};
use uv_core::scan_type::ScanType;
use uv_core::timing::TimingTemplate;
use uv_core::types::port::PortRange;
use uv_output::formatter::OutputFormat;

#[derive(Debug, Clone)]
pub struct ScanJob {
    pub targets: Vec<IpAddr>,
    pub ports: Vec<PortRange>,
    pub rate_pps: u64,
    pub timeout_ms: u32,
    pub no_banner: bool,
    pub os_detect: bool,
    pub vuln_scan: bool,
    pub open_only: bool,
    pub output_format: OutputFormat,
    pub concurrency: usize,
    pub retries: u8,
    pub timing: TimingTemplate,
    pub scan_type: ScanType,
    pub ip_exclude: IpExcludeList,
    pub port_exclude: PortExcludeList,
    pub resume_file: Option<String>,
    // masscan: --source-ip / --source-port (used by raw-socket SYN/SCTP engine)
    pub source_ip: Option<IpAddr>,
    pub source_port: Option<u16>,
    // masscan: --shard N/M — distribute scan across M workers, this is shard N (1-based)
    pub shard: u32,
    pub shards: u32,
    // adapter name for raw sockets (masscan: --adapter / --interface)
    pub interface: Option<String>,
}

pub struct ScanJobBuilder {
    job: ScanJob,
}

impl ScanJobBuilder {
    pub fn new() -> Self {
        Self {
            job: ScanJob {
                targets: vec![],
                ports: vec![PortRange {
                    start: uv_core::types::port::Port(1),
                    end: uv_core::types::port::Port(1024),
                }],
                rate_pps: 0,   // 0 = use timing template default
                timeout_ms: 0, // 0 = use timing template default
                no_banner: false,
                os_detect: false,
                open_only: false,
                output_format: OutputFormat::Plain,
                concurrency: 0, // 0 = use timing template default
                retries: 0,     // 0 = use timing template default
                timing: TimingTemplate::T3,
                scan_type: ScanType::TcpConnect,
                ip_exclude: IpExcludeList::new(),
                port_exclude: PortExcludeList::new(),
                resume_file: None,
                vuln_scan: false,
                source_ip: None,
                source_port: None,
                shard: 1,
                shards: 1,
                interface: None,
            },
        }
    }

    pub fn target(mut self, ip: IpAddr) -> Self {
        self.job.targets.push(ip);
        self
    }

    pub fn targets(mut self, ips: Vec<IpAddr>) -> Self {
        self.job.targets.extend(ips);
        self
    }

    pub fn ports(mut self, ranges: Vec<PortRange>) -> Self {
        self.job.ports = ranges;
        self
    }

    pub fn rate(mut self, pps: u64) -> Self {
        self.job.rate_pps = pps;
        self
    }

    pub fn timeout(mut self, ms: u32) -> Self {
        self.job.timeout_ms = ms;
        self
    }

    pub fn no_banner(mut self) -> Self {
        self.job.no_banner = true;
        self
    }

    pub fn open_only(mut self) -> Self {
        self.job.open_only = true;
        self
    }

    pub fn os_detect(mut self) -> Self {
        self.job.os_detect = true;
        self
    }

    pub fn output(mut self, fmt: OutputFormat) -> Self {
        self.job.output_format = fmt;
        self
    }

    pub fn concurrency(mut self, n: usize) -> Self {
        self.job.concurrency = n;
        self
    }

    pub fn retries(mut self, n: u8) -> Self {
        self.job.retries = n;
        self
    }

    pub fn timing(mut self, t: TimingTemplate) -> Self {
        self.job.timing = t;
        self
    }

    pub fn scan_type(mut self, st: ScanType) -> Self {
        self.job.scan_type = st;
        self
    }

    pub fn exclude_ip(mut self, cidr: &str) -> Self {
        let _ = self.job.ip_exclude.add(cidr);
        self
    }

    pub fn exclude_ip_file(mut self, path: &str) -> Self {
        if let Ok(list) = IpExcludeList::from_file(path) {
            self.job.ip_exclude = list;
        }
        self
    }

    pub fn exclude_ports(mut self, spec: &str) -> Self {
        self.job.port_exclude = PortExcludeList::parse(spec);
        self
    }

    pub fn resume(mut self, path: impl Into<String>) -> Self {
        self.job.resume_file = Some(path.into());
        self
    }

    pub fn vuln_scan(mut self) -> Self {
        self.job.vuln_scan = true;
        self
    }

    pub fn source_ip(mut self, ip: IpAddr) -> Self {
        self.job.source_ip = Some(ip);
        self
    }

    pub fn source_port(mut self, port: u16) -> Self {
        self.job.source_port = Some(port);
        self
    }

    /// masscan-style sharding: this node is shard `n` of `total` (1-based).
    pub fn shard(mut self, n: u32, total: u32) -> Self {
        self.job.shard = n.max(1);
        self.job.shards = total.max(1);
        self
    }

    pub fn interface(mut self, iface: impl Into<String>) -> Self {
        self.job.interface = Some(iface.into());
        self
    }

    pub fn build(self) -> ScanJob {
        self.job
    }
}

impl Default for ScanJobBuilder {
    fn default() -> Self {
        Self::new()
    }
}
