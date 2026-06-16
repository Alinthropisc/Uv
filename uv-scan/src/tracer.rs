// Scan-level tracing helpers.
// Provides span macros for pipeline stages and per-host events.

use std::net::IpAddr;
use tracing::{debug, info, warn};

/// Log scan job start with key parameters.
pub fn log_job_start(targets: usize, ports: usize, rate_pps: u64, timing: &str) {
    info!(targets, ports, rate_pps, timing, "scan started");
}

/// Log per-host result summary.
pub fn log_host_result(ip: IpAddr, open: usize, total: usize, elapsed_ms: u64) {
    if open > 0 {
        info!(%ip, open, total, elapsed_ms, "host scanned — open ports found");
    } else {
        debug!(%ip, total, elapsed_ms, "host scanned — no open ports");
    }
}

/// Log a port found open.
pub fn log_open_port(ip: IpAddr, port: u16, service: Option<&str>) {
    info!(
        %ip,
        port,
        service = service.unwrap_or("unknown"),
        "open port"
    );
}

/// Log a retry attempt.
pub fn log_retry(ip: IpAddr, port: u16, attempt: u8) {
    debug!(%ip, port, attempt, "retrying filtered port");
}

/// Log scan completion.
pub fn log_scan_complete(hosts: usize, open_ports: u64, duration_ms: u64, rate_pps: f64) {
    info!(
        hosts,
        open_ports,
        duration_ms,
        rate_pps = format!("{rate_pps:.0}"),
        "scan complete"
    );
}

/// Log exclusion events.
pub fn log_excluded(ip: IpAddr, reason: &str) {
    debug!(%ip, reason, "target excluded");
}

/// Log vuln check result.
pub fn log_vuln(ip: IpAddr, port: u16, check: &str, severity: &str, detail: &str) {
    warn!(
        %ip,
        port,
        check,
        severity,
        detail,
        "vulnerability found"
    );
}
