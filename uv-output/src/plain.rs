// nmap-style aligned table output.
// PORT      STATE  SERVICE        VERSION
// 22/tcp    open   ssh            OpenSSH 8.9p1
// Column widths auto-sized to the widest entry.

use crate::formatter::Formatter;
use uv_core::types::port::PortState;
use uv_core::types::result::ScanResult;

pub struct PlainFormatter;

impl Formatter for PlainFormatter {
    fn name(&self) -> &'static str {
        "plain"
    }

    fn format(&self, result: &ScanResult) -> String {
        let mut out = String::new();
        let hosts_up = result
            .hosts
            .iter()
            .filter(|h| h.open_ports().next().is_some())
            .count();
        out.push_str(&format!(
            "uv scan report — {}/{} hosts up — {:.2}s\n",
            hosts_up,
            result.hosts.len(),
            result.duration_ms as f64 / 1000.0,
        ));

        for host in &result.hosts {
            out.push('\n');
            out.push_str(&format!(
                "Scan report for {} ({})\n",
                host.addr,
                host.hostname.as_deref().unwrap_or("—")
            ));

            if let Some(os) = host.top_os() {
                out.push_str(&format!(
                    "OS: {} ({}%) [{}]\n",
                    os.name, os.accuracy, os.os_class
                ));
            }

            // Build table rows first to size columns
            struct Row {
                port_proto: String,
                state: String,
                service: String,
                version: String,
                banner: String,
                ttl: String,
            }

            let rows: Vec<Row> = host
                .ports
                .iter()
                .filter(|p| p.state != PortState::Closed)
                .map(|probe| {
                    let svc = probe
                        .service
                        .as_ref()
                        .map(|s| s.service.to_string())
                        .unwrap_or_else(|| "unknown".into());

                    let version = probe
                        .service
                        .as_ref()
                        .and_then(|s| s.version.as_deref())
                        .unwrap_or("")
                        .to_string();

                    let banner = probe
                        .service
                        .as_ref()
                        .and_then(|s| s.banner.as_ref())
                        .and_then(|b| b.text.as_deref())
                        .map(|t| t.trim().to_string())
                        .unwrap_or_default();

                    let ttl = probe.ttl.map(|t| format!("ttl={t}")).unwrap_or_default();

                    let state_str = match probe.state {
                        PortState::Open => "open",
                        PortState::Filtered => "filtered",
                        PortState::Closed => "closed",
                        PortState::OpenFiltered => "open|filtered",
                    };

                    Row {
                        port_proto: format!("{}/{}", probe.port.0, probe.proto),
                        state: state_str.to_string(),
                        service: svc,
                        version,
                        banner,
                        ttl,
                    }
                })
                .collect();

            if rows.is_empty() {
                out.push_str("All scanned ports are closed or filtered.\n");
            } else {
                // Column widths
                let w_port = rows
                    .iter()
                    .map(|r| r.port_proto.len())
                    .max()
                    .unwrap_or(9)
                    .max(9);
                let w_state = rows.iter().map(|r| r.state.len()).max().unwrap_or(5).max(5);
                let w_svc = rows
                    .iter()
                    .map(|r| r.service.len())
                    .max()
                    .unwrap_or(7)
                    .max(7);
                let w_ver = rows
                    .iter()
                    .map(|r| r.version.len())
                    .max()
                    .unwrap_or(7)
                    .max(7);

                // Header
                out.push_str(&format!(
                    "{:<w_port$}  {:<w_state$}  {:<w_svc$}  {:<w_ver$}  BANNER / TTL\n",
                    "PORT",
                    "STATE",
                    "SERVICE",
                    "VERSION",
                    w_port = w_port,
                    w_state = w_state,
                    w_svc = w_svc,
                    w_ver = w_ver
                ));
                out.push_str(&"-".repeat(w_port + w_state + w_svc + w_ver + 30));
                out.push('\n');

                for row in &rows {
                    let extra = match (row.banner.is_empty(), row.ttl.is_empty()) {
                        (true, true) => String::new(),
                        (true, _) => row.ttl.clone(),
                        (_, true) => row.banner.chars().take(60).collect(),
                        _ => format!(
                            "{}  {}",
                            row.banner.chars().take(40).collect::<String>(),
                            row.ttl
                        ),
                    };
                    out.push_str(&format!(
                        "{:<w_port$}  {:<w_state$}  {:<w_svc$}  {:<w_ver$}  {}\n",
                        row.port_proto,
                        row.state,
                        row.service,
                        row.version,
                        extra,
                        w_port = w_port,
                        w_state = w_state,
                        w_svc = w_svc,
                        w_ver = w_ver
                    ));
                }
            }

            // Vulns
            if !host.vulns.is_empty() {
                out.push_str("\nVULNERABILITIES:\n");
                for v in &host.vulns {
                    let cve = v
                        .cve
                        .as_deref()
                        .map(|c| format!(" [{c}]"))
                        .unwrap_or_default();
                    out.push_str(&format!(
                        "  [{}]{} {} — {}\n",
                        v.severity, cve, v.check, v.detail
                    ));
                }
            }
        }

        // Summary
        out.push('\n');
        let total_vulns = result.vuln_count();
        if total_vulns > 0 {
            out.push_str(&format!(
                "Vulnerabilities found: {} across {} hosts\n",
                total_vulns,
                result.hosts.iter().filter(|h| h.has_vulns()).count()
            ));
        }
        out.push_str(&format!(
            "uv done: {} IP{} ({} host{} up) — {:.2}s elapsed\n",
            result.hosts.len(),
            if result.hosts.len() == 1 { "" } else { "s" },
            hosts_up,
            if hosts_up == 1 { "" } else { "s" },
            result.duration_ms as f64 / 1000.0,
        ));
        out
    }
}
