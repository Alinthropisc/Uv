// nmap -oG style: one line per host, tab-separated fields.

use crate::formatter::Formatter;
use uv_core::types::result::ScanResult;

pub struct GrepFormatter;

impl Formatter for GrepFormatter {
    fn name(&self) -> &'static str {
        "greppable"
    }

    fn format(&self, result: &ScanResult) -> String {
        let mut out = String::from("# uv scan — greppable output\n");
        for host in &result.hosts {
            let ports: Vec<String> = host
                .open_ports()
                .map(|p| {
                    let svc = p
                        .service
                        .as_ref()
                        .map(|s| s.service.to_string())
                        .unwrap_or_else(|| "unknown".into());
                    format!("{}/{}/open/{}/", p.port.0, p.proto, svc)
                })
                .collect();

            let os = host
                .top_os()
                .map(|o| format!("\tOS: {}", o.name))
                .unwrap_or_default();

            let vulns: Vec<String> = host
                .vulns
                .iter()
                .map(|v| format!("{}({})", v.check, v.severity))
                .collect();
            let vuln_str = if vulns.is_empty() {
                String::new()
            } else {
                format!("\tVulns: {}", vulns.join(", "))
            };

            out.push_str(&format!(
                "Host: {}\tPorts: {}{}{}\n",
                host.addr,
                ports.join(", "),
                os,
                vuln_str,
            ));
        }
        out
    }
}
