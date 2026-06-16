use crate::engine::{VulnResult, VulnSeverity};
use std::net::IpAddr;

#[derive(Debug, Default)]
pub struct VulnReport {
    entries: Vec<ReportEntry>,
}

#[derive(Debug)]
struct ReportEntry {
    ip: IpAddr,
    port: u16,
    result: VulnResult,
}

impl VulnReport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, ip: IpAddr, port: u16, result: VulnResult) {
        if result.vulnerable {
            self.entries.push(ReportEntry { ip, port, result });
        }
    }

    pub fn add_many(&mut self, ip: IpAddr, port: u16, results: Vec<VulnResult>) {
        for r in results {
            self.add(ip, port, r);
        }
    }

    pub fn count(&self) -> usize {
        self.entries.len()
    }

    pub fn critical(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.result.severity >= VulnSeverity::High)
            .count()
    }

    pub fn format_plain(&self) -> String {
        if self.entries.is_empty() {
            return "No vulnerabilities found.\n".to_string();
        }
        let mut out = String::new();
        for e in &self.entries {
            let cve = e.result.cve.unwrap_or("-");
            out.push_str(&format!(
                "[{}] {}:{} — {} | {} | CVE: {}\n",
                e.result.severity.label(),
                e.ip,
                e.port,
                e.result.check,
                e.result.detail,
                cve,
            ));
        }
        out
    }

    pub fn format_json(&self) -> String {
        let mut out = String::from("[\n");
        for (i, e) in self.entries.iter().enumerate() {
            let comma = if i + 1 < self.entries.len() { "," } else { "" };
            out.push_str(&format!(
                "  {{\"ip\":\"{}\",\"port\":{},\"check\":\"{}\",\"severity\":\"{}\",\
                 \"detail\":\"{}\",\"cve\":{}}}{}\n",
                e.ip,
                e.port,
                e.result.check,
                e.result.severity.label(),
                e.result.detail.replace('"', "'"),
                e.result
                    .cve
                    .map(|c| format!("\"{}\"", c))
                    .unwrap_or("null".into()),
                comma,
            ));
        }
        out.push_str("]\n");
        out
    }
}
