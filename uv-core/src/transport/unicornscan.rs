// Unicornscan-compatible output — masscan out-unicornscan.c style.
// Format: "TCP open <ip>:<port> [ <service> ] from <ip> ttl <ttl>"

use crate::formatter::Formatter;
use uv_core::types::port::PortState;
use uv_core::types::result::ScanResult;

pub struct UnicornscanFormatter;

impl Formatter for UnicornscanFormatter {
    fn name(&self) -> &'static str {
        "unicornscan"
    }

    fn format(&self, result: &ScanResult) -> String {
        let mut out = String::new();

        for host in &result.hosts {
            for port in host.ports.iter().filter(|p| p.state == PortState::Open) {
                let proto = port.proto.to_string().to_uppercase();
                let svc = port
                    .service
                    .as_ref()
                    .map(|s| s.service.to_string())
                    .unwrap_or_else(|| "unknown".into());
                let ttl = port.ttl.unwrap_or(0);
                let ver = port
                    .service
                    .as_ref()
                    .and_then(|s| s.version.as_deref())
                    .unwrap_or("");

                if ver.is_empty() {
                    out.push_str(&format!(
                        "{} open\t{:>5}\t[ {} ]\t\tfrom {}\tttl {}\n",
                        proto, port.port.0, svc, host.addr, ttl
                    ));
                } else {
                    out.push_str(&format!(
                        "{} open\t{:>5}\t[ {} ({}) ]\t\tfrom {}\tttl {}\n",
                        proto, port.port.0, svc, ver, host.addr, ttl
                    ));
                }
            }
        }

        out
    }
}
