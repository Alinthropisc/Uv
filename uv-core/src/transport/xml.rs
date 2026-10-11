use crate::formatter::Formatter;
use uv_core::types::result::ScanResult;

pub struct XmlFormatter;

impl Formatter for XmlFormatter {
    fn name(&self) -> &'static str {
        "xml"
    }

    fn format(&self, result: &ScanResult) -> String {
        let hosts_up = result
            .hosts
            .iter()
            .filter(|h| h.open_ports().next().is_some())
            .count();
        let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<uvscan>\n");
        out.push_str(&format!(
            "  <runstats elapsed_ms=\"{}\" hosts_up=\"{}\" total=\"{}\" vulns=\"{}\"/>\n",
            result.duration_ms,
            hosts_up,
            result.hosts.len(),
            result.vuln_count()
        ));

        for host in &result.hosts {
            out.push_str(&format!(
                "  <host ip=\"{}\" name=\"{}\">\n",
                host.addr,
                x(host.hostname.as_deref().unwrap_or(""))
            ));

            // OS
            for os in &host.os_matches {
                out.push_str(&format!(
                    "    <osmatch name=\"{}\" accuracy=\"{}\" class=\"{}\" cpe=\"{}\"/>\n",
                    x(&os.name),
                    os.accuracy,
                    x(&os.os_class),
                    x(&os.cpe)
                ));
            }

            // Ports
            for p in host.open_ports() {
                let svc = x(&p
                    .service
                    .as_ref()
                    .map(|s| s.service.to_string())
                    .unwrap_or_else(|| "unknown".into()));
                let banner = p
                    .service
                    .as_ref()
                    .and_then(|s| s.banner.as_ref())
                    .and_then(|b| b.text.as_deref())
                    .map(x)
                    .unwrap_or_default();
                let ttl = p.ttl.map(|t| format!(" ttl=\"{t}\"")).unwrap_or_default();
                out.push_str(&format!(
                    "    <port number=\"{}\" protocol=\"{}\" state=\"open\" service=\"{}\" banner=\"{}\"{}/>\n",
                    p.port.0, p.proto, svc, banner, ttl
                ));
            }

            // Vulns
            for v in &host.vulns {
                let cve = v
                    .cve
                    .as_deref()
                    .map(|c| format!(" cve=\"{c}\""))
                    .unwrap_or_default();
                out.push_str(&format!(
                    "    <vuln check=\"{}\" severity=\"{}\" detail=\"{}\"{}/>\n",
                    x(&v.check),
                    x(&v.severity),
                    x(&v.detail),
                    cve
                ));
            }

            out.push_str("  </host>\n");
        }
        out.push_str("</uvscan>\n");
        out
    }
}

fn x(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
