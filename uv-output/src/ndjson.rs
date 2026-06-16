// NDJSON output — masscan out-ndjson.c style.
// One JSON object per host, newline-delimited. Suitable for streaming/grep.

use crate::formatter::Formatter;
use uv_core::types::result::ScanResult;

pub struct NdJsonFormatter;

impl Formatter for NdJsonFormatter {
    fn name(&self) -> &'static str {
        "ndjson"
    }

    fn format(&self, result: &ScanResult) -> String {
        let mut out = String::new();
        for host in &result.hosts {
            let open: Vec<serde_json::Value> = host
                .open_ports()
                .map(|p| {
                    let svc = p
                        .service
                        .as_ref()
                        .map(|s| s.service.to_string())
                        .unwrap_or_else(|| "unknown".into());
                    let ver = p
                        .service
                        .as_ref()
                        .and_then(|s| s.version.clone())
                        .unwrap_or_default();
                    let banner = p
                        .service
                        .as_ref()
                        .and_then(|s| s.banner.as_ref())
                        .and_then(|b| b.text.clone())
                        .unwrap_or_default();
                    serde_json::json!({
                        "port": p.port.0,
                        "proto": p.proto.to_string(),
                        "service": svc,
                        "version": ver,
                        "banner": banner,
                        "ttl": p.ttl,
                    })
                })
                .collect();

            let vulns: Vec<serde_json::Value> = host
                .vulns
                .iter()
                .map(|v| {
                    serde_json::json!({
                        "check": v.check,
                        "severity": v.severity,
                        "detail": v.detail,
                        "cve": v.cve,
                    })
                })
                .collect();

            let os: Vec<serde_json::Value> = host
                .os_matches
                .iter()
                .map(|o| {
                    serde_json::json!({
                        "name": o.name,
                        "accuracy": o.accuracy,
                        "class": o.os_class,
                        "cpe": o.cpe,
                    })
                })
                .collect();

            let obj = serde_json::json!({
                "ip": host.addr.to_string(),
                "hostname": host.hostname,
                "latency_ms": host.latency_ms,
                "ports": open,
                "vulns": vulns,
                "os": os,
            });
            out.push_str(&obj.to_string());
            out.push('\n');
        }
        out
    }
}
