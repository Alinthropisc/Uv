// Kubernetes API server exposed — HTTP GET /api/v1/namespaces.
// Unauthenticated K8s API = cluster admin access.
// Ports: 6443 (HTTPS), 8080 (plain/insecure, disabled by default in newer K8s).

use crate::engine::{Checker, VulnResult, VulnSeverity};
use async_trait::async_trait;
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

pub struct KubernetesApi;

#[async_trait]
impl Checker for KubernetesApi {
    fn name(&self) -> &'static str {
        "kubernetes-api-exposed"
    }
    fn ports(&self) -> &'static [u16] {
        &[8080, 6443]
    }

    async fn check(&self, ip: IpAddr, port: u16) -> VulnResult {
        let sa = SocketAddr::new(ip, port);
        let result = tokio::task::spawn_blocking(move || probe(sa)).await;
        match result {
            Ok(Some(info)) => VulnResult::vuln(
                "kubernetes-api-exposed",
                VulnSeverity::Critical,
                format!("Kubernetes API accessible without auth — {info}"),
            ),
            _ => VulnResult::safe("kubernetes-api-exposed"),
        }
    }
}

fn probe(sa: SocketAddr) -> Option<String> {
    let timeout = Duration::from_secs(4);
    let stream = TcpStream::connect_timeout(&sa, timeout).ok()?;
    stream.set_read_timeout(Some(timeout)).ok();
    stream.set_write_timeout(Some(Duration::from_secs(3))).ok();

    let mut writer = stream.try_clone().ok()?;
    let mut reader = BufReader::new(stream);

    // /version endpoint is unauthenticated in many clusters
    let req = format!("GET /version HTTP/1.0\r\nHost: {sa}\r\nAccept: application/json\r\n\r\n");
    writer.write_all(req.as_bytes()).ok()?;

    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    if !line.contains("200") {
        return None;
    }

    let mut body = String::new();
    let mut in_body = false;
    for _ in 0..64 {
        line.clear();
        reader.read_line(&mut line).ok()?;
        if line.trim().is_empty() {
            in_body = true;
            continue;
        }
        if in_body {
            body.push_str(&line);
            if body.len() > 2048 {
                break;
            }
        }
    }

    if !body.contains("gitVersion") && !body.contains("kubernetes") {
        return None;
    }
    let version = extract_json_str(&body, "gitVersion").unwrap_or("unknown");
    Some(version.to_string())
}

fn extract_json_str<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("\"{key}\"");
    let pos = json.find(&needle)?;
    let rest = &json[pos + needle.len()..];
    let colon = rest.find(':')? + 1;
    let rest = rest[colon..].trim_start();
    if let Some(inner) = rest.strip_prefix('"') {
        let end = inner.find('"')?;
        Some(&inner[..end])
    } else {
        None
    }
}
