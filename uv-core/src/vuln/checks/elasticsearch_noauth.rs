// Elasticsearch no-auth check — HTTP GET /_cat/health, expect 200 with JSON.
// Unauthenticated ES cluster = full read/write access to all indices.

use crate::engine::{Checker, VulnResult, VulnSeverity};
use async_trait::async_trait;
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

pub struct ElasticsearchNoAuth;

#[async_trait]
impl Checker for ElasticsearchNoAuth {
    fn name(&self) -> &'static str {
        "elasticsearch-noauth"
    }
    fn ports(&self) -> &'static [u16] {
        &[9200, 9300]
    }

    async fn check(&self, ip: IpAddr, port: u16) -> VulnResult {
        let sa = SocketAddr::new(ip, port);
        let result = tokio::task::spawn_blocking(move || probe(sa)).await;
        match result {
            Ok(Some(version)) => VulnResult::vuln(
                "elasticsearch-noauth",
                VulnSeverity::Critical,
                format!("Elasticsearch {version} accessible without authentication"),
            ),
            _ => VulnResult::safe("elasticsearch-noauth"),
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

    let req = format!("GET / HTTP/1.0\r\nHost: {sa}\r\nAccept: application/json\r\n\r\n");
    writer.write_all(req.as_bytes()).ok()?;

    // Read status line
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    if !line.contains("200") {
        return None;
    }

    // Read body (skip headers)
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
        }
        if body.len() > 2048 {
            break;
        }
    }

    // Look for "version" in JSON response
    if !body.contains("\"tagline\"") && !body.contains("elasticsearch") {
        return None;
    }
    let version = extract_json_str(&body, "number").unwrap_or("unknown");
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
