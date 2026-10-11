// Redis without authentication — send PING, check for +PONG.
// An unauthenticated Redis means full DB access, possible RCE via config set.

use crate::engine::{Checker, VulnResult, VulnSeverity};
use async_trait::async_trait;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

pub struct RedisNoAuth;

#[async_trait]
impl Checker for RedisNoAuth {
    fn name(&self) -> &'static str {
        "redis-noauth"
    }
    fn ports(&self) -> &'static [u16] {
        &[6379]
    }

    async fn check(&self, ip: IpAddr, port: u16) -> VulnResult {
        let sa = SocketAddr::new(ip, port);
        let result = tokio::task::spawn_blocking(move || probe(sa)).await;
        match result {
            Ok(Some(info)) => VulnResult::vuln(
                "redis-noauth",
                VulnSeverity::Critical,
                format!("Redis accessible without auth — {info}"),
            ),
            _ => VulnResult::safe("redis-noauth"),
        }
    }
}

fn probe(sa: SocketAddr) -> Option<String> {
    let timeout = Duration::from_secs(3);
    let mut sock = TcpStream::connect_timeout(&sa, timeout).ok()?;
    sock.set_read_timeout(Some(Duration::from_secs(3))).ok();
    sock.set_write_timeout(Some(Duration::from_secs(3))).ok();

    // Redis inline command: PING
    sock.write_all(b"PING\r\n").ok()?;
    let mut buf = [0u8; 64];
    let n = sock.read(&mut buf).ok()?;
    let resp = std::str::from_utf8(&buf[..n]).unwrap_or("");

    if resp.contains("+PONG") {
        // Also grab server info
        sock.write_all(b"INFO server\r\n").ok()?;
        let mut info_buf = [0u8; 512];
        let m = sock.read(&mut info_buf).unwrap_or(0);
        let info_str = std::str::from_utf8(&info_buf[..m]).unwrap_or("");
        let version = info_str
            .lines()
            .find(|l| l.starts_with("redis_version:"))
            .map(|l| l.trim())
            .unwrap_or("unknown version");
        return Some(version.to_string());
    }
    None
}
