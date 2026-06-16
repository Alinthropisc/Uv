// memcached-info — connects, sends "stats\r\n", checks if we get stats back.
// No auth required = CRITICAL (memcached has no auth by default).

use async_trait::async_trait;
use std::net::IpAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

use crate::engine::{Checker, VulnResult, VulnSeverity};

pub struct MemcachedNoAuth;

#[async_trait]
impl Checker for MemcachedNoAuth {
    fn name(&self) -> &'static str {
        "memcached-noauth"
    }
    fn ports(&self) -> &'static [u16] {
        &[11211]
    }

    async fn check(&self, ip: IpAddr, port: u16) -> VulnResult {
        let addr = std::net::SocketAddr::new(ip, port);
        let dur = Duration::from_millis(3000);
        let Ok(Ok(mut stream)) = timeout(dur, TcpStream::connect(addr)).await else {
            return VulnResult::safe(self.name());
        };
        if timeout(dur, stream.write_all(b"stats\r\n")).await.is_err() {
            return VulnResult::safe(self.name());
        }
        let mut buf = vec![0u8; 256];
        let Ok(Ok(n)) = timeout(dur, stream.read(&mut buf)).await else {
            return VulnResult::safe(self.name());
        };
        let resp = std::str::from_utf8(&buf[..n]).unwrap_or("");
        if resp.contains("STAT ") {
            VulnResult::vuln(
                self.name(),
                VulnSeverity::Critical,
                format!("{ip}:{port} — memcached accessible without authentication"),
            )
        } else {
            VulnResult::safe(self.name())
        }
    }
}
