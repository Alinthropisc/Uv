// etcd-noauth — checks if etcd HTTP API is accessible without auth.
// Sends GET /version, unauthenticated 200 = no auth (CRITICAL).
// etcd is a critical k8s component — unauth access exposes all cluster secrets.

use async_trait::async_trait;
use std::net::IpAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

use crate::engine::{Checker, VulnResult, VulnSeverity};

pub struct EtcdNoAuth;

#[async_trait]
impl Checker for EtcdNoAuth {
    fn name(&self) -> &'static str {
        "etcd-noauth"
    }
    fn ports(&self) -> &'static [u16] {
        &[2379, 2380, 4001]
    }

    async fn check(&self, ip: IpAddr, port: u16) -> VulnResult {
        let addr = std::net::SocketAddr::new(ip, port);
        let dur = Duration::from_millis(3000);
        let Ok(Ok(mut stream)) = timeout(dur, TcpStream::connect(addr)).await else {
            return VulnResult::safe(self.name());
        };
        let req = b"GET /version HTTP/1.0\r\nHost: localhost\r\n\r\n";
        if timeout(dur, stream.write_all(req)).await.is_err() {
            return VulnResult::safe(self.name());
        }
        let mut buf = vec![0u8; 512];
        let Ok(Ok(n)) = timeout(dur, stream.read(&mut buf)).await else {
            return VulnResult::safe(self.name());
        };
        let resp = std::str::from_utf8(&buf[..n]).unwrap_or("");
        if resp.starts_with("HTTP/") && resp.contains("200") && resp.contains("etcdserver") {
            VulnResult::vuln(
                self.name(),
                VulnSeverity::Critical,
                format!("{ip}:{port} — etcd API accessible without authentication (cluster keys exposed)"),
            )
            .with_cve("CVE-2018-1098")
        } else {
            VulnResult::safe(self.name())
        }
    }
}
