// vnc-noauth — checks if VNC server uses SecurityType=1 (None, no auth).
// RFB protocol: server sends "RFB 003.008\n" then a list of security types.
// SecurityType 1 = None (no password).

use async_trait::async_trait;
use std::net::IpAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

use crate::engine::{Checker, VulnResult, VulnSeverity};

pub struct VncNoAuth;

#[async_trait]
impl Checker for VncNoAuth {
    fn name(&self) -> &'static str {
        "vnc-noauth"
    }
    fn ports(&self) -> &'static [u16] {
        &[5900, 5901, 5902, 5903]
    }

    async fn check(&self, ip: IpAddr, port: u16) -> VulnResult {
        let addr = std::net::SocketAddr::new(ip, port);
        let dur = Duration::from_millis(3000);
        let Ok(Ok(mut stream)) = timeout(dur, TcpStream::connect(addr)).await else {
            return VulnResult::safe(self.name());
        };

        // Read server version: "RFB 003.008\n" (12 bytes)
        let mut ver = [0u8; 12];
        if timeout(dur, stream.read_exact(&mut ver)).await.is_err() {
            return VulnResult::safe(self.name());
        }
        let ver_str = std::str::from_utf8(&ver).unwrap_or("");
        if !ver_str.starts_with("RFB ") {
            return VulnResult::safe(self.name());
        }

        // Echo back our version
        if timeout(dur, stream.write_all(b"RFB 003.008\n"))
            .await
            .is_err()
        {
            return VulnResult::safe(self.name());
        }

        // RFB 3.7+: server sends number of security types (1 byte) then the types
        let mut n_types = [0u8; 1];
        if timeout(dur, stream.read_exact(&mut n_types)).await.is_err() {
            return VulnResult::safe(self.name());
        }
        let count = n_types[0] as usize;
        if count == 0 {
            // Security type 0 = connection failed
            return VulnResult::safe(self.name());
        }
        let mut types = vec![0u8; count];
        if timeout(dur, stream.read_exact(&mut types)).await.is_err() {
            return VulnResult::safe(self.name());
        }
        if types.contains(&1) {
            VulnResult::vuln(
                self.name(),
                VulnSeverity::Critical,
                format!(
                    "{ip}:{port} — VNC server allows no-authentication access (SecurityType=None)"
                ),
            )
        } else {
            VulnResult::safe(self.name())
        }
    }
}
