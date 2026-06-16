use async_trait::async_trait;
use std::net::IpAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

use crate::engine::{Checker, VulnResult, VulnSeverity};

pub struct Spring4Shell;

#[async_trait]
impl Checker for Spring4Shell {
    fn name(&self) -> &'static str {
        "spring4shell"
    }

    fn ports(&self) -> &'static [u16] {
        &[80, 443, 8080, 8443, 8000, 9000]
    }

    async fn check(&self, ip: IpAddr, port: u16) -> VulnResult {
        let addr = format!("{}:{}", ip, port);
        let Some(mut stream) = timeout(Duration::from_secs(5), TcpStream::connect(&addr))
            .await
            .ok()
            .and_then(|r| r.ok())
        else {
            return VulnResult::safe(self.name());
        };

        // CVE-2022-22965: Spring Framework RCE via class.module.classLoader
        // Detection: send crafted POST with class.module probe, look for 400 with Spring error
        let payload = format!(
            "POST / HTTP/1.1\r\nHost: {}:{}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 90\r\n\r\nclass.module.classLoader.resources.context.parent.pipeline.first.pattern=spring4shell",
            ip, port
        );
        if stream.write_all(payload.as_bytes()).await.is_err() {
            return VulnResult::safe(self.name());
        }

        let mut buf = [0u8; 2048];
        let Ok(Ok(n)) = timeout(Duration::from_secs(3), stream.read(&mut buf)).await else {
            return VulnResult::safe(self.name());
        };

        let resp = String::from_utf8_lossy(&buf[..n]);
        // Vulnerable Spring apps return 400 with specific Spring error text or 200 if misconfigured
        if resp.contains("400")
            && (resp.contains("Spring")
                || resp.contains("WhitelabelError")
                || resp.contains("classLoader"))
        {
            VulnResult::vuln(
                self.name(),
                VulnSeverity::Critical,
                format!(
                    "Spring4Shell (CVE-2022-22965) probe triggered Spring error on {}:{}",
                    ip, port
                ),
            )
            .with_cve("CVE-2022-22965")
        } else {
            VulnResult::safe(self.name())
        }
    }
}
