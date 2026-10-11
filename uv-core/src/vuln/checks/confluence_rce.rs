// CVE-2022-26134 — Atlassian Confluence OGNL injection RCE.
// Unauthenticated GET /%24%7B%40java.lang.Runtime%40getRuntime%28%29...%7D/
// A vulnerable server returns 302/200 and evaluates the OGNL expression.

use crate::engine::{Checker, VulnResult, VulnSeverity};
use async_trait::async_trait;
use std::net::IpAddr;

pub struct ConfluenceRce;

#[async_trait]
impl Checker for ConfluenceRce {
    fn name(&self) -> &'static str {
        "confluence-rce"
    }

    fn ports(&self) -> &'static [u16] {
        &[8090, 8443, 80, 443]
    }

    async fn check(&self, ip: IpAddr, port: u16) -> VulnResult {
        // Safe detection payload: OGNL that sets a header to a known value.
        // We use a benign expression that just returns a string.
        let req = format!(
            "GET /%24%7B%22uv_probe%22%7D/ HTTP/1.1\r\n\
             Host: {ip}:{port}\r\n\
             Connection: close\r\n\r\n"
        );

        let result = tokio::time::timeout(
            std::time::Duration::from_millis(3000),
            raw_http(ip, port, req.as_bytes()),
        )
        .await;

        match result {
            Ok(Ok(resp)) => {
                let text = String::from_utf8_lossy(&resp);
                // Confluence RCE results in OGNL expression being evaluated.
                // Indicator: the literal "uv_probe" appears in the response Location header.
                if text.contains("uv_probe") {
                    VulnResult::vuln(
                        "confluence-rce",
                        VulnSeverity::Critical,
                        format!(
                            "Confluence OGNL injection detected at {ip}:{port} (CVE-2022-26134)"
                        ),
                    )
                    .with_cve("CVE-2022-26134")
                } else if text.contains("Confluence") {
                    // Confluence is running but not vulnerable (or patched)
                    VulnResult::safe("confluence-rce")
                } else {
                    VulnResult::safe("confluence-rce")
                }
            }
            _ => VulnResult::safe("confluence-rce"),
        }
    }
}

async fn raw_http(ip: IpAddr, port: u16, data: &[u8]) -> std::io::Result<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let mut stream = TcpStream::connect((ip, port)).await?;
    stream.write_all(data).await?;
    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await?;
    buf.truncate(n);
    Ok(buf)
}
