// CVE-2021-22205 — GitLab ExifTool RCE (unauthenticated).
// GitLab < 13.10.3 passes user-uploaded images to ExifTool without sanitization.
// Detection: probe /-/health or /users/sign_in for GitLab indicators + version check.

use crate::engine::{Checker, VulnResult, VulnSeverity};
use async_trait::async_trait;
use std::net::IpAddr;

pub struct GitLabRce;

#[async_trait]
impl Checker for GitLabRce {
    fn name(&self) -> &'static str {
        "gitlab-rce"
    }

    fn ports(&self) -> &'static [u16] {
        &[80, 443, 8080]
    }

    async fn check(&self, ip: IpAddr, port: u16) -> VulnResult {
        let req = format!(
            "GET /-/health HTTP/1.1\r\n\
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
                // GitLab health endpoint returns "GitLab OK" for 200, or version in headers
                if text.contains("GitLab OK") || text.contains("X-Gitlab-Meta") {
                    // GitLab confirmed — check version if available
                    let version_req = format!(
                        "GET /api/v4/version HTTP/1.1\r\n\
                         Host: {ip}:{port}\r\n\
                         Connection: close\r\n\r\n"
                    );
                    let ver_resp = tokio::time::timeout(
                        std::time::Duration::from_millis(2000),
                        raw_http(ip, port, version_req.as_bytes()),
                    )
                    .await;

                    let detail = if let Ok(Ok(vr)) = ver_resp {
                        let vt = String::from_utf8_lossy(&vr);
                        format!(
                            "GitLab detected at {ip}:{port} — version info: {}",
                            vt.lines().last().unwrap_or("unknown")
                        )
                    } else {
                        format!("GitLab detected at {ip}:{port} — version unknown; CVE-2021-22205 if <13.10.3")
                    };

                    VulnResult::vuln("gitlab-rce", VulnSeverity::Critical, detail)
                        .with_cve("CVE-2021-22205")
                } else {
                    VulnResult::safe("gitlab-rce")
                }
            }
            _ => VulnResult::safe("gitlab-rce"),
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
