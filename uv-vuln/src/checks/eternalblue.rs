use async_trait::async_trait;
use std::net::IpAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

use crate::engine::{Checker, VulnResult, VulnSeverity};

pub struct EternalBlue;

// SMBv1 negotiate request — checks if SMBv1 is enabled (prerequisite for MS17-010).
const SMB_NEGOTIATE: &[u8] = &[
    // NetBIOS session
    0x00, 0x00, 0x00, 0x54, // SMB header
    0xFF, 0x53, 0x4D, 0x42, // \xFFSMB
    0x72, // command: negotiate
    0x00, 0x00, 0x00, 0x00, // status
    0x18, 0x01, 0x48, 0x00, // flags
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    // negotiate request
    0x00, 0x31, 0x00, 0x02, 0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x31, 0x2E, 0x30,
    0x00, // LANMAN1.0
    0x02, 0x4C, 0x4D, 0x31, 0x32, 0x58, 0x30, 0x30, 0x32, 0x00, // LM1.2X002
    0x02, 0x4E, 0x54, 0x20, 0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x20, 0x31, 0x2E, 0x30,
    0x00, // NT LANMAN 1.0
    0x02, 0x4E, 0x54, 0x20, 0x4C, 0x4D, 0x20, 0x30, 0x2E, 0x31, 0x32, 0x00, // NT LM 0.12
];

#[async_trait]
impl Checker for EternalBlue {
    fn name(&self) -> &'static str {
        "eternalblue"
    }

    fn ports(&self) -> &'static [u16] {
        &[445]
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

        if stream.write_all(SMB_NEGOTIATE).await.is_err() {
            return VulnResult::safe(self.name());
        }

        let mut buf = [0u8; 256];
        let Ok(Ok(n)) = timeout(Duration::from_secs(3), stream.read(&mut buf)).await else {
            return VulnResult::safe(self.name());
        };

        if n < 5 {
            return VulnResult::safe(self.name());
        }

        // Check SMBv1 negotiate response magic \xFFSMB
        if buf[4..8] == [0xFF, 0x53, 0x4D, 0x42] && buf[8] == 0x72 {
            VulnResult::vuln(
                self.name(),
                VulnSeverity::Critical,
                format!(
                    "SMBv1 enabled on {}:{} — likely vulnerable to MS17-010 (EternalBlue)",
                    ip, port
                ),
            )
            .with_cve("CVE-2017-0144")
        } else {
            VulnResult::safe(self.name())
        }
    }
}
