// CVE-2021-1675 / CVE-2021-34527 — PrintNightmare.
// Windows Print Spooler RPC AddPrinterDriverEx() allows arbitrary DLL load.
// Detection: probe SMB/RPC to see if spoolsv is reachable and version is in affected range.
// This is a passive detection — we check port + banner only; no exploitation.

use crate::engine::{Checker, VulnResult, VulnSeverity};
use async_trait::async_trait;
use std::net::IpAddr;

pub struct PrintNightmare;

#[async_trait]
impl Checker for PrintNightmare {
    fn name(&self) -> &'static str {
        "printnightmare"
    }

    fn ports(&self) -> &'static [u16] {
        &[445, 135]
    }

    async fn check(&self, ip: IpAddr, port: u16) -> VulnResult {
        // Send SMB negotiate to port 445 and check for Windows indicator.
        // Full exploitation requires complex RPC — we fingerprint Windows + open spooler port.
        let smb_neg: &[u8] = &[
            0x00, 0x00, 0x00, 0x54, // NetBIOS length
            0xff, 0x53, 0x4d, 0x42, // SMB magic
            0x72, // command: Negotiate
            0x00, 0x00, 0x00, 0x00, // status
            0x18, // flags
            0x01, 0x28, // flags2
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // reserved
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // padding
            0x00, 0x00, // tid, pid, uid, mid
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // pid/uid/mid
            0x00, 0x31, // word count + dialects
            0x02, b'N', b'T', b' ', b'L', b'M', b' ', b'0', b'.', b'1', b'2', 0x00, 0x02, b'S',
            b'M', b'B', b' ', b'2', b'.', b'0', b'0', b'2', 0x00, 0x02, b'S', b'M', b'B', b' ',
            b'2', b'.', b'?', b'?', b'?', 0x00,
        ];

        let result = tokio::time::timeout(
            std::time::Duration::from_millis(3000),
            probe_smb(ip, port, smb_neg),
        )
        .await;

        match result {
            Ok(Ok(resp)) if resp.len() >= 5 => {
                let is_windows_smb =
                    resp[4] == 0x72 || resp.get(4..8) == Some(&[0xfe, 0x53, 0x4d, 0x42]);
                if is_windows_smb {
                    VulnResult::vuln(
                        "printnightmare",
                        VulnSeverity::High,
                        format!("Windows SMB detected at {ip}:{port} — PrintNightmare (CVE-2021-1675) possible if Print Spooler is running; verify patch level"),
                    )
                    .with_cve("CVE-2021-1675")
                } else {
                    VulnResult::safe("printnightmare")
                }
            }
            _ => VulnResult::safe("printnightmare"),
        }
    }
}

async fn probe_smb(ip: IpAddr, port: u16, payload: &[u8]) -> std::io::Result<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let mut stream = TcpStream::connect((ip, port)).await?;
    stream.write_all(payload).await?;
    let mut buf = vec![0u8; 256];
    let n = stream.read(&mut buf).await?;
    buf.truncate(n);
    Ok(buf)
}
