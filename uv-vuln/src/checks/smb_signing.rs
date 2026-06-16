// SMB signing check — negotiate SMB2; inspect SecurityMode field.
// Signing not required = relay attacks possible (pass-the-hash, NTLM relay).
// Mirrors nmap smb2-security-mode script.

use crate::engine::{Checker, VulnResult, VulnSeverity};
use async_trait::async_trait;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

pub struct SmbSigning;

#[async_trait]
impl Checker for SmbSigning {
    fn name(&self) -> &'static str {
        "smb-signing"
    }
    fn ports(&self) -> &'static [u16] {
        &[445, 139]
    }

    async fn check(&self, ip: IpAddr, port: u16) -> VulnResult {
        let sa = SocketAddr::new(ip, port);
        let result = tokio::task::spawn_blocking(move || probe(sa)).await;
        match result {
            Ok(Some(required)) if !required => VulnResult::vuln(
                "smb-signing",
                VulnSeverity::Medium,
                "SMB signing not required — NTLM relay attacks possible",
            ),
            Ok(Some(_)) => VulnResult::safe("smb-signing"),
            _ => VulnResult::safe("smb-signing"),
        }
    }
}

fn probe(sa: SocketAddr) -> Option<bool> {
    let timeout = Duration::from_secs(5);
    let mut sock = TcpStream::connect_timeout(&sa, timeout).ok()?;
    sock.set_read_timeout(Some(Duration::from_secs(4))).ok();
    sock.set_write_timeout(Some(Duration::from_secs(4))).ok();

    // SMB2 Negotiate Request (minimal — 4-byte NetBIOS + SMB2 header + negotiate body)
    let negotiate: &[u8] = &[
        // NetBIOS session message
        0x00, 0x00, 0x00, 0x54, // SMB2 header
        0xfe, 0x53, 0x4d, 0x42, // ProtocolId = \xfeSMB
        0x40, 0x00, // StructureSize = 64
        0x00, 0x00, // CreditCharge
        0x00, 0x00, // ChannelSequence
        0x00, 0x00, // Reserved
        0x00, 0x00, // Command = NEGOTIATE (0)
        0x00, 0x00, // CreditRequest
        0x00, 0x00, 0x00, 0x00, // Flags
        0x00, 0x00, 0x00, 0x00, // NextCommand
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MessageId
        0x00, 0x00, 0x00, 0x00, // Reserved
        0xff, 0xfe, 0x00, 0x00, // TreeId
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SessionId
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // NEGOTIATE body
        0x24, 0x00, // StructureSize = 36
        0x02, 0x00, // DialectCount = 2
        0x01, 0x00, // SecurityMode bit0 = signing enabled
        0x00, 0x00, // Reserved
        0x7f, 0x00, 0x00, 0x00, // Capabilities
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ClientGuid
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, // ClientStartTime
        0x02, 0x02, // Dialect SMB 2.0.2
        0x10, 0x02, // Dialect SMB 2.1
    ];

    sock.write_all(negotiate).ok()?;

    let mut buf = [0u8; 256];
    let n = sock.read(&mut buf).ok()?;
    if n < 74 {
        return None;
    }

    // SMB2 response: ProtocolId at offset 4
    if &buf[4..8] != b"\xfeSMB" {
        return None;
    }

    // SecurityMode field at offset 70 in the response (after 4-byte NetBIOS)
    // Bit 0x01 = signing enabled; bit 0x02 = signing required
    let sec_mode = buf[70];
    let required = sec_mode & 0x02 != 0;
    Some(required)
}
