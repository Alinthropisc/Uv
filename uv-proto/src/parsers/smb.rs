// SMB/CIFS banner parser — detects SMB1 (NT LM 0.12) and SMB2/3.
// SMB1: \xff SMB; SMB2/3: \xfe SMB with dialect version in negotiate response.

use crate::banner::{BannerParser, ParsedBanner};

pub struct SmbParser;

impl BannerParser for SmbParser {
    fn name(&self) -> &'static str {
        "smb"
    }

    fn parse(&self, banner: &[u8], _port: u16) -> Option<ParsedBanner> {
        // NetBIOS session wrapper: first 4 bytes (type + length)
        let smb_offset = if banner.len() > 4 && banner[0] == 0x00 {
            4
        } else {
            0
        };
        let data = &banner[smb_offset..];

        if data.len() < 4 {
            return None;
        }

        if &data[..4] == b"\xffSMB" {
            // SMB1 header
            let cmd = if data.len() > 4 { data[4] } else { 0 };
            let detail = match cmd {
                0x72 => "SMB1 negotiate response",
                0x73 => "SMB1 session setup",
                _ => "SMB1",
            };
            return Some(
                ParsedBanner::new("microsoft-ds")
                    .with_version("SMB1")
                    .with_info(detail),
            );
        }

        if &data[..4] == b"\xfeSMB" {
            // SMB2/3 header — command at byte 12 (little-endian)
            let cmd = if data.len() > 13 {
                u16::from_le_bytes([data[12], data[13]])
            } else {
                0
            };
            // For negotiate response, dialect is at offset 70 in body
            let dialect = if data.len() > 72 {
                u16::from_le_bytes([data[70], data[71]])
            } else {
                0
            };
            let version = match dialect {
                0x0202 => "SMB 2.0.2",
                0x0210 => "SMB 2.1",
                0x0300 => "SMB 3.0",
                0x0302 => "SMB 3.0.2",
                0x0311 => "SMB 3.1.1",
                _ => "SMB2+",
            };
            let detail = if cmd == 0 {
                "negotiate response"
            } else {
                "SMB2/3"
            };
            return Some(
                ParsedBanner::new("microsoft-ds")
                    .with_version(version)
                    .with_info(detail),
            );
        }

        None
    }
}
