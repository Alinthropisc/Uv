// MySQL/MariaDB banner parser.
// Initial handshake packet: length(3) + seq(1) + protocol_version(1) + server_version(NUL)
// Protocol v10 (MySQL 4.1+), v9 (old).

use crate::banner::{BannerParser, ParsedBanner};

pub struct MysqlParser;

impl BannerParser for MysqlParser {
    fn name(&self) -> &'static str {
        "mysql"
    }

    fn parse(&self, banner: &[u8], _port: u16) -> Option<ParsedBanner> {
        if banner.len() < 6 {
            return None;
        }

        // First 3 bytes = packet length (little-endian), byte 3 = seq=0
        let pkt_len = u32::from_le_bytes([banner[0], banner[1], banner[2], 0]) as usize;
        if pkt_len == 0 || pkt_len > 1024 {
            return None;
        }
        if banner[3] != 0 {
            return None;
        } // seq must be 0 for initial handshake

        let proto = banner[4];
        if proto != 9 && proto != 10 {
            return None;
        }

        // Version string starts at byte 5, NUL-terminated
        let version_bytes = &banner[5..];
        let nul = version_bytes.iter().position(|&b| b == 0)?;
        let version = std::str::from_utf8(&version_bytes[..nul]).ok()?;

        // Distinguish MySQL from MariaDB
        let service = if version.contains("MariaDB") {
            "mariadb"
        } else {
            "mysql"
        };

        Some(ParsedBanner::new(service).with_version(version))
    }
}
