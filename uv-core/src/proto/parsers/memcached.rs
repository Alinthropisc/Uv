// Memcached banner parser — text protocol and binary protocol detection.
// Text: VERSION <ver>\r\n  or  ERROR\r\n  or  CLIENT_ERROR\r\n
// Binary: magic byte 0x81 (response), opcode, key len, ...

use crate::banner::{BannerParser, ParsedBanner};

pub struct MemcachedParser;

impl BannerParser for MemcachedParser {
    fn name(&self) -> &'static str {
        "memcached"
    }

    fn parse(&self, banner: &[u8], _port: u16) -> Option<ParsedBanner> {
        if banner.is_empty() {
            return None;
        }

        // Binary protocol response magic
        if banner[0] == 0x81 && banner.len() >= 24 {
            return Some(ParsedBanner::new("memcached").with_info("binary protocol"));
        }

        // Text protocol
        let s = std::str::from_utf8(banner).ok()?;
        if let Some(ver_line) = s.lines().find(|l| l.starts_with("VERSION ")) {
            let version = ver_line.strip_prefix("VERSION ")?.trim();
            return Some(ParsedBanner::new("memcached").with_version(version));
        }
        if s.starts_with("ERROR") || s.starts_with("CLIENT_ERROR") || s.starts_with("SERVER_ERROR")
        {
            return Some(ParsedBanner::new("memcached").with_info("text protocol"));
        }
        if s.starts_with("STAT ") {
            return Some(ParsedBanner::new("memcached").with_info("stats response"));
        }
        None
    }
}
