// Redis banner parser — RESP protocol detection.
// Redis replies with +PONG, -ERR, :integer, $bulk, *array.
// An unauthenticated server returns +PONG on PING; authenticated returns -NOAUTH.

use crate::banner::{BannerParser, ParsedBanner};

pub struct RedisParser;

impl BannerParser for RedisParser {
    fn name(&self) -> &'static str {
        "redis"
    }

    fn parse(&self, banner: &[u8], _port: u16) -> Option<ParsedBanner> {
        if banner.len() < 4 {
            return None;
        }
        let s = std::str::from_utf8(banner).ok()?;

        // RESP inline: +PONG, -ERR ..., -NOAUTH, :integer, $bulk
        if !matches!(banner[0], b'+' | b'-' | b':' | b'$' | b'*') {
            return None;
        }

        let (service, detail) = if s.starts_with("+PONG") {
            ("redis", "no authentication required")
        } else if s.starts_with("-NOAUTH") {
            ("redis", "authentication required")
        } else if s.starts_with("-ERR") {
            ("redis", s.lines().next().unwrap_or("").trim())
        } else if s.starts_with('*') || s.starts_with('$') || s.starts_with(':') {
            ("redis", "RESP protocol")
        } else {
            return None;
        };

        // Try to extract version from INFO response if present
        let version = s
            .lines()
            .find(|l| l.starts_with("redis_version:"))
            .and_then(|l| l.strip_prefix("redis_version:"))
            .map(|v| v.trim());

        let mut pb = ParsedBanner::new(service).with_info(detail);
        if let Some(v) = version {
            pb = pb.with_version(v);
        }
        Some(pb)
    }
}
