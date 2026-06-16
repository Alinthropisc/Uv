use crate::banner::{BannerParser, ParsedBanner};

pub struct HttpParser;

impl BannerParser for HttpParser {
    fn name(&self) -> &'static str {
        "http"
    }

    fn parse(&self, banner: &[u8], port: u16) -> Option<ParsedBanner> {
        let text = std::str::from_utf8(banner).ok()?;

        // HTTP response: "HTTP/1.1 200 OK\r\n..."
        if text.starts_with("HTTP/") {
            let status_line = text.lines().next()?;
            let mut parts = status_line.splitn(3, ' ');
            let _version = parts.next()?;
            let code = parts.next()?;
            let reason = parts.next().unwrap_or("");

            let server = text
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("server:"))
                .and_then(|l| l.splitn(2, ':').nth(1))
                .map(|s| s.trim().to_owned());

            let is_tls = port == 443
                || port == 8443
                || text.lines().any(|l| {
                    let l = l.to_ascii_lowercase();
                    l.contains("strict-transport-security") || l.contains("upgrade-insecure")
                });

            let service = if is_tls { "https" } else { "http" };

            let mut r = ParsedBanner::new(service)
                .with_info(format!("{code} {reason}"))
                .with_raw(status_line.to_string());
            if let Some(srv) = server {
                r = r.with_version(srv);
            }
            return Some(r);
        }

        // Request echo-back
        if text.starts_with("GET ") || text.starts_with("POST ") || text.starts_with("HEAD ") {
            return Some(ParsedBanner::new("http").with_raw(text.lines().next()?.to_string()));
        }

        None
    }
}
