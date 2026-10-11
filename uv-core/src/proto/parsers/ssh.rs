use crate::banner::{BannerParser, ParsedBanner};

pub struct SshParser;

impl BannerParser for SshParser {
    fn name(&self) -> &'static str {
        "ssh"
    }

    fn parse(&self, banner: &[u8], _port: u16) -> Option<ParsedBanner> {
        // SSH banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
        if !banner.starts_with(b"SSH-") {
            return None;
        }
        let text = std::str::from_utf8(banner).ok()?.trim();
        // SSH-<proto>-<software> [<comment>]
        let parts: Vec<&str> = text.splitn(3, '-').collect();
        if parts.len() < 3 {
            return None;
        }
        let proto = parts[1];
        let rest = parts[2];
        let (software, comment) = rest
            .split_once(' ')
            .map(|(s, c)| (s, Some(c)))
            .unwrap_or((rest, None));

        let mut r = ParsedBanner::new("ssh")
            .with_version(software)
            .with_raw(text.to_string());
        if let Some(c) = comment {
            r = r.with_info(c.to_string());
        }
        // Embed protocol version in info if comment absent
        if r.info.is_none() {
            r = r.with_info(format!("proto={proto}"));
        }
        Some(r)
    }
}
