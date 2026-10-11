use crate::banner::{BannerParser, ParsedBanner};

pub struct SmtpParser;

impl BannerParser for SmtpParser {
    fn name(&self) -> &'static str {
        "smtp"
    }

    fn parse(&self, banner: &[u8], port: u16) -> Option<ParsedBanner> {
        let text = std::str::from_utf8(banner).ok()?.trim();
        // SMTP: "220 mail.example.com ESMTP Postfix"
        if !text.starts_with("220") {
            return None;
        }
        // Skip if already matched as FTP (FTP uses same 220 code but different ports)
        if port == 21 {
            return None;
        }
        let msg = text.split_once(' ').map(|x| x.1).unwrap_or("").trim();
        let service = if port == 465 { "smtps" } else { "smtp" };
        Some(
            ParsedBanner::new(service)
                .with_version(msg)
                .with_raw(text.to_string()),
        )
    }
}
