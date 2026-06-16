use crate::banner::{BannerParser, ParsedBanner};

pub struct FtpParser;

impl BannerParser for FtpParser {
    fn name(&self) -> &'static str {
        "ftp"
    }

    fn parse(&self, banner: &[u8], _port: u16) -> Option<ParsedBanner> {
        let text = std::str::from_utf8(banner).ok()?.trim();
        // FTP: "220 ProFTPD 1.3.5 Server" or "220-FileZilla..."
        if !text.starts_with("220") {
            return None;
        }
        let msg = text
            .split_once([' ', '-'])
            .map(|x| x.1)
            .unwrap_or("")
            .trim();
        Some(
            ParsedBanner::new("ftp")
                .with_version(msg)
                .with_raw(text.to_string()),
        )
    }
}
