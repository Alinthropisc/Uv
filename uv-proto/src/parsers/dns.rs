use crate::banner::{BannerParser, ParsedBanner};

pub struct DnsParser;

impl BannerParser for DnsParser {
    fn name(&self) -> &'static str {
        "dns"
    }

    fn parse(&self, banner: &[u8], port: u16) -> Option<ParsedBanner> {
        if port != 53 {
            return None;
        }
        if banner.len() < 12 {
            return None;
        }
        // DNS response: QR bit (bit 15 of flags word) must be set
        let flags = u16::from_be_bytes([banner[2], banner[3]]);
        if flags & 0x8000 == 0 {
            return None;
        }
        let rcode = flags & 0x000F;
        let info = match rcode {
            0 => "NOERROR",
            1 => "FORMERR",
            2 => "SERVFAIL",
            3 => "NXDOMAIN",
            _ => "OTHER",
        };
        Some(ParsedBanner::new("dns").with_info(info))
    }
}
