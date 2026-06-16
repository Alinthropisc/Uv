// RDP (Remote Desktop Protocol) banner parser.
// Detection via TPKT/X.224 Connection Confirm PDU (0x03 0x00 ...).
// Also detects NLA (Network Level Authentication) requirement.

use crate::banner::{BannerParser, ParsedBanner};

pub struct RdpParser;

impl BannerParser for RdpParser {
    fn name(&self) -> &'static str {
        "rdp"
    }

    fn parse(&self, banner: &[u8], port: u16) -> Option<ParsedBanner> {
        if banner.len() < 4 {
            return None;
        }
        if port != 3389 && port != 3388 {
            return None;
        }

        // TPKT header: version=3, reserved=0, then length
        if banner[0] != 0x03 || banner[1] != 0x00 {
            return None;
        }

        let detail = if banner.len() >= 11 {
            // X.224 Connection Confirm (0xd0)
            if banner[5] == 0xd0 {
                // Check rdpNegData if present (byte 11 onward)
                if banner.len() >= 19 && banner[11] == 0x02 {
                    // TYPE_RDP_NEG_FAILURE
                    "connection refused (NLA required)"
                } else if banner.len() >= 19 && banner[11] == 0x02 {
                    "NLA (Network Level Authentication)"
                } else {
                    "connection confirm"
                }
            } else {
                "TPKT/X.224"
            }
        } else {
            "TPKT"
        };

        Some(ParsedBanner::new("ms-wbt-server").with_info(detail))
    }
}
