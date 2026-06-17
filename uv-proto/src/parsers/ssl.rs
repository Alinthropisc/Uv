use crate::banner::{BannerParser, ParsedBanner};

pub struct SslParser;

/// Known TLS ports that imply HTTPS/TLS even without header inspection.
const TLS_PORTS: &[u16] = &[443, 636, 993, 995];

impl BannerParser for SslParser {
    fn name(&self) -> &'static str {
        "ssl"
    }

    fn parse(&self, banner: &[u8], port: u16) -> Option<ParsedBanner> {
        if banner.len() < 5 {
            return None;
        }

        // TLS record: content_type=0x16 (handshake), legacy_version=0x0301-0x0304
        let is_tls_record = banner[0] == 0x16 && banner[1] == 0x03;
        // SSLv2 ClientHello: high bit set, message type 0x01
        let is_sslv2 = banner[0] & 0x80 != 0 && banner[2] == 0x01;

        if !is_tls_record && !is_sslv2 {
            return None;
        }

        let tls_ver = if is_sslv2 {
            "SSLv2"
        } else {
            // Actual negotiated version may differ from record version.
            // For TLS 1.3 the record layer still shows 0x0303.
            // Peek at handshake body (byte 9 = legacy_version for ServerHello) if long enough.
            let inner_ver = if banner.len() >= 10 {
                match (banner[9], banner[10].checked_sub(0)) {
                    _ if banner.len() >= 10 => (banner[9], banner[10]),
                    _ => (0x03, banner[2]),
                }
            } else {
                (0x03, banner[2])
            };
            match inner_ver {
                (0x03, 0x01) => "TLS 1.0",
                (0x03, 0x02) => "TLS 1.1",
                (0x03, 0x03) => "TLS 1.2",
                (0x03, 0x04) => "TLS 1.3",
                _ => match banner[2] {
                    0x01 => "TLS 1.0",
                    0x02 => "TLS 1.1",
                    0x03 => "TLS 1.2",
                    0x04 => "TLS 1.3",
                    _ => "TLS",
                },
            }
        };

        let service = if TLS_PORTS.contains(&port) {
            "https"
        } else {
            "tls"
        };
        Some(
            ParsedBanner::new(service)
                .with_version(tls_ver)
                .with_info(format!("port={port}")),
        )
    }
}
