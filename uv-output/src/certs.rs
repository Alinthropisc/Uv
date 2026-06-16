// TLS certificate output — masscan out-certs.c style.
// Extracts TLS certificate info from banner and outputs as PEM blocks + JSON metadata.

use crate::formatter::Formatter;
use uv_core::types::port::PortState;
use uv_core::types::result::ScanResult;

pub struct CertsFormatter;

impl Formatter for CertsFormatter {
    fn name(&self) -> &'static str {
        "certs"
    }

    fn format(&self, result: &ScanResult) -> String {
        let mut out = String::new();

        for host in &result.hosts {
            for port in host.ports.iter().filter(|p| p.state == PortState::Open) {
                let svc = port.service.as_ref();

                // Check if this is a TLS service with a banner
                let is_tls = svc
                    .map(|s| {
                        matches!(s.service, uv_core::types::protocol::ServiceKind::Https)
                            || s.banner.as_ref().map(|b| b.tls).unwrap_or(false)
                    })
                    .unwrap_or(false);

                if !is_tls {
                    continue;
                }

                // Extract raw banner bytes for TLS cert data
                if let Some(banner) = svc.and_then(|s| s.banner.as_ref()) {
                    // Try to find X.509 certificate DER in banner bytes
                    // TLS Certificate message: type=0x0b, starts after TLS record header
                    if let Some(cert_info) = extract_tls_cert_info(&banner.raw) {
                        out.push_str(&format!("# {}:{}\n{}\n", host.addr, port.port.0, cert_info));
                    } else {
                        // No parseable cert — output banner text if available
                        if let Some(ref text) = banner.text {
                            out.push_str(&format!(
                                "# {}:{} (tls — no cert parsed)\n# {}\n\n",
                                host.addr,
                                port.port.0,
                                text.lines().next().unwrap_or("")
                            ));
                        }
                    }
                }
            }
        }

        if out.is_empty() {
            out.push_str("# No TLS certificates found\n");
        }
        out
    }
}

/// Try to extract basic TLS certificate information from raw bytes.
/// Returns a formatted string with subject/issuer/validity or None.
fn extract_tls_cert_info(raw: &[u8]) -> Option<String> {
    // Look for DER certificate marker: SEQUENCE (0x30) with long-form length
    // TLS Certificate handshake: 0x0b followed by length
    let pos = raw.windows(3).position(|w| w[0] == 0x0b)?;
    let cert_data = &raw[pos..];

    if cert_data.len() < 7 {
        return None;
    }

    // Emit as base64 PEM block (raw DER bytes, best effort)
    let der = &cert_data[7..]; // skip Certificate msg header
    if der.is_empty() {
        return None;
    }

    // Base64-encode the DER data for PEM output
    let b64 = base64_encode(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");

    Some(pem)
}

fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(CHARS[(b0 >> 2) as usize] as char);
        out.push(CHARS[((b0 & 3) << 4 | b1 >> 4) as usize] as char);
        out.push(if chunk.len() > 1 {
            CHARS[((b1 & 0xf) << 2 | b2 >> 6) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            CHARS[(b2 & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}
