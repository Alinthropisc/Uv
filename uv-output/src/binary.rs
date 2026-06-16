// Binary output format — mirrors masscan's --output-format binary.
// Format v2 (little-endian):
//   Magic:    u32 = 0x564E4D41 ("UVNM")
//   Version:  u8  = 2
//   Pad:      u8[3]
//   Duration: u64 (ms)
//
//   Per record — first byte is type:
//     0x04 — IPv4 record (13 bytes total):
//       type(1) + ip(4,BE) + port(2,BE) + proto(1) + ttl(1) + pad(4) = 13
//     0x06 — IPv6 record (25 bytes total):
//       type(1) + ip(16,BE) + port(2,BE) + proto(1) + ttl(1) + pad(4) = 25
//
//   End: u32 = 0xFFFFFFFF (sentinel)

use crate::formatter::Formatter;
use uv_core::types::port::PortState;
use uv_core::types::protocol::Protocol;
use uv_core::types::result::ScanResult;

pub const BINARY_MAGIC: u32 = 0x564E_4D41; // "UVNM"
pub const BINARY_VERSION: u8 = 2;
pub const BINARY_SENTINEL: u32 = 0xFFFF_FFFF;
const REC_V4: u8 = 0x04;
const REC_V6: u8 = 0x06;

pub struct BinaryFormatter;

impl Formatter for BinaryFormatter {
    fn name(&self) -> &'static str {
        "binary"
    }

    fn format(&self, result: &ScanResult) -> String {
        // Binary output is not valid UTF-8, so we base64-encode it for the String return type.
        // Callers that want raw bytes should use `encode_binary()` directly.
        let bytes = encode_binary(result);
        base64_encode(&bytes)
    }
}

/// Encode a ScanResult to the uv binary wire format.
pub fn encode_binary(result: &ScanResult) -> Vec<u8> {
    let mut buf = Vec::with_capacity(512);

    // Header
    buf.extend_from_slice(&BINARY_MAGIC.to_le_bytes());
    buf.push(BINARY_VERSION);
    // 3 bytes padding
    buf.extend_from_slice(&[0u8; 3]);
    // duration_ms
    buf.extend_from_slice(&result.duration_ms.to_le_bytes());

    for host in &result.hosts {
        for port in host.ports.iter().filter(|p| p.state == PortState::Open) {
            match host.addr {
                std::net::IpAddr::V4(v4) => {
                    // type(1) + ip(4) + port(2) + proto(1) + ttl(1) + pad(4) = 13 bytes
                    buf.push(REC_V4);
                    buf.extend_from_slice(&u32::from(v4).to_be_bytes());
                    buf.extend_from_slice(&port.port.0.to_be_bytes());
                    buf.push(proto_byte(port.proto));
                    buf.push(port.ttl.unwrap_or(0));
                    buf.extend_from_slice(&0u32.to_le_bytes());
                }
                std::net::IpAddr::V6(v6) => {
                    // type(1) + ip(16) + port(2) + proto(1) + ttl(1) + pad(4) = 25 bytes
                    buf.push(REC_V6);
                    buf.extend_from_slice(&v6.octets());
                    buf.extend_from_slice(&port.port.0.to_be_bytes());
                    buf.push(proto_byte(port.proto));
                    buf.push(port.ttl.unwrap_or(0));
                    buf.extend_from_slice(&0u32.to_le_bytes());
                }
            }
        }
    }

    // Sentinel
    buf.extend_from_slice(&BINARY_SENTINEL.to_le_bytes());
    buf
}

/// Decoded record from uv binary format.
pub enum BinaryRecord {
    V4 {
        ip: std::net::Ipv4Addr,
        port: u16,
        proto: u8,
        ttl: u8,
    },
    V6 {
        ip: std::net::Ipv6Addr,
        port: u16,
        proto: u8,
        ttl: u8,
    },
}

/// Decode uv binary format v2 back into records.
pub fn decode_binary(data: &[u8]) -> Option<Vec<BinaryRecord>> {
    if data.len() < 16 {
        return None;
    }
    let magic = u32::from_le_bytes(data[0..4].try_into().ok()?);
    if magic != BINARY_MAGIC {
        return None;
    }
    // Skip 4 (magic) + 1 (version) + 3 (pad) + 8 (duration) = 16 bytes header
    let mut pos = 16;
    let mut records = Vec::new();

    while pos < data.len() {
        // Check sentinel (need 4 bytes with type=0xFF repeated)
        if pos + 4 <= data.len() {
            let sentinel = u32::from_le_bytes(data[pos..pos + 4].try_into().ok()?);
            if sentinel == BINARY_SENTINEL {
                break;
            }
        }
        let rec_type = data[pos];
        pos += 1;
        match rec_type {
            0x04 if pos + 12 <= data.len() => {
                let ip = u32::from_be_bytes(data[pos..pos + 4].try_into().ok()?);
                let port = u16::from_be_bytes(data[pos + 4..pos + 6].try_into().ok()?);
                let proto = data[pos + 6];
                let ttl = data[pos + 7];
                records.push(BinaryRecord::V4 {
                    ip: std::net::Ipv4Addr::from(ip),
                    port,
                    proto,
                    ttl,
                });
                pos += 12;
            }
            0x06 if pos + 24 <= data.len() => {
                let octets: [u8; 16] = data[pos..pos + 16].try_into().ok()?;
                let port = u16::from_be_bytes(data[pos + 16..pos + 18].try_into().ok()?);
                let proto = data[pos + 18];
                let ttl = data[pos + 19];
                records.push(BinaryRecord::V6 {
                    ip: std::net::Ipv6Addr::from(octets),
                    port,
                    proto,
                    ttl,
                });
                pos += 24;
            }
            _ => break,
        }
    }

    Some(records)
}

fn proto_byte(proto: Protocol) -> u8 {
    match proto {
        Protocol::Tcp => 6,
        Protocol::Udp => 17,
        Protocol::Sctp => 132,
        Protocol::Icmp => 1,
    }
}

/// Minimal base64 encoder (no external dep).
fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
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
