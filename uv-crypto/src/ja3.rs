// JA3 / JA3S TLS fingerprinting — based on Salesforce JA3 spec.
// JA3:  MD5(SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats)
// JA3S: MD5(SSLVersion,Cipher,Extensions)
//
// Used to fingerprint TLS clients (JA3) and servers (JA3S) for threat intel.
// MD5/SHA1 implemented here without external deps — pure Rust.

// ─── MD5 ─────────────────────────────────────────────────────────────────────

fn md5(data: &[u8]) -> [u8; 16] {
    let s: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    let k: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];
    let mut a0: u32 = 0x67452301;
    let mut b0: u32 = 0xefcdab89;
    let mut c0: u32 = 0x98badcfe;
    let mut d0: u32 = 0x10325476;

    // Pre-processing: add padding
    let orig_len_bits = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&orig_len_bits.to_le_bytes());

    for chunk in msg.chunks(64) {
        let mut m = [0u32; 16];
        for i in 0..16 {
            m[i] = u32::from_le_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0usize..64 {
            let (f, g): (u32, usize) = if i < 16 {
                ((b & c) | (!b & d), i)
            } else if i < 32 {
                ((d & b) | (!d & c), (5 * i + 1) % 16)
            } else if i < 48 {
                (b ^ c ^ d, (3 * i + 5) % 16)
            } else {
                (c ^ (b | !d), (7 * i) % 16)
            };
            let f = f.wrapping_add(a).wrapping_add(k[i]).wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f.rotate_left(s[i]));
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}

pub fn md5_hex(data: &[u8]) -> String {
    md5(data).iter().map(|b| format!("{b:02x}")).collect()
}

// ─── SHA-1 ───────────────────────────────────────────────────────────────────

pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

    let orig_len_bits = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&orig_len_bits.to_be_bytes());

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        #[allow(clippy::needless_range_loop)]
        for i in 0..80 {
            let (f, k): (u32, u32) = if i < 20 {
                ((b & c) | (!b & d), 0x5A827999)
            } else if i < 40 {
                (b ^ c ^ d, 0x6ED9EBA1)
            } else if i < 60 {
                ((b & c) | (b & d) | (c & d), 0x8F1BBCDC)
            } else {
                (b ^ c ^ d, 0xCA62C1D6)
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    let mut out = [0u8; 20];
    for i in 0..5 {
        out[i * 4..i * 4 + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    out
}

pub fn sha1_hex(data: &[u8]) -> String {
    sha1(data).iter().map(|b| format!("{b:02x}")).collect()
}

// ─── JA3 ─────────────────────────────────────────────────────────────────────

/// GREASE values to exclude from JA3 strings (RFC 8701).
const GREASE: &[u16] = &[
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

fn is_grease(v: u16) -> bool {
    GREASE.contains(&v)
}

/// Parsed fields needed for JA3 fingerprint.
#[derive(Debug, Clone, Default)]
pub struct Ja3Fields {
    pub tls_version: u16,
    pub ciphers: Vec<u16>,
    pub extensions: Vec<u16>,
    pub elliptic_curves: Vec<u16>,
    pub ec_point_formats: Vec<u8>,
}

impl Ja3Fields {
    /// Compute JA3 hash string (MD5 of the canonical CSV).
    pub fn ja3(&self) -> String {
        let ciphers: Vec<String> = self
            .ciphers
            .iter()
            .filter(|&&c| !is_grease(c))
            .map(|c| c.to_string())
            .collect();
        let exts: Vec<String> = self
            .extensions
            .iter()
            .filter(|&&e| !is_grease(e))
            .map(|e| e.to_string())
            .collect();
        let curves: Vec<String> = self
            .elliptic_curves
            .iter()
            .filter(|&&c| !is_grease(c))
            .map(|c| c.to_string())
            .collect();
        let fmts: Vec<String> = self
            .ec_point_formats
            .iter()
            .map(|f| f.to_string())
            .collect();

        let raw = format!(
            "{},{},{},{},{}",
            self.tls_version,
            ciphers.join("-"),
            exts.join("-"),
            curves.join("-"),
            fmts.join("-"),
        );
        md5_hex(raw.as_bytes())
    }

    /// Return the raw JA3 string (before hashing), for debugging.
    pub fn ja3_string(&self) -> String {
        let ciphers: Vec<String> = self
            .ciphers
            .iter()
            .filter(|&&c| !is_grease(c))
            .map(|c| c.to_string())
            .collect();
        let exts: Vec<String> = self
            .extensions
            .iter()
            .filter(|&&e| !is_grease(e))
            .map(|e| e.to_string())
            .collect();
        let curves: Vec<String> = self
            .elliptic_curves
            .iter()
            .filter(|&&c| !is_grease(c))
            .map(|c| c.to_string())
            .collect();
        let fmts: Vec<String> = self
            .ec_point_formats
            .iter()
            .map(|f| f.to_string())
            .collect();
        format!(
            "{},{},{},{},{}",
            self.tls_version,
            ciphers.join("-"),
            exts.join("-"),
            curves.join("-"),
            fmts.join("-"),
        )
    }
}

/// Server-side JA3S fields.
#[derive(Debug, Clone, Default)]
pub struct Ja3sFields {
    pub tls_version: u16,
    pub cipher: u16,
    pub extensions: Vec<u16>,
}

impl Ja3sFields {
    pub fn ja3s(&self) -> String {
        let exts: Vec<String> = self
            .extensions
            .iter()
            .filter(|&&e| !is_grease(e))
            .map(|e| e.to_string())
            .collect();
        let raw = format!("{},{},{}", self.tls_version, self.cipher, exts.join("-"));
        md5_hex(raw.as_bytes())
    }
}

/// Parse a TLS ClientHello and extract JA3 fields.
/// `data` should be the raw TLS record bytes (starting with 0x16).
pub fn parse_client_hello(data: &[u8]) -> Option<Ja3Fields> {
    // TLS record: type(1) ver(2) len(2) = 5 bytes header
    if data.len() < 44 || data[0] != 0x16 {
        return None;
    }
    // Handshake: type(1)=0x01(ClientHello) len(3) client_version(2) random(32) ...
    let hs = &data[5..];
    if hs[0] != 0x01 {
        return None;
    }
    let hs_len = u24_to_usize(hs, 1);
    if hs.len() < 4 + hs_len {
        return None;
    }
    let body = &hs[4..4 + hs_len];

    let tls_version = u16::from_be_bytes([body[0], body[1]]);
    let mut pos = 2 + 32; // skip version + random

    // Session ID
    let sid_len = body[pos] as usize;
    pos += 1 + sid_len;
    if pos + 2 > body.len() {
        return None;
    }

    // Cipher suites
    let cs_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    let mut ciphers = Vec::new();
    for i in (0..cs_len).step_by(2) {
        let c = u16::from_be_bytes([body[pos + i], body[pos + i + 1]]);
        ciphers.push(c);
    }
    pos += cs_len;

    // Compression methods
    let comp_len = body[pos] as usize;
    pos += 1 + comp_len;

    // Extensions
    if pos + 2 > body.len() {
        return Some(Ja3Fields {
            tls_version,
            ciphers,
            ..Default::default()
        });
    }
    let ext_total = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_total;

    let mut extensions = Vec::new();
    let mut elliptic_curves = Vec::new();
    let mut ec_point_formats = Vec::new();

    while pos + 4 <= ext_end.min(body.len()) {
        let ext_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let ext_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;
        extensions.push(ext_type);

        match ext_type {
            0x000a if pos + 2 <= body.len() => {
                // supported_groups (elliptic curves)
                let list_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
                for i in (0..list_len).step_by(2) {
                    if pos + 2 + i + 1 < body.len() {
                        elliptic_curves.push(u16::from_be_bytes([
                            body[pos + 2 + i],
                            body[pos + 2 + i + 1],
                        ]));
                    }
                }
            }
            0x000b if pos < body.len() => {
                // ec_point_formats
                let list_len = body[pos] as usize;
                for i in 0..list_len {
                    if pos + 1 + i < body.len() {
                        ec_point_formats.push(body[pos + 1 + i]);
                    }
                }
            }
            _ => {}
        }
        pos += ext_len;
    }

    Some(Ja3Fields {
        tls_version,
        ciphers,
        extensions,
        elliptic_curves,
        ec_point_formats,
    })
}

/// Parse a TLS ServerHello and extract JA3S fields.
pub fn parse_server_hello(data: &[u8]) -> Option<Ja3sFields> {
    if data.len() < 44 || data[0] != 0x16 {
        return None;
    }
    let hs = &data[5..];
    if hs[0] != 0x02 {
        return None;
    } // ServerHello
    let hs_len = u24_to_usize(hs, 1);
    if hs.len() < 4 + hs_len {
        return None;
    }
    let body = &hs[4..4 + hs_len];

    let tls_version = u16::from_be_bytes([body[0], body[1]]);
    let mut pos = 2 + 32;

    let sid_len = body[pos] as usize;
    pos += 1 + sid_len;
    if pos + 2 > body.len() {
        return None;
    }

    let cipher = u16::from_be_bytes([body[pos], body[pos + 1]]);
    pos += 3; // cipher(2) + compression(1)

    let mut extensions = Vec::new();
    if pos + 2 <= body.len() {
        let ext_total = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
        pos += 2;
        let ext_end = pos + ext_total;
        while pos + 4 <= ext_end.min(body.len()) {
            let ext_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
            let ext_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
            pos += 4;
            extensions.push(ext_type);
            pos += ext_len;
        }
    }

    Some(Ja3sFields {
        tls_version,
        cipher,
        extensions,
    })
}

fn u24_to_usize(data: &[u8], offset: usize) -> usize {
    ((data[offset] as usize) << 16)
        | ((data[offset + 1] as usize) << 8)
        | (data[offset + 2] as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_empty() {
        assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn md5_hello() {
        assert_eq!(md5_hex(b"hello"), "5d41402abc4b2a76b9719d911017c592");
    }

    #[test]
    fn sha1_empty() {
        assert_eq!(sha1_hex(b""), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    #[test]
    fn ja3_fields_hash() {
        let f = Ja3Fields {
            tls_version: 769,
            ciphers: vec![49195, 49199, 52393],
            extensions: vec![0, 23, 65281],
            elliptic_curves: vec![29, 23, 24],
            ec_point_formats: vec![0],
        };
        let h = f.ja3();
        assert_eq!(h.len(), 32); // MD5 hex is always 32 chars
    }
}
