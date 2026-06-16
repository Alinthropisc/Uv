// SipHash-2-4 — masscan crypto-siphash24 re-implemented in pure Rust.
// Used for SYN cookies and fast keyed hashing of (IP, port) pairs.

macro_rules! sip_round {
    ($v0:expr, $v1:expr, $v2:expr, $v3:expr) => {
        $v0 = $v0.wrapping_add($v1);
        $v1 = $v1.rotate_left(13);
        $v1 ^= $v0;
        $v0 = $v0.rotate_left(32);
        $v2 = $v2.wrapping_add($v3);
        $v3 = $v3.rotate_left(16);
        $v3 ^= $v2;
        $v0 = $v0.wrapping_add($v3);
        $v3 = $v3.rotate_left(21);
        $v3 ^= $v0;
        $v2 = $v2.wrapping_add($v1);
        $v1 = $v1.rotate_left(17);
        $v1 ^= $v2;
        $v2 = $v2.rotate_left(32);
    };
}

/// SipHash-2-4: 2 compression rounds, 4 finalisation rounds.
/// `key` is two 64-bit words (128-bit key total).
pub fn siphash24(data: &[u8], key: [u64; 2]) -> u64 {
    let mut v0 = key[0] ^ 0x736f6d6570736575u64;
    let mut v1 = key[1] ^ 0x646f72616e646f6du64;
    let mut v2 = key[0] ^ 0x6c7967656e657261u64;
    let mut v3 = key[1] ^ 0x7465646279746573u64;

    let chunks = data.chunks_exact(8);
    let remainder = chunks.remainder();

    for chunk in chunks {
        let m = u64::from_le_bytes(chunk.try_into().unwrap());
        v3 ^= m;
        sip_round!(v0, v1, v2, v3);
        sip_round!(v0, v1, v2, v3);
        v0 ^= m;
    }

    // Last block: pad remainder with length byte
    let mut last = (data.len() as u64 & 0xFF) << 56;
    for (i, &b) in remainder.iter().enumerate() {
        last |= (b as u64) << (i * 8);
    }
    v3 ^= last;
    sip_round!(v0, v1, v2, v3);
    sip_round!(v0, v1, v2, v3);
    v0 ^= last;

    v2 ^= 0xFF;
    sip_round!(v0, v1, v2, v3);
    sip_round!(v0, v1, v2, v3);
    sip_round!(v0, v1, v2, v3);
    sip_round!(v0, v1, v2, v3);

    v0 ^ v1 ^ v2 ^ v3
}

/// Keyed hasher with a fixed key — Builder pattern for reuse.
pub struct SipHasher {
    key: [u64; 2],
}

impl SipHasher {
    pub fn new(key: [u64; 2]) -> Self {
        Self { key }
    }

    pub fn from_secret(secret: u128) -> Self {
        Self {
            key: [secret as u64, (secret >> 64) as u64],
        }
    }

    pub fn hash(&self, data: &[u8]) -> u64 {
        siphash24(data, self.key)
    }

    pub fn hash_u64(&self, v: u64) -> u64 {
        self.hash(&v.to_le_bytes())
    }

    pub fn hash_ip_port(&self, ip: u32, port: u16) -> u64 {
        let mut buf = [0u8; 6];
        buf[..4].copy_from_slice(&ip.to_le_bytes());
        buf[4..].copy_from_slice(&port.to_le_bytes());
        self.hash(&buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vector from the SipHash reference implementation
    #[test]
    fn known_vector() {
        let key = [0x0706050403020100u64, 0x0f0e0d0c0b0a0908u64];
        let data: Vec<u8> = (0u8..15).collect();
        let hash = siphash24(&data, key);
        assert_eq!(hash, 0xa129ca6149be45e5);
    }

    #[test]
    fn deterministic() {
        let h = SipHasher::new([1, 2]);
        assert_eq!(h.hash(b"hello"), h.hash(b"hello"));
    }

    #[test]
    fn different_inputs_differ() {
        let h = SipHasher::new([0xdeadbeef, 0xcafebabe]);
        assert_ne!(
            h.hash_ip_port(0x01020304, 80),
            h.hash_ip_port(0x01020304, 443)
        );
    }
}
