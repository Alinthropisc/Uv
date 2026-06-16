// SYN Cookie — stateless connection tracking for raw-socket scanner.
// Factory Method pattern: CookieFactory creates & validates cookies.

use crate::siphash::SipHasher;

/// Opaque 32-bit SYN cookie embedded in the TCP sequence number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cookie(pub u32);

/// Factory Method — one factory instance per scan session with a fixed secret.
pub struct CookieFactory {
    hasher: SipHasher,
}

impl CookieFactory {
    pub fn new(secret: u128) -> Self {
        Self {
            hasher: SipHasher::from_secret(secret),
        }
    }

    /// Generate a cookie for (src_ip, src_port, dst_ip, dst_port).
    pub fn make(&self, src_ip: u32, src_port: u16, dst_ip: u32, dst_port: u16) -> Cookie {
        let mut buf = [0u8; 12];
        buf[0..4].copy_from_slice(&src_ip.to_le_bytes());
        buf[4..6].copy_from_slice(&src_port.to_le_bytes());
        buf[6..10].copy_from_slice(&dst_ip.to_le_bytes());
        buf[10..12].copy_from_slice(&dst_port.to_le_bytes());
        Cookie(self.hasher.hash(&buf) as u32)
    }

    /// Validate an incoming ACK: the ack_num should equal cookie+1.
    pub fn validate(
        &self,
        src_ip: u32,
        src_port: u16,
        dst_ip: u32,
        dst_port: u16,
        ack_num: u32,
    ) -> bool {
        let expected = self.make(src_ip, src_port, dst_ip, dst_port);
        ack_num.wrapping_sub(1) == expected.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let f = CookieFactory::new(0xdeadbeef_cafebabe_0102030405060708);
        let c = f.make(0x01020304, 12345, 0x05060708, 80);
        assert!(f.validate(0x01020304, 12345, 0x05060708, 80, c.0.wrapping_add(1)));
    }

    #[test]
    fn wrong_port_fails() {
        let f = CookieFactory::new(0x1234);
        let c = f.make(1, 1000, 2, 80);
        assert!(!f.validate(1, 1001, 2, 80, c.0.wrapping_add(1)));
    }
}
