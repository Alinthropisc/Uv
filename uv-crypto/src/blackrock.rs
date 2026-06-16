// Strategy pattern: Permutation trait + BlackRock2 (Feistel over variable-width block)

/// Strategy trait — any bijective mapping over [0, range).
pub trait Permutation: Send + Sync {
    fn shuffle(&self, index: u64) -> u64;
    fn range(&self) -> u64;

    /// Decode a shuffled index into (left_half, right_half).
    /// Useful for splitting ip_index and port_index.
    fn split(&self, idx: u64, divisor: u64) -> (u64, u64) {
        (idx / divisor, idx % divisor)
    }
}

/// BlackRock2 — Feistel permutation with SipHash-inspired round function.
/// Gives masscan-style pseudo-random ordering of the full ip:port space
/// without allocating any list in memory.
pub struct BlackRock {
    range: u64,
    rounds: u32,
    keys: [u64; 4],
}

impl BlackRock {
    pub fn new(seed: u64, range: u64) -> Self {
        let k0 = Self::mix(seed, 0x736f6d6570736575);
        let k1 = Self::mix(seed ^ k0, 0x646f72616e646f6d);
        let k2 = Self::mix(seed ^ k1, 0x6c7967656e657261);
        let k3 = Self::mix(seed ^ k2, 0x7465646279746573);
        Self {
            range,
            rounds: 6,
            keys: [k0, k1, k2, k3],
        }
    }

    /// Avalanche mix — used for subkey derivation.
    fn mix(v: u64, k: u64) -> u64 {
        let v = v ^ k;
        let v = v.wrapping_add(v.rotate_right(17));
        let v = v ^ v.rotate_right(31);
        let v = v.wrapping_add(v.rotate_right(23));
        v ^ v.rotate_right(47)
    }

    /// Split range into two rectangle halves (a × b ≥ range, a ≈ √range).
    fn half_sizes(range: u64) -> (u64, u64) {
        let mut a = 1u64;
        let mut b = 1u64;
        while a.saturating_mul(b) < range {
            if a <= b {
                a += 1;
            } else {
                b += 1;
            }
        }
        (a, b)
    }

    fn feistel(&self, mut l: u64, mut r: u64, a: u64, b: u64) -> u64 {
        for round in 0..self.rounds {
            let key = self.keys[(round & 3) as usize] ^ round as u64;
            if round & 1 == 1 {
                r = (r + Self::mix(l, key) % b) % b;
            } else {
                l = (l + Self::mix(r, key) % a) % a;
            }
        }
        l * b + r
    }

    /// Decode global index → (ip_index, port_index) given port count.
    pub fn split_pair(&self, idx: u64, port_count: u32) -> (u32, u16) {
        let pc = port_count as u64;
        ((idx / pc) as u32, (idx % pc) as u16)
    }

    /// Total space = ip_count × port_count.
    pub fn space(ip_count: u64, port_count: u32) -> u64 {
        ip_count.saturating_mul(port_count as u64)
    }
}

impl Permutation for BlackRock {
    fn shuffle(&self, index: u64) -> u64 {
        let (a, b) = Self::half_sizes(self.range);
        let l = index / b;
        let r = index % b;
        let mut result = self.feistel(l, r, a, b);
        // Cycle-walk: skip values outside [0, range)
        while result >= self.range {
            let l2 = result / b;
            let r2 = result % b;
            result = self.feistel(l2, r2, a, b);
        }
        result
    }

    fn range(&self) -> u64 {
        self.range
    }
}

/// Zero-allocation iterator over the full permuted space.
pub struct ShuffleIter<'a> {
    perm: &'a dyn Permutation,
    index: u64,
}

impl<'a> ShuffleIter<'a> {
    pub fn new(perm: &'a dyn Permutation) -> Self {
        Self { perm, index: 0 }
    }
}

impl Iterator for ShuffleIter<'_> {
    type Item = u64;
    fn next(&mut self) -> Option<u64> {
        if self.index >= self.perm.range() {
            return None;
        }
        let v = self.perm.shuffle(self.index);
        self.index += 1;
        Some(v)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = (self.perm.range() - self.index) as usize;
        (remaining, Some(remaining))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn bijection_no_duplicates() {
        let br = BlackRock::new(42, 1000);
        let set: HashSet<u64> = ShuffleIter::new(&br as &dyn Permutation).collect();
        assert_eq!(set.len(), 1000);
    }

    #[test]
    fn all_in_range() {
        let br = BlackRock::new(7, 500);
        assert!(ShuffleIter::new(&br as &dyn Permutation).all(|v| v < 500));
    }

    #[test]
    fn split_pair_roundtrip() {
        let br = BlackRock::new(1, 65535 * 256);
        let shuffled = br.shuffle(12345);
        let (ip_idx, port_idx) = br.split_pair(shuffled, 65535);
        assert!((ip_idx as u64) < 256);
        assert!((port_idx as u64) < 65535);
    }

    #[test]
    fn size_hint_correct() {
        let br = BlackRock::new(0, 100);
        let mut it = ShuffleIter::new(&br as &dyn Permutation);
        assert_eq!(it.size_hint(), (100, Some(100)));
        it.next();
        assert_eq!(it.size_hint(), (99, Some(99)));
    }
}
