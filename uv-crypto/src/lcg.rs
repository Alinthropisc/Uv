// LCG — Linear Congruential Generator (masscan crypto-lcg, pure Rust).
// Builder pattern for parameter construction.

/// Builder for LCG parameters — ensures `a` and `c` are valid for the range.
pub struct LcgBuilder {
    range: u64,
    seed: u64,
}

impl LcgBuilder {
    pub fn new(range: u64) -> Self {
        Self { range, seed: 0 }
    }

    pub fn seed(mut self, seed: u64) -> Self {
        self.seed = seed;
        self
    }

    pub fn build(self) -> Lcg {
        let (a, c) = lcg_params(self.range);
        Lcg {
            a,
            c,
            range: self.range,
            index: self.seed % self.range.max(1),
        }
    }
}

fn gcd(a: u64, b: u64) -> u64 {
    if b == 0 { a } else { gcd(b, a % b) }
}

fn lcm(a: u64, b: u64) -> u64 {
    a / gcd(a, b) * b
}

/// Compute Hull-Dobell LCG constants for the given range m.
/// Hull-Dobell theorem: full period iff gcd(c,m)=1; a≡1 mod p for every prime p|m; a≡1 mod 4 if 4|m.
/// We set a = L+1 where L = lcm of all prime factors of m (and 4 if 4|m), c = 1.
fn lcg_params(m: u64) -> (u64, u64) {
    if m <= 1 {
        return (1, 0);
    }
    let mut l: u64 = 1;
    let mut tmp = m;
    let mut p = 2u64;
    while p * p <= tmp {
        if tmp.is_multiple_of(p) {
            l = lcm(l, p);
            while tmp.is_multiple_of(p) {
                tmp /= p;
            }
        }
        p += 1;
    }
    if tmp > 1 {
        l = lcm(l, tmp);
    }
    if m.is_multiple_of(4) {
        l = lcm(l, 4);
    }
    let a = (l + 1) % m;
    let c = 1u64;
    (a, c)
}

/// Stateful LCG iterator — yields all values in [0, range) without repeats.
pub struct Lcg {
    a: u64,
    c: u64,
    range: u64,
    index: u64,
}

impl Lcg {
    pub fn builder(range: u64) -> LcgBuilder {
        LcgBuilder::new(range)
    }

    pub fn next_val(&mut self) -> u64 {
        let v = self.index;
        self.index = (self.a.wrapping_mul(self.index).wrapping_add(self.c)) % self.range.max(1);
        v
    }

    pub fn range(&self) -> u64 {
        self.range
    }
}

impl Iterator for Lcg {
    type Item = u64;
    fn next(&mut self) -> Option<u64> {
        if self.range == 0 {
            return None;
        }
        Some(self.next_val())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn full_period_small() {
        let mut lcg = LcgBuilder::new(100).seed(0).build();
        let vals: HashSet<u64> = (0..100).map(|_| lcg.next_val()).collect();
        assert_eq!(vals.len(), 100, "LCG must cover full range without repeats");
    }

    #[test]
    fn all_in_range() {
        let mut lcg = LcgBuilder::new(256).build();
        assert!((0..256).map(|_| lcg.next_val()).all(|v| v < 256));
    }
}
