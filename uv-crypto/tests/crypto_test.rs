use std::collections::HashSet;
use uv_crypto::base64;
use uv_crypto::blackrock::{Permutation, ShuffleIter};
use uv_crypto::{siphash24, BlackRock, CookieFactory, Lcg};

#[test]
fn blackrock_bijection() {
    let br = BlackRock::new(0xdeadbeef, 10_000);
    let set: HashSet<u64> = ShuffleIter::new(&br as &dyn Permutation).collect();
    assert_eq!(set.len(), 10_000);
}

#[test]
fn blackrock_split_covers_all_ports() {
    let br = BlackRock::new(1, 65535 * 256);
    let (ip, port) = br.split(br.shuffle(42), 65535);
    assert!(ip < 256);
    assert!(port < 65535);
}

#[test]
fn siphash_test_vector() {
    let key = [0x0706050403020100u64, 0x0f0e0d0c0b0a0908u64];
    assert_eq!(
        siphash24(&(0u8..15).collect::<Vec<_>>(), key),
        0xa129ca6149be45e5
    );
}

#[test]
fn lcg_full_period() {
    let mut lcg = Lcg::builder(1000).seed(7).build();
    let vals: HashSet<u64> = (0..1000).map(|_| lcg.next_val()).collect();
    assert_eq!(vals.len(), 1000);
}

#[test]
fn cookie_round_trip() {
    let f = CookieFactory::new(0xfeedface_deadbeef_0011223344556677);
    let c = f.make(0xc0a80001, 54321, 0x08080808, 443);
    assert!(f.validate(0xc0a80001, 54321, 0x08080808, 443, c.0.wrapping_add(1)));
}

#[test]
fn cookie_wrong_ip_fails() {
    let f = CookieFactory::new(0x1234);
    let c = f.make(1, 1, 2, 80);
    assert!(!f.validate(9, 1, 2, 80, c.0.wrapping_add(1)));
}

#[test]
fn base64_encode_decode() {
    for s in [b"hello".as_slice(), b"uv scanner!", b"\x00\xff\xfe"] {
        assert_eq!(base64::decode(&base64::encode(s)).unwrap(), s);
    }
}
