/* crypto-blackrock2.c — BlackRock2 Feistel permutation (clean, no external deps)
 * Derived from masscan/src/crypto-blackrock2.c (AGPL-3.0, reference)
 * Replaces original which required pixie-timer / util-malloc / util-safefunc.
 */
#include "crypto-blackrock2.h"
#include "crypto-siphash.h"
#include <string.h>

#define BR_ROUNDS 4

void uv_blackrock2_init(uv_blackrock2_t *br, uint64_t range, uint64_t seed) {
    memset(br, 0, sizeof(*br));
    br->range = range;

    uint64_t bits = 0, n = range;
    while (n > 1) { n >>= 1; bits++; }

    br->a_bits = bits / 2;
    br->b_bits = bits - br->a_bits;
    br->a_mask = (1ULL << br->a_bits) - 1;
    br->b_mask = (1ULL << br->b_bits) - 1;

    uint8_t key_buf[16];
    memcpy(key_buf,     &seed, 8);
    memcpy(key_buf + 8, &seed, 8);
    for (int i = 0; i < BR_ROUNDS; i++) {
        uint64_t ri = (uint64_t)i;
        br->keys[i * 2]     = uv_siphash24_keyed(&ri, 8, key_buf);
        key_buf[0] ^= (uint8_t)(i + 1);
        br->keys[i * 2 + 1] = uv_siphash24_keyed(&ri, 8, key_buf);
    }
}

static uint64_t feistel_f(uint64_t k0, uint64_t k1, uint64_t x, uint64_t mask) {
    uint8_t buf[16];
    memcpy(buf,     &k0, 8);
    memcpy(buf + 8, &k1, 8);
    return uv_siphash24_keyed(&x, 8, buf) & mask;
}

uint64_t uv_blackrock2_shuffle(const uv_blackrock2_t *br, uint64_t i) {
    uint64_t a = i >> br->b_bits;
    uint64_t b = i  & br->b_mask;
    for (int r = 0; r < BR_ROUNDS; r++) {
        uint64_t f  = feistel_f(br->keys[r*2], br->keys[r*2+1], b, br->a_mask);
        uint64_t na = b;
        uint64_t nb = (a ^ f) & br->b_mask;
        a = na; b = nb;
    }
    uint64_t result = (a << br->b_bits) | b;
    if (result >= br->range) return uv_blackrock2_shuffle(br, result);
    return result;
}

uint64_t uv_blackrock2_unshuffle(const uv_blackrock2_t *br, uint64_t x) {
    uint64_t a = x >> br->b_bits;
    uint64_t b = x  & br->b_mask;
    for (int r = BR_ROUNDS - 1; r >= 0; r--) {
        uint64_t f  = feistel_f(br->keys[r*2], br->keys[r*2+1], a, br->a_mask);
        uint64_t nb = a;
        uint64_t na = (b ^ f) & br->a_mask;
        a = na; b = nb;
    }
    uint64_t result = (a << br->b_bits) | b;
    if (result >= br->range) return uv_blackrock2_unshuffle(br, result);
    return result;
}
