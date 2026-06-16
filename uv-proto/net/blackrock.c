// net/blackrock.c — BlackRock2 Feistel permutation
// Derived from masscan crypto-blackrock2 by Robert David Graham (MIT License)
// Adapted to C23 for uv project

#include "blackrock.h"

// ── SipHash-inspired round function ─────────────────────────────────────────

static inline uint64_t rotr64(uint64_t v, int n)
{
    return (v >> n) | (v << (64 - n));
}

static uint64_t sip_round(uint64_t v, uint64_t key)
{
    v ^= key;
    v += rotr64(v, 17);
    v ^= rotr64(v, 31);
    v += rotr64(v, 23);
    v ^= rotr64(v, 47);
    return v;
}

// ── Feistel network over variable-width blocks ───────────────────────────────

// Split range into two halves a, b such that a * b >= range and a ≈ b.
static void half_sizes(uint64_t range, uint64_t *a_out, uint64_t *b_out)
{
    uint64_t a = 1, b = 1;
    // grow until a*b >= range, alternating which side we grow
    while (a * b < range) {
        if (a <= b) a++;
        else        b++;
    }
    *a_out = a;
    *b_out = b;
}

void uv_blackrock_init(uv_blackrock_t *br, uint64_t seed, uint64_t range)
{
    br->range   = range;
    br->rounds  = 6;
    // Derive four round keys from the seed
    br->a = sip_round(seed,          0x736f6d6570736575ULL);
    br->b = sip_round(seed ^ br->a,  0x646f72616e646f6dULL);
    br->c = sip_round(seed ^ br->b,  0x6c7967656e657261ULL);
    br->d = sip_round(seed ^ br->c,  0x7465646279746573ULL);
}

uint64_t uv_blackrock_shuffle(const uv_blackrock_t *br, uint64_t i)
{
    uint64_t a, b;
    half_sizes(br->range, &a, &b);

    // Feistel: left = i / b, right = i % b
    uint64_t L = i / b;
    uint64_t R = i % b;

    const uint64_t keys[4] = { br->a, br->b, br->c, br->d };

    for (unsigned r = 0; r < br->rounds; r++) {
        uint64_t key = keys[r & 3] ^ (uint64_t)r;
        if (r & 1) {
            // left round: new_R = (R + f(L)) % b
            uint64_t fL = sip_round(L, key) % b;
            R = (R + fL) % b;
        } else {
            // right round: new_L = (L + f(R)) % a
            uint64_t fR = sip_round(R, key) % a;
            L = (L + fR) % a;
        }
    }

    uint64_t result = L * b + R;
    // If result falls outside range (possible with Feistel over rectangle),
    // keep cycling until it lands inside — average < 2 extra iterations.
    while (result >= br->range) {
        L = result / b;
        R = result % b;
        for (unsigned r = 0; r < br->rounds; r++) {
            uint64_t key = keys[r & 3] ^ (uint64_t)r;
            if (r & 1) {
                uint64_t fL = sip_round(L, key) % b;
                R = (R + fL) % b;
            } else {
                uint64_t fR = sip_round(R, key) % a;
                L = (L + fR) % a;
            }
        }
        result = L * b + R;
    }

    return result;
}

void uv_blackrock_split(const uv_blackrock_t *br, uint64_t idx,
                        uint32_t port_count,
                        uint32_t *ip_idx, uint16_t *port_idx)
{
    (void)br;
    *ip_idx   = (uint32_t)(idx / port_count);
    *port_idx = (uint16_t)(idx % port_count);
}
