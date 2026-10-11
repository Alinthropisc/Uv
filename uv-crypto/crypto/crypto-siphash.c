/* crypto-siphash.c — SipHash-2-4
 * Reference: Aumasson & Bernstein 2012.
 * Derived from masscan/src/crypto-siphash.c (AGPL-3.0, reference)
 */
#include "crypto-siphash.h"
#include <string.h>

#define ROTL64(x, r) (((x) << (r)) | ((x) >> (64 - (r))))

#define SIP_ROUND(v0,v1,v2,v3) \
    v0 += v1; v1 = ROTL64(v1,13); v1 ^= v0; v0 = ROTL64(v0,32); \
    v2 += v3; v3 = ROTL64(v3,16); v3 ^= v2;                       \
    v0 += v3; v3 = ROTL64(v3,21); v3 ^= v0;                       \
    v2 += v1; v1 = ROTL64(v1,17); v1 ^= v2; v2 = ROTL64(v2,32)

static uint64_t load_le64(const uint8_t *p) {
    return (uint64_t)p[0]       | ((uint64_t)p[1] << 8)
         | ((uint64_t)p[2]<<16) | ((uint64_t)p[3]<<24)
         | ((uint64_t)p[4]<<32) | ((uint64_t)p[5]<<40)
         | ((uint64_t)p[6]<<48) | ((uint64_t)p[7]<<56);
}

uint64_t uv_siphash24(const void *data, size_t len, const uint8_t key[16]) {
    uint64_t k0 = load_le64(key);
    uint64_t k1 = load_le64(key + 8);

    uint64_t v0 = k0 ^ 0x736f6d6570736575ULL;
    uint64_t v1 = k1 ^ 0x646f72616e646f6dULL;
    uint64_t v2 = k0 ^ 0x6c7967656e657261ULL;
    uint64_t v3 = k1 ^ 0x7465646279746573ULL;

    const uint8_t *in  = (const uint8_t *)data;
    size_t blocks = len / 8;

    for (size_t i = 0; i < blocks; i++) {
        uint64_t m = load_le64(in + i * 8);
        v3 ^= m;
        SIP_ROUND(v0,v1,v2,v3);
        SIP_ROUND(v0,v1,v2,v3);
        v0 ^= m;
    }

    /* Last partial block */
    uint64_t last = (uint64_t)(len & 0xFF) << 56;
    const uint8_t *tail = in + blocks * 8;
    switch (len & 7) {
    case 7: last |= (uint64_t)tail[6] << 48; /* fall through */
    case 6: last |= (uint64_t)tail[5] << 40; /* fall through */
    case 5: last |= (uint64_t)tail[4] << 32; /* fall through */
    case 4: last |= (uint64_t)tail[3] << 24; /* fall through */
    case 3: last |= (uint64_t)tail[2] << 16; /* fall through */
    case 2: last |= (uint64_t)tail[1] <<  8; /* fall through */
    case 1: last |= (uint64_t)tail[0];       break;
    case 0: break;
    }
    v3 ^= last;
    SIP_ROUND(v0,v1,v2,v3);
    SIP_ROUND(v0,v1,v2,v3);
    v0 ^= last;

    /* Finalise */
    v2 ^= 0xFF;
    SIP_ROUND(v0,v1,v2,v3);
    SIP_ROUND(v0,v1,v2,v3);
    SIP_ROUND(v0,v1,v2,v3);
    SIP_ROUND(v0,v1,v2,v3);

    return v0 ^ v1 ^ v2 ^ v3;
}

uint64_t uv_siphash24_keyed(const void *data, size_t len, const uint8_t key[16]) {
    return uv_siphash24(data, len, key);
}

uint64_t uv_siphash24_ip_port(uint32_t ip, uint16_t port,
                               uint64_t k0, uint64_t k1) {
    uint8_t key[16];
    memcpy(key,     &k0, 8);
    memcpy(key + 8, &k1, 8);
    uint8_t buf[6];
    memcpy(buf,     &ip,   4);
    memcpy(buf + 4, &port, 2);
    return uv_siphash24(buf, 6, key);
}
