// net/cookie.c — Stateless SYN cookie engine (C23)
// SipHash-1-2 based: fast, non-cryptographic, collision-resistant for ISN use

#include "cookie.h"

#include <stdint.h>

// ── SipHash-1-2 ───────────────────────────────────────────────────────────────

static uint64_t g_k0 = 0;
static uint64_t g_k1 = 0;

#define ROTL64(v, n) (((v) << (n)) | ((v) >> (64 - (n))))
#define SIPROUND(v0,v1,v2,v3) do {                          \
    (v0)+=(v1); (v1)=ROTL64((v1),13); (v1)^=(v0);          \
    (v0)=ROTL64((v0),32);                                   \
    (v2)+=(v3); (v3)=ROTL64((v3),16); (v3)^=(v2);          \
    (v0)+=(v3); (v3)=ROTL64((v3),21); (v3)^=(v0);          \
    (v2)+=(v1); (v1)=ROTL64((v1),17); (v1)^=(v2);          \
    (v2)=ROTL64((v2),32); } while(0)

static uint64_t siphash13(uint64_t k0, uint64_t k1, uint64_t msg)
{
    uint64_t v0 = k0 ^ (uint64_t)0x736f6d6570736575;
    uint64_t v1 = k1 ^ (uint64_t)0x646f72616e646f6d;
    uint64_t v2 = k0 ^ (uint64_t)0x6c7967656e657261;
    uint64_t v3 = k1 ^ (uint64_t)0x7465646279746573;

    v3 ^= msg;
    SIPROUND(v0, v1, v2, v3);
    v0 ^= msg;
    v2 ^= 0xFF;
    SIPROUND(v0, v1, v2, v3);
    SIPROUND(v0, v1, v2, v3);

    return v0 ^ v1 ^ v2 ^ v3;
}

// ── Public API ────────────────────────────────────────────────────────────────

void uv_cookie_init(uint64_t seed)
{
    g_k0 = seed ^ (uint64_t)0xdeadbeefcafe1234;
    g_k1 = seed ^ (uint64_t)0xfeedface0ba4c0de;
}

uint32_t uv_cookie_encode(uint32_t dst_ip, uint16_t dst_port,
                          uint32_t src_ip, uint16_t src_port)
{
    uint64_t msg = ((uint64_t)dst_ip << 32)
                 | ((uint64_t)dst_port << 16)
                 | ((uint64_t)(src_ip ^ src_port));

    return (uint32_t)(siphash13(g_k0, g_k1, msg) >> 32);
}

bool uv_cookie_verify(uint32_t isn,
                      uint32_t src_ip,  uint16_t src_port,
                      uint32_t dst_ip,  uint16_t dst_port,
                      uint32_t *out_target_ip,
                      uint16_t *out_target_port)
{
    // SYN-ACK acks our ISN+1, so received ack_seq == our_isn + 1
    uint32_t expected = uv_cookie_encode(src_ip, src_port, dst_ip, dst_port);
    if ((isn - 1) != expected) return false;

    if (out_target_ip)   *out_target_ip   = src_ip;
    if (out_target_port) *out_target_port = src_port;
    return true;
}
