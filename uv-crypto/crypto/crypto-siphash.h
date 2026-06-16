/* crypto-siphash.h — SipHash-2-4 (masscan/src/crypto-siphash.h inspired)
 * Used as the round function in BlackRock2 and for SYN cookie generation.
 */
#pragma once
#include <stdint.h>
#include <stddef.h>

/* One-shot SipHash-2-4: key must be exactly 16 bytes */
uint64_t uv_siphash24(const void *data, size_t len, const uint8_t key[16]);

/* Convenience: pass key as two 64-bit words */
uint64_t uv_siphash24_keyed(const void *data, size_t len, const uint8_t key[16]);

/* Hash a single (ip, port) pair — used for SYN cookies */
uint64_t uv_siphash24_ip_port(uint32_t ip, uint16_t port,
                               uint64_t k0, uint64_t k1);
