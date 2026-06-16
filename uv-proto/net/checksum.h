#pragma once
// net/checksum.h — Internet checksum (IPv4/IPv6/TCP/UDP/ICMP)
// Derived from masscan util-checksum by Robert David Graham (MIT License)
// Adapted to C23 for uv project

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Compute Internet checksum over buf[0..length).
// Returns raw (non-inverted) 32-bit accumulator — call checksum_finish() after.
uint32_t checksum_calculate(const void *buf, size_t length);

// Fold carry bits and invert → final 16-bit checksum ready to put in header.
uint16_t checksum_finish(uint32_t sum);

// Full IPv4 pseudo-header + payload checksum (TCP/UDP/ICMP).
// All addresses in host byte order.
uint16_t checksum_ipv4(uint32_t src, uint32_t dst,
                       uint8_t proto, size_t payload_len,
                       const void *payload);

// Full IPv6 pseudo-header + payload checksum.
uint16_t checksum_ipv6(const uint8_t src[16], const uint8_t dst[16],
                       uint8_t proto, size_t payload_len,
                       const void *payload);

#ifdef __cplusplus
}
#endif
