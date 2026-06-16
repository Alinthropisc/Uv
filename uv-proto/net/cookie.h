#pragma once
// net/cookie.h — Stateless SYN cookie engine (C23)
// Encodes target ip:port into TCP ISN → no per-connection state table needed

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Call once at startup with a random 64-bit seed
void uv_cookie_init(uint64_t seed);

// Produce a 32-bit ISN embedding ip:port identity
uint32_t uv_cookie_encode(uint32_t dst_ip, uint16_t dst_port,
                          uint32_t src_ip, uint16_t src_port);

// Validate incoming SYN-ACK: returns true if valid cookie
// fills out_target_ip / out_target_port with the original probe target
bool uv_cookie_verify(uint32_t isn,
                      uint32_t src_ip,  uint16_t src_port,
                      uint32_t dst_ip,  uint16_t dst_port,
                      uint32_t *out_target_ip,
                      uint16_t *out_target_port);

#ifdef __cplusplus
}
#endif
