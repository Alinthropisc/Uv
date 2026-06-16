#pragma once
// net/icmp.h — ICMP echo ping sweep + port-unreachable parser (C23)

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t ip;
    bool     alive;       // true = echo reply received
    uint32_t rtt_us;      // round-trip time in microseconds
} uv_ping_result_t;

typedef void (*uv_ping_result_cb)(const uv_ping_result_t *result, void *ctx);

// Send single ICMP echo; result fires via cb (reply or timeout)
bool uv_icmp_ping(uint32_t dst_ip, uint32_t timeout_ms,
                  uv_ping_result_cb cb, void *ctx);

// Bulk ping sweep over ip array
void uv_icmp_sweep(const uint32_t *ips, size_t ip_count,
                   uint32_t timeout_ms,
                   uv_ping_result_cb cb, void *ctx);

// Parse ICMP raw buffer; true = ICMP port-unreachable for dst_port (closed UDP)
bool uv_icmp_is_port_unreachable(const uint8_t *buf, size_t len,
                                 uint16_t dst_port);

#ifdef __cplusplus
}
#endif
