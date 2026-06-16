#pragma once
// net/udp.h — Raw UDP probe engine (C23)

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct uv_udp_ring uv_udp_ring_t;

typedef struct {
    const char *iface;
    uint32_t    src_ip;
    uint32_t    batch_size;
    uint32_t    timeout_ms;
} uv_udp_cfg_t;

typedef struct {
    uint32_t ip;
    uint16_t port;
    bool     open;           // no ICMP port-unreachable received = open/filtered
    uint8_t  response[64];
    size_t   response_len;
} uv_udp_result_t;

typedef void (*uv_udp_result_cb)(const uv_udp_result_t *result, void *ctx);

uv_udp_ring_t *uv_udp_ring_create(const uv_udp_cfg_t *cfg);
void           uv_udp_ring_destroy(uv_udp_ring_t *ring);

// Send a UDP probe with optional nmap-style payload
bool uv_udp_send_probe(uv_udp_ring_t *ring,
                       uint32_t       dst_ip,
                       uint16_t       dst_port,
                       const uint8_t *payload,
                       size_t         payload_len);

void uv_udp_recv_loop(uv_udp_ring_t *ring, uv_udp_result_cb cb, void *ctx);
void uv_udp_flush(uv_udp_ring_t *ring);

#ifdef __cplusplus
}
#endif
