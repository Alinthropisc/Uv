#pragma once
// net/tcp.h — Raw TCP send/receive engine (C23)
// Target throughput: 10M pps (masscan-style PF_PACKET / raw socket path)

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque handle to a raw TCP transmit ring
typedef struct uv_tcp_ring uv_tcp_ring_t;

typedef struct {
    const char *iface;       // network interface, e.g. "eth0"
    uint32_t    src_ip;      // source IPv4 (host byte order)
    uint16_t    src_port_lo;
    uint16_t    src_port_hi;
    uint32_t    batch_size;  // packets per send burst
    uint32_t    timeout_ms;
} uv_tcp_cfg_t;

typedef struct {
    uint32_t ip;
    uint16_t port;
    bool     open;
} uv_tcp_result_t;

// Called for every responsive port (from rx thread)
typedef void (*uv_tcp_result_cb)(const uv_tcp_result_t *result, void *ctx);

uv_tcp_ring_t *uv_tcp_ring_create(const uv_tcp_cfg_t *cfg);
void           uv_tcp_ring_destroy(uv_tcp_ring_t *ring);

// Enqueue a SYN; returns false when ring is full
bool uv_tcp_send_syn(uv_tcp_ring_t *ring, uint32_t dst_ip, uint16_t dst_port);

// Drain receive ring and fire callbacks; run in dedicated rx thread
void uv_tcp_recv_loop(uv_tcp_ring_t *ring, uv_tcp_result_cb cb, void *ctx);

// Flush pending SYNs and wait for all responses / timeouts
void uv_tcp_flush(uv_tcp_ring_t *ring);

#ifdef __cplusplus
}
#endif
