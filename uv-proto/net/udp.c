// net/udp.c — Raw UDP probe engine (C23)

#include "udp.h"

#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>

#define UV_UDP_RING_SLOTS 32768

typedef struct {
    uint32_t dst_ip;
    uint16_t dst_port;
    uint8_t  payload[64];
    size_t   payload_len;
    bool     pending;
} uv_udp_slot_t;

struct uv_udp_ring {
    uv_udp_cfg_t     cfg;
    uv_udp_slot_t    slots[UV_UDP_RING_SLOTS];
    atomic_uint      head;
    atomic_uint      tail;
    int              raw_fd;
    uv_udp_result_cb cb;
    void            *cb_ctx;
};

uv_udp_ring_t *uv_udp_ring_create(const uv_udp_cfg_t *cfg)
{
    uv_udp_ring_t *ring = calloc(1, sizeof(*ring));
    if (!ring) return NULL;

    ring->cfg    = *cfg;
    ring->head   = 0;
    ring->tail   = 0;
    ring->raw_fd = -1;

    // TODO: socket(AF_INET, SOCK_RAW, IPPROTO_UDP) + IP_HDRINCL
    return ring;
}

void uv_udp_ring_destroy(uv_udp_ring_t *ring)
{
    if (!ring) return;
    free(ring);
}

bool uv_udp_send_probe(uv_udp_ring_t *ring,
                       uint32_t       dst_ip,
                       uint16_t       dst_port,
                       const uint8_t *payload,
                       size_t         payload_len)
{
    unsigned head = atomic_load_explicit(&ring->head, memory_order_relaxed);
    unsigned tail = atomic_load_explicit(&ring->tail, memory_order_acquire);

    if ((head - tail) >= UV_UDP_RING_SLOTS) return false;

    uv_udp_slot_t *slot = &ring->slots[head & (UV_UDP_RING_SLOTS - 1)];
    slot->dst_ip   = dst_ip;
    slot->dst_port = dst_port;

    size_t copy_len = payload_len < sizeof(slot->payload) ? payload_len : sizeof(slot->payload);
    memcpy(slot->payload, payload, copy_len);
    slot->payload_len = copy_len;
    slot->pending     = true;

    atomic_store_explicit(&ring->head, head + 1, memory_order_release);

    // TODO: craft IP/UDP datagram and sendmsg() via raw_fd
    return true;
}

void uv_udp_recv_loop(uv_udp_ring_t *ring, uv_udp_result_cb cb, void *ctx)
{
    ring->cb     = cb;
    ring->cb_ctx = ctx;

    // TODO: recvmsg loop; distinguish UDP response vs ICMP port-unreachable
    //
    // while (running) {
    //     ssize_t n = recvmsg(ring->raw_fd, &msg, 0);
    //     if (is_icmp_unreachable(buf, n)) { /* closed */ }
    //     else { uv_udp_result_t r = {…}; cb(&r, ctx); }
    // }
}

void uv_udp_flush(uv_udp_ring_t *ring)
{
    (void)ring;
    // TODO: drain ring slots and wait ICMP timeout windows
}
