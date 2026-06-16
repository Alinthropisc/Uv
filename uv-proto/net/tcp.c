// net/tcp.c — Raw TCP engine implementation (C23)
// Inspired by masscan's PF_PACKET/MMAP transmit ring approach.
// Full implementation requires AF_PACKET on Linux (or WinPcap on Windows).

#include "tcp.h"

#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <threads.h>

// ── internal ring structure ───────────────────────────────────────────────────

#define UV_RING_SLOTS 65536  // power-of-two for fast modulo

typedef struct {
    uint32_t dst_ip;
    uint16_t dst_port;
    bool     pending;
} uv_slot_t;

struct uv_tcp_ring {
    uv_tcp_cfg_t     cfg;
    uv_slot_t        slots[UV_RING_SLOTS];
    atomic_uint      head;
    atomic_uint      tail;
    int              raw_fd;
    uv_tcp_result_cb cb;
    void            *cb_ctx;
};

// ── public API ────────────────────────────────────────────────────────────────

uv_tcp_ring_t *uv_tcp_ring_create(const uv_tcp_cfg_t *cfg)
{
    uv_tcp_ring_t *ring = calloc(1, sizeof(*ring));
    if (!ring) return NULL;  // nullptr is C23; use NULL for broader compat

    ring->cfg  = *cfg;
    ring->head = 0;
    ring->tail = 0;

    // TODO: socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)) + PACKET_TX_RING mmap
    ring->raw_fd = -1;

    return ring;
}

void uv_tcp_ring_destroy(uv_tcp_ring_t *ring)
{
    if (!ring) return;
    // TODO: munmap TX/RX rings, close raw_fd
    free(ring);
}

bool uv_tcp_send_syn(uv_tcp_ring_t *ring, uint32_t dst_ip, uint16_t dst_port)
{
    unsigned head = atomic_load_explicit(&ring->head, memory_order_relaxed);
    unsigned tail = atomic_load_explicit(&ring->tail, memory_order_acquire);

    if ((head - tail) >= UV_RING_SLOTS) return false;

    uv_slot_t *slot = &ring->slots[head & (UV_RING_SLOTS - 1)];
    slot->dst_ip   = dst_ip;
    slot->dst_port = dst_port;
    slot->pending  = true;

    atomic_store_explicit(&ring->head, head + 1, memory_order_release);

    // TODO: craft Ethernet/IP/TCP SYN frame, write to PACKET_TX_RING slot, tp_status = TP_STATUS_SEND_REQUEST
    return true;
}

void uv_tcp_recv_loop(uv_tcp_ring_t *ring, uv_tcp_result_cb cb, void *ctx)
{
    ring->cb     = cb;
    ring->cb_ctx = ctx;

    // TODO: poll PACKET_RX_RING for SYN-ACK / RST:
    //
    // while (running) {
    //     struct tpacket3_hdr *hdr = rx_next(ring);
    //     if (frame_is_syn_ack(hdr)) {
    //         uv_tcp_result_t r = { .ip = src_ip, .port = src_port, .open = true };
    //         cb(&r, ctx);
    //     } else if (frame_is_rst(hdr)) {
    //         uv_tcp_result_t r = { .ip = src_ip, .port = src_port, .open = false };
    //         cb(&r, ctx);
    //     }
    //     rx_advance(ring);
    // }
}

void uv_tcp_flush(uv_tcp_ring_t *ring)
{
    // TODO: spin until head == tail (all slots drained) or global timeout
    (void)ring;
}
