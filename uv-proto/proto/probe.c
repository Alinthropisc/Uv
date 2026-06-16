// proto/probe.c — Intelligent protocol probe dispatcher (C23)

#include "probe.h"
#include "../net/tcp.h"
#include "../net/udp.h"

#include <string.h>
#include <stdlib.h>

// ── Built-in probe payloads ───────────────────────────────────────────────────

static const uint8_t PAYLOAD_HTTP[] = "GET / HTTP/1.0\r\n\r\n";

// DNS version.bind TXT query over UDP (CHAOS class)
static const uint8_t PAYLOAD_DNS[] = {
    0x00, 0x06, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x07,'v','e','r','s','i','o','n',
    0x04,'b','i','n','d',
    0x00, 0x00, 0x10, 0x00, 0x03,
};

static const uint8_t PAYLOAD_EMPTY[] = "";

static const uv_probe_t PROBE_TABLE[] = {
    [UV_PROBE_NULL]  = { UV_PROBE_NULL, PAYLOAD_EMPTY, 0,                      false },
    [UV_PROBE_HTTP]  = { UV_PROBE_HTTP, PAYLOAD_HTTP,  sizeof(PAYLOAD_HTTP)-1,  false },
    [UV_PROBE_SSH]   = { UV_PROBE_SSH,  PAYLOAD_EMPTY, 0,                      false },
    [UV_PROBE_FTP]   = { UV_PROBE_FTP,  PAYLOAD_EMPTY, 0,                      false },
    [UV_PROBE_SMTP]  = { UV_PROBE_SMTP, PAYLOAD_EMPTY, 0,                      false },
    [UV_PROBE_DNS]   = { UV_PROBE_DNS,  PAYLOAD_DNS,   sizeof(PAYLOAD_DNS),    true  },
};

// ── Port → probe heuristic ────────────────────────────────────────────────────

const uv_probe_t *uv_probe_select(uint16_t port, bool is_udp)
{
    if (is_udp) {
        if (port == 53) return &PROBE_TABLE[UV_PROBE_DNS];
        return &PROBE_TABLE[UV_PROBE_NULL];
    }

    switch (port) {
        case 80: case 8080: case 8000: case 3000:
            return &PROBE_TABLE[UV_PROBE_HTTP];
        case 22:
            return &PROBE_TABLE[UV_PROBE_SSH];
        case 21:
            return &PROBE_TABLE[UV_PROBE_FTP];
        case 25: case 587: case 465:
            return &PROBE_TABLE[UV_PROBE_SMTP];
        default:
            return &PROBE_TABLE[UV_PROBE_NULL];
    }
}

// ── Synchronous single-port probe ─────────────────────────────────────────────

bool uv_probe_dispatch(const uv_probe_t  *probe,
                       uint32_t           ip,
                       uint16_t           port,
                       uint32_t           timeout_ms,
                       uv_probe_result_t *out)
{
    if (!probe || !out) return false;
    memset(out, 0, sizeof(*out));
    out->ip   = ip;
    out->port = port;

    // TODO: connect → send payload → recv banner → match service signatures
    (void)timeout_ms;
    return false;  // stub
}

// ── Bulk async scan (TCP path) ────────────────────────────────────────────────

typedef struct {
    uv_probe_result_cb cb;
    void              *ctx;
} scan_ctx_t;

static void on_tcp_result(const uv_tcp_result_t *r, void *ctx)
{
    scan_ctx_t        *sc  = ctx;
    uv_probe_result_t  res = {0};

    res.ip   = r->ip;
    res.port = r->port;
    res.open = r->open;

    if (r->open) {
        const uv_probe_t *probe = uv_probe_select(r->port, false);
        uv_probe_dispatch(probe, r->ip, r->port, 1500, &res);
    }

    sc->cb(&res, sc->ctx);
}

void uv_probe_scan(const uint32_t    *ips,
                   size_t             ip_count,
                   const uint16_t    *ports,
                   size_t             port_count,
                   uint32_t           timeout_ms,
                   uv_probe_result_cb cb,
                   void              *ctx)
{
    scan_ctx_t sc = { cb, ctx };

    uv_tcp_cfg_t cfg = {
        .iface       = "eth0",
        .src_ip      = 0,
        .src_port_lo = 40000,
        .src_port_hi = 60000,
        .batch_size  = 10000,
        .timeout_ms  = timeout_ms,
    };

    uv_tcp_ring_t *ring = uv_tcp_ring_create(&cfg);
    if (!ring) return;

    for (size_t i = 0; i < ip_count; i++) {
        for (size_t j = 0; j < port_count; j++) {
            // Back-pressure: flush when ring is full
            while (!uv_tcp_send_syn(ring, ips[i], ports[j]))
                uv_tcp_flush(ring);
        }
    }

    uv_tcp_recv_loop(ring, on_tcp_result, &sc);
    uv_tcp_flush(ring);
    uv_tcp_ring_destroy(ring);
}
