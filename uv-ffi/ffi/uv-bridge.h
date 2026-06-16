/* uv-bridge.h — Rust↔C bridge: SYN scan control plane.
 * The Rust orchestrator drives the C TX/RX engine via this API.
 */
#pragma once
#include "uv-ffi.h"

/* Opaque scan engine handle */
typedef struct uv_engine uv_engine_t;

/* Create a scan engine with the given config.
 * Opens AF_PACKET socket — requires root or CAP_NET_RAW.
 * Returns NULL on error; use uv_engine_error() for details. */
uv_engine_t *uv_engine_create(const uv_scan_cfg_t *cfg);

/* Destroy engine, close socket */
void uv_engine_destroy(uv_engine_t *eng);

/* Register callback for open ports (called from RX thread) */
void uv_engine_set_cb(uv_engine_t *eng, uv_port_cb cb, void *ctx);

/* Send SYN to one target; uses internal throttle + BlackRock2 cookie */
uv_status_t uv_engine_send_syn(uv_engine_t *eng,
                                uv_ipv4_t dst_ip,
                                uint16_t  dst_port);

/* Start background RX thread — calls cb for each open port */
uv_status_t uv_engine_start_rx(uv_engine_t *eng);

/* Signal RX thread to stop + join */
void uv_engine_stop_rx(uv_engine_t *eng);

/* Human-readable error string for last operation */
const char *uv_engine_error(const uv_engine_t *eng);

/* Stats snapshot (thread-safe read) */
typedef struct uv_engine_stats {
    uint64_t sent;
    uint64_t recv;
    uint64_t open;
    double   rate_pps;
} uv_engine_stats_t;

void uv_engine_stats(const uv_engine_t *eng, uv_engine_stats_t *out);
