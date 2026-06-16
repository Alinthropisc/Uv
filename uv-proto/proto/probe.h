#pragma once
// proto/probe.h — Intelligent protocol probe dispatcher (C23)
// nmap-style service detection: pick the right payload for each port/protocol

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Known probe types (extend as needed)
typedef enum {
    UV_PROBE_NULL   = 0,  // empty TCP connect (generic open check)
    UV_PROBE_HTTP   = 1,  // GET / HTTP/1.0\r\n\r\n
    UV_PROBE_HTTPS  = 2,  // TLS ClientHello
    UV_PROBE_SSH    = 3,  // read server banner
    UV_PROBE_FTP    = 4,  // read server banner
    UV_PROBE_SMTP   = 5,  // read server banner
    UV_PROBE_DNS    = 6,  // UDP: version.bind TXT query
    UV_PROBE_SNMP   = 7,  // UDP: SNMPv1 GetRequest
    UV_PROBE_CUSTOM = 255,
} uv_probe_type_t;

typedef struct {
    uv_probe_type_t type;
    const uint8_t  *payload;
    size_t          payload_len;
    bool            is_udp;
} uv_probe_t;

typedef struct {
    uint32_t ip;
    uint16_t port;
    bool     open;
    uint8_t  banner[256];
    size_t   banner_len;
    char     service[32];  // detected service name, e.g. "ssh", "http"
} uv_probe_result_t;

typedef void (*uv_probe_result_cb)(const uv_probe_result_t *result, void *ctx);

// Select the best probe for a port (nmap-service-probes style heuristic)
const uv_probe_t *uv_probe_select(uint16_t port, bool is_udp);

// Synchronous single-port probe + banner grab
bool uv_probe_dispatch(const uv_probe_t  *probe,
                       uint32_t           ip,
                       uint16_t           port,
                       uint32_t           timeout_ms,
                       uv_probe_result_t *out);

// Bulk async probe scan over net/tcp + net/udp engines
void uv_probe_scan(const uint32_t    *ips,
                   size_t             ip_count,
                   const uint16_t    *ports,
                   size_t             port_count,
                   uint32_t           timeout_ms,
                   uv_probe_result_cb cb,
                   void              *ctx);

#ifdef __cplusplus
}
#endif
