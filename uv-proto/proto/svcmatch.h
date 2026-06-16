#pragma once
// proto/svcmatch.h — Service name lookup from port + protocol
// Uses nmap-service-probes data embedded as a compact table (no file I/O).

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint16_t    port;
    uint8_t     proto;   // 6=TCP 17=UDP
    const char    *service;   // e.g. "ssh", "http"
    const uint8_t *probe;     // bytes to send (NULL = passive listen)
    uint16_t       probe_len;
} uv_svc_entry_t;

// Returns service name for port/proto, or "unknown".
const char *uv_svc_name(uint16_t port, uint8_t proto);

// Returns probe payload to send for active banner grabbing, or NULL.
// probe_len is filled with the payload length.
const uint8_t *uv_svc_probe(uint16_t port, uint8_t proto, uint16_t *probe_len);

// Match a received banner against known signatures.
// Returns service name on match, NULL if unrecognised.
const char *uv_svc_match_banner(const uint8_t *banner, uint16_t len,
                                 uint16_t port, uint8_t proto);

#ifdef __cplusplus
}
#endif
