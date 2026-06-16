#pragma once
// proto/banner.h — Banner grabber + service fingerprinting (C23)
// nmap-service-probes style signature matching in C

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define UV_BANNER_MAX 512

typedef struct {
    uint16_t port;
    char     service[32];    // "ssh", "http", "ftp", "smtp", ...
    char     version[64];    // "OpenSSH 8.9p1"
    char     product[64];    // "nginx"
    char     info[128];
    uint8_t  raw[UV_BANNER_MAX];
    size_t   raw_len;
} uv_banner_t;

// TCP connect, send probe, recv banner (blocking, timeout in ms)
bool uv_banner_grab(uint32_t ip, uint16_t port,
                    const uint8_t *probe, size_t probe_len,
                    uint32_t timeout_ms,
                    uv_banner_t *out);

// Match banner->raw against built-in signatures; fills service/version/product
bool uv_banner_identify(uv_banner_t *banner);

// Fast port→service name without I/O (IANA well-known ports)
const char *uv_banner_port_name(uint16_t port, bool is_udp);

#ifdef __cplusplus
}
#endif
