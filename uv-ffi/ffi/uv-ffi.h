/* uv-ffi.h — master FFI header: types shared between C layer and Rust.
 * All structs are packed/stable-ABI so Rust #[repr(C)] can mirror them.
 */
#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* ---- Result type ---- */
typedef enum uv_status {
    UV_OK           = 0,
    UV_ERR_IO       = 1,
    UV_ERR_PERM     = 2,   /* needs root / CAP_NET_RAW */
    UV_ERR_NOMEM    = 3,
    UV_ERR_INVAL    = 4,
    UV_ERR_TIMEOUT  = 5,
    UV_ERR_NODEV    = 6,   /* interface not found */
} uv_status_t;

/* ---- IP address (v4 only for raw path) ---- */
typedef uint32_t uv_ipv4_t;   /* host byte order */

/* ---- MAC address ---- */
typedef struct uv_mac { uint8_t b[6]; } uv_mac_t;

/* ---- Port record (open port result) ---- */
typedef struct uv_port_rec {
    uv_ipv4_t ip;
    uint16_t  port;
    uint8_t   proto;    /* IPPROTO_TCP=6 / IPPROTO_UDP=17 */
    uint8_t   state;    /* 0=open 1=closed 2=filtered */
    uint32_t  rtt_us;
} uv_port_rec_t;

/* ---- Scan configuration passed from Rust → C ---- */
typedef struct uv_scan_cfg {
    uv_ipv4_t  src_ip;
    uv_mac_t   src_mac;
    uv_mac_t   gw_mac;
    char       iface[16];   /* e.g. "eth0" */
    uint64_t   rate_pps;
    uint32_t   timeout_ms;
    uint32_t   retries;
    bool       randomise;   /* BlackRock2 shuffle */
    uint64_t   seed;        /* shuffle seed */
} uv_scan_cfg_t;

/* Callback invoked from C RX thread for each open port found */
typedef void (*uv_port_cb)(const uv_port_rec_t *rec, void *ctx);

/* ---- Version ---- */
const char *uv_version(void);
