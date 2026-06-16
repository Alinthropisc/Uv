#pragma once
// net/rawsock_linux.h — AF_PACKET raw socket TX/RX engine (Linux only)
// Inspired by masscan rawsock architecture; C23, no libpcap dependency.

#include "pkt.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque TX/RX context
typedef struct uv_rawsock uv_rawsock_t;

typedef struct {
    const char *iface;        // "eth0"
    uint32_t    src_ip;       // host byte order
    uint8_t     src_mac[6];
    uint8_t     dst_mac[6];   // gateway MAC
    uint16_t    src_port_lo;  // ephemeral source port range
    uint16_t    src_port_hi;
    uint32_t    send_buf_size; // SO_SNDBUF bytes (0 = default 4MB)
} uv_rawsock_cfg_t;

// Called from rx thread for every SYN-ACK / RST received.
typedef void (*uv_rawsock_rx_cb)(uint32_t ip, uint16_t port,
                                  bool open, void *ctx);

// Create raw socket bound to iface.  Returns NULL on error (check errno).
uv_rawsock_t *uv_rawsock_open(const uv_rawsock_cfg_t *cfg);
void          uv_rawsock_close(uv_rawsock_t *rs);

// Send one pre-built frame.  Non-blocking; returns false if send() fails.
bool uv_rawsock_send(uv_rawsock_t *rs, const uv_pkt_t *pkt);

// Blocking receive loop — call in a dedicated thread.
// Exits when uv_rawsock_stop() sets the stop flag.
void uv_rawsock_rx_loop(uv_rawsock_t *rs, uv_rawsock_rx_cb cb, void *ctx);

// Signal the rx loop to exit.
void uv_rawsock_stop(uv_rawsock_t *rs);

// Get interface index (needed for sendto sockaddr_ll).
int uv_rawsock_ifindex(uv_rawsock_t *rs);

#ifdef __cplusplus
}
#endif
