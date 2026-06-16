// net/icmp.c — ICMP engine (C23)

#include "icmp.h"
#include "eth.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef struct __attribute__((packed)) {
    uint8_t  type, code;
    uint16_t checksum, id, seq;
} icmp_echo_t;

typedef struct __attribute__((packed)) {
    uint8_t  type, code;
    uint16_t checksum;
    uint32_t unused;
} icmp_unreach_t;

typedef struct __attribute__((packed)) {
    uint8_t  version_ihl, dscp;
    uint16_t total_len, id, flags_frag;
    uint8_t  ttl, protocol;
    uint16_t checksum;
    uint32_t src_ip, dst_ip;
} ip4_lite_t;

bool uv_icmp_ping(uint32_t dst_ip, uint32_t timeout_ms,
                  uv_ping_result_cb cb, void *ctx)
{
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (fd < 0) return false;

    icmp_echo_t req = {
        .type = 8, .code = 0,
        .id   = (uint16_t)(dst_ip & 0xFFFF), .seq = 1,
    };
    req.checksum = uv_inet_checksum(&req, sizeof(req));

    struct sockaddr_in dst_addr = {
        .sin_family = AF_INET,
        .sin_addr   = { .s_addr = htonl(dst_ip) },
    };

    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    sendto(fd, &req, sizeof(req), 0,
           (struct sockaddr *)&dst_addr, sizeof(dst_addr));

    uint8_t rxbuf[256];
    struct timeval tv = { .tv_sec  = timeout_ms / 1000,
                          .tv_usec = (timeout_ms % 1000) * 1000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ssize_t n = recv(fd, rxbuf, sizeof(rxbuf), 0);

    struct timespec t1;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    close(fd);

    uv_ping_result_t result = { .ip = dst_ip, .alive = false };
    if (n >= (ssize_t)(sizeof(ip4_lite_t) + sizeof(icmp_echo_t))) {
        icmp_echo_t *rep = (icmp_echo_t *)(rxbuf + sizeof(ip4_lite_t));
        if (rep->type == 0 && rep->id == req.id) {
            result.alive  = true;
            result.rtt_us = (uint32_t)(
                (t1.tv_sec  - t0.tv_sec)  * 1000000 +
                (t1.tv_nsec - t0.tv_nsec) / 1000);
        }
    }

    if (cb) cb(&result, ctx);
    return result.alive;
}

void uv_icmp_sweep(const uint32_t *ips, size_t ip_count,
                   uint32_t timeout_ms, uv_ping_result_cb cb, void *ctx)
{
    for (size_t i = 0; i < ip_count; i++)
        uv_icmp_ping(ips[i], timeout_ms, cb, ctx);
    // TODO: parallelise — single raw socket recv loop + batch sends
}

bool uv_icmp_is_port_unreachable(const uint8_t *buf, size_t len,
                                 uint16_t dst_port)
{
    size_t min_len = sizeof(ip4_lite_t) + sizeof(icmp_unreach_t)
                   + sizeof(ip4_lite_t) + 8;
    if (len < min_len) return false;

    const ip4_lite_t    *outer = (const ip4_lite_t *)buf;
    size_t               ohdr  = (outer->version_ihl & 0x0F) * 4;
    const icmp_unreach_t *unr  = (const icmp_unreach_t *)(buf + ohdr);

    if (unr->type != 3 || unr->code != 3) return false;

    const ip4_lite_t *inner = (const ip4_lite_t *)(buf + ohdr + sizeof(*unr));
    size_t            ihdr  = (inner->version_ihl & 0x0F) * 4;
    const uint8_t    *udp   = (const uint8_t *)inner + ihdr;

    uint16_t orig_dst = (uint16_t)(udp[2] << 8 | udp[3]);
    return orig_dst == dst_port;
}
