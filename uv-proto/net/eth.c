// net/eth.c — Raw Ethernet + IPv4 + TCP/UDP frame builder (C23)

#include "eth.h"

#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

// ── RFC 1071 internet checksum ────────────────────────────────────────────────

uint16_t uv_inet_checksum(const void *data, size_t len)
{
    const uint8_t *ptr = data;
    uint32_t       sum = 0;

    while (len > 1) {
        sum += (uint32_t)((uint16_t)ptr[0] << 8 | ptr[1]);
        ptr += 2; len -= 2;
    }
    if (len == 1) sum += (uint32_t)(*ptr << 8);

    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

// ── TCP pseudo-header checksum ────────────────────────────────────────────────

typedef struct __attribute__((packed)) {
    uint32_t src_ip, dst_ip;
    uint8_t  zero, proto;
    uint16_t tcp_len;
} pseudo_hdr_t;

uint16_t uv_tcp_checksum(uint32_t src_ip, uint32_t dst_ip,
                         const void *tcp_seg, size_t tcp_len)
{
    pseudo_hdr_t ph = {
        .src_ip  = htonl(src_ip), .dst_ip = htonl(dst_ip),
        .zero    = 0, .proto = 6,
        .tcp_len = htons((uint16_t)tcp_len),
    };
    uint32_t sum = 0;
    const uint8_t *p; size_t n;

    p = (const uint8_t *)&ph; n = sizeof(ph);
    while (n > 1) { sum += (uint32_t)((uint16_t)p[0] << 8 | p[1]); p += 2; n -= 2; }

    p = tcp_seg; n = tcp_len;
    while (n > 1) { sum += (uint32_t)((uint16_t)p[0] << 8 | p[1]); p += 2; n -= 2; }
    if (n == 1)   sum += (uint32_t)(*p << 8);

    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

// ── Frame structs ─────────────────────────────────────────────────────────────

typedef struct __attribute__((packed)) {
    uint8_t dst[UV_ETH_ALEN], src[UV_ETH_ALEN];
    uint16_t ethertype;
} eth_hdr_t;

typedef struct __attribute__((packed)) {
    uint8_t  version_ihl, dscp_ecn;
    uint16_t total_len, id, flags_frag;
    uint8_t  ttl, protocol;
    uint16_t checksum;
    uint32_t src_ip, dst_ip;
} ip4_hdr_t;

typedef struct __attribute__((packed)) {
    uint16_t src_port, dst_port;
    uint32_t seq, ack;
    uint8_t  data_offset, flags;
    uint16_t window, checksum, urgent;
} tcp_hdr_t;

typedef struct __attribute__((packed)) {
    uint16_t src_port, dst_port, length, checksum;
} udp_hdr_t;

// ── SYN builder ───────────────────────────────────────────────────────────────

size_t uv_eth_build_syn(uint8_t *buf, size_t buf_len,
                        const uint8_t src_mac[UV_ETH_ALEN],
                        const uint8_t dst_mac[UV_ETH_ALEN],
                        uint32_t src_ip, uint32_t dst_ip,
                        uint16_t src_port, uint16_t dst_port,
                        uint32_t isn)
{
    const size_t frame_len = UV_ETH_HDR + UV_IP4_HDR + UV_TCP_HDR;
    if (buf_len < frame_len) return 0;
    memset(buf, 0, frame_len);

    eth_hdr_t *eth = (eth_hdr_t *)buf;
    memcpy(eth->dst, dst_mac, UV_ETH_ALEN);
    memcpy(eth->src, src_mac, UV_ETH_ALEN);
    eth->ethertype = htons(0x0800);

    ip4_hdr_t *ip = (ip4_hdr_t *)(buf + UV_ETH_HDR);
    ip->version_ihl = 0x45;
    ip->total_len   = htons(UV_IP4_HDR + UV_TCP_HDR);
    ip->ttl         = 64;
    ip->protocol    = 6;
    ip->src_ip      = htonl(src_ip);
    ip->dst_ip      = htonl(dst_ip);
    ip->checksum    = uv_inet_checksum(ip, UV_IP4_HDR);

    tcp_hdr_t *tcp = (tcp_hdr_t *)(buf + UV_ETH_HDR + UV_IP4_HDR);
    tcp->src_port    = htons(src_port);
    tcp->dst_port    = htons(dst_port);
    tcp->seq         = htonl(isn);
    tcp->data_offset = 0x50;
    tcp->flags       = 0x02; // SYN
    tcp->window      = htons(65535);
    tcp->checksum    = uv_tcp_checksum(src_ip, dst_ip, tcp, UV_TCP_HDR);

    return frame_len;
}

// ── UDP builder ───────────────────────────────────────────────────────────────

size_t uv_eth_build_udp(uint8_t *buf, size_t buf_len,
                        const uint8_t src_mac[UV_ETH_ALEN],
                        const uint8_t dst_mac[UV_ETH_ALEN],
                        uint32_t src_ip, uint32_t dst_ip,
                        uint16_t src_port, uint16_t dst_port,
                        const uint8_t *payload, size_t payload_len)
{
    const size_t frame_len = UV_ETH_HDR + UV_IP4_HDR + UV_UDP_HDR + payload_len;
    if (buf_len < frame_len) return 0;
    memset(buf, 0, frame_len);

    eth_hdr_t *eth = (eth_hdr_t *)buf;
    memcpy(eth->dst, dst_mac, UV_ETH_ALEN);
    memcpy(eth->src, src_mac, UV_ETH_ALEN);
    eth->ethertype = htons(0x0800);

    ip4_hdr_t *ip = (ip4_hdr_t *)(buf + UV_ETH_HDR);
    ip->version_ihl = 0x45;
    ip->total_len   = htons((uint16_t)(UV_IP4_HDR + UV_UDP_HDR + payload_len));
    ip->ttl         = 64;
    ip->protocol    = 17;
    ip->src_ip      = htonl(src_ip);
    ip->dst_ip      = htonl(dst_ip);
    ip->checksum    = uv_inet_checksum(ip, UV_IP4_HDR);

    udp_hdr_t *udp = (udp_hdr_t *)(buf + UV_ETH_HDR + UV_IP4_HDR);
    udp->src_port = htons(src_port);
    udp->dst_port = htons(dst_port);
    udp->length   = htons((uint16_t)(UV_UDP_HDR + payload_len));
    udp->checksum = 0; // optional for IPv4

    if (payload && payload_len)
        memcpy(buf + UV_ETH_HDR + UV_IP4_HDR + UV_UDP_HDR, payload, payload_len);

    return frame_len;
}
