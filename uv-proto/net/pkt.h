#pragma once
// net/pkt.h — Ethernet + IPv4 + TCP/UDP/ICMP packet builder (C23, no deps)
// Builds raw frames ready for AF_PACKET sendto()

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ── Wire-format structs (packed, big-endian fields) ─────────────────────────

typedef struct [[gnu::packed]] {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t ethertype;   // 0x0800 = IPv4
} uv_eth_hdr_t;

typedef struct [[gnu::packed]] {
    uint8_t  ver_ihl;     // 0x45 = version 4, IHL 5 (no options)
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t flags_frag;  // DF bit = 0x4000
    uint8_t  ttl;
    uint8_t  proto;       // 6=TCP 17=UDP 1=ICMP
    uint16_t checksum;
    uint32_t src;
    uint32_t dst;
} uv_ip4_hdr_t;

typedef struct [[gnu::packed]] {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_off;    // header len in 32-bit words << 4
    uint8_t  flags;       // SYN=0x02 ACK=0x10 RST=0x04 FIN=0x01
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
} uv_tcp_hdr_t;

typedef struct [[gnu::packed]] {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} uv_udp_hdr_t;

typedef struct [[gnu::packed]] {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
} uv_icmp_hdr_t;

// TCP flags
#define UV_TCP_SYN  0x02u
#define UV_TCP_ACK  0x10u
#define UV_TCP_RST  0x04u
#define UV_TCP_FIN  0x01u
#define UV_TCP_PSH  0x08u

// ── Frame buffer ─────────────────────────────────────────────────────────────

// Max raw frame we ever build (1 MTU)
#define UV_PKT_MAXLEN 1514u

typedef struct {
    uint8_t  data[UV_PKT_MAXLEN];
    uint16_t len;
} uv_pkt_t;

// ── Builder API ──────────────────────────────────────────────────────────────

// Build a TCP SYN frame.
//   src_mac / dst_mac : 6-byte arrays
//   src_ip / dst_ip   : host byte order
//   src_port/dst_port : host byte order
//   seq               : initial sequence number (use blackrock result)
// Returns frame length written into pkt->data, or 0 on error.
uint16_t uv_pkt_build_syn(uv_pkt_t *pkt,
                           const uint8_t src_mac[6],
                           const uint8_t dst_mac[6],
                           uint32_t src_ip, uint32_t dst_ip,
                           uint16_t src_port, uint16_t dst_port,
                           uint32_t seq);

// Build a UDP probe frame with payload.
uint16_t uv_pkt_build_udp(uv_pkt_t *pkt,
                           const uint8_t src_mac[6],
                           const uint8_t dst_mac[6],
                           uint32_t src_ip, uint32_t dst_ip,
                           uint16_t src_port, uint16_t dst_port,
                           const uint8_t *payload, uint16_t payload_len);

// Build an ICMP echo request.
uint16_t uv_pkt_build_icmp_echo(uv_pkt_t *pkt,
                                  const uint8_t src_mac[6],
                                  const uint8_t dst_mac[6],
                                  uint32_t src_ip, uint32_t dst_ip,
                                  uint16_t id, uint16_t seq);

// Parse an incoming raw frame — returns true if it's a TCP SYN-ACK or RST
// targeting our src_ip:src_port.  Fills rsp_ip / rsp_port with sender.
bool uv_pkt_parse_tcp_rsp(const uint8_t *frame, size_t len,
                            uint32_t our_ip, uint16_t our_port_lo,
                            uint16_t our_port_hi,
                            uint32_t *rsp_ip, uint16_t *rsp_port,
                            bool *is_open);

#ifdef __cplusplus
}
#endif
