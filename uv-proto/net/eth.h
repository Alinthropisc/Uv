#pragma once
// net/eth.h — Raw Ethernet + IPv4 + TCP/UDP frame builder (C23)
// Constructs complete L2 frames for PF_PACKET TX ring (no kernel TCP stack)

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define UV_ETH_ALEN 6
#define UV_ETH_HDR  14
#define UV_IP4_HDR  20
#define UV_TCP_HDR  20
#define UV_UDP_HDR  8

// Build Ethernet/IPv4/TCP SYN frame into buf (needs >= 54 bytes)
// Returns frame length, 0 on error
size_t uv_eth_build_syn(uint8_t       *buf,
                        size_t         buf_len,
                        const uint8_t  src_mac[UV_ETH_ALEN],
                        const uint8_t  dst_mac[UV_ETH_ALEN],
                        uint32_t       src_ip,
                        uint32_t       dst_ip,
                        uint16_t       src_port,
                        uint16_t       dst_port,
                        uint32_t       isn);

// Build Ethernet/IPv4/UDP frame with payload
size_t uv_eth_build_udp(uint8_t       *buf,
                        size_t         buf_len,
                        const uint8_t  src_mac[UV_ETH_ALEN],
                        const uint8_t  dst_mac[UV_ETH_ALEN],
                        uint32_t       src_ip,
                        uint32_t       dst_ip,
                        uint16_t       src_port,
                        uint16_t       dst_port,
                        const uint8_t *payload,
                        size_t         payload_len);

// RFC 1071 internet checksum
uint16_t uv_inet_checksum(const void *data, size_t len);

// TCP checksum over pseudo-header
uint16_t uv_tcp_checksum(uint32_t src_ip, uint32_t dst_ip,
                         const void *tcp_seg, size_t tcp_len);

#ifdef __cplusplus
}
#endif
