// net/pkt.c — Ethernet+IPv4+TCP/UDP/ICMP packet builder (C23)

#include "pkt.h"
#include "checksum.h"

#include <string.h>
#include <arpa/inet.h>   // htons / htonl

// ── internal helpers ─────────────────────────────────────────────────────────

static void fill_eth(uint8_t *out,
                     const uint8_t src[6], const uint8_t dst[6],
                     uint16_t ethertype)
{
    uv_eth_hdr_t *e = (uv_eth_hdr_t *)out;
    memcpy(e->dst, dst, 6);
    memcpy(e->src, src, 6);
    e->ethertype = htons(ethertype);
}

static void fill_ip4(uint8_t *out,
                     uint32_t src, uint32_t dst,
                     uint8_t proto, uint16_t total_len,
                     uint16_t id)
{
    uv_ip4_hdr_t *ip = (uv_ip4_hdr_t *)out;
    ip->ver_ihl    = 0x45;
    ip->tos        = 0;
    ip->total_len  = htons(total_len);
    ip->id         = htons(id);
    ip->flags_frag = htons(0x4000); // DF
    ip->ttl        = 64;
    ip->proto      = proto;
    ip->checksum   = 0;
    ip->src        = htonl(src);
    ip->dst        = htonl(dst);

    // IP header checksum (no pseudo-header, just the 20-byte header itself)
    uint32_t sum = 0;
    const uint16_t *hw = (const uint16_t *)out;
    for (int i = 0; i < 10; i++) sum += ntohs(hw[i]);
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum = (sum >> 16) + (sum & 0xFFFF);
    ip->checksum = htons((uint16_t)(~sum & 0xFFFF));
}

// ── TCP SYN ──────────────────────────────────────────────────────────────────

uint16_t uv_pkt_build_syn(uv_pkt_t *pkt,
                           const uint8_t src_mac[6],
                           const uint8_t dst_mac[6],
                           uint32_t src_ip, uint32_t dst_ip,
                           uint16_t src_port, uint16_t dst_port,
                           uint32_t seq)
{
    enum { ETH = 14, IP = 20, TCP = 20 };
    uint16_t total = ETH + IP + TCP;

    memset(pkt->data, 0, total);
    fill_eth(pkt->data, src_mac, dst_mac, 0x0800);
    fill_ip4(pkt->data + ETH, src_ip, dst_ip, 6, IP + TCP, (uint16_t)seq);

    uv_tcp_hdr_t *tcp = (uv_tcp_hdr_t *)(pkt->data + ETH + IP);
    tcp->src_port = htons(src_port);
    tcp->dst_port = htons(dst_port);
    tcp->seq      = htonl(seq);
    tcp->ack      = 0;
    tcp->data_off = (TCP / 4) << 4;
    tcp->flags    = UV_TCP_SYN;
    tcp->window   = htons(65535);
    tcp->checksum = 0;
    tcp->urgent   = 0;

    tcp->checksum = htons(checksum_ipv4(src_ip, dst_ip, 6, TCP, tcp));

    pkt->len = total;
    return total;
}

// ── UDP probe ────────────────────────────────────────────────────────────────

uint16_t uv_pkt_build_udp(uv_pkt_t *pkt,
                           const uint8_t src_mac[6],
                           const uint8_t dst_mac[6],
                           uint32_t src_ip, uint32_t dst_ip,
                           uint16_t src_port, uint16_t dst_port,
                           const uint8_t *payload, uint16_t payload_len)
{
    enum { ETH = 14, IP = 20, UDP = 8 };
    uint16_t udp_total = UDP + payload_len;
    uint16_t ip_total  = IP + udp_total;
    uint16_t frame_len = ETH + ip_total;

    if (frame_len > UV_PKT_MAXLEN) return 0;

    memset(pkt->data, 0, frame_len);
    fill_eth(pkt->data, src_mac, dst_mac, 0x0800);
    fill_ip4(pkt->data + ETH, src_ip, dst_ip, 17, ip_total, 0);

    uv_udp_hdr_t *udp = (uv_udp_hdr_t *)(pkt->data + ETH + IP);
    udp->src_port = htons(src_port);
    udp->dst_port = htons(dst_port);
    udp->length   = htons(udp_total);
    udp->checksum = 0;

    if (payload_len)
        memcpy(pkt->data + ETH + IP + UDP, payload, payload_len);

    udp->checksum = htons(checksum_ipv4(src_ip, dst_ip, 17, udp_total, udp));

    pkt->len = frame_len;
    return frame_len;
}

// ── ICMP echo ────────────────────────────────────────────────────────────────

uint16_t uv_pkt_build_icmp_echo(uv_pkt_t *pkt,
                                  const uint8_t src_mac[6],
                                  const uint8_t dst_mac[6],
                                  uint32_t src_ip, uint32_t dst_ip,
                                  uint16_t id, uint16_t seq)
{
    enum { ETH = 14, IP = 20, ICMP = 8 };
    uint16_t frame_len = ETH + IP + ICMP;

    memset(pkt->data, 0, frame_len);
    fill_eth(pkt->data, src_mac, dst_mac, 0x0800);
    fill_ip4(pkt->data + ETH, src_ip, dst_ip, 1, IP + ICMP, 0);

    uv_icmp_hdr_t *icmp = (uv_icmp_hdr_t *)(pkt->data + ETH + IP);
    icmp->type     = 8; // echo request
    icmp->code     = 0;
    icmp->checksum = 0;
    icmp->id       = htons(id);
    icmp->seq      = htons(seq);

    icmp->checksum = htons(checksum_ipv4(src_ip, dst_ip, 1, ICMP, icmp));

    pkt->len = frame_len;
    return frame_len;
}

// ── Response parser ──────────────────────────────────────────────────────────

bool uv_pkt_parse_tcp_rsp(const uint8_t *frame, size_t len,
                            uint32_t our_ip, uint16_t our_port_lo,
                            uint16_t our_port_hi,
                            uint32_t *rsp_ip, uint16_t *rsp_port,
                            bool *is_open)
{
    enum { ETH = 14, IP = 20, TCP = 20 };
    if (len < (size_t)(ETH + IP + TCP)) return false;

    const uv_eth_hdr_t *eth = (const uv_eth_hdr_t *)frame;
    if (ntohs(eth->ethertype) != 0x0800) return false;

    const uv_ip4_hdr_t *ip = (const uv_ip4_hdr_t *)(frame + ETH);
    if (ip->proto != 6) return false;
    if (ntohl(ip->dst) != our_ip) return false;

    uint8_t ihl = (ip->ver_ihl & 0x0F) * 4;
    if (len < (size_t)(ETH + ihl + TCP)) return false;

    const uv_tcp_hdr_t *tcp = (const uv_tcp_hdr_t *)(frame + ETH + ihl);

    uint16_t dport = ntohs(tcp->dst_port);
    if (dport < our_port_lo || dport > our_port_hi) return false;

    // SYN-ACK → open, RST → closed
    if (tcp->flags & UV_TCP_RST) {
        *is_open  = false;
    } else if ((tcp->flags & (UV_TCP_SYN | UV_TCP_ACK)) == (UV_TCP_SYN | UV_TCP_ACK)) {
        *is_open  = true;
    } else {
        return false;
    }

    *rsp_ip   = ntohl(ip->src);
    *rsp_port = ntohs(tcp->src_port);
    return true;
}
