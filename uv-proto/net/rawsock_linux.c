// net/rawsock_linux.c — AF_PACKET raw socket TX/RX (Linux, C23)
// No libpcap. Uses SOCK_RAW + ETH_P_ALL for RX, ETH_P_IP for TX.

#ifdef __linux__

#include "rawsock_linux.h"
#include "pkt.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_ether.h>

struct uv_rawsock {
    int                 tx_fd;
    int                 rx_fd;
    int                 ifindex;
    uv_rawsock_cfg_t    cfg;
    atomic_bool         stop;
};

// ── open/close ───────────────────────────────────────────────────────────────

uv_rawsock_t *uv_rawsock_open(const uv_rawsock_cfg_t *cfg)
{
    uv_rawsock_t *rs = calloc(1, sizeof(*rs));
    if (!rs) return nullptr;

    rs->cfg  = *cfg;
    rs->stop = false;

    // TX socket: ETH_P_IP — we supply the full Ethernet frame
    rs->tx_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (rs->tx_fd < 0) goto err;

    // RX socket: ETH_P_ALL — capture everything, filter in software
    rs->rx_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (rs->rx_fd < 0) goto err;

    // Resolve interface index
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, cfg->iface, IFNAMSIZ - 1);
    if (ioctl(rs->tx_fd, SIOCGIFINDEX, &ifr) < 0) goto err;
    rs->ifindex = ifr.ifr_ifindex;

    // Bind RX socket to the interface
    struct sockaddr_ll sll = {
        .sll_family   = AF_PACKET,
        .sll_protocol = htons(ETH_P_ALL),
        .sll_ifindex  = rs->ifindex,
    };
    if (bind(rs->rx_fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) goto err;

    // Increase send buffer
    int sndbuf = (int)(cfg->send_buf_size ? cfg->send_buf_size : 4 * 1024 * 1024);
    setsockopt(rs->tx_fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    return rs;

err:
    if (rs->tx_fd >= 0) close(rs->tx_fd);
    if (rs->rx_fd >= 0) close(rs->rx_fd);
    free(rs);
    return nullptr;
}

void uv_rawsock_close(uv_rawsock_t *rs)
{
    if (!rs) return;
    close(rs->tx_fd);
    close(rs->rx_fd);
    free(rs);
}

int uv_rawsock_ifindex(uv_rawsock_t *rs) { return rs->ifindex; }

// ── transmit ─────────────────────────────────────────────────────────────────

bool uv_rawsock_send(uv_rawsock_t *rs, const uv_pkt_t *pkt)
{
    struct sockaddr_ll dst = {
        .sll_family  = AF_PACKET,
        .sll_ifindex = rs->ifindex,
        .sll_halen   = 6,
    };
    memcpy(dst.sll_addr, rs->cfg.dst_mac, 6);

    ssize_t n = sendto(rs->tx_fd, pkt->data, pkt->len, 0,
                       (struct sockaddr *)&dst, sizeof(dst));
    return n == pkt->len;
}

// ── receive loop ──────────────────────────────────────────────────────────────

void uv_rawsock_rx_loop(uv_rawsock_t *rs, uv_rawsock_rx_cb cb, void *ctx)
{
    uint8_t buf[UV_PKT_MAXLEN + 64];

    while (!atomic_load_explicit(&rs->stop, memory_order_relaxed)) {
        ssize_t n = recv(rs->rx_fd, buf, sizeof(buf), 0);
        if (n <= 0) {
            if (errno == EINTR) continue;
            break;
        }

        uint32_t rsp_ip;
        uint16_t rsp_port;
        bool     is_open;

        bool matched = uv_pkt_parse_tcp_rsp(
            buf, (size_t)n,
            rs->cfg.src_ip,
            rs->cfg.src_port_lo,
            rs->cfg.src_port_hi,
            &rsp_ip, &rsp_port, &is_open);

        if (matched)
            cb(rsp_ip, rsp_port, is_open, ctx);
    }
}

void uv_rawsock_stop(uv_rawsock_t *rs)
{
    atomic_store_explicit(&rs->stop, true, memory_order_relaxed);
    // Wake the blocked recv() by shutting down the socket
    shutdown(rs->rx_fd, SHUT_RDWR);
}

#endif // __linux__
