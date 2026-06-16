/* uv-bridge.c — AF_PACKET SYN scan engine: TX thread + RX thread.
 * Masscan-style stateless scan: TX sends raw SYN frames, RX validates
 * SYN-ACK replies via SipHash-2-4 cookie, fires callback for open ports.
 *
 * Requires: Linux, CAP_NET_RAW or root.
 */

#include "uv-bridge.h"
#include "uv-ffi.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* ── SipHash-2-4 (inline, no external dep) ─────────────────────────── */
#define ROTL64(x, b) (((x) << (b)) | ((x) >> (64 - (b))))
#define SIP_ROUND(v0,v1,v2,v3) \
    v0 += v1; v1 = ROTL64(v1,13); v1 ^= v0; v0 = ROTL64(v0,32); \
    v2 += v3; v3 = ROTL64(v3,16); v3 ^= v2;                       \
    v0 += v3; v3 = ROTL64(v3,21); v3 ^= v0;                       \
    v2 += v1; v1 = ROTL64(v1,17); v1 ^= v2; v2 = ROTL64(v2,32)

static uint64_t siphash24(uint64_t key0, uint64_t key1,
                           uint32_t ip, uint16_t port) {
    uint64_t v0 = key0 ^ 0x736f6d6570736575ULL;
    uint64_t v1 = key1 ^ 0x646f72616e646f6dULL;
    uint64_t v2 = key0 ^ 0x6c7967656e657261ULL;
    uint64_t v3 = key1 ^ 0x7465646279746573ULL;
    uint64_t m  = ((uint64_t)ip << 16) | port;
    v3 ^= m;
    SIP_ROUND(v0,v1,v2,v3);
    SIP_ROUND(v0,v1,v2,v3);
    v0 ^= m;
    v2 ^= 0xff;
    SIP_ROUND(v0,v1,v2,v3); SIP_ROUND(v0,v1,v2,v3);
    SIP_ROUND(v0,v1,v2,v3); SIP_ROUND(v0,v1,v2,v3);
    return v0 ^ v1 ^ v2 ^ v3;
}

/* ── Internet checksum ──────────────────────────────────────────────── */
static uint16_t inet_cksum(const void *data, size_t len) {
    const uint16_t *p = data;
    uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(const uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return ~(uint16_t)sum;
}

/* ── TCP checksum (pseudo-header) ───────────────────────────────────── */
static uint16_t tcp_cksum(uint32_t src, uint32_t dst,
                           const struct tcphdr *tcp, size_t tcp_len) {
    struct { uint32_t src, dst; uint8_t zero, proto; uint16_t len; } ph;
    ph.src   = src;
    ph.dst   = dst;
    ph.zero  = 0;
    ph.proto = IPPROTO_TCP;
    ph.len   = htons((uint16_t)tcp_len);
    uint32_t sum = 0;
    const uint16_t *p;
    p = (const uint16_t *)&ph;
    for (size_t i = 0; i < sizeof(ph)/2; i++) sum += p[i];
    p = (const uint16_t *)tcp;
    for (size_t i = 0; i < tcp_len/2; i++) sum += p[i];
    if (tcp_len & 1) sum += ((const uint8_t *)tcp)[tcp_len-1];
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return ~(uint16_t)sum;
}

/* ── Dedup ring buffer ──────────────────────────────────────────────── */
#define DEDUP_SLOTS 65536
#define DEDUP_MASK  (DEDUP_SLOTS - 1)

typedef struct {
    uint64_t entries[DEDUP_SLOTS][4];
    uint32_t idx;
} dedup_t;

static void dedup_init(dedup_t *d) { memset(d, 0, sizeof(*d)); }

static int dedup_is_new(dedup_t *d, uint32_t ip, uint16_t port) {
    uint64_t key = ((uint64_t)ip << 16) | port;
    uint32_t slot = (uint32_t)(key & DEDUP_MASK);
    for (int i = 0; i < 4; i++)
        if (d->entries[slot][i] == key) return 0;
    d->entries[slot][d->idx & 3] = key;
    d->idx++;
    return 1;
}

/* ── Token bucket rate limiter ──────────────────────────────────────── */
typedef struct {
    uint64_t tokens_milli;   /* tokens × 1000 */
    uint64_t rate_milli;     /* tokens/sec × 1000 */
    struct timespec last;
} throttle_t;

static void throttle_init(throttle_t *t, uint64_t pps) {
    t->rate_milli  = pps * 1000ULL;
    t->tokens_milli = pps * 1000ULL;
    clock_gettime(CLOCK_MONOTONIC, &t->last);
}

static void throttle_wait(throttle_t *t) {
    if (t->rate_milli == 0) return;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    uint64_t elapsed_ns = (uint64_t)(now.tv_sec - t->last.tv_sec) * 1000000000ULL
                        + (uint64_t)(now.tv_nsec - t->last.tv_nsec);
    t->tokens_milli += (uint64_t)(elapsed_ns / 1000) * t->rate_milli / 1000000ULL;
    t->last = now;
    if (t->tokens_milli > t->rate_milli * 10) t->tokens_milli = t->rate_milli * 10;
    if (t->tokens_milli >= 1000) {
        t->tokens_milli -= 1000;
        return;
    }
    /* sleep until token available */
    uint64_t wait_us = (1000 - t->tokens_milli) * 1000000ULL / t->rate_milli;
    struct timespec ts = { .tv_sec = 0, .tv_nsec = (long)(wait_us * 1000) };
    nanosleep(&ts, NULL);
    t->tokens_milli = 0;
}

/* ── Engine struct ──────────────────────────────────────────────────── */
#define FRAME_SIZE (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr))

struct uv_engine {
    int           tx_fd;          /* AF_PACKET SOCK_RAW TX */
    int           rx_fd;          /* AF_PACKET SOCK_RAW RX */
    int           if_index;
    uint8_t       src_mac[6];
    uint8_t       dst_mac[6];     /* gateway MAC or broadcast */
    uint32_t      src_ip;
    uint16_t      src_port_base;
    uint64_t      cookie_key0;
    uint64_t      cookie_key1;
    uv_port_cb    cb;
    void         *cb_ctx;
    throttle_t    throttle;
    dedup_t       dedup;
    pthread_t     rx_thread;
    volatile int  rx_running;
    char          errbuf[256];

    /* stats (atomic) */
    _Atomic uint64_t sent;
    _Atomic uint64_t recv;
    _Atomic uint64_t open;
};

/* ── Open AF_PACKET socket ──────────────────────────────────────────── */
static int open_raw_socket(int *if_index_out, const char *iface,
                            uint8_t *mac_out, char *errbuf) {
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        snprintf(errbuf, 256, "socket(AF_PACKET): %s", strerror(errno));
        return -1;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    if (iface && iface[0]) {
        strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);
    } else {
        /* pick first non-loopback interface */
        struct if_nameindex *ifs = if_nameindex();
        if (ifs) {
            for (struct if_nameindex *p = ifs; p->if_index; p++) {
                if (strcmp(p->if_name, "lo") != 0) {
                    strncpy(ifr.ifr_name, p->if_name, IFNAMSIZ-1);
                    break;
                }
            }
            if_freenameindex(ifs);
        }
        if (!ifr.ifr_name[0]) strncpy(ifr.ifr_name, "eth0", IFNAMSIZ-1);
    }
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        snprintf(errbuf, 256, "SIOCGIFINDEX(%s): %s", ifr.ifr_name, strerror(errno));
        close(fd); return -1;
    }
    *if_index_out = ifr.ifr_ifindex;
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0)
        memcpy(mac_out, ifr.ifr_hwaddr.sa_data, 6);
    /* bind to interface */
    struct sockaddr_ll sll = {
        .sll_family   = AF_PACKET,
        .sll_protocol = htons(ETH_P_ALL),
        .sll_ifindex  = *if_index_out,
    };
    if (bind(fd, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        snprintf(errbuf, 256, "bind AF_PACKET: %s", strerror(errno));
        close(fd); return -1;
    }
    return fd;
}

/* ── Build SYN frame in-place ───────────────────────────────────────── */
static void build_syn(uint8_t *frame, const struct uv_engine *eng,
                      uint32_t dst_ip, uint16_t dst_port) {
    /* Ethernet */
    struct ethhdr *eth = (struct ethhdr *)frame;
    memcpy(eth->h_dest,   eng->dst_mac, 6);
    memcpy(eth->h_source, eng->src_mac, 6);
    eth->h_proto = htons(ETH_P_IP);

    /* IP */
    struct iphdr *ip = (struct iphdr *)(frame + sizeof(*eth));
    ip->version  = 4;
    ip->ihl      = 5;
    ip->tos      = 0;
    ip->tot_len  = htons(sizeof(*ip) + sizeof(struct tcphdr));
    ip->id       = htons((uint16_t)(dst_ip ^ dst_port));
    ip->frag_off = htons(IP_DF);
    ip->ttl      = 64;
    ip->protocol = IPPROTO_TCP;
    ip->check    = 0;
    ip->saddr    = htonl(eng->src_ip);
    ip->daddr    = htonl(dst_ip);
    ip->check    = inet_cksum(ip, sizeof(*ip));

    /* TCP SYN */
    uint32_t cookie = (uint32_t)siphash24(eng->cookie_key0, eng->cookie_key1,
                                           dst_ip, dst_port);
    struct tcphdr *tcp = (struct tcphdr *)(frame + sizeof(*eth) + sizeof(*ip));
    memset(tcp, 0, sizeof(*tcp));
    tcp->source  = htons(eng->src_port_base + (dst_port & 0x3fff));
    tcp->dest    = htons(dst_port);
    tcp->seq     = htonl(cookie);
    tcp->doff    = 5;
    tcp->syn     = 1;
    tcp->window  = htons(1024);
    tcp->check   = tcp_cksum(htonl(eng->src_ip), htonl(dst_ip),
                              tcp, sizeof(*tcp));
}

/* ── TX: send SYN ───────────────────────────────────────────────────── */
uv_status_t uv_engine_send_syn(uv_engine_t *eng,
                                uv_ipv4_t dst_ip, uint16_t dst_port) {
    throttle_wait(&eng->throttle);

    uint8_t frame[FRAME_SIZE];
    build_syn(frame, eng, dst_ip, dst_port);

    struct sockaddr_ll sll = {
        .sll_ifindex = eng->if_index,
        .sll_halen   = 6,
    };
    memcpy(sll.sll_addr, eng->dst_mac, 6);

    ssize_t n = sendto(eng->tx_fd, frame, sizeof(frame), 0,
                       (struct sockaddr*)&sll, sizeof(sll));
    if (n < 0) {
        snprintf(eng->errbuf, sizeof(eng->errbuf),
                 "sendto: %s", strerror(errno));
        return UV_ERR_IO;
    }
    atomic_fetch_add(&eng->sent, 1);
    return UV_OK;
}

/* ── RX thread: validate SYN-ACK via cookie ────────────────────────── */
static void *rx_thread_fn(void *arg) {
    uv_engine_t *eng = arg;
    uint8_t buf[2048];

    while (eng->rx_running) {
        ssize_t n = recv(eng->rx_fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                struct timespec ts = { .tv_nsec = 100000 }; /* 100µs */
                nanosleep(&ts, NULL);
                continue;
            }
            break;
        }
        if ((size_t)n < sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr))
            continue;

        struct iphdr  *ip  = (struct iphdr  *)(buf + sizeof(struct ethhdr));
        if (ip->protocol != IPPROTO_TCP) continue;

        struct tcphdr *tcp = (struct tcphdr *)((uint8_t*)ip + ip->ihl*4);

        /* only SYN-ACK */
        if (!tcp->syn || !tcp->ack) continue;

        atomic_fetch_add(&eng->recv, 1);

        uint32_t src_ip   = ntohl(ip->saddr);
        uint16_t src_port = ntohs(tcp->source);
        uint32_t ack_seq  = ntohl(tcp->ack_seq);

        /* verify cookie: ACK = our_SEQ + 1 */
        uint32_t expected = (uint32_t)siphash24(eng->cookie_key0, eng->cookie_key1,
                                                 src_ip, src_port) + 1;
        if (ack_seq != expected) continue;

        /* dedup */
        if (!dedup_is_new(&eng->dedup, src_ip, src_port)) continue;

        atomic_fetch_add(&eng->open, 1);

        if (eng->cb) {
            uv_port_rec_t rec = {
                .ip   = src_ip,
                .port = src_port,
            };
            eng->cb(&rec, eng->cb_ctx);
        }

        /* send RST to clean up target's half-open state */
        uint8_t rst_frame[FRAME_SIZE];
        build_syn(rst_frame, eng, src_ip, src_port);
        struct tcphdr *rst = (struct tcphdr *)(rst_frame
            + sizeof(struct ethhdr) + sizeof(struct iphdr));
        rst->syn = 0;
        rst->rst = 1;
        rst->seq = tcp->ack_seq; /* use their ACK as our RST seq */
        rst->check = 0;
        rst->check = tcp_cksum(htonl(eng->src_ip), htonl(src_ip), rst, sizeof(*rst));
        struct sockaddr_ll sll = { .sll_ifindex = eng->if_index, .sll_halen = 6 };
        sendto(eng->tx_fd, rst_frame, sizeof(rst_frame), 0,
               (struct sockaddr*)&sll, sizeof(sll));
    }
    return NULL;
}

/* ── Public API ─────────────────────────────────────────────────────── */

uv_engine_t *uv_engine_create(const uv_scan_cfg_t *cfg) {
    uv_engine_t *eng = calloc(1, sizeof(*eng));
    if (!eng) return NULL;

    /* generate SipHash keys from /dev/urandom */
    int rfd = open("/dev/urandom", 0);
    if (rfd >= 0) {
        read(rfd, &eng->cookie_key0, 8);
        read(rfd, &eng->cookie_key1, 8);
        close(rfd);
    } else {
        eng->cookie_key0 = 0xdeadbeef12345678ULL;
        eng->cookie_key1 = 0xcafebabedeadcafeULL;
    }

    eng->src_ip        = cfg ? cfg->src_ip   : 0;
    eng->src_port_base = 40000;
    uint64_t rate      = cfg ? cfg->rate_pps  : 10000;

    /* Destination MAC: use broadcast for now; real impl would ARP for gateway */
    memset(eng->dst_mac, 0xff, 6);

    int if_idx = 0;
    eng->tx_fd = open_raw_socket(&if_idx, cfg ? cfg->iface : NULL,
                                 eng->src_mac, eng->errbuf);
    if (eng->tx_fd < 0) { free(eng); return NULL; }

    eng->rx_fd = open_raw_socket(&if_idx, cfg ? cfg->iface : NULL,
                                 eng->src_mac, eng->errbuf);
    if (eng->rx_fd < 0) { close(eng->tx_fd); free(eng); return NULL; }

    eng->if_index = if_idx;

    throttle_init(&eng->throttle, rate);
    dedup_init(&eng->dedup);

    atomic_init(&eng->sent, 0);
    atomic_init(&eng->recv, 0);
    atomic_init(&eng->open, 0);

    return eng;
}

void uv_engine_destroy(uv_engine_t *eng) {
    if (!eng) return;
    uv_engine_stop_rx(eng);
    if (eng->tx_fd >= 0) close(eng->tx_fd);
    if (eng->rx_fd >= 0) close(eng->rx_fd);
    free(eng);
}

void uv_engine_set_cb(uv_engine_t *eng, uv_port_cb cb, void *ctx) {
    eng->cb     = cb;
    eng->cb_ctx = ctx;
}

uv_status_t uv_engine_start_rx(uv_engine_t *eng) {
    eng->rx_running = 1;
    if (pthread_create(&eng->rx_thread, NULL, rx_thread_fn, eng) != 0) {
        snprintf(eng->errbuf, sizeof(eng->errbuf),
                 "pthread_create: %s", strerror(errno));
        eng->rx_running = 0;
        return UV_ERR_IO;
    }
    return UV_OK;
}

void uv_engine_stop_rx(uv_engine_t *eng) {
    if (!eng->rx_running) return;
    eng->rx_running = 0;
    pthread_join(eng->rx_thread, NULL);
}

const char *uv_engine_error(const uv_engine_t *eng) {
    return eng ? eng->errbuf : "null engine";
}

void uv_engine_stats(const uv_engine_t *eng, uv_engine_stats_t *out) {
    out->sent     = atomic_load(&eng->sent);
    out->recv     = atomic_load(&eng->recv);
    out->open     = atomic_load(&eng->open);
    out->rate_pps = (double)eng->throttle.rate_milli / 1000.0;
}
