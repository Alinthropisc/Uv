/* output.h — masscan-inspired output layer for uv
 * Supports: plain, greppable (-oG), JSON (-oJ), XML (-oX), binary (-oB)
 * Derived from masscan/src/output.h (MIT License)
 */
#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

/* Output format selector */
typedef enum uv_output_fmt {
    UV_OUT_PLAIN     = 0,
    UV_OUT_GREPPABLE = 1,   /* nmap -oG */
    UV_OUT_JSON      = 2,   /* nmap -oJ */
    UV_OUT_XML       = 3,   /* nmap -oX */
    UV_OUT_BINARY    = 4,   /* masscan -oB */
    UV_OUT_LIST      = 5,   /* one ip:port per line */
} uv_output_fmt_t;

/* Port state (mirrors masscan port_status) */
typedef enum uv_port_state {
    UV_PORT_OPEN      = 0,
    UV_PORT_CLOSED    = 1,
    UV_PORT_FILTERED  = 2,
} uv_port_state_t;

/* A single open port record */
typedef struct uv_port_record {
    uint32_t        ip;         /* IPv4 in host byte order */
    uint16_t        port;
    uint8_t         proto;      /* IPPROTO_TCP / IPPROTO_UDP */
    uv_port_state_t state;
    const char     *service;    /* nullable */
    const char     *banner;     /* nullable — first 256 bytes of response */
    uint32_t        rtt_us;     /* round-trip time in microseconds */
} uv_port_record_t;

/* Output handle — opaque */
typedef struct uv_output uv_output_t;

/* Open output destination (path=NULL → stdout) */
uv_output_t *uv_output_open(uv_output_fmt_t fmt, const char *path);

/* Write one record */
void uv_output_write(uv_output_t *out, const uv_port_record_t *rec);

/* Flush + close */
void uv_output_close(uv_output_t *out);

/* Helpers */
const char *uv_output_fmt_name(uv_output_fmt_t fmt);
uv_output_fmt_t uv_output_fmt_parse(const char *s);
