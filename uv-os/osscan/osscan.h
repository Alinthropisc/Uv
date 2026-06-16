/* osscan.h — OS fingerprinting C layer, inspired by nmap osscan.h
 * Implements FPEngine concepts: probe specs, response collection, matching.
 * Derived from nmap/osscan.h (GPL-2.0, reference implementation only)
 */
#pragma once
#include <stdint.h>
#include <stdbool.h>

/* ---- Probe types (mirrors nmap FP probe set) ---- */
typedef enum uv_fp_probe_type {
    UV_FP_SEQ   = 0,  /* TCP ISN sequence probes (SEQ1-SEQ6) */
    UV_FP_OPS   = 1,  /* TCP options probes */
    UV_FP_WIN   = 2,  /* Window size probes */
    UV_FP_ECN   = 3,  /* ECN probe */
    UV_FP_T1_T7 = 4,  /* T1-T7 probes */
    UV_FP_IE    = 5,  /* ICMP echo probes */
    UV_FP_U1    = 6,  /* UDP closed-port probe */
} uv_fp_probe_type_t;

/* ---- Extracted fingerprint features ---- */
typedef struct uv_os_fp {
    /* SEQ analysis */
    uint32_t  isn[6];           /* 6 initial sequence numbers */
    uint32_t  seq_rate;         /* ISN generation rate */
    uint8_t   seq_index;        /* GCD-based predictability 0-9 */

    /* IP/TCP header features */
    uint8_t   ttl;              /* observed TTL */
    uint8_t   ttl_guess;        /* inferred initial TTL (32/64/128/255) */
    bool      df;               /* IP don't-fragment bit */
    bool      ecn;              /* ECN support detected */

    /* TCP options fingerprint — order matters */
    char      tcp_opt_str[16];  /* e.g. "MSTNW" */
    uint16_t  mss;              /* MSS value from SYN-ACK */
    uint8_t   wscale;           /* window scale value */
    uint16_t  win_size;         /* TCP window size */

    /* ICMP */
    bool      icmp_echo_df;
    uint8_t   icmp_code;
    uint8_t   icmp_type;

    /* UDP */
    bool      udp_closed_response;  /* got ICMP port-unreach */
} uv_os_fp_t;

/* ---- Match result ---- */
typedef struct uv_os_match {
    char      name[64];         /* "Linux 5.x" */
    char      os_class[32];     /* "Linux" */
    char      cpe[64];          /* CPE 2.3 URI */
    uint8_t   accuracy;         /* 0-100 */
} uv_os_match_t;

/* ---- API ---- */

/* Initialise fingerprint to default/unknown state */
void uv_fp_init(uv_os_fp_t *fp);

/* Ingest a TTL value → update ttl and ttl_guess */
void uv_fp_update_ttl(uv_os_fp_t *fp, uint8_t observed_ttl);

/* Build tcp_opt_str from raw TCP options bytes */
void uv_fp_parse_tcp_opts(uv_os_fp_t *fp, const uint8_t *opts, uint8_t len);

/* Record one ISN sample (call up to 6 times) */
void uv_fp_add_isn(uv_os_fp_t *fp, uint32_t isn, int idx);

/* Finalise SEQ analysis after all ISN samples collected */
void uv_fp_finalize_seq(uv_os_fp_t *fp);

/* Match fingerprint against built-in database.
 * out_matches: caller-allocated array of at least max_matches entries.
 * Returns number of matches written. */
int uv_fp_match(const uv_os_fp_t *fp,
                uv_os_match_t *out_matches,
                int max_matches);
