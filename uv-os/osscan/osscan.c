/* osscan.c — OS fingerprinting implementation
 * Inspired by nmap/osscan.cc (GPL-2.0, reference implementation)
 */
#include "osscan.h"
#include "fp-db.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>

void uv_fp_init(uv_os_fp_t *fp) {
    memset(fp, 0, sizeof(*fp));
    fp->ttl_guess = 64;  /* most common default */
}

void uv_fp_update_ttl(uv_os_fp_t *fp, uint8_t observed) {
    fp->ttl = observed;
    static const uint8_t candidates[] = {32, 64, 128, 255};
    for (int i = 0; i < 4; i++) {
        if (observed <= candidates[i]) {
            fp->ttl_guess = candidates[i];
            return;
        }
    }
    fp->ttl_guess = 255;
}

/* TCP option kind bytes */
#define TCPOPT_EOL        0
#define TCPOPT_NOP        1
#define TCPOPT_MSS        2
#define TCPOPT_WSCALE     3
#define TCPOPT_SACK_PERM  4
#define TCPOPT_TIMESTAMP  8

void uv_fp_parse_tcp_opts(uv_os_fp_t *fp, const uint8_t *opts, uint8_t len) {
    char *s   = fp->tcp_opt_str;
    int   pos = 0;
    int   i   = 0;

    while (i < len && pos < (int)sizeof(fp->tcp_opt_str) - 1) {
        uint8_t kind = opts[i];
        switch (kind) {
        case TCPOPT_EOL:      s[pos++] = 'E'; i++;  break;
        case TCPOPT_NOP:      s[pos++] = 'N'; i++;  break;
        case TCPOPT_MSS:
            if (i + 4 <= len) {
                fp->mss = (uint16_t)((opts[i+2] << 8) | opts[i+3]);
                s[pos++] = 'M';
            }
            i += (i + 1 < len) ? opts[i+1] : 1;
            break;
        case TCPOPT_WSCALE:
            if (i + 3 <= len) fp->wscale = opts[i+2];
            s[pos++] = 'W';
            i += (i + 1 < len) ? opts[i+1] : 1;
            break;
        case TCPOPT_SACK_PERM:
            s[pos++] = 'S';
            i += (i + 1 < len) ? opts[i+1] : 1;
            break;
        case TCPOPT_TIMESTAMP:
            s[pos++] = 'T';
            i += (i + 1 < len) ? opts[i+1] : 1;
            break;
        default:
            s[pos++] = '?';
            i += (i + 1 < len && opts[i+1] >= 2) ? opts[i+1] : 1;
            break;
        }
    }
    s[pos] = '\0';
}

void uv_fp_add_isn(uv_os_fp_t *fp, uint32_t isn, int idx) {
    if (idx >= 0 && idx < 6)
        fp->isn[idx] = isn;
}

void uv_fp_finalize_seq(uv_os_fp_t *fp) {
    /* Compute average diff between consecutive ISNs */
    uint32_t diffs[5] = {0};
    int n = 0;
    for (int i = 1; i < 6; i++) {
        if (fp->isn[i] != 0 || fp->isn[i-1] != 0) {
            diffs[n++] = fp->isn[i] - fp->isn[i-1];
        }
    }
    if (n == 0) { fp->seq_index = 0; return; }

    uint64_t sum = 0;
    for (int i = 0; i < n; i++) sum += diffs[i];
    fp->seq_rate = (uint32_t)(sum / n);

    /* Predictability index 0-9: lower rate = more predictable */
    if (fp->seq_rate == 0)            fp->seq_index = 0;
    else if (fp->seq_rate < 10)       fp->seq_index = 1;
    else if (fp->seq_rate < 100)      fp->seq_index = 3;
    else if (fp->seq_rate < 1000)     fp->seq_index = 5;
    else if (fp->seq_rate < 100000)   fp->seq_index = 7;
    else                              fp->seq_index = 9;
}

/* Score one DB entry against the live fingerprint */
static uint8_t score_entry(const uv_os_fp_t *fp, const uv_fp_db_entry_t *e) {
    uint32_t score = 0, total = 100;

    /* TTL (25 pts) */
    if (fp->ttl_guess == e->ttl)      score += 25;

    /* TCP opt order (30 pts) */
    if (strcmp(fp->tcp_opt_str, e->tcp_opt_str) == 0) score += 30;

    /* Window scale (15 pts) */
    if (e->wscale == 255 || fp->wscale == e->wscale) score += 15;  /* 255 = don't care */

    /* DF bit (10 pts) */
    if (fp->df == e->df)               score += 10;

    /* ECN (10 pts) */
    if (fp->ecn == e->ecn)             score += 10;

    /* ICMP DF echo (10 pts) */
    if (fp->icmp_echo_df == e->icmp_echo_df) score += 10;

    return (uint8_t)((score * 100) / total);
}

int uv_fp_match(const uv_os_fp_t *fp,
                uv_os_match_t *out,
                int max_matches)
{
    int n_entries = 0;
    const uv_fp_db_entry_t *db = uv_fp_db_get(&n_entries);
    if (!db || max_matches <= 0) return 0;

    /* Temporary scored list */
    typedef struct { uint8_t score; int idx; } scored_t;
    scored_t *scored = calloc(n_entries, sizeof(scored_t));
    if (!scored) return 0;

    for (int i = 0; i < n_entries; i++) {
        scored[i].score = score_entry(fp, &db[i]);
        scored[i].idx   = i;
    }

    /* Partial sort — bubble top max_matches to front */
    for (int i = 0; i < max_matches && i < n_entries; i++) {
        for (int j = i + 1; j < n_entries; j++) {
            if (scored[j].score > scored[i].score) {
                scored_t tmp = scored[i]; scored[i] = scored[j]; scored[j] = tmp;
            }
        }
    }

    int written = 0;
    for (int i = 0; i < max_matches && i < n_entries; i++) {
        if (scored[i].score < 30) break;  /* below threshold */
        const uv_fp_db_entry_t *e = &db[scored[i].idx];
        strncpy(out[written].name,     e->name,     sizeof(out[written].name)     - 1);
        strncpy(out[written].os_class, e->os_class, sizeof(out[written].os_class) - 1);
        strncpy(out[written].cpe,      e->cpe,      sizeof(out[written].cpe)      - 1);
        out[written].accuracy = scored[i].score;
        written++;
    }
    free(scored);
    return written;
}
