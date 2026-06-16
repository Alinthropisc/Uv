/* fp-db.h — OS fingerprint database (static, embedded)
 * Subset of nmap-os-db entries translated to C structs.
 */
#pragma once
#include <stdint.h>
#include <stdbool.h>

typedef struct uv_fp_db_entry {
    const char *name;
    const char *os_class;
    const char *cpe;
    uint8_t     ttl;           /* expected initial TTL */
    char        tcp_opt_str[16]; /* expected option order e.g. "MSTNW" */
    uint8_t     wscale;        /* 255 = don't care */
    bool        df;
    bool        ecn;
    bool        icmp_echo_df;
} uv_fp_db_entry_t;

/* Returns pointer to static array and sets *count */
const uv_fp_db_entry_t *uv_fp_db_get(int *count);
