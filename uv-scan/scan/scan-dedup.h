/* scan-dedup.h — duplicate SYN-ACK suppression (masscan main-dedup.h inspired)
 * Uses a fixed-size hash table with bitset buckets — zero allocation after init.
 */
#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Default: 64K buckets × 8 entries = 512K state, ~0.5 MB */
#define UV_DEDUP_BUCKETS  (1u << 16)
#define UV_DEDUP_ENTRY_SZ 8

typedef struct uv_dedup {
    uint32_t table[UV_DEDUP_BUCKETS][UV_DEDUP_ENTRY_SZ];
    uint8_t  counts[UV_DEDUP_BUCKETS];
} uv_dedup_t;

/* Allocate + zero-initialise */
uv_dedup_t *uv_dedup_create(void);
void        uv_dedup_destroy(uv_dedup_t *d);

/* Returns true if (ip, port) is NOT a duplicate → should be reported.
 * Inserts the pair on first call. */
bool uv_dedup_is_new(uv_dedup_t *d, uint32_t ip, uint16_t port);

/* Reset all state */
void uv_dedup_reset(uv_dedup_t *d);
