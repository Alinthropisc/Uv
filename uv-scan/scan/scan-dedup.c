/* scan-dedup.c — SYN-ACK duplicate suppression
 * Derived from masscan/src/main-dedup.c (AGPL-3.0, reference implementation)
 */
#include "scan-dedup.h"
#include <stdlib.h>
#include <string.h>

uv_dedup_t *uv_dedup_create(void) {
    uv_dedup_t *d = calloc(1, sizeof(*d));
    return d;
}

void uv_dedup_destroy(uv_dedup_t *d) { free(d); }

void uv_dedup_reset(uv_dedup_t *d) {
    memset(d, 0, sizeof(*d));
}

/* Mix ip+port into a 16-bit bucket index */
static uint32_t dedup_hash(uint32_t ip, uint16_t port) {
    /* FNV-1a inspired mix */
    uint32_t h = 0x811c9dc5u;
    h ^= (ip & 0xFF);       h *= 0x01000193u;
    h ^= ((ip >> 8) & 0xFF);  h *= 0x01000193u;
    h ^= ((ip >>16) & 0xFF);  h *= 0x01000193u;
    h ^= (ip >> 24);           h *= 0x01000193u;
    h ^= (port & 0xFF);        h *= 0x01000193u;
    h ^= (port >> 8);          h *= 0x01000193u;
    return h & (UV_DEDUP_BUCKETS - 1);
}

/* Encode ip+port into a 32-bit key */
static uint32_t dedup_key(uint32_t ip, uint16_t port) {
    return (ip ^ ((uint32_t)port << 16) ^ (uint32_t)port);
}

bool uv_dedup_is_new(uv_dedup_t *d, uint32_t ip, uint16_t port) {
    uint32_t bucket = dedup_hash(ip, port);
    uint32_t key    = dedup_key(ip, port);
    uint8_t  count  = d->counts[bucket];

    /* Search existing entries */
    for (uint8_t i = 0; i < count && i < UV_DEDUP_ENTRY_SZ; i++) {
        if (d->table[bucket][i] == key)
            return false;  /* duplicate */
    }

    /* Insert (evict oldest if bucket full — ring buffer) */
    uint8_t slot = count % UV_DEDUP_ENTRY_SZ;
    d->table[bucket][slot] = key;
    if (count < UV_DEDUP_ENTRY_SZ) d->counts[bucket]++;
    return true;
}
