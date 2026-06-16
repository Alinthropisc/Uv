/* crypto-blackrock2.h — BlackRock2 Feistel permutation
 * Used by masscan to randomise ip:port scan order without a list.
 * Derived from masscan/src/crypto-blackrock2.c (AGPL-3.0, reference)
 *
 * Algorithm: 4-round Feistel over a variable-width block.
 * Block width is split into two halves; each round uses SipHash-2-4
 * as the round function with per-round subkeys.
 */
#pragma once
#include <stdint.h>

typedef struct uv_blackrock2 {
    uint64_t range;      /* total number of elements to permute */
    uint64_t a_bits;     /* bit width of left half */
    uint64_t b_bits;     /* bit width of right half */
    uint64_t a_mask;
    uint64_t b_mask;
    uint64_t keys[8];    /* 4 rounds × 2 SipHash keys */
} uv_blackrock2_t;

/* Initialise permutation for [0, range) with the given seed */
void uv_blackrock2_init(uv_blackrock2_t *br, uint64_t range, uint64_t seed);

/* Return the i-th element of the pseudo-random permutation of [0, range).
 * Always maps [0,range) → [0,range) bijectively. */
uint64_t uv_blackrock2_shuffle(const uv_blackrock2_t *br, uint64_t i);

/* Inverse: given output, return the original index */
uint64_t uv_blackrock2_unshuffle(const uv_blackrock2_t *br, uint64_t x);
