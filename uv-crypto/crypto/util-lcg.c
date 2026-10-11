/* util-lcg.c — Hull-Dobell LCG
 * Derived from masscan/src/util-lcg.c (AGPL-3.0, reference)
 */
#include "util-lcg.h"
#include <string.h>

/* Find smallest power-of-2 ≥ range */
static uint64_t next_pow2(uint64_t n) {
    if (n == 0) return 1;
    n--;
    n |= n >> 1; n |= n >> 2; n |= n >> 4;
    n |= n >> 8; n |= n >> 16; n |= n >> 32;
    return n + 1;
}

void uv_lcg_init(uv_lcg_t *lcg, uint64_t range, uint64_t seed) {
    memset(lcg, 0, sizeof(*lcg));
    lcg->range   = range;
    lcg->modulus = next_pow2(range);

    /* Hull-Dobell: a ≡ 1 (mod 4), c odd */
    lcg->a = 0x5DEECE66DULL & ~3ULL | 1ULL;  /* ≡ 1 mod 4 */
    lcg->c = 0xBULL | 1ULL;                  /* odd */
    lcg->state = seed & (lcg->modulus - 1);
}

uint64_t uv_lcg_next(uv_lcg_t *lcg) {
    uint64_t mask = lcg->modulus - 1;
    do {
        lcg->state = (lcg->a * lcg->state + lcg->c) & mask;
    } while (lcg->state >= lcg->range);
    return lcg->state;
}

void uv_lcg_reset(uv_lcg_t *lcg, uint64_t seed) {
    lcg->state = seed & (lcg->modulus - 1);
}
