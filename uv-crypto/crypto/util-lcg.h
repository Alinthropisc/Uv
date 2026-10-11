/* util-lcg.h — Linear Congruential Generator for port ordering
 * Hull-Dobell theorem: a≡1(mod4), c odd → full-period LCG.
 * Derived from masscan/src/util-lcg.c (AGPL-3.0, reference)
 */
#pragma once
#include <stdint.h>

typedef struct uv_lcg {
    uint64_t state;
    uint64_t a;       /* multiplier: a ≡ 1 (mod 4) */
    uint64_t c;       /* increment: c odd */
    uint64_t modulus; /* 2^k for some k */
    uint64_t range;   /* actual range [0, range) */
} uv_lcg_t;

/* Initialise LCG to iterate over [0, range) pseudo-randomly */
void uv_lcg_init(uv_lcg_t *lcg, uint64_t range, uint64_t seed);

/* Next value in [0, range) — skips values ≥ range (cycle-walking) */
uint64_t uv_lcg_next(uv_lcg_t *lcg);

/* Reset to initial state */
void uv_lcg_reset(uv_lcg_t *lcg, uint64_t seed);
