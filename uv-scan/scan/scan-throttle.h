/* scan-throttle.h — token-bucket rate limiter (masscan main-throttle.h inspired)
 * Controls packet send rate in packets-per-second.
 */
#pragma once
#include <stdint.h>
#include <stdbool.h>

typedef struct uv_throttle {
    uint64_t rate_pps;      /* target rate packets/second */
    uint64_t tokens;        /* current token count (fixed-point ×1000) */
    uint64_t last_tick_ns;  /* last refill timestamp (nanoseconds) */
    uint64_t burst_max;     /* max burst tokens */
} uv_throttle_t;

void uv_throttle_init(uv_throttle_t *t, uint64_t rate_pps);

/* Block (spin) until a token is available, then consume it.
 * Returns immediately if rate_pps == 0 (unlimited). */
void uv_throttle_wait(uv_throttle_t *t);

/* Try to consume a token without blocking.
 * Returns true if token was available. */
bool uv_throttle_try(uv_throttle_t *t);

/* Update rate at runtime */
void uv_throttle_set_rate(uv_throttle_t *t, uint64_t rate_pps);

/* Current measured rate (tokens consumed in last second) */
double uv_throttle_actual_rate(const uv_throttle_t *t);
