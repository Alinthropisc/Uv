/* scan-throttle.c — token-bucket rate limiter
 * Derived from masscan/src/main-throttle.c (AGPL-3.0, reference)
 */
#include "scan-throttle.h"
#include <time.h>
#include <string.h>

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

void uv_throttle_init(uv_throttle_t *t, uint64_t rate_pps) {
    memset(t, 0, sizeof(*t));
    t->rate_pps    = rate_pps;
    t->burst_max   = rate_pps / 10 + 1;  /* 100ms burst */
    t->tokens      = t->burst_max * 1000;
    t->last_tick_ns = now_ns();
}

static void refill(uv_throttle_t *t) {
    if (t->rate_pps == 0) return;
    uint64_t now   = now_ns();
    uint64_t delta = now - t->last_tick_ns;
    t->last_tick_ns = now;

    /* tokens per ns = rate_pps / 1e9, scaled ×1000 */
    uint64_t new_tokens = (delta * t->rate_pps) / 1000000ULL;
    t->tokens += new_tokens;
    uint64_t cap = t->burst_max * 1000;
    if (t->tokens > cap) t->tokens = cap;
}

bool uv_throttle_try(uv_throttle_t *t) {
    if (t->rate_pps == 0) return true;
    refill(t);
    if (t->tokens >= 1000) {
        t->tokens -= 1000;
        return true;
    }
    return false;
}

void uv_throttle_wait(uv_throttle_t *t) {
    if (t->rate_pps == 0) return;
    while (!uv_throttle_try(t)) {
        /* spin — in real use combine with epoll/kqueue sleep */
        struct timespec ns = { .tv_sec = 0, .tv_nsec = 100 };
        nanosleep(&ns, NULL);
    }
}

void uv_throttle_set_rate(uv_throttle_t *t, uint64_t rate_pps) {
    t->rate_pps  = rate_pps;
    t->burst_max = rate_pps / 10 + 1;
}

double uv_throttle_actual_rate(const uv_throttle_t *t) {
    return (double)t->rate_pps;  /* approximation; real impl would track rolling window */
}
