// net/rate.c — Token bucket rate limiter (C23)

#include "rate.h"

#include <stdlib.h>
#include <stdatomic.h>
#include <time.h>

struct uv_rate_limiter {
    uint64_t             pps;
    uint64_t             burst_size;
    atomic_uint_fast64_t tokens;
    struct timespec      last_refill;
};

static inline uint64_t ns_per_token(uint64_t pps)
{
    return pps ? (1000000000ULL / pps) : 0;
}

static void refill(uv_rate_limiter_t *rl)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    uint64_t elapsed_ns =
        (uint64_t)(now.tv_sec  - rl->last_refill.tv_sec)  * 1000000000ULL +
        (uint64_t)(now.tv_nsec - rl->last_refill.tv_nsec);

    uint64_t npt = ns_per_token(rl->pps);
    if (npt == 0 || elapsed_ns < npt) return;

    uint64_t new_tokens = elapsed_ns / npt;
    rl->last_refill = now;

    uint64_t cur  = atomic_load_explicit(&rl->tokens, memory_order_relaxed);
    uint64_t next = cur + new_tokens;
    if (next > rl->burst_size) next = rl->burst_size;
    atomic_store_explicit(&rl->tokens, next, memory_order_release);
}

uv_rate_limiter_t *uv_rate_create(uint64_t pps, uint64_t burst_size)
{
    uv_rate_limiter_t *rl = calloc(1, sizeof(*rl));
    if (!rl) return NULL;

    rl->pps        = pps;
    rl->burst_size = burst_size;
    atomic_store(&rl->tokens, burst_size);
    clock_gettime(CLOCK_MONOTONIC, &rl->last_refill);
    return rl;
}

void uv_rate_destroy(uv_rate_limiter_t *rl) { free(rl); }

bool uv_rate_acquire(uv_rate_limiter_t *rl)
{
    for (;;) {
        refill(rl);
        uint64_t cur = atomic_load_explicit(&rl->tokens, memory_order_acquire);
        if (cur > 0) {
            if (atomic_compare_exchange_weak_explicit(
                    &rl->tokens, &cur, cur - 1,
                    memory_order_acq_rel, memory_order_relaxed))
                return true;
        } else {
            struct timespec ts = { .tv_sec = 0,
                                   .tv_nsec = (long)ns_per_token(rl->pps) };
            nanosleep(&ts, NULL);
        }
    }
}

bool uv_rate_acquire_n(uv_rate_limiter_t *rl, uint32_t n)
{
    if (n > rl->burst_size) return false;
    for (uint32_t i = 0; i < n; i++)
        uv_rate_acquire(rl);
    return true;
}

uint64_t uv_rate_tokens(const uv_rate_limiter_t *rl)
{
    return atomic_load_explicit(&rl->tokens, memory_order_relaxed);
}
