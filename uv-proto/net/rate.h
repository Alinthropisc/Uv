#pragma once
// net/rate.h — Token bucket rate limiter (C23)
// Controls packets-per-second to avoid flooding NIC or target network

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct uv_rate_limiter uv_rate_limiter_t;

// Create a limiter targeting `pps` packets/second with a burst allowance
uv_rate_limiter_t *uv_rate_create(uint64_t pps, uint64_t burst_size);
void               uv_rate_destroy(uv_rate_limiter_t *rl);

// Consume one token; spins/yields if bucket is empty until token available
bool uv_rate_acquire(uv_rate_limiter_t *rl);

// Consume n tokens (for batch sends); returns false if n > burst_size
bool uv_rate_acquire_n(uv_rate_limiter_t *rl, uint32_t n);

// Current available tokens (for monitoring)
uint64_t uv_rate_tokens(const uv_rate_limiter_t *rl);

#ifdef __cplusplus
}
#endif
