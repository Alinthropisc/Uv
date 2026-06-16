#pragma once
// net/blackrock.h — BlackRock2 IP:port permutation (no malloc, no deps)
// Derived from masscan crypto-blackrock2 by Robert David Graham (MIT License)
// Used to randomize scan order without storing the full list in memory.

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t a, b, c, d;   // round keys
    uint64_t range;         // total number of (ip, port) pairs
    unsigned rounds;        // 6 is enough for 64-bit
} uv_blackrock_t;

// Initialise with a random seed and the total scan range (ip_count * port_count).
void uv_blackrock_init(uv_blackrock_t *br, uint64_t seed, uint64_t range);

// Map index i → pseudo-random index in [0, range).
// Call with i = 0, 1, 2, … range-1 to walk the full space without repeats.
uint64_t uv_blackrock_shuffle(const uv_blackrock_t *br, uint64_t i);

// Convenience: split a shuffled index back into (ip_index, port_index).
void uv_blackrock_split(const uv_blackrock_t *br, uint64_t idx,
                        uint32_t port_count,
                        uint32_t *ip_idx, uint16_t *port_idx);

#ifdef __cplusplus
}
#endif
