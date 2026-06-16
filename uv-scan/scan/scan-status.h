/* scan-status.h — scan progress tracker (masscan main-status.h inspired) */
#pragma once
#include <stdint.h>
#include <time.h>

typedef struct uv_scan_status {
    uint64_t  total;          /* total ip:port pairs */
    uint64_t  sent;
    uint64_t  received;
    uint64_t  open;
    uint64_t  closed;
    uint64_t  filtered;
    time_t    start_time;
    double    rate_pps;
    uint32_t  print_interval_secs;
    time_t    last_print;
} uv_scan_status_t;

void uv_scan_status_init(uv_scan_status_t *s, uint64_t total);
void uv_scan_status_tick(uv_scan_status_t *s,
                         uint64_t sent, uint64_t received,
                         uint64_t open, uint64_t closed, uint64_t filtered);
/* Print progress line to stderr if interval elapsed */
void uv_scan_status_maybe_print(uv_scan_status_t *s);
/* Force print final summary line */
void uv_scan_status_final(const uv_scan_status_t *s);
double uv_scan_status_percent(const uv_scan_status_t *s);
double uv_scan_status_eta(const uv_scan_status_t *s);
