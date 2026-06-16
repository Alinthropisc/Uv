/* output-status.h — scan progress/status line (masscan main-status.h inspired) */
#pragma once
#include <stdint.h>
#include <time.h>

typedef struct uv_status {
    uint64_t   packets_sent;
    uint64_t   packets_recv;
    uint64_t   open_ports;
    uint64_t   total_targets;   /* total ip:port combinations */
    uint64_t   done_targets;
    time_t     start_time;
    double     rate_pps;        /* current send rate packets/sec */
} uv_status_t;

void uv_status_init(uv_status_t *st, uint64_t total);
void uv_status_update(uv_status_t *st, uint64_t sent, uint64_t recv, uint64_t open);
void uv_status_print(const uv_status_t *st);   /* prints \r progress line */
double uv_status_eta_secs(const uv_status_t *st);
double uv_status_percent(const uv_status_t *st);
