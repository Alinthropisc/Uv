/* output-status.c — scan progress printer (masscan main-status.c inspired) */
#include "output-status.h"
#include <stdio.h>
#include <math.h>

void uv_status_init(uv_status_t *st, uint64_t total) {
    *st = (uv_status_t){0};
    st->total_targets = total;
    st->start_time    = time(NULL);
}

void uv_status_update(uv_status_t *st, uint64_t sent, uint64_t recv, uint64_t open) {
    st->packets_sent = sent;
    st->packets_recv = recv;
    st->open_ports   = open;
    st->done_targets = sent;

    double elapsed = difftime(time(NULL), st->start_time);
    st->rate_pps = elapsed > 0.0 ? (double)sent / elapsed : 0.0;
}

double uv_status_percent(const uv_status_t *st) {
    if (st->total_targets == 0) return 100.0;
    return (double)st->done_targets * 100.0 / (double)st->total_targets;
}

double uv_status_eta_secs(const uv_status_t *st) {
    if (st->rate_pps < 1.0) return INFINITY;
    uint64_t remaining = st->total_targets > st->done_targets
                       ? st->total_targets - st->done_targets : 0;
    return (double)remaining / st->rate_pps;
}

void uv_status_print(const uv_status_t *st) {
    double pct  = uv_status_percent(st);
    double eta  = uv_status_eta_secs(st);
    double rate = st->rate_pps;

    if (eta < 3600.0) {
        fprintf(stderr,
            "\rrate: %8.0f pps  sent: %10llu  open: %7llu  done: %5.1f%%  eta: %4.0fs   ",
            rate,
            (unsigned long long)st->packets_sent,
            (unsigned long long)st->open_ports,
            pct, eta);
    } else {
        fprintf(stderr,
            "\rrate: %8.0f pps  sent: %10llu  open: %7llu  done: %5.1f%%  eta: %4.0fh   ",
            rate,
            (unsigned long long)st->packets_sent,
            (unsigned long long)st->open_ports,
            pct, eta / 3600.0);
    }
    fflush(stderr);
}
