/* scan-status.c — scan progress tracking + printing
 * Derived from masscan/src/main-status.c (AGPL-3.0, reference)
 */
#include "scan-status.h"
#include <stdio.h>
#include <string.h>
#include <math.h>

void uv_scan_status_init(uv_scan_status_t *s, uint64_t total) {
    memset(s, 0, sizeof(*s));
    s->total              = total;
    s->start_time         = time(NULL);
    s->last_print         = s->start_time;
    s->print_interval_secs = 1;
}

void uv_scan_status_tick(uv_scan_status_t *s,
                          uint64_t sent, uint64_t received,
                          uint64_t open, uint64_t closed, uint64_t filtered) {
    s->sent     = sent;
    s->received = received;
    s->open     = open;
    s->closed   = closed;
    s->filtered = filtered;

    double elapsed = difftime(time(NULL), s->start_time);
    s->rate_pps = elapsed > 0.0 ? (double)sent / elapsed : 0.0;
}

double uv_scan_status_percent(const uv_scan_status_t *s) {
    if (s->total == 0) return 100.0;
    return (double)s->sent * 100.0 / (double)s->total;
}

double uv_scan_status_eta(const uv_scan_status_t *s) {
    if (s->rate_pps < 1.0) return INFINITY;
    uint64_t remaining = s->total > s->sent ? s->total - s->sent : 0;
    return (double)remaining / s->rate_pps;
}

static void print_line(const uv_scan_status_t *s) {
    double eta = uv_scan_status_eta(s);
    double pct = uv_scan_status_percent(s);

    if (!isinf(eta) && eta < 3600.0) {
        fprintf(stderr,
            "\rrate: %7.0f pps  sent: %9llu  open: %6llu  "
            "closed: %7llu  done: %5.1f%%  eta: %3.0fs    ",
            s->rate_pps,
            (unsigned long long)s->sent,
            (unsigned long long)s->open,
            (unsigned long long)s->closed,
            pct, eta);
    } else {
        fprintf(stderr,
            "\rrate: %7.0f pps  sent: %9llu  open: %6llu  "
            "closed: %7llu  done: %5.1f%%  eta: ---    ",
            s->rate_pps,
            (unsigned long long)s->sent,
            (unsigned long long)s->open,
            (unsigned long long)s->closed,
            pct);
    }
    fflush(stderr);
}

void uv_scan_status_maybe_print(uv_scan_status_t *s) {
    time_t now = time(NULL);
    if (difftime(now, s->last_print) >= s->print_interval_secs) {
        print_line(s);
        s->last_print = now;
    }
}

void uv_scan_status_final(const uv_scan_status_t *s) {
    double elapsed = difftime(time(NULL), s->start_time);
    fprintf(stderr,
        "\nScan complete — %.0fs elapsed  "
        "sent: %llu  open: %llu  closed: %llu  filtered: %llu\n",
        elapsed,
        (unsigned long long)s->sent,
        (unsigned long long)s->open,
        (unsigned long long)s->closed,
        (unsigned long long)s->filtered);
}
