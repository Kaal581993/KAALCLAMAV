/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "kaalclam.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <systemd/sd-journal.h>
#include <time.h>

static char *field(sd_journal *j, const char *name, size_t limit) {
    const void *data;
    size_t n;
    int r = sd_journal_get_data(j, name, &data, &n);
    if (r < 0)
        return NULL;
    size_t prefix = strlen(name) + 1;
    if (n < prefix)
        return NULL;
    n -= prefix;
    if (n > limit)
        n = limit;
    char *s = malloc(n + 1);
    if (!s)
        return NULL;
    memcpy(s, (const char *)data + prefix, n);
    s[n] = 0;
    return s;
}
void kc_journal_scan(struct kc_context *c) {
    sd_journal *j = NULL;
    int r = sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY);
    if (r < 0) {
        kc_emit(c, KC_GAP, "journal.unavailable", "systemd journal", "%s", strerror(-r));
        return;
    }
    uint64_t now = (uint64_t)time(NULL) * 1000000,
             lookback = (uint64_t)c->cfg.journal_hours * 3600 * 1000000;
    uint64_t since = now > lookback ? now - lookback : 0, first = 0, last = 0;
    unsigned visited = 0, matches = 0;
    sd_journal_set_data_threshold(j, 16384);
    r = sd_journal_seek_realtime_usec(j, since);
    if (r < 0) {
        kc_emit(c, KC_GAP, "journal.seek_failed", "systemd journal", "%s", strerror(-r));
        sd_journal_close(j);
        return;
    }
    while (!kc_stop && (r = sd_journal_next(j)) > 0 && visited < 200000) {
        ++visited;
        uint64_t at = 0;
        (void)sd_journal_get_realtime_usec(j, &at);
        if (!first)
            first = at;
        last = at;
        char *message = field(j, "MESSAGE", 4096);
        if (!message)
            continue;
        unsigned flags = kc_ac_flags(&c->matcher, message, strlen(message));
        if (!flags) {
            free(message);
            continue;
        }
        char *transport = field(j, "_TRANSPORT", 64),
             *identifier = field(j, "SYSLOG_IDENTIFIER", 256);
        bool kernel = transport && !strcmp(transport, "kernel");
        bool relevant = false;
        const char *code = "journal.context";
        enum kc_level level = KC_INFO;
        if (flags & KC_INPUT_FAULT) {
            if (strcasestr(message, "jump") || strcasestr(message, "error") ||
                strcasestr(message, "fail") || strcasestr(message, "timeout") ||
                strcasestr(message, "syn_dropped")) {
                relevant = true;
                code = "journal.input_fault";
                level = KC_REVIEW;
            }
        }
        if (kernel && (flags & KC_KERNEL_FAULT)) {
            relevant = true;
            code = "journal.kernel_fault";
            level = KC_REVIEW;
        }
        if (flags & KC_AUTH) {
            relevant = true;
            code = "journal.authentication";
        }
        if ((flags & KC_REMOTE) && identifier &&
            (strcasestr(identifier, "rustdesk") || strcasestr(identifier, "anydesk") ||
             strcasestr(identifier, "sshd") || strcasestr(identifier, "krdp") ||
             strcasestr(identifier, "krfb") || strcasestr(identifier, "teamviewer"))) {
            relevant = true;
            code = "journal.remote_service";
        }
        if (relevant) {
            ++matches;
            char subject[512];
            snprintf(subject, sizeof(subject), "%s time_us=%llu",
                     identifier ? identifier
                     : kernel   ? "kernel"
                                : "unknown",
                     (unsigned long long)at);
            kc_emit_once(c, level, code, subject, "%s", message);
        }
        free(message);
        free(transport);
        free(identifier);
    }
    if (r < 0)
        kc_emit(c, KC_GAP, "journal.read_error", "systemd journal", "%s", strerror(-r));
    if (visited >= 200000)
        kc_emit(c, KC_GAP, "journal.record_limit", "systemd journal",
                "200000-entry cap reached; requested lookback is incomplete.");
    if (!visited)
        kc_emit(c, KC_GAP, "journal.no_readable_records", "systemd journal",
                "No readable records in requested lookback. This is not evidence of no incidents.");
    kc_emit(c, KC_INFO, "journal.summary", "systemd journal",
            "requested_since_us=%llu first_readable_us=%llu last_readable_us=%llu visited=%u "
            "matched=%u. Retention, permissions and log suppression can create gaps; logs can be "
            "falsified by a compromised kernel or administrator.",
            (unsigned long long)since, (unsigned long long)first, (unsigned long long)last, visited,
            matches);
    sd_journal_close(j);
}
