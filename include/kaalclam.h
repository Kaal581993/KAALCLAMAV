/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef KAALCLAM_H
#define KAALCLAM_H
#define _GNU_SOURCE 1
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

#define KC_VERSION "0.1.1"
#define KC_MAX_PATHS 128
#define KC_MAX_DEVICES 128
#define KC_MAX_PATTERNS 64
#define KC_MIB (1024ULL * 1024ULL)

enum kc_level { KC_INFO, KC_REVIEW, KC_ALERT, KC_GAP };
enum kc_pattern_flags {
    KC_REMOTE = 1,
    KC_INJECT = 2,
    KC_SHELL = 4,
    KC_OBFUSCATED = 8,
    KC_ROOTKIT_NAME = 16,
    KC_KERNEL_FAULT = 32,
    KC_INPUT_FAULT = 64,
    KC_AUTH = 128
};

struct kc_config {
    unsigned duration, interval, update_interval, updater_timeout, scan_timeout;
    unsigned max_files, journal_hours;
    uint64_t max_file_bytes, max_total_bytes, max_report_bytes;
    bool watch, hands_off, update, signatures, update_only, scan_processes, default_scope, live;
    char report[PATH_MAX], state[PATH_MAX], home[PATH_MAX];
    const char *scan_paths[KC_MAX_PATHS];
    size_t scan_path_count;
    const char *baseline_create, *baseline_check;
    uid_t desktop_uid;
};

struct kc_stats {
    uint64_t info, review, alerts, gaps, files, bytes, malware, limits, skipped;
};

struct kc_map_entry {
    uint64_t key, value;
    bool used;
};
struct kc_map {
    struct kc_map_entry *entries;
    size_t capacity, count;
};
struct kc_ac_node {
    int next[128], fail;
    uint64_t outputs;
};
struct kc_pattern {
    const char *text;
    unsigned flags;
};
struct kc_ac {
    struct kc_ac_node *nodes;
    size_t count, capacity;
    struct kc_pattern patterns[KC_MAX_PATTERNS];
    size_t pattern_count;
    bool built;
};

struct kc_context {
    struct kc_config cfg;
    struct kc_stats stats;
    struct kc_ac matcher;
    struct kc_map reported;
    int report_fd;
    bool report_full, report_failed, namespace_limited;
    uint64_t started_ms;
};

extern volatile sig_atomic_t kc_stop;
uint64_t kc_mono_ms(void);
uint64_t kc_hash_bytes(const void *bytes, size_t n);
bool kc_path(char out[PATH_MAX], const char *base, const char *leaf);
bool kc_number(const char *text, uint64_t min, uint64_t max, uint64_t *value);
char *kc_read_text(const char *path, size_t max, size_t *length);
ssize_t kc_readlink(const char *path, char *out, size_t size);
bool kc_write_all(int fd, const void *data, size_t n);
char *kc_json_escape(const char *text);
void kc_emit(struct kc_context *ctx, enum kc_level level, const char *code, const char *subject,
             const char *fmt, ...) __attribute__((format(printf, 5, 6)));
void kc_emit_once(struct kc_context *ctx, enum kc_level level, const char *code,
                  const char *subject, const char *fmt, ...) __attribute__((format(printf, 5, 6)));
int kc_report_open(struct kc_context *ctx);
int kc_secure_dir(const char *path, mode_t mode);
int kc_run_child(const char *absolute_program, char *const argv[], int log_fd,
                 unsigned timeout_seconds, uid_t uid, gid_t gid);

bool kc_map_init(struct kc_map *map, size_t capacity);
void kc_map_destroy(struct kc_map *map);
bool kc_map_put(struct kc_map *map, uint64_t key, uint64_t value);
bool kc_map_get(const struct kc_map *map, uint64_t key, uint64_t *value);
bool kc_ac_init(struct kc_ac *ac);
bool kc_ac_add(struct kc_ac *ac, const char *text, unsigned flags);
bool kc_ac_build(struct kc_ac *ac);
uint64_t kc_ac_feed(const struct kc_ac *ac, const void *bytes, size_t n, int *state);
unsigned kc_ac_flags(const struct kc_ac *ac, const void *bytes, size_t n);
void kc_ac_destroy(struct kc_ac *ac);
bool kc_patterns_init(struct kc_ac *ac);

void kc_audit_environment(struct kc_context *ctx);
void kc_audit_processes(struct kc_context *ctx);
bool kc_net_endpoint(const char *text, bool ipv6, char out[96]);
void kc_audit_kernel(struct kc_context *ctx);
void kc_audit_persistence(struct kc_context *ctx);
void kc_journal_scan(struct kc_context *ctx);

struct kc_input;
struct kc_input *kc_input_open(struct kc_context *ctx);
void kc_input_tick(struct kc_input *input, int wait_ms);
void kc_input_close(struct kc_input *input);

/* Pure state machine, also used by synthetic-event tests. */
struct kc_button_state {
    bool known, down, desynchronized;
    uint64_t presses, releases, repeats, transitions, interval_n, last_press_us;
    double mean_interval_us, interval_m2;
};
enum kc_button_result {
    KC_BUTTON_NONE,
    KC_BUTTON_PRESS,
    KC_BUTTON_RELEASE,
    KC_BUTTON_REPEAT,
    KC_BUTTON_GAP,
    KC_BUTTON_RESYNC
};
enum kc_button_result kc_button_step(struct kc_button_state *state, unsigned type, unsigned code,
                                     int value, uint64_t time_us);

bool kc_sha256(const char *path, char hex[65], char *reason, size_t reason_size);
bool kc_sha256_limited(const char *path, uint64_t limit, uint64_t *bytes, char hex[65],
                       char *reason, size_t reason_size);
int kc_baseline(struct kc_context *ctx, bool create);
int kc_av_worker(struct kc_context *ctx, int stats_fd);
/* Testable scanner return classification; limit alerts never count as malware. */
enum kc_scan_class { KC_SCAN_CLEAN, KC_SCAN_MATCH, KC_SCAN_LIMIT, KC_SCAN_ERROR };
enum kc_scan_class kc_scan_classify(int result, bool matched, const char *signature);
int kc_selftest_av(void);
#endif
