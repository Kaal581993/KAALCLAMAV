/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "kaalclam.h"
#include <clamav.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/input.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <systemd/sd-json.h>
#include <time.h>
#include <unistd.h>

static unsigned failures, checks;
#define CHECK(x)                                                                                   \
    do {                                                                                           \
        ++checks;                                                                                  \
        if (!(x)) {                                                                                \
            ++failures;                                                                            \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x);                           \
        }                                                                                          \
    } while (0)
static unsigned folded(unsigned c) {
    return c >= 'A' && c <= 'Z' ? c + 32 : c;
}
static bool naive(const unsigned char *text, size_t n, const char *pattern) {
    size_t k = strlen(pattern);
    if (k > n)
        return false;
    for (size_t i = 0; i <= n - k; ++i) {
        bool same = true;
        for (size_t j = 0; j < k; ++j)
            if (folded(text[i + j]) != folded((unsigned char)pattern[j]))
                same = false;
        if (same)
            return true;
    }
    return false;
}
static void test_matcher(void) {
    const char *patterns[] = {"he", "she", "hers",        "his",      "aaa",
                              "aa", "a",   "/dev/uinput", "rustdesk", "BASE64 -D"};
    struct kc_ac ac;
    CHECK(kc_ac_init(&ac));
    for (unsigned i = 0; i < 10; ++i)
        CHECK(kc_ac_add(&ac, patterns[i], 1U << i));
    CHECK(kc_ac_build(&ac));
    CHECK(!kc_ac_add(&ac, "late", 1));
    unsigned char text[4096];
    uint32_t rng = 1234567;
    for (unsigned round = 0; round < 100; ++round) {
        for (size_t i = 0; i < sizeof(text); ++i) {
            rng = rng * 1664525U + 1013904223U;
            text[i] = (unsigned char)(rng >> 24);
        }
        for (unsigned i = 0; i < 10; ++i) {
            size_t at = (round * 37U + i * 313U) % (sizeof(text) - 32);
            memcpy(text + at, patterns[i], strlen(patterns[i]));
        }
        uint64_t expected = 0;
        unsigned expected_flags = 0;
        for (unsigned i = 0; i < 10; ++i)
            if (naive(text, sizeof(text), patterns[i])) {
                expected |= UINT64_C(1) << i;
                expected_flags |= 1U << i;
            }
        int state = 0;
        uint64_t actual = 0;
        for (size_t offset = 0; offset < sizeof(text);) {
            size_t length = 1 + (offset + round) % 79;
            if (length > sizeof(text) - offset)
                length = sizeof(text) - offset;
            actual |= kc_ac_feed(&ac, text + offset, length, &state);
            offset += length;
        }
        CHECK(actual == expected);
        CHECK(kc_ac_flags(&ac, text, sizeof(text)) == expected_flags);
    }
    kc_ac_destroy(&ac);
}
static void test_map(void) {
    struct kc_map m;
    CHECK(kc_map_init(&m, 1));
    for (uint64_t i = 0; i < 20000; ++i)
        CHECK(kc_map_put(&m, i * UINT64_C(16777619), i ^ UINT64_C(0xabcdef)));
    CHECK(m.count == 20000);
    for (uint64_t i = 0; i < 20000; ++i) {
        uint64_t value = 0;
        CHECK(kc_map_get(&m, i * UINT64_C(16777619), &value));
        CHECK(value == (i ^ UINT64_C(0xabcdef)));
    }
    CHECK(kc_map_put(&m, 0, 42));
    CHECK(m.count == 20000);
    uint64_t value = 0;
    CHECK(kc_map_get(&m, 0, &value) && value == 42);
    CHECK(!kc_map_get(&m, UINT64_MAX, NULL));
    kc_map_destroy(&m);
}
static void test_button(void) {
    struct kc_button_state s = {0};
    CHECK(kc_button_step(&s, EV_KEY, KEY_A, 1, 10) == KC_BUTTON_NONE);
    CHECK(kc_button_step(&s, EV_KEY, BTN_LEFT, 0, 10) == KC_BUTTON_RELEASE);
    CHECK(kc_button_step(&s, EV_KEY, BTN_LEFT, 1, 1000) == KC_BUTTON_PRESS);
    CHECK(kc_button_step(&s, EV_KEY, BTN_LEFT, 1, 1001) == KC_BUTTON_REPEAT);
    CHECK(kc_button_step(&s, EV_KEY, BTN_LEFT, 2, 1002) == KC_BUTTON_REPEAT);
    CHECK(kc_button_step(&s, EV_KEY, BTN_LEFT, 0, 1500) == KC_BUTTON_RELEASE);
    CHECK(kc_button_step(&s, EV_SYN, SYN_DROPPED, 0, 2000) == KC_BUTTON_GAP);
    CHECK(kc_button_step(&s, EV_KEY, BTN_LEFT, 1, 2500) == KC_BUTTON_NONE);
    CHECK(kc_button_step(&s, EV_SYN, SYN_REPORT, 0, 3000) == KC_BUTTON_RESYNC);
    CHECK(kc_button_step(&s, EV_KEY, BTN_LEFT, 1, 4000) == KC_BUTTON_PRESS);
    CHECK(s.presses == 2 && s.repeats == 2);
    memset(&s, 0, sizeof(s));
    for (unsigned i = 1; i <= 30; ++i) {
        kc_button_step(&s, EV_KEY, BTN_LEFT, 1, (uint64_t)i * 100000);
        kc_button_step(&s, EV_KEY, BTN_LEFT, 0, (uint64_t)i * 100000 + 1000);
    }
    CHECK(s.interval_n == 29 && fabs(s.mean_interval_us - 100000) < 0.001 &&
          fabs(s.interval_m2) < 0.001);
}
static void test_parsing(void) {
    uint64_t n;
    CHECK(kc_number("0", 0, 10, &n) && n == 0);
    CHECK(!kc_number("-1", 0, 10, &n));
    CHECK(!kc_number(" 1", 0, 10, &n));
    CHECK(!kc_number("1x", 0, 10, &n));
    CHECK(!kc_number("18446744073709551616", 0, UINT64_MAX, &n));
    char endpoint[96];
    CHECK(kc_net_endpoint("0100007F:1F90", false, endpoint) && !strcmp(endpoint, "127.0.0.1:8080"));
    CHECK(kc_net_endpoint("00000000000000000000000001000000:0035", true, endpoint) &&
          !strcmp(endpoint, "[::1]:53"));
    CHECK(!kc_net_endpoint("010000ZZ:1F90", false, endpoint));
    CHECK(!kc_net_endpoint("0100007F:0035junk", false, endpoint));
    CHECK(!kc_net_endpoint("bad", false, endpoint));
    CHECK(kc_scan_classify(CL_SUCCESS, true, "Heuristics.Limits.Exceeded.MaxScanTime") ==
          KC_SCAN_LIMIT);
    CHECK(kc_scan_classify(CL_ETIMEOUT, false, NULL) == KC_SCAN_LIMIT);
    CHECK(kc_scan_classify(CL_SUCCESS, true, "Example.Trojan") == KC_SCAN_MATCH);
    CHECK(kc_scan_classify(CL_EOPEN, false, NULL) == KC_SCAN_ERROR);
    CHECK(kc_scan_classify(CL_SUCCESS, false, NULL) == KC_SCAN_CLEAN);
    char *escaped = kc_json_escape("a\"b\\c\n\033\377");
    CHECK(escaped && !strcmp(escaped, "a\\\"b\\\\c\\u000a\\u001b\\u00ff"));
    free(escaped);
}
static void write_file(const char *path, const char *text) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    CHECK(fd >= 0);
    if (fd >= 0) {
        CHECK(kc_write_all(fd, text, strlen(text)));
        close(fd);
    }
}
static void test_files_and_reports(const char *self) {
    char directory[] = "/tmp/kaalclam-unit-XXXXXX";
    CHECK(mkdtemp(directory) != NULL);
    char sample[PATH_MAX], report[PATH_MAX], manifest[PATH_MAX], link[PATH_MAX], fifo[PATH_MAX],
        childlog[PATH_MAX];
    kc_path(sample, directory, "sample with\nnewline");
    kc_path(report, directory, "report.jsonl");
    kc_path(manifest, directory, "baseline");
    kc_path(link, directory, "symlink");
    kc_path(fifo, directory, "fifo");
    kc_path(childlog, directory, "child.log");
    write_file(sample, "abc");
    char hash[65], why[256];
    CHECK(kc_sha256(sample, hash, why, sizeof(why)));
    CHECK(!strcmp(hash, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    uint64_t bytes;
    CHECK(!kc_sha256_limited(sample, 2, &bytes, hash, why, sizeof(why)) && bytes == 0);
    CHECK(kc_sha256_limited(sample, 3, &bytes, hash, why, sizeof(why)) && bytes == 3);
    CHECK(symlink(sample, link) == 0);
    CHECK(!kc_sha256(link, hash, why, sizeof(why)));
    CHECK(mkfifo(fifo, 0600) == 0);
    CHECK(!kc_sha256(fifo, hash, why, sizeof(why)));
    struct kc_context *c = calloc(1, sizeof(*c));
    CHECK(c != NULL);
    if (!c)
        goto cleanup;
    c->started_ms = kc_mono_ms();
    c->cfg.max_report_bytes = 16 * KC_MIB;
    c->cfg.max_file_bytes = KC_MIB;
    c->cfg.max_total_bytes = 10 * KC_MIB;
    c->cfg.max_files = 100;
    snprintf(c->cfg.report, sizeof(c->cfg.report), "%s", report);
    CHECK(kc_report_open(c) == 0);
    CHECK(kc_map_init(&c->reported, 16));
    kc_emit(c, KC_INFO, "test.escaping", "\n\"subject", "special=%s", "\033\\\"\377");
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        for (unsigned i = 0; i < 100; ++i)
            kc_emit(c, KC_INFO, "test.child", "parallel", "row=%u", i);
        _exit(0);
    }
    for (unsigned i = 0; i < 100; ++i)
        kc_emit(c, KC_INFO, "test.parent", "parallel", "row=%u", i);
    if (child > 0) {
        int status;
        CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
    c->cfg.scan_paths[0] = sample;
    c->cfg.scan_path_count = 1;
    c->cfg.baseline_create = manifest;
    c->cfg.baseline_check = manifest;
    c->cfg.max_file_bytes = 2;
    CHECK(kc_baseline(c, true) == 2);
    CHECK(kc_baseline(c, false) == 2);
    unlink(manifest);
    c->cfg.max_file_bytes = KC_MIB;
    /* Creating a baseline inside its scope must exclude the report/manifest. */
    c->cfg.scan_paths[0] = directory;
    CHECK(kc_baseline(c, true) == 0);
    CHECK(kc_baseline(c, true) == 2);
    c->cfg.max_total_bytes = 2;
    CHECK(kc_baseline(c, false) == 2);
    c->cfg.max_total_bytes = 10 * KC_MIB;
    c->cfg.max_files = 1;
    CHECK(kc_baseline(c, false) == 0);
    c->cfg.max_files = 100;
    CHECK(kc_baseline(c, false) == 0);
    write_file(sample, "changed");
    CHECK(kc_baseline(c, false) == 3);
    unlink(manifest);
    write_file(manifest, "# empty baseline\n");
    CHECK(kc_baseline(c, false) == 2);
    c->cfg.baseline_check = fifo;
    CHECK(kc_baseline(c, false) == 2);
    c->cfg.baseline_check = manifest;
    char *ok_argv[] = {(char *)self, "--child-ok", NULL};
    int childfd = open(childlog, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    CHECK(childfd >= 0);
    CHECK(kc_run_child(self, ok_argv, childfd, 3, geteuid(), getegid()) == 0);
    CHECK(setenv("KC_TEST_INHERITED", "must not reach updater", 1) == 0);
    char *env_argv[] = {(char *)self, "--child-check-env", NULL};
    CHECK(kc_run_child(self, env_argv, childfd, 3, geteuid(), getegid()) == 0);
    unsetenv("KC_TEST_INHERITED");
    char *wait_argv[] = {(char *)self, "--child-wait", NULL};
    uint64_t start = kc_mono_ms();
    CHECK(kc_run_child(self, wait_argv, childfd, 1, geteuid(), getegid()) == 124);
    if (childfd >= 0)
        close(childfd);
    CHECK(kc_mono_ms() - start < 4000);
    close(c->report_fd);
    FILE *f = fopen(report, "re");
    CHECK(f != NULL);
    if (f) {
        char *line = NULL;
        size_t capacity = 0;
        unsigned records = 0;
        while (getline(&line, &capacity, f) >= 0) {
            sd_json_variant *v = NULL;
            CHECK(sd_json_parse(line, 0, &v, NULL, NULL) >= 0);
            CHECK(sd_json_variant_is_object(v));
            sd_json_variant_unref(v);
            ++records;
        }
        CHECK(records >= 201);
        free(line);
        fclose(f);
    }
    kc_map_destroy(&c->reported);
    free(c);
cleanup:
    unlink(fifo);
    unlink(link);
    unlink(sample);
    unlink(report);
    unlink(manifest);
    unlink(childlog);
    rmdir(directory);
}
static void test_report_limits(void) {
    char path[] = "/tmp/kaalclam-report-limit-XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    if (fd < 0)
        return;
    close(fd);
    unlink(path);
    struct kc_context *c = calloc(1, sizeof(*c));
    CHECK(c != NULL);
    if (!c)
        return;
    c->cfg.max_report_bytes = 1024;
    c->started_ms = kc_mono_ms();
    snprintf(c->cfg.report, sizeof(c->cfg.report), "%s", path);
    CHECK(kc_report_open(c) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    for (unsigned i = 0; i < 100; ++i)
        kc_emit(c, KC_INFO, "test.limit", "concurrent", "row=%u", i);
    if (child == 0)
        _exit(0);
    if (child > 0) {
        int status;
        CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
    struct stat st;
    CHECK(fstat(c->report_fd, &st) == 0 && st.st_size > 0 && st.st_size <= 1024);
    CHECK(c->report_full && kc_stop && c->stats.gaps > 0);
    close(c->report_fd);
    FILE *f = fopen(path, "re");
    CHECK(f != NULL);
    if (f) {
        char *line = NULL;
        size_t capacity = 0;
        while (getline(&line, &capacity, f) >= 0) {
            sd_json_variant *v = NULL;
            CHECK(sd_json_parse(line, 0, &v, NULL, NULL) >= 0);
            CHECK(sd_json_variant_is_object(v));
            sd_json_variant_unref(v);
        }
        free(line);
        fclose(f);
    }
    unlink(path);
    kc_stop = 0;
    c->report_fd = -1;
    c->report_full = false;
    kc_emit(c, KC_INFO, "test.bad_fd", "report", "must fail");
    CHECK(c->report_failed && kc_stop);
    kc_stop = 0;
    free(c);
}
int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--child-ok"))
        _exit(0);
    if (argc == 2 && !strcmp(argv[1], "--child-check-env"))
        _exit(getenv("KC_TEST_INHERITED") == NULL && getenv("LD_PRELOAD") == NULL &&
                      prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1
                  ? 0
                  : 1);
    if (argc == 2 && !strcmp(argv[1], "--child-wait")) {
        struct timespec t = {10, 0};
        nanosleep(&t, NULL);
        return 0;
    }
    char self[PATH_MAX];
    if (kc_readlink("/proc/self/exe", self, sizeof(self)) < 0)
        return 1;
    test_map();
    test_matcher();
    test_button();
    test_parsing();
    test_files_and_reports(self);
    test_report_limits();
    CHECK(kc_selftest_av() == 0);
    printf("C tests: %u checks, %u failures\n", checks, failures);
    return failures ? 1 : 0;
}
