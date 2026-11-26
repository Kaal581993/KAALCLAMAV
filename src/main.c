/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "kaalclam.h"
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void stop_handler(int signal_number) {
    (void)signal_number;
    kc_stop = 1;
}
static void usage(FILE *out) {
    fputs(
        "KaalClam " KC_VERSION " — Linux input, kernel and malware diagnostics (C)\n"
        "Usage: KaalClam [options]\n\n"
        "  --duration SEC          Observe input for SEC seconds (default 300; 0=snapshot)\n"
        "  --watch                 Observe continuously until Ctrl+C; refresh signatures "
        "periodically\n"
        "  --live                  Print new connection owners and review/coverage findings\n"
        "  --hands-off             You will not touch input devices during observation\n"
        "  --scan PATH             Signature scan scope (repeatable; replaces default paths)\n"
        "  --scan-processes        Include accessible live executable file objects\n"
        "  --no-signatures         Hardware/kernel/process checks only; no updater\n"
        "  --no-update             Use existing signatures without refreshing\n"
        "  --update-only           Refresh official signatures, then exit\n"
        "  --update-interval SEC   Refresh interval, 3600..86400 (default 14400)\n"
        "  --updater-timeout SEC   FreshClam timeout (default 120)\n"
        "  --scan-timeout SEC      Engine time budget per file (default 20)\n"
        "  --max-file-mb MB        File scan size limit (default 256)\n"
        "  --max-total-mb MB       Total input-file byte budget (default 1024)\n"
        "  --max-files COUNT       File-count budget (default 5000)\n"
        "  --max-report-mb MB      Stop before report exceeds this limit (default 64)\n"
        "  --interval SEC         Process snapshot interval (default 30)\n"
        "  --journal-hours HOURS  Journal lookback (default 24)\n"
        "  --report FILE          New private JSONL report; existing files are never overwritten\n"
        "  --state-dir DIR        Private signature/update state (absolute path)\n"
        "  --baseline-create FILE Create SHA256 baseline of --scan paths; separate mode\n"
        "  --baseline-check FILE  Compare files with an existing baseline; separate mode\n"
        "  --self-test            Test native signature engine with an inert local test marker\n"
        "  --help                 Show help\n"
        "  --version              Show version\n\n"
        "Refreshes official ClamAV signatures automatically unless --no-update is given.\n"
        "No deletion, quarantine, device grabbing, kernel modules, or settings changes.\n"
        "A normal host terminal/root run is required for some device/kernel/process checks.\n"
        "A compromised kernel may falsify every live view: no exhaustive malware guarantee.\n"
        "Exit: 0=completed, 1=signature alert, 2=incomplete coverage/error, 3=review findings\n"
        "      (including baseline changes). Alerts take precedence over coverage gaps.\n",
        out);
}
static bool set_path(char out[PATH_MAX], const char *s) {
    if (!s || strlen(s) >= PATH_MAX)
        return false;
    memcpy(out, s, strlen(s) + 1);
    return true;
}
static int config(struct kc_config *c, int argc, char **argv) {
    memset(c, 0, sizeof(*c));
    c->duration = 300;
    c->interval = 30;
    c->update_interval = 14400;
    c->updater_timeout = 120;
    c->scan_timeout = 20;
    c->max_files = 5000;
    c->journal_hours = 24;
    c->max_file_bytes = 256 * KC_MIB;
    c->max_total_bytes = 1024 * KC_MIB;
    c->max_report_bytes = 64 * KC_MIB;
    c->update = true;
    c->signatures = true;
    c->desktop_uid = getuid();
    uint64_t sudo_uid;
    if (geteuid() == 0 && kc_number(getenv("SUDO_UID"), 1, UINT_MAX, &sudo_uid))
        c->desktop_uid = (uid_t)sudo_uid;
    struct passwd *pw = getpwuid(c->desktop_uid);
    if (!pw || !set_path(c->home, pw->pw_dir)) {
        fprintf(stderr, "KaalClam: cannot determine user's home directory.\n");
        return -1;
    }
    if (geteuid() == 0)
        set_path(c->state, "/var/lib/kaalclam");
    else if (!kc_path(c->state, c->home, ".local/share/kaalclam"))
        return -1;
    enum {
        OPT_DURATION = 256,
        OPT_WATCH,
        OPT_LIVE,
        OPT_HANDS,
        OPT_SCAN,
        OPT_SCAN_PROC,
        OPT_NO_SIG,
        OPT_NO_UPDATE,
        OPT_UPDATE_ONLY,
        OPT_UPDATE_INTERVAL,
        OPT_UPDATE_TIMEOUT,
        OPT_SCAN_TIMEOUT,
        OPT_FILE_MB,
        OPT_TOTAL_MB,
        OPT_FILES,
        OPT_REPORT_MB,
        OPT_INTERVAL,
        OPT_HOURS,
        OPT_REPORT,
        OPT_STATE,
        OPT_BASE_CREATE,
        OPT_BASE_CHECK,
        OPT_SELF_TEST,
        OPT_VERSION
    };
    static const struct option opts[] = {
        {"duration", required_argument, NULL, OPT_DURATION},
        {"watch", no_argument, NULL, OPT_WATCH},
        {"live", no_argument, NULL, OPT_LIVE},
        {"hands-off", no_argument, NULL, OPT_HANDS},
        {"scan", required_argument, NULL, OPT_SCAN},
        {"scan-processes", no_argument, NULL, OPT_SCAN_PROC},
        {"no-signatures", no_argument, NULL, OPT_NO_SIG},
        {"no-update", no_argument, NULL, OPT_NO_UPDATE},
        {"update-only", no_argument, NULL, OPT_UPDATE_ONLY},
        {"update-interval", required_argument, NULL, OPT_UPDATE_INTERVAL},
        {"updater-timeout", required_argument, NULL, OPT_UPDATE_TIMEOUT},
        {"scan-timeout", required_argument, NULL, OPT_SCAN_TIMEOUT},
        {"max-file-mb", required_argument, NULL, OPT_FILE_MB},
        {"max-total-mb", required_argument, NULL, OPT_TOTAL_MB},
        {"max-files", required_argument, NULL, OPT_FILES},
        {"max-report-mb", required_argument, NULL, OPT_REPORT_MB},
        {"interval", required_argument, NULL, OPT_INTERVAL},
        {"journal-hours", required_argument, NULL, OPT_HOURS},
        {"report", required_argument, NULL, OPT_REPORT},
        {"state-dir", required_argument, NULL, OPT_STATE},
        {"baseline-create", required_argument, NULL, OPT_BASE_CREATE},
        {"baseline-check", required_argument, NULL, OPT_BASE_CHECK},
        {"self-test", no_argument, NULL, OPT_SELF_TEST},
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, OPT_VERSION},
        {NULL, 0, NULL, 0}};
    bool processes_requested = false;
    int option;
    while ((option = getopt_long(argc, argv, "h", opts, NULL)) != -1) {
        uint64_t n = 0, min = 1, max = 86400;
        bool number = false;
        switch (option) {
        case 'h':
            usage(stdout);
            return 1;
        case OPT_VERSION:
            puts("KaalClam " KC_VERSION);
            return 1;
        case OPT_SELF_TEST: {
            int r = kc_selftest_av();
            printf("Native ClamAV inert-marker self-test: %s\n", r ? "FAILED" : "passed");
            return r ? -1 : 1;
        }
        case OPT_WATCH:
            c->watch = true;
            break;
        case OPT_LIVE:
            c->live = true;
            break;
        case OPT_HANDS:
            c->hands_off = true;
            break;
        case OPT_NO_SIG:
            c->signatures = false;
            break;
        case OPT_NO_UPDATE:
            c->update = false;
            break;
        case OPT_UPDATE_ONLY:
            c->update_only = true;
            break;
        case OPT_SCAN:
            if (c->scan_path_count >= KC_MAX_PATHS) {
                fprintf(stderr, "KaalClam: too many scan paths.\n");
                return -1;
            }
            c->scan_paths[c->scan_path_count++] = optarg;
            break;
        case OPT_SCAN_PROC:
            processes_requested = true;
            break;
        case OPT_REPORT:
            if (!set_path(c->report, optarg))
                return -1;
            break;
        case OPT_STATE:
            if (!set_path(c->state, optarg) || optarg[0] != '/') {
                fprintf(stderr, "KaalClam: --state-dir must be an absolute path.\n");
                return -1;
            }
            break;
        case OPT_BASE_CREATE:
            c->baseline_create = optarg;
            break;
        case OPT_BASE_CHECK:
            c->baseline_check = optarg;
            break;
        case OPT_DURATION:
            number = true;
            min = 0;
            max = 86400;
            break;
        case OPT_UPDATE_INTERVAL:
            number = true;
            min = 3600;
            max = 86400;
            break;
        case OPT_UPDATE_TIMEOUT:
            number = true;
            max = 1800;
            break;
        case OPT_SCAN_TIMEOUT:
            number = true;
            max = 3600;
            break;
        case OPT_FILE_MB:
            number = true;
            max = 2048;
            break;
        case OPT_TOTAL_MB:
            number = true;
            max = 1048576;
            break;
        case OPT_REPORT_MB:
            number = true;
            max = 4096;
            break;
        case OPT_FILES:
            number = true;
            max = 1000000;
            break;
        case OPT_INTERVAL:
            number = true;
            min = 5;
            max = 3600;
            break;
        case OPT_HOURS:
            number = true;
            max = 720;
            break;
        default:
            usage(stderr);
            return -1;
        }
        if (number) {
            if (!kc_number(optarg, min, max, &n)) {
                fprintf(stderr, "KaalClam: invalid numeric option: %s\n", optarg);
                return -1;
            }
            switch (option) {
            case OPT_DURATION:
                c->duration = (unsigned)n;
                break;
            case OPT_UPDATE_INTERVAL:
                c->update_interval = (unsigned)n;
                break;
            case OPT_UPDATE_TIMEOUT:
                c->updater_timeout = (unsigned)n;
                break;
            case OPT_SCAN_TIMEOUT:
                c->scan_timeout = (unsigned)n;
                break;
            case OPT_FILE_MB:
                c->max_file_bytes = n * KC_MIB;
                break;
            case OPT_TOTAL_MB:
                c->max_total_bytes = n * KC_MIB;
                break;
            case OPT_REPORT_MB:
                c->max_report_bytes = n * KC_MIB;
                break;
            case OPT_FILES:
                c->max_files = (unsigned)n;
                break;
            case OPT_INTERVAL:
                c->interval = (unsigned)n;
                break;
            case OPT_HOURS:
                c->journal_hours = (unsigned)n;
                break;
            default:
                break;
            }
        }
    }
    if (optind != argc || (c->baseline_create && c->baseline_check) ||
        (c->update_only && (!c->update || !c->signatures)) ||
        (c->update_only && (c->baseline_check || c->baseline_create)) ||
        ((c->baseline_check || c->baseline_create) && c->watch)) {
        fprintf(stderr, "KaalClam: incompatible options or unexpected positional arguments.\n");
        return -1;
    }
    if (c->baseline_create && !c->scan_path_count) {
        fprintf(stderr, "KaalClam: --baseline-create requires explicit --scan paths.\n");
        return -1;
    }
    if (!c->report[0]) {
        char cwd[PATH_MAX];
        if (!getcwd(cwd, sizeof(cwd)))
            return -1;
        char leaf[128];
        struct timespec now;
        clock_gettime(CLOCK_REALTIME, &now);
        snprintf(leaf, sizeof(leaf), "KaalClam-report-%lld-%09ld-%ld.jsonl", (long long)now.tv_sec,
                 now.tv_nsec, (long)getpid());
        if (!kc_path(c->report, cwd, leaf))
            return -1;
    }
    c->scan_processes = processes_requested || !c->scan_path_count;
    return 0;
}
static void default_scope(struct kc_config *c, char paths[24][PATH_MAX]) {
    c->default_scope = true;
    const char *relative[] = {".config/autostart",
                              ".config/autostart-scripts",
                              ".config/systemd/user",
                              ".config/environment.d",
                              ".config/plasma-workspace/env",
                              ".local/bin",
                              ".bashrc",
                              ".bash_profile",
                              ".profile",
                              ".zshrc",
                              ".zshenv",
                              ".config/fish/config.fish"};
    unsigned used = 0;
    for (size_t i = 0; i < sizeof(relative) / sizeof(*relative); ++i)
        if (kc_path(paths[used], c->home, relative[i]))
            c->scan_paths[c->scan_path_count++] = paths[used++];
    const char *system[] = {"/usr/local/bin",    "/usr/local/sbin",   "/etc/systemd/system",
                            "/etc/systemd/user", "/etc/udev/rules.d", "/etc/cron.d",
                            "/etc/cron.hourly",  "/dev/shm",          "/tmp"};
    for (size_t i = 0; i < sizeof(system) / sizeof(*system); ++i)
        c->scan_paths[c->scan_path_count++] = system[i];
}
static pid_t start_worker(struct kc_context *c, int *readfd) {
    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC) < 0) {
        kc_emit(c, KC_GAP, "av.worker_pipe", "scan", "%s", strerror(errno));
        return 0;
    }
    pid_t pid = fork();
    if (pid < 0) {
        kc_emit(c, KC_GAP, "av.worker_fork", "scan", "%s", strerror(errno));
        close(pipefd[0]);
        close(pipefd[1]);
        return 0;
    }
    if (pid == 0) {
        close(pipefd[0]);
        (void)setpgid(0, 0);
        int status = kc_av_worker(c, pipefd[1]);
        close(c->report_fd);
        _exit(status);
    }
    close(pipefd[1]);
    *readfd = pipefd[0];
    (void)setpgid(pid, pid);
    return pid;
}
static bool reap_worker(struct kc_context *c, pid_t *pid, int *readfd) {
    if (!*pid)
        return true;
    int status;
    pid_t r = waitpid(*pid, &status, WNOHANG);
    if (r == 0 || (r < 0 && errno == EINTR))
        return false;
    if (r < 0) {
        kc_emit(c, KC_GAP, "av.worker_wait", "scan", "%s", strerror(errno));
        *pid = 0;
        if (*readfd >= 0)
            close(*readfd);
        *readfd = -1;
        return true;
    }
    struct kc_stats s;
    size_t n = 0;
    while (n < sizeof(s)) {
        ssize_t got = read(*readfd, (char *)&s + n, sizeof(s) - n);
        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0)
            break;
        n += (size_t)got;
    }
    close(*readfd);
    *readfd = -1;
    *pid = 0;
    if (n == sizeof(s)) {
        c->stats.info += s.info;
        c->stats.review += s.review;
        c->stats.alerts += s.alerts;
        c->stats.gaps += s.gaps;
        c->stats.files += s.files;
        c->stats.bytes += s.bytes;
        c->stats.malware += s.malware;
        c->stats.limits += s.limits;
        c->stats.skipped += s.skipped;
    } else
        kc_emit(c, KC_GAP, "av.worker_incomplete", "scan",
                "Worker ended without complete statistics; signature coverage is incomplete.");
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        kc_emit(c, KC_GAP, "av.worker_status", "scan",
                "worker_wait_status=%d; review preceding scan errors.", status);
    return true;
}
int main(int argc, char **argv) {
    umask(0077);
    struct kc_context *c = calloc(1, sizeof(*c));
    if (!c)
        return 2;
    c->report_fd = -1;
    c->started_ms = kc_mono_ms();
    int parsed = config(&c->cfg, argc, argv);
    if (parsed) {
        free(c);
        return parsed > 0 ? 0 : 2;
    }
    if (kc_report_open(c) < 0) {
        fprintf(stderr, "KaalClam: cannot create new report %s: %s\n", c->cfg.report,
                strerror(errno));
        free(c);
        return 2;
    }
    if (!kc_patterns_init(&c->matcher) || !kc_map_init(&c->reported, 512)) {
        fprintf(stderr, "KaalClam: allocation failure.\n");
        close(c->report_fd);
        kc_ac_destroy(&c->matcher);
        free(c);
        return 2;
    }
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = stop_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    printf("KaalClam %s\nReport: %s\n", KC_VERSION, c->cfg.report);
    fflush(stdout);
    kc_emit(c, KC_INFO, "run.started", "KaalClam",
            "version=%s hands_off_assumed=%d duration_seconds=%u watch=%d; findings are "
            "evidence/heuristics, not exhaustive kernel integrity proof.",
            KC_VERSION, c->cfg.hands_off, c->cfg.duration, c->cfg.watch);
    int result = 0;
    char default_paths[24][PATH_MAX];
    pid_t worker = 0;
    int workerfd = -1;
    if (c->cfg.baseline_create || c->cfg.baseline_check) {
        result = kc_baseline(c, c->cfg.baseline_create != NULL);
        goto finish;
    }
    if (!c->cfg.scan_path_count)
        default_scope(&c->cfg, default_paths);
    kc_audit_environment(c);
    if (!c->cfg.update_only) {
        kc_audit_processes(c);
        kc_audit_kernel(c);
        kc_audit_persistence(c);
        kc_journal_scan(c);
    }
    if (c->cfg.signatures && !kc_stop)
        worker = start_worker(c, &workerfd);
    else if (!c->cfg.signatures)
        kc_emit(c, KC_GAP, "av.not_requested", "signature scan",
                "Signature scanning and refresh explicitly disabled; only input/kernel/process "
                "heuristics were requested.");
    struct kc_input *input = c->cfg.update_only ? NULL : kc_input_open(c);
    uint64_t start = kc_mono_ms(), deadline = start + (uint64_t)c->cfg.duration * 1000,
             next_audit = start + (uint64_t)c->cfg.interval * 1000,
             next_refresh = start + (uint64_t)c->cfg.update_interval * 1000;
    bool observing = !c->cfg.update_only && (c->cfg.watch || c->cfg.duration > 0);
    unsigned rounds = 0;
    if (!observing && input) {
        kc_input_close(input);
        input = NULL;
    }
    while (!kc_stop) {
        (void)reap_worker(c, &worker, &workerfd);
        uint64_t now = kc_mono_ms();
        if (observing && !c->cfg.watch && now >= deadline) {
            observing = false;
            kc_input_close(input);
            input = NULL;
            kc_emit(
                c, KC_INFO, "input.observation_finished", "input",
                "Requested observation window finished; waiting for any remaining signature scan.");
        }
        if (!observing && !worker)
            break;
        if (observing && now >= next_audit) {
            kc_audit_processes(c);
            if (++rounds % 5 == 0) {
                kc_audit_kernel(c);
                kc_audit_persistence(c);
                kc_journal_scan(c);
            }
            next_audit = kc_mono_ms() + (uint64_t)c->cfg.interval * 1000;
        }
        if (c->cfg.watch && c->cfg.signatures && !worker && now >= next_refresh) {
            worker = start_worker(c, &workerfd);
            next_refresh = now + (uint64_t)c->cfg.update_interval * 1000;
        }
        if (input)
            kc_input_tick(input, 100);
        else {
            struct timespec pause = {0, 100000000};
            nanosleep(&pause, NULL);
        }
    }
    if (input)
        kc_input_close(input);
    if (kc_stop)
        kc_emit(c, KC_GAP, "run.interrupted", "KaalClam",
                "Run interrupted or stopped after an error/limit; coverage is incomplete.");
    if (worker) {
        kill(-worker, SIGTERM);
        uint64_t until = kc_mono_ms() + 2000;
        while (worker && kc_mono_ms() < until) {
            if (!reap_worker(c, &worker, &workerfd)) {
                struct timespec t = {0, 50000000};
                nanosleep(&t, NULL);
            }
        }
        if (worker) {
            kill(-worker, SIGKILL);
            while (worker && !reap_worker(c, &worker, &workerfd)) {
                struct timespec t = {0, 10000000};
                nanosleep(&t, NULL);
            }
        }
        kc_emit(c, KC_GAP, "av.cancelled", "signature scan",
                "Observation stopped before signature worker completed.");
    }
    if (!c->cfg.update_only)
        kc_journal_scan(c);
finish:
    kc_emit(
        c, KC_INFO, "run.summary", "KaalClam",
        "signature_matches=%llu review_findings=%llu unavailable_findings=%llu scanned_files=%llu "
        "scan_limit_alerts=%llu. No proof of absence of malware is implied. Rootkits can falsify "
        "procfs/sysfs/journals; trusted offline comparison is needed for stronger assurance.",
        (unsigned long long)c->stats.malware, (unsigned long long)c->stats.review,
        (unsigned long long)c->stats.gaps, (unsigned long long)c->stats.files,
        (unsigned long long)c->stats.limits);
    printf("Signature matches: %llu | review findings: %llu | unavailable/limited checks: "
           "%llu\nScanned files: %llu | scan-limit alerts: %llu\n",
           (unsigned long long)c->stats.malware, (unsigned long long)c->stats.review,
           (unsigned long long)c->stats.gaps, (unsigned long long)c->stats.files,
           (unsigned long long)c->stats.limits);
    result = c->stats.alerts                                                                 ? 1
             : result == 2 || c->stats.gaps || c->report_full || c->report_failed || kc_stop ? 2
             : result == 3 || c->stats.review                                                ? 3
                                                                                             : 0;
    if (fsync(c->report_fd) < 0) {
        fprintf(stderr, "KaalClam: report sync failed: %s\n", strerror(errno));
        result = 2;
    }
    close(c->report_fd);
    kc_map_destroy(&c->reported);
    kc_ac_destroy(&c->matcher);
    free(c);
    return result;
}
