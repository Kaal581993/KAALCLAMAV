/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "kaalclam.h"
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

volatile sig_atomic_t kc_stop;
uint64_t kc_mono_ms(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t))
        return 0;
    return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}
bool kc_path(char out[PATH_MAX], const char *base, const char *leaf) {
    int n = snprintf(out, PATH_MAX, "%s%s%s", base,
                     *base && base[strlen(base) - 1] == '/' ? "" : "/", leaf);
    return n >= 0 && n < PATH_MAX;
}
bool kc_number(const char *s, uint64_t min, uint64_t max, uint64_t *v) {
    if (!s || !*s || *s == '-' || *s == '+')
        return false;
    for (const char *p = s; *p; ++p)
        if (*p < '0' || *p > '9')
            return false;
    errno = 0;
    char *end;
    unsigned long long n = strtoull(s, &end, 10);
    if (errno || *end || n < min || n > max)
        return false;
    *v = (uint64_t)n;
    return true;
}
char *kc_read_text(const char *path, size_t limit, size_t *len) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0)
        return NULL;
    char *b = malloc(limit + 1);
    if (!b) {
        close(fd);
        return NULL;
    }
    size_t n = 0;
    while (n < limit) {
        ssize_t r = read(fd, b + n, limit - n);
        if (r < 0 && errno == EINTR)
            continue;
        if (r < 0) {
            int e = errno;
            free(b);
            close(fd);
            errno = e;
            return NULL;
        }
        if (!r)
            break;
        n += (size_t)r;
    }
    b[n] = 0;
    close(fd);
    if (len)
        *len = n;
    return b;
}
ssize_t kc_readlink(const char *path, char *out, size_t size) {
    if (!size) {
        errno = EINVAL;
        return -1;
    }
    ssize_t n = readlink(path, out, size - 1);
    if (n < 0)
        return n;
    if ((size_t)n == size - 1) {
        errno = ENAMETOOLONG;
        return -1;
    }
    out[n] = 0;
    return n;
}
bool kc_write_all(int fd, const void *data, size_t n) {
    const char *p = data;
    while (n) {
        ssize_t k = write(fd, p, n);
        if (k < 0 && errno == EINTR)
            continue;
        if (k <= 0)
            return false;
        p += (size_t)k;
        n -= (size_t)k;
    }
    return true;
}
char *kc_json_escape(const char *s) {
    if (!s)
        s = "";
    size_t len = strlen(s);
    if (len > (SIZE_MAX - 1) / 6)
        return NULL;
    char *b = malloc(len * 6 + 1);
    if (!b)
        return NULL;
    char *p = b;
    static const char hex[] = "0123456789abcdef";
    for (const unsigned char *q = (const unsigned char *)s; *q; ++q) {
        unsigned c = *q;
        if (c == '"' || c == '\\') {
            *p++ = '\\';
            *p++ = (char)c;
        } else if (c < 32 || c >= 127) {
            *p++ = '\\';
            *p++ = 'u';
            *p++ = '0';
            *p++ = '0';
            *p++ = hex[c >> 4];
            *p++ = hex[c & 15];
        } else
            *p++ = (char)c;
    }
    *p = 0;
    return b;
}
int kc_report_open(struct kc_context *c) {
    c->report_fd =
        open(c->cfg.report, O_WRONLY | O_CREAT | O_EXCL | O_APPEND | O_CLOEXEC | O_NOFOLLOW, 0600);
    return c->report_fd < 0 ? -1 : 0;
}
static void emitv(struct kc_context *c, enum kc_level level, const char *code, const char *subject,
                  const char *fmt, va_list ap) {
    static const char *names[] = {"info", "review", "alert", "unavailable"};
    char details[6000];
    vsnprintf(details, sizeof(details), fmt, ap);
    if (level == KC_INFO)
        ++c->stats.info;
    else if (level == KC_REVIEW)
        ++c->stats.review;
    else if (level == KC_ALERT)
        ++c->stats.alerts;
    else
        ++c->stats.gaps;
    char *a = kc_json_escape(code), *b = kc_json_escape(subject), *d = kc_json_escape(details);
    if (!a || !b || !d) {
        free(a);
        free(b);
        free(d);
        c->report_failed = true;
        ++c->stats.gaps;
        kc_stop = 1;
        return;
    }
    struct timespec ts = {0};
    (void)clock_gettime(CLOCK_REALTIME, &ts);
    char *line = NULL;
    int n =
        asprintf(&line,
                 "{\"time_unix_ms\":%llu,\"elapsed_ms\":%llu,\"level\":\"%s\",\"code\":\"%s\","
                 "\"subject\":\"%s\",\"detail\":\"%s\"}\n",
                 (unsigned long long)((uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000),
                 (unsigned long long)(kc_mono_ms() - c->started_ms), names[level], a, b, d);
    if (c->cfg.live && (level != KC_INFO || !strcmp(code, "network.socket_owner") ||
                        !strcmp(code, "process.indicator") || !strcmp(code, "input.write_handle") ||
                        !strcmp(code, "persistence.indicator") || !strncmp(code, "updates.", 8) ||
                        !strcmp(code, "av.engine_ready") || !strcmp(code, "av.summary"))) {
        /* Escaping also prevents filenames/log messages from controlling the terminal. */
        (void)dprintf(STDOUT_FILENO, "[%s] %s | %s | %s\n", names[level], a, b, d);
    }
    free(a);
    free(b);
    free(d);
    if (n <= 0 || !line) {
        c->report_failed = true;
        ++c->stats.gaps;
        kc_stop = 1;
    } else if (!c->report_full && !c->report_failed) {
        /* POSIX record locks are per process, unlike flock() on the shared
         * open file description inherited by the signature worker. */
        struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET};
        int locked;
        do {
            locked = fcntl(c->report_fd, F_SETLKW, &lock);
        } while (locked < 0 && errno == EINTR);
        struct stat st;
        if (locked < 0 || fstat(c->report_fd, &st) < 0 || !S_ISREG(st.st_mode)) {
            fprintf(stderr, "KaalClam: cannot lock/stat report: %s\n", strerror(errno));
            c->report_failed = true;
            ++c->stats.gaps;
            kc_stop = 1;
        } else if ((uint64_t)n > c->cfg.max_report_bytes ||
                   (uint64_t)st.st_size > c->cfg.max_report_bytes - (uint64_t)n) {
            fprintf(stderr,
                    "KaalClam: report limit reached; stopping to preserve bounded storage.\n");
            c->report_full = true;
            ++c->stats.gaps;
            kc_stop = 1;
        } else if (!kc_write_all(c->report_fd, line, (size_t)n)) {
            fprintf(stderr, "KaalClam: report write failed: %s\n", strerror(errno));
            c->report_failed = true;
            ++c->stats.gaps;
            kc_stop = 1;
        }
        if (locked == 0) {
            lock.l_type = F_UNLCK;
            if (fcntl(c->report_fd, F_SETLK, &lock) < 0) {
                c->report_failed = true;
                ++c->stats.gaps;
                kc_stop = 1;
            }
        }
    }
    free(line);
}
void kc_emit(struct kc_context *c, enum kc_level level, const char *code, const char *subject,
             const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    emitv(c, level, code, subject, fmt, ap);
    va_end(ap);
}
void kc_emit_once(struct kc_context *c, enum kc_level level, const char *code, const char *subject,
                  const char *fmt, ...) {
    uint64_t key = kc_hash_bytes(code, strlen(code)) ^
                   (kc_hash_bytes(subject, strlen(subject)) * UINT64_C(0x9e3779b97f4a7c15));
    if (kc_map_get(&c->reported, key, NULL))
        return;
    if (c->reported.count >= 100000) {
        kc_emit(c, KC_GAP, "dedup_limit", "report", "Deduplication cap reached.");
        return;
    }
    if (!kc_map_put(&c->reported, key, 1)) {
        kc_stop = 1;
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    emitv(c, level, code, subject, fmt, ap);
    va_end(ap);
}
int kc_secure_dir(const char *path, mode_t mode) {
    if (!path || path[0] != '/') {
        errno = EINVAL;
        return -1;
    }
    if (!strcmp(path, "/")) {
        errno = EINVAL;
        return -1;
    }
    char buf[PATH_MAX];
    if (strlen(path) >= sizeof(buf)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    strcpy(buf, path);
    int fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    char *save = NULL;
    for (char *s = strtok_r(buf, "/", &save); s; s = strtok_r(NULL, "/", &save)) {
        if (!strcmp(s, ".") || !strcmp(s, "..")) {
            close(fd);
            errno = EINVAL;
            return -1;
        }
        /* A privileged updater must never create/chown files below an ancestor
         * that another user can replace. Root mode uses /var/lib by default. */
        struct stat parent;
        if (geteuid() == 0 &&
            (fstat(fd, &parent) < 0 || parent.st_uid != 0 || (parent.st_mode & 0022))) {
            close(fd);
            errno = EPERM;
            return -1;
        }
        if (mkdirat(fd, s, mode) < 0 && errno != EEXIST) {
            int e = errno;
            close(fd);
            errno = e;
            return -1;
        }
        int next = openat(fd, s, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0) {
            int e = errno;
            close(fd);
            errno = e;
            return -1;
        }
        close(fd);
        fd = next;
    }
    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return -1;
    }
    if (st.st_uid != geteuid() || (st.st_mode & 0022)) {
        close(fd);
        errno = EPERM;
        return -1;
    }
    close(fd);
    return 0;
}
int kc_run_child(const char *program, char *const argv[], int logfd, unsigned timeout, uid_t uid,
                 gid_t gid) {
    if (!program || program[0] != '/') {
        errno = EINVAL;
        return -1;
    }
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        (void)signal(SIGINT, SIG_DFL);
        (void)signal(SIGTERM, SIG_DFL);
        int null = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (null >= 0) {
            dup2(null, STDIN_FILENO);
            close(null);
        }
        if (logfd >= 0) {
            if (dup2(logfd, STDOUT_FILENO) < 0 || dup2(logfd, STDERR_FILENO) < 0)
                _exit(126);
        }
        if (geteuid() == 0 && uid != 0) {
            if (setgroups(0, NULL) || setgid(gid) || setuid(uid))
                _exit(126);
        }
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
            _exit(126);
        /* No shell, loader overrides, proxy overrides, or inherited callbacks. */
        char *environment[] = {"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", NULL};
        execve(program, argv, environment);
        _exit(errno == ENOENT ? 127 : 126);
    }
    uint64_t end = kc_mono_ms() + (uint64_t)timeout * 1000;
    int status;
    for (;;) {
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid)
            return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
        if (r < 0 && errno != EINTR)
            return -1;
        if (kc_stop || kc_mono_ms() >= end) {
            kill(pid, SIGTERM);
            for (unsigned i = 0; i < 20; ++i) {
                if (waitpid(pid, &status, WNOHANG) == pid)
                    return 124;
                struct timespec t = {0, 50000000};
                nanosleep(&t, NULL);
            }
            kill(pid, SIGKILL);
            while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
            }
            return 124;
        }
        struct timespec t = {0, 100000000};
        nanosleep(&t, NULL);
    }
}
