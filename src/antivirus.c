/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "kaalclam.h"
#include <clamav.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

enum kc_scan_class kc_scan_classify(int result, bool matched, const char *signature) {
    bool limit = signature && !strncmp(signature, "Heuristics.Limits.Exceeded.",
                                       strlen("Heuristics.Limits.Exceeded."));
    if (matched && !limit)
        return KC_SCAN_MATCH;
    if (limit || result == CL_ETIMEOUT || result == CL_EMAXSIZE || result == CL_EMAXREC ||
        result == CL_EMAXFILES)
        return KC_SCAN_LIMIT;
    if (result != CL_SUCCESS && result != CL_CLEAN)
        return KC_SCAN_ERROR;
    return KC_SCAN_CLEAN;
}
struct scan_context {
    struct kc_context *c;
    const char *path;
    unsigned matches, limits;
};
static void record_alert(struct scan_context *s, const char *name) {
    if (!s || !name)
        return;
    if (kc_scan_classify(CL_SUCCESS, true, name) == KC_SCAN_LIMIT) {
        ++s->limits;
        ++s->c->stats.limits;
        kc_emit(s->c, KC_GAP, "av.scan_limit", s->path,
                "signature=%s; scan coverage is incomplete. This is not an identified malware "
                "signature.",
                name);
    } else {
        ++s->matches;
        ++s->c->stats.malware;
        bool heuristic = !strncmp(name, "Heuristics.", 11) || !strncmp(name, "PUA.", 4);
        kc_emit(s->c, heuristic ? KC_REVIEW : KC_ALERT, "av.signature_match", s->path,
                "signature=%s heuristic_or_PUA=%d; preserve the file and verify possible false "
                "positives. KaalClam does not delete or quarantine files.",
                name, heuristic);
    }
}
#if CLAMAV_VERSION_NUM >= 0x010500
static cl_error_t alert_callback(cl_scan_layer_t *layer, void *opaque) {
    const char *name = NULL;
    if (cl_scan_layer_get_last_alert(layer, &name) == CL_SUCCESS)
        record_alert(opaque, name);
    return CL_VIRUS; /* Accept each alert; do not suppress another match in all-match mode. */
}
#else
static void alert_callback(int fd, const char *name, void *opaque) {
    (void)fd;
    record_alert(opaque, name);
}
#endif
static void install_callback(struct cl_engine *engine) {
#if CLAMAV_VERSION_NUM >= 0x010500
    cl_engine_set_scan_callback(engine, alert_callback, CL_SCAN_CALLBACK_ALERT);
#else
    cl_engine_set_clcb_virus_found(engine, alert_callback);
#endif
}
static bool official_db_filename(const char *name) {
    bool prefix = !strncmp(name, "main.", 5) || !strncmp(name, "daily.", 6) ||
                  !strncmp(name, "bytecode.", 9) || !strncmp(name, "main-", 5) ||
                  !strncmp(name, "daily-", 6) || !strncmp(name, "bytecode-", 9);
    size_t n = strlen(name);
    return prefix &&
           ((n > 4 && !strcmp(name + n - 4, ".cvd")) || (n > 4 && !strcmp(name + n - 4, ".cld")) ||
            (n > 5 && !strcmp(name + n - 5, ".sign")));
}
static int copy_seed(const char *source, const char *dest, uid_t owner, gid_t group) {
    int src = open(source, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (src < 0)
        return -1;
    struct stat st;
    if (fstat(src, &st) < 0 || !S_ISREG(st.st_mode) || st.st_size > 256 * (off_t)KC_MIB) {
        close(src);
        errno = EINVAL;
        return -1;
    }
    int out = open(dest, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (out < 0) {
        int e = errno;
        close(src);
        errno = e;
        return e == EEXIST ? 0 : -1;
    }
    bool ok = true;
    char data[65536];
    uint64_t remaining = (uint64_t)st.st_size;
    while (remaining && !kc_stop) {
        size_t amount = remaining < sizeof(data) ? (size_t)remaining : sizeof(data);
        ssize_t n = read(src, data, amount);
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0) {
            ok = false;
            break;
        }
        if (!n) {
            ok = false;
            break;
        }
        remaining -= (uint64_t)n;
        if (!kc_write_all(out, data, (size_t)n)) {
            ok = false;
            break;
        }
    }
    struct stat after;
    if (kc_stop || remaining || fstat(src, &after) < 0 || st.st_size != after.st_size ||
        st.st_mtim.tv_sec != after.st_mtim.tv_sec || st.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
        st.st_ctim.tv_sec != after.st_ctim.tv_sec || st.st_ctim.tv_nsec != after.st_ctim.tv_nsec)
        ok = false;
    if (geteuid() == 0 && fchown(out, owner, group) < 0)
        ok = false;
    if (fsync(out) < 0)
        ok = false;
    close(src);
    if (close(out) < 0)
        ok = false;
    if (!ok)
        unlink(dest);
    return ok ? 0 : -1;
}
static bool database_exists(const char *dir) {
    const char *names[] = {"daily.cvd", "daily.cld", "main.cvd", "main.cld"};
    char path[PATH_MAX];
    for (size_t i = 0; i < sizeof(names) / sizeof(*names); ++i)
        if (kc_path(path, dir, names[i]) && access(path, R_OK) == 0)
            return true;
    return false;
}
/* O_NOFOLLOW does not reject hard links, FIFOs, or unsafe existing owners.
 * Validate the opened object before truncating any managed state file. */
static int managed_file(const char *path, int access, mode_t mode, bool truncate) {
    int fd = open(path, access | O_CREAT | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC, mode);
    if (fd < 0)
        return -1;
    struct stat st;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_uid != geteuid() || st.st_nlink != 1 ||
        (st.st_mode & 0022)) {
        close(fd);
        errno = EPERM;
        return -1;
    }
    if (fchmod(fd, mode) < 0 || (truncate && ftruncate(fd, 0) < 0)) {
        int error = errno;
        close(fd);
        errno = error;
        return -1;
    }
    return fd;
}
static bool state_prepare(struct kc_context *c, char db[PATH_MAX], uid_t *uid, gid_t *gid,
                          char user[128]) {
    *uid = geteuid();
    *gid = getegid();
    struct passwd *pw = getpwuid(*uid);
    if (!pw) {
        kc_emit(c, KC_GAP, "updates.identity", "freshclam", "Cannot resolve the updater user.");
        return false;
    }
    snprintf(user, 128, "%s", pw->pw_name);
    if (*uid == 0) {
        pw = getpwnam("clamav");
        if (!pw || pw->pw_uid == 0) {
            kc_emit(
                c, KC_GAP, "updates.unprivileged_user", "freshclam",
                "A non-root clamav service account is required for root-mode automatic updates.");
            return false;
        }
        *uid = pw->pw_uid;
        *gid = pw->pw_gid;
        snprintf(user, 128, "%s", pw->pw_name);
    }
    if (strpbrk(c->cfg.state, "\n\r\"\\")) {
        kc_emit(c, KC_GAP, "updates.invalid_state_path", c->cfg.state,
                "State path contains configuration delimiter characters.");
        return false;
    }
    char state_marker[PATH_MAX];
    if (!kc_path(state_marker, c->cfg.state, ".kaalclam-state"))
        return false;
    const char *state_id = "KaalClam managed signature state v1\n";
    struct stat existing;
    bool existed = lstat(c->cfg.state, &existing) == 0;
    int state_error = errno;
    if (!existed && state_error != ENOENT) {
        kc_emit(c, KC_GAP, "updates.state_unavailable", c->cfg.state, "%s", strerror(state_error));
        return false;
    }
    if (kc_secure_dir(c->cfg.state, 0700) < 0) {
        kc_emit(c, KC_GAP, "updates.state_unavailable", c->cfg.state,
                "%s; state must be owned by the effective user with safe permissions and no "
                "symlink components. Root mode also requires root-owned, non-writable ancestors.",
                strerror(errno));
        return false;
    }
    if (existed) {
        struct stat marker_stat;
        char *id = kc_read_text(state_marker, 256, NULL);
        bool valid = id && !strcmp(id, state_id) && lstat(state_marker, &marker_stat) == 0 &&
                     S_ISREG(marker_stat.st_mode) && marker_stat.st_uid == geteuid() &&
                     marker_stat.st_nlink == 1 && !(marker_stat.st_mode & 0022);
        free(id);
        if (!valid) {
            kc_emit(
                c, KC_GAP, "updates.unmanaged_state_directory", c->cfg.state,
                "Existing directory has no valid KaalClam state marker; it will not be modified. "
                "Choose a new directory or the established KaalClam state directory.");
            return false;
        }
    }
    if (!existed) {
        int mark = open(state_marker, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (mark < 0 || !kc_write_all(mark, state_id, strlen(state_id))) {
            kc_emit(c, KC_GAP, "updates.state_marker", state_marker, "%s", strerror(errno));
            if (mark >= 0)
                close(mark);
            return false;
        }
        close(mark);
    }
    if (geteuid() == 0) {
        if (chown(c->cfg.state, 0, *gid) < 0 || chmod(c->cfg.state, 0750) < 0) {
            kc_emit(c, KC_GAP, "updates.state_permissions", c->cfg.state, "%s", strerror(errno));
            return false;
        }
    }
    if (!kc_path(db, c->cfg.state, "signatures"))
        return false;
    if (mkdir(db, 0700) < 0 && errno != EEXIST) {
        kc_emit(c, KC_GAP, "updates.database_directory", db, "%s", strerror(errno));
        return false;
    }
    struct stat st;
    if (lstat(db, &st) < 0 || !S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode) ||
        (st.st_uid != geteuid() && st.st_uid != *uid) || (st.st_mode & 0022)) {
        kc_emit(c, KC_GAP, "updates.database_permissions", db,
                "Unsafe owner, mode or object type for signature directory.");
        return false;
    }
    if (geteuid() == 0 && (chown(db, *uid, *gid) < 0 || chmod(db, 0700) < 0)) {
        kc_emit(c, KC_GAP, "updates.database_permissions", db, "%s", strerror(errno));
        return false;
    }
    /* Start with installed official databases to avoid unnecessary full downloads. */
    if (!database_exists(db)) {
        DIR *d = opendir(cl_retdbdir());
        if (d) {
            struct dirent *e;
            while ((e = readdir(d))) {
                if (!official_db_filename(e->d_name))
                    continue;
                char src[PATH_MAX], dst[PATH_MAX];
                if (kc_path(src, cl_retdbdir(), e->d_name) && kc_path(dst, db, e->d_name) &&
                    copy_seed(src, dst, *uid, *gid) < 0)
                    kc_emit(c, KC_GAP, "updates.seed_copy", src, "%s", strerror(errno));
            }
            closedir(d);
        }
    }
    return true;
}
static bool update_database(struct kc_context *c, const char *db, uid_t uid, gid_t gid,
                            const char *user) {
    char lockpath[PATH_MAX], confpath[PATH_MAX], logpath[PATH_MAX], marker[PATH_MAX];
    if (!kc_path(lockpath, c->cfg.state, "update.lock") ||
        !kc_path(confpath, c->cfg.state, "freshclam.conf") ||
        !kc_path(logpath, c->cfg.state, "freshclam.log") ||
        !kc_path(marker, c->cfg.state, "last-update-attempt"))
        return false;
    int lock = managed_file(lockpath, O_RDWR, 0600, false);
    if (lock < 0 || flock(lock, LOCK_EX | LOCK_NB) < 0) {
        kc_emit(c, KC_GAP, "updates.lock", lockpath,
                "Updater already running or lock unavailable: %s", strerror(errno));
        if (lock >= 0)
            close(lock);
        return false;
    }
    uint64_t now = (uint64_t)time(NULL), then = 0;
    int previous = -1;
    char *last = kc_read_text(marker, 128, NULL);
    if (last) {
        unsigned long long value;
        if (sscanf(last, "%llu %d", &value, &previous) == 2)
            then = (uint64_t)value;
        free(last);
    }
    uint64_t hold = previous == 0 ? c->cfg.update_interval : 900;
    if (!c->cfg.update_only && then && now >= then && now - then < hold) {
        kc_emit(c, previous == 0 ? KC_INFO : KC_GAP, "updates.backoff", marker,
                "Last updater result=%d age_seconds=%llu; refresh throttled for %llu seconds. "
                "FreshClam also enforces CDN retry/cooldown policy.",
                previous, (unsigned long long)(now - then), (unsigned long long)hold);
        close(lock);
        return previous == 0;
    }
    int conf = managed_file(confpath, O_WRONLY, 0644, true);
    if (conf < 0) {
        kc_emit(c, KC_GAP, "updates.config", confpath, "%s", strerror(errno));
        close(lock);
        return false;
    }
    char contents[PATH_MAX + 1024];
    int n =
        snprintf(contents, sizeof(contents),
                 "# Generated by KaalClam; no execute callbacks or private "
                 "mirrors.\nDatabaseDirectory \"%s\"\nDatabaseOwner %s\nDatabaseMirror "
                 "database.clamav.net\nDNSDatabaseInfo current.cvd.clamav.net\nScriptedUpdates "
                 "yes\nTestDatabases yes\nConnectTimeout 15\nReceiveTimeout 60\nMaxAttempts 2\n",
                 db, user);
    bool wrote = n > 0 && (size_t)n < sizeof(contents) && kc_write_all(conf, contents, (size_t)n);
    close(conf);
    if (!wrote) {
        close(lock);
        return false;
    }
    int log = managed_file(logpath, O_WRONLY, 0600, true);
    if (log < 0) {
        kc_emit(c, KC_GAP, "updates.log", logpath, "%s", strerror(errno));
        close(lock);
        return false;
    }
    char option[PATH_MAX + 32];
    snprintf(option, sizeof(option), "--config-file=%s", confpath);
    char *argv[] = {"/usr/bin/freshclam", option, "--stdout", NULL};
    kc_emit(c, KC_INFO, "updates.started", db,
            "Official FreshClam updater, timeout_seconds=%u log=%s; downloads signatures only, not "
            "uploaded samples.",
            c->cfg.updater_timeout, logpath);
    int status = kc_run_child(argv[0], argv, log, c->cfg.updater_timeout, uid, gid);
    close(log);
    int mark = managed_file(marker, O_WRONLY, 0600, true);
    if (mark >= 0) {
        char value[128];
        int count = snprintf(value, sizeof(value), "%llu %d\n", (unsigned long long)now, status);
        if (count > 0)
            (void)kc_write_all(mark, value, (size_t)count);
        close(mark);
    } else
        kc_emit(c, KC_GAP, "updates.attempt_marker", marker, "%s", strerror(errno));
    kc_emit(c, status == 0 ? KC_INFO : KC_GAP, status == 0 ? "updates.succeeded" : "updates.failed",
            db,
            "FreshClam exit_status=%d; 124 means timeout/interruption. See %s. Failed refreshes do "
            "not make existing signatures current.",
            status, logpath);
    close(lock);
    return status == 0;
}
static void signature_age(struct kc_context *c, const char *db) {
    const char *names[] = {"daily.cld", "daily.cvd"};
    bool found = false;
    for (size_t i = 0; i < 2; ++i) {
        char path[PATH_MAX];
        if (!kc_path(path, db, names[i]) || access(path, R_OK))
            continue;
        struct cl_cvd *header = cl_cvdhead(path);
        if (!header)
            continue;
        found = true;
        int64_t age = (int64_t)time(NULL) - (int64_t)header->stime;
        kc_emit(c, age > 48 * 3600 || age < -3600 ? KC_GAP : KC_INFO, "av.database_age", path,
                "daily_version=%u database_time_unix=%u age_seconds=%lld signatures_in_daily=%u. "
                "Header age is not independent authenticity verification; signed-database loading "
                "is checked separately.",
                header->version, header->stime, (long long)age, header->sigs);
        cl_cvdfree(header);
        break;
    }
    if (!found)
        kc_emit(c, KC_GAP, "av.database_age_unavailable", db,
                "Daily database header is unavailable; freshness cannot be established.");
}
struct scan_walk {
    struct kc_context *c;
    struct cl_engine *engine;
    struct kc_map seen;
    uint64_t visited;
    bool exhausted;
};
static void scan_fd(struct scan_walk *w, int fd, const char *path) {
    struct kc_context *c = w->c;
    struct stat before, after;
    if (fstat(fd, &before) < 0 || !S_ISREG(before.st_mode)) {
        kc_emit(c, KC_GAP, "av.file_type_changed", path,
                "Opened object is not a regular file or could not be inspected.");
        close(fd);
        return;
    }
    struct stat report;
    if (fstat(c->report_fd, &report) == 0 && before.st_dev == report.st_dev &&
        before.st_ino == report.st_ino) {
        close(fd);
        return;
    }
    uint64_t previous;
    if (kc_map_get(&w->seen, (uint64_t)before.st_ino, &previous) &&
        previous == (uint64_t)before.st_dev) {
        close(fd);
        return;
    }
    if (!kc_map_put(&w->seen, (uint64_t)before.st_ino, (uint64_t)before.st_dev)) {
        close(fd);
        kc_stop = 1;
        return;
    }
    if (c->stats.files + c->stats.skipped >= c->cfg.max_files) {
        w->exhausted = true;
        close(fd);
        return;
    }
    if ((uint64_t)before.st_size > c->cfg.max_file_bytes) {
        ++c->stats.skipped;
        kc_emit(c, KC_GAP, "av.file_size_limit", path,
                "bytes=%llu exceeds max_file_bytes=%llu; not scanned.",
                (unsigned long long)before.st_size, (unsigned long long)c->cfg.max_file_bytes);
        close(fd);
        return;
    }
    if ((uint64_t)before.st_size > c->cfg.max_total_bytes - c->stats.bytes) {
        w->exhausted = true;
        close(fd);
        return;
    }
    struct scan_context sc = {.c = c, .path = path};
    struct cl_scan_options options = {0};
    options.general = CL_SCAN_GENERAL_ALLMATCHES | CL_SCAN_GENERAL_HEURISTICS;
    options.parse = CL_SCAN_PARSE_ARCHIVE | CL_SCAN_PARSE_ELF | CL_SCAN_PARSE_PE |
                    CL_SCAN_PARSE_PDF | CL_SCAN_PARSE_XMLDOCS | CL_SCAN_PARSE_MAIL |
                    CL_SCAN_PARSE_OLE2 | CL_SCAN_PARSE_HTML | CL_SCAN_PARSE_ONENOTE;
    options.heuristic = CL_SCAN_HEURISTIC_EXCEEDS_MAX;
    const char *signature = NULL;
    bool matched = false;
    int result;
    uint64_t scanned_bytes = 0;
#if CLAMAV_VERSION_NUM >= 0x010500
    cl_verdict_t verdict = CL_VERDICT_NOTHING_FOUND;
    result = cl_scandesc_ex(fd, path, &verdict, &signature, &scanned_bytes, w->engine, &options,
                            &sc, NULL, NULL, NULL, NULL, NULL);
    matched = verdict == CL_VERDICT_STRONG_INDICATOR || verdict == CL_VERDICT_POTENTIALLY_UNWANTED;
#else
    unsigned long blocks = 0;
    result = cl_scandesc_callback(fd, path, &signature, &blocks, w->engine, &options, &sc);
    scanned_bytes = (uint64_t)blocks * CL_COUNT_PRECISION;
    matched = result == CL_VIRUS;
#endif
    ++c->stats.files;
    c->stats.bytes += (uint64_t)before.st_size;
    enum kc_scan_class classification = kc_scan_classify(result, matched, signature);
    enum kc_scan_class coverage =
        kc_scan_classify(result == CL_VIRUS ? CL_SUCCESS : result, false, NULL);
    if (classification == KC_SCAN_MATCH && !sc.matches)
        record_alert(&sc, signature ? signature : "Unnamed.ClamAV.Match");
    if ((classification == KC_SCAN_LIMIT || coverage == KC_SCAN_LIMIT) && !sc.limits) {
        ++c->stats.limits;
        kc_emit(c, KC_GAP, "av.scan_limit", path,
                "Engine result=%s; coverage incomplete, not a malware identification.",
                cl_strerror((cl_error_t)result));
    } else if (classification == KC_SCAN_ERROR || coverage == KC_SCAN_ERROR)
        kc_emit(c, KC_GAP, "av.scan_error", path, "%s", cl_strerror((cl_error_t)result));
    else if (classification == KC_SCAN_CLEAN && !sc.matches && !sc.limits)
        kc_emit(c, KC_INFO, "av.no_signature_match", path,
                "file_bytes=%llu engine_scanned_bytes=%llu. No match within configured "
                "scope/limits; not a guarantee of a clean file or system.",
                (unsigned long long)before.st_size, (unsigned long long)scanned_bytes);
    if (fstat(fd, &after) < 0 || before.st_size != after.st_size ||
        before.st_mtim.tv_sec != after.st_mtim.tv_sec ||
        before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
        before.st_ctim.tv_sec != after.st_ctim.tv_sec ||
        before.st_ctim.tv_nsec != after.st_ctim.tv_nsec)
        kc_emit(c, KC_GAP, "av.file_changed_during_scan", path,
                "The file changed or disappeared during inspection; results are a non-atomic "
                "snapshot.");
    close(fd);
}
static bool excluded(struct scan_walk *w, const char *path) {
    const char *virtual_roots[] = {"/proc", "/sys", "/dev", "/run"};
    for (unsigned i = 0; i < 4; ++i) {
        if (i == 2 && (!strncmp(path, "/dev/shm/", 9) || !strcmp(path, "/dev/shm")))
            continue;
        size_t n = strlen(virtual_roots[i]);
        if (!strncmp(path, virtual_roots[i], n) && (path[n] == '/' || !path[n]))
            return true;
    }
    size_t n = strlen(w->c->cfg.state);
    return (!strncmp(path, w->c->cfg.state, n) && (path[n] == '/' || !path[n])) ||
           !strcmp(path, w->c->cfg.report);
}
static void scan_walk(struct scan_walk *w, const char *path, unsigned depth) {
    if (kc_stop || w->exhausted)
        return;
    if (depth > 32) {
        kc_emit_once(w->c, KC_GAP, "av.directory_depth", path, "32-directory depth limit reached.");
        return;
    }
    if (++w->visited > (uint64_t)w->c->cfg.max_files * 8 + 1024) {
        w->exhausted = true;
        kc_emit(w->c, KC_GAP, "av.traversal_limit", path,
                "Directory-entry traversal budget exhausted; remaining paths were not inspected.");
        return;
    }
    struct stat st;
    if (lstat(path, &st) < 0) {
        bool optional = depth == 0 && w->c->cfg.default_scope && errno == ENOENT;
        kc_emit(w->c, optional ? KC_INFO : KC_GAP,
                optional ? "av.optional_path_absent" : "av.path_unavailable", path,
                "%s; path was not scanned.", strerror(errno));
        return;
    }
    char real[PATH_MAX];
    if (!realpath(path, real)) {
        kc_emit_once(w->c, KC_GAP, "av.resolve_failed", path, "%s", strerror(errno));
        return;
    }
    if (excluded(w, real))
        return;
    if (S_ISDIR(st.st_mode)) {
        int dirfd = open(path, O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
        DIR *d = dirfd < 0 ? NULL : fdopendir(dirfd);
        if (!d) {
            int error = errno;
            if (dirfd >= 0)
                close(dirfd);
            kc_emit(w->c, KC_GAP, "av.directory_unavailable", path, "%s", strerror(error));
            return;
        }
        struct dirent *e;
        while (!kc_stop && !w->exhausted) {
            errno = 0;
            e = readdir(d);
            if (!e) {
                if (errno)
                    kc_emit(w->c, KC_GAP, "av.directory_read_error", path, "%s", strerror(errno));
                break;
            }
            if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
                continue;
            char next[PATH_MAX];
            if (kc_path(next, path, e->d_name))
                scan_walk(w, next, depth + 1);
            else
                kc_emit(w->c, KC_GAP, "av.path_too_long", path, "A child path exceeds PATH_MAX.");
        }
        closedir(d);
        return;
    }
    /* Follow file symlinks, never directory symlinks. Reject devices/FIFOs before opening. */
    if (stat(real, &st) < 0 || !S_ISREG(st.st_mode)) {
        if (depth == 0 || S_ISDIR(st.st_mode))
            kc_emit(w->c, KC_GAP, "av.unsupported_path", path,
                    "Non-regular files and directory symlinks are not scanned.");
        return;
    }
    int fd = open(real, O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        kc_emit(w->c, KC_GAP, "av.file_unavailable", real, "%s", strerror(errno));
        return;
    }
    scan_fd(w, fd, real);
}
static void scan_live_executables(struct scan_walk *w) {
    DIR *d = opendir("/proc");
    if (!d) {
        kc_emit(w->c, KC_GAP, "av.process_executables", "/proc", "%s", strerror(errno));
        return;
    }
    struct dirent *e;
    while (!kc_stop && !w->exhausted && (e = readdir(d))) {
        uint64_t pid;
        if (!kc_number(e->d_name, 1, INT_MAX, &pid))
            continue;
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "/proc/%s/exe", e->d_name);
        int fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
        if (fd < 0) {
            if (errno != ENOENT && errno != ESRCH)
                kc_emit_once(w->c, KC_GAP, "av.process_executable_unreadable", path, "%s",
                             strerror(errno));
            continue;
        }
        scan_fd(w, fd, path);
    }
    closedir(d);
}
int kc_av_worker(struct kc_context *c, int statsfd) {
    memset(&c->stats, 0, sizeof(c->stats));
    (void)setpriority(PRIO_PROCESS, 0, 15);
    int exitcode = 0;
    struct cl_engine *engine = NULL;
    struct scan_walk walk = {.c = c};
    if (cl_init(CL_INIT_DEFAULT) != CL_SUCCESS) {
        kc_emit(c, KC_GAP, "av.initialization", "libclamav", "Initialization failed.");
        exitcode = 2;
        goto done;
    }
    char private_db[PATH_MAX] = "", user[128];
    uid_t uid = geteuid();
    gid_t gid = getegid();
    bool private_ready = false;
    if (c->cfg.update)
        private_ready = state_prepare(c, private_db, &uid, &gid, user);
    else if (kc_path(private_db, c->cfg.state, "signatures"))
        private_ready = database_exists(private_db);
    if (c->cfg.update && private_ready)
        (void)update_database(c, private_db, uid, gid, user);
    else if (c->cfg.update)
        kc_emit(c, KC_GAP, "updates.not_performed", "freshclam",
                "State/identity preparation failed; signatures were not refreshed.");
    else
        kc_emit(c, KC_INFO, "updates.disabled", "freshclam",
                "Automatic refresh explicitly disabled for this run.");
    const char *db = private_ready && database_exists(private_db) ? private_db : cl_retdbdir();
    signature_age(c, db);
    if (c->cfg.update_only)
        goto done;
    engine = cl_engine_new();
    if (!engine) {
        kc_emit(c, KC_GAP, "av.engine_allocation", "libclamav",
                "Cannot allocate signature engine.");
        exitcode = 2;
        goto done;
    }
    unsigned signatures = 0;
    cl_error_t r = cl_load(db, engine, &signatures, CL_DB_STDOPT | CL_DB_OFFICIAL_ONLY);
    if (r != CL_SUCCESS || !signatures) {
        kc_emit(c, KC_GAP, "av.database_load_failed", db,
                "%s; loaded_signatures=%u; only official databases are accepted.", cl_strerror(r),
                signatures);
        exitcode = 2;
        goto done;
    }
    if (cl_engine_set_num(engine, CL_ENGINE_MAX_FILESIZE, (long long)c->cfg.max_file_bytes) !=
            CL_SUCCESS ||
        cl_engine_set_num(engine, CL_ENGINE_MAX_SCANSIZE, (long long)(c->cfg.max_file_bytes * 4)) !=
            CL_SUCCESS ||
        cl_engine_set_num(engine, CL_ENGINE_MAX_SCANTIME, (long long)c->cfg.scan_timeout * 1000) !=
            CL_SUCCESS) {
        kc_emit(c, KC_GAP, "av.engine_limits", "libclamav", "Cannot apply engine resource limits.");
        exitcode = 2;
        goto done;
    }
    install_callback(engine);
    r = cl_engine_compile(engine);
    if (r != CL_SUCCESS) {
        kc_emit(c, KC_GAP, "av.engine_compile_failed", db, "%s", cl_strerror(r));
        exitcode = 2;
        goto done;
    }
    kc_emit(c, KC_INFO, "av.engine_ready", db,
            "engine=%s signatures=%u official_signed_databases_only=true max_file_bytes=%llu "
            "max_total_input_bytes=%llu per_file_timeout_seconds=%u; scans run in a separate "
            "low-priority process so hardware observation continues.",
            cl_retver(), signatures, (unsigned long long)c->cfg.max_file_bytes,
            (unsigned long long)c->cfg.max_total_bytes, c->cfg.scan_timeout);
    walk.engine = engine;
    if (!kc_map_init(&walk.seen, 512)) {
        exitcode = 2;
        goto done;
    }
    for (size_t i = 0; i < c->cfg.scan_path_count && !kc_stop && !walk.exhausted; ++i)
        scan_walk(&walk, c->cfg.scan_paths[i], 0);
    if (c->cfg.scan_processes && !walk.exhausted && !kc_stop)
        scan_live_executables(&walk);
    if (walk.exhausted)
        kc_emit(c, KC_GAP, "av.total_scope_limit", "scan",
                "File-count or total-byte budget exhausted; remaining paths were not inspected.");
    if (kc_stop)
        kc_emit(c, KC_GAP, "av.interrupted", "scan",
                "Signature scan interrupted; coverage is partial.");
    if (!c->stats.files)
        kc_emit(c, KC_GAP, "av.no_files_scanned", "scan",
                "No regular files were scanned; no signature coverage was established.");
done:
    kc_map_destroy(&walk.seen);
    if (engine)
        cl_engine_free(engine);
    kc_emit(c, KC_INFO, "av.summary", "signature scan",
            "scanned_files=%llu input_bytes=%llu signature_matches=%llu limit_alerts=%llu "
            "skipped_files=%llu unavailable_findings=%llu. Signature matches require "
            "investigation; heuristics/limits are reported separately.",
            (unsigned long long)c->stats.files, (unsigned long long)c->stats.bytes,
            (unsigned long long)c->stats.malware, (unsigned long long)c->stats.limits,
            (unsigned long long)c->stats.skipped, (unsigned long long)c->stats.gaps);
    if (statsfd >= 0) {
        (void)kc_write_all(statsfd, &c->stats, sizeof(c->stats));
        close(statsfd);
    }
    return exitcode;
}

int kc_selftest_av(void) {
    char directory[] = "/tmp/kaalclam-test-XXXXXX";
    if (!mkdtemp(directory))
        return 1;
    char db[PATH_MAX], sample[PATH_MAX], report[PATH_MAX], missing[PATH_MAX];
    kc_path(db, directory, "test.ndb");
    kc_path(sample, directory, "sample");
    kc_path(report, directory, "report.jsonl");
    kc_path(missing, directory, "does-not-exist");
    const char *marker = "KAALCLAM_INERT_SELFTEST_MARKER_42";
    int failures = 0;
    FILE *f = fopen(db, "we");
    if (!f) {
        rmdir(directory);
        return 1;
    }
    fputs("KaalClam.SelfTest:0:*:", f);
    for (const unsigned char *p = (const unsigned char *)marker; *p; ++p)
        fprintf(f, "%02x", *p);
    fputc('\n', f);
    fclose(f);
    f = fopen(sample, "we");
    if (!f) {
        unlink(db);
        rmdir(directory);
        return 1;
    }
    fputs(marker, f);
    fclose(f);
    struct cl_engine *engine = NULL;
    struct kc_context *context = NULL;
    struct scan_walk walk = {0};
    if (cl_init(CL_INIT_DEFAULT) != CL_SUCCESS || (engine = cl_engine_new()) == NULL) {
        failures = 1;
        goto done;
    }
    unsigned sigs = 0;
    if (cl_load(db, engine, &sigs, 0) != CL_SUCCESS || cl_engine_compile(engine) != CL_SUCCESS) {
        failures = 1;
        goto done;
    }
    struct cl_scan_options options = {0};
    const char *name = NULL;
    int result;
    bool matched;
#if CLAMAV_VERSION_NUM >= 0x010500
    cl_verdict_t verdict;
    uint64_t scanned;
    result = cl_scanfile_ex(sample, &verdict, &name, &scanned, engine, &options, NULL, NULL, NULL,
                            NULL, NULL, NULL);
    matched = verdict == CL_VERDICT_STRONG_INDICATOR;
#else
    unsigned long scanned;
    result = cl_scanfile(sample, &name, &scanned, engine, &options);
    matched = result == CL_VIRUS;
#endif
    if (kc_scan_classify(result, matched, name) != KC_SCAN_MATCH || !name ||
        !strstr(name, "KaalClam.SelfTest"))
        failures = 1;
    /* Exercise the production descriptor scanner and its actual alert callback. */
    context = calloc(1, sizeof(*context));
    if (!context) {
        failures = 1;
        goto done;
    }
    context->report_fd = -1;
    context->started_ms = kc_mono_ms();
    context->cfg.max_report_bytes = KC_MIB;
    context->cfg.max_file_bytes = KC_MIB;
    context->cfg.max_total_bytes = 10 * KC_MIB;
    context->cfg.max_files = 10;
    snprintf(context->cfg.report, sizeof(context->cfg.report), "%s", report);
    walk.c = context;
    walk.engine = engine;
    if (kc_report_open(context) < 0 || !kc_map_init(&walk.seen, 16)) {
        failures = 1;
        goto done;
    }
    install_callback(engine);
    int fd = open(sample, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        failures = 1;
        goto done;
    }
    scan_fd(&walk, fd, sample);
    if (context->stats.files != 1 || context->stats.malware != 1 || context->stats.alerts != 1 ||
        context->stats.gaps)
        failures = 1;
    scan_walk(&walk, report, 0);
    if (context->stats.files != 1 || context->stats.gaps)
        failures = 1;
    scan_walk(&walk, missing, 0);
    if (context->stats.gaps != 1)
        failures = 1;
    f = fopen(sample, "we");
    if (!f) {
        failures = 1;
        goto done;
    }
    fputs("ordinary harmless content", f);
    fclose(f);
#if CLAMAV_VERSION_NUM >= 0x010500
    verdict = CL_VERDICT_NOTHING_FOUND;
    name = NULL;
    result = cl_scanfile_ex(sample, &verdict, &name, &scanned, engine, &options, NULL, NULL, NULL,
                            NULL, NULL, NULL);
    matched = verdict == CL_VERDICT_STRONG_INDICATOR;
#else
    name = NULL;
    result = cl_scanfile(sample, &name, &scanned, engine, &options);
    matched = result == CL_VIRUS;
#endif
    if (kc_scan_classify(result, matched, name) != KC_SCAN_CLEAN)
        failures = 1;
done:
    kc_map_destroy(&walk.seen);
    if (context) {
        if (context->report_fd >= 0)
            close(context->report_fd);
        free(context);
    }
    if (engine)
        cl_engine_free(engine);
    unlink(sample);
    unlink(db);
    unlink(report);
    rmdir(directory);
    return failures;
}
