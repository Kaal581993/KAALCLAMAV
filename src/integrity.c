/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "kaalclam.h"
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

bool kc_sha256_limited(const char *path, uint64_t limit, uint64_t *bytes, char hex[65],
                       char *reason, size_t capacity) {
    *bytes = 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) {
        snprintf(reason, capacity, "%s", strerror(errno));
        return false;
    }
    struct stat before, after;
    if (fstat(fd, &before) < 0 || !S_ISREG(before.st_mode) || before.st_size < 0) {
        snprintf(reason, capacity, "Not a readable regular file");
        close(fd);
        return false;
    }
    if ((uint64_t)before.st_size > limit) {
        snprintf(reason, capacity, "File exceeds configured byte budget (%llu bytes)",
                 (unsigned long long)limit);
        close(fd);
        return false;
    }
    *bytes = (uint64_t)before.st_size;
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    bool ok = md && EVP_DigestInit_ex(md, EVP_sha256(), NULL) == 1;
    unsigned char data[65536], digest[EVP_MAX_MD_SIZE];
    unsigned size = 0;
    uint64_t remaining = (uint64_t)before.st_size;
    while (ok && remaining && !kc_stop) {
        size_t amount = remaining < sizeof(data) ? (size_t)remaining : sizeof(data);
        ssize_t n = read(fd, data, amount);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            ok = false;
            break;
        }
        remaining -= (uint64_t)n;
        ok = EVP_DigestUpdate(md, data, (size_t)n) == 1;
    }
    unsigned char extra;
    ssize_t tail = -1;
    if (ok && !remaining && !kc_stop) {
        do {
            tail = read(fd, &extra, 1);
        } while (tail < 0 && errno == EINTR && !kc_stop);
    }
    ok = ok && !kc_stop && !remaining && tail == 0;
    if (ok)
        ok = EVP_DigestFinal_ex(md, digest, &size) == 1 && size == 32;
    if (ok)
        ok = fstat(fd, &after) == 0 && before.st_dev == after.st_dev &&
             before.st_ino == after.st_ino && before.st_size == after.st_size &&
             before.st_mtim.tv_sec == after.st_mtim.tv_sec &&
             before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
             before.st_ctim.tv_sec == after.st_ctim.tv_sec &&
             before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
    EVP_MD_CTX_free(md);
    close(fd);
    if (!ok) {
        snprintf(reason, capacity,
                 "Read/hash failed or file changed while hashing; result is inconclusive");
        return false;
    }
    static const char digits[] = "0123456789abcdef";
    for (unsigned i = 0; i < 32; ++i) {
        hex[i * 2] = digits[digest[i] >> 4];
        hex[i * 2 + 1] = digits[digest[i] & 15];
    }
    hex[64] = 0;
    return true;
}
bool kc_sha256(const char *path, char hex[65], char *reason, size_t capacity) {
    uint64_t bytes;
    return kc_sha256_limited(path, UINT64_MAX, &bytes, hex, reason, capacity);
}
static char *path_encode(const char *path) {
    size_t n = strlen(path);
    char *out = malloc(n * 2 + 1);
    if (!out)
        return NULL;
    const char *h = "0123456789abcdef";
    for (size_t i = 0; i < n; ++i) {
        unsigned ch = (unsigned char)path[i];
        out[2 * i] = h[ch >> 4];
        out[2 * i + 1] = h[ch & 15];
    }
    out[n * 2] = 0;
    return out;
}
static int unhex(unsigned char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    return -1;
}
static char *path_decode(const char *s) {
    size_t n = strlen(s);
    if (!n || n % 2 || n / 2 >= PATH_MAX)
        return NULL;
    char *out = malloc(n / 2 + 1);
    if (!out)
        return NULL;
    for (size_t i = 0; i < n; i += 2) {
        int a = unhex((unsigned char)s[i]), b = unhex((unsigned char)s[i + 1]);
        if (a < 0 || b < 0 || (a == 0 && b == 0)) {
            free(out);
            return NULL;
        }
        out[i / 2] = (char)((a << 4) | b);
    }
    out[n / 2] = 0;
    if (out[0] != '/') {
        free(out);
        return NULL;
    }
    return out;
}
struct baseline_walk {
    struct kc_context *c;
    FILE *out;
    unsigned files;
    uint64_t bytes, visited;
    dev_t manifest_dev;
    ino_t manifest_ino;
    bool exhausted;
    struct kc_map seen;
};
static void baseline_add(struct baseline_walk *w, const char *path, unsigned depth) {
    if (kc_stop || w->exhausted)
        return;
    if (w->files >= w->c->cfg.max_files ||
        ++w->visited > (uint64_t)w->c->cfg.max_files * 8 + 1024) {
        w->exhausted = true;
        kc_emit_once(w->c, KC_GAP, "integrity.baseline_limit", "baseline",
                     "Depth, file-count, or traversal budget reached; baseline is partial.");
        return;
    }
    if (depth > 32) {
        kc_emit_once(w->c, KC_GAP, "integrity.depth_limit", path,
                     "32-directory depth limit reached; baseline is partial.");
        return;
    }
    struct stat st;
    if (lstat(path, &st) < 0) {
        kc_emit(w->c, KC_GAP, "integrity.path_unavailable", path, "%s", strerror(errno));
        return;
    }
    if (S_ISDIR(st.st_mode)) {
        int dirfd = open(path, O_RDONLY | O_DIRECTORY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
        DIR *d = dirfd < 0 ? NULL : fdopendir(dirfd);
        if (!d) {
            int error = errno;
            if (dirfd >= 0)
                close(dirfd);
            kc_emit(w->c, KC_GAP, "integrity.directory_unavailable", path, "%s", strerror(error));
            return;
        }
        struct dirent *e;
        while (!kc_stop && !w->exhausted) {
            errno = 0;
            e = readdir(d);
            if (!e) {
                if (errno)
                    kc_emit(w->c, KC_GAP, "integrity.directory_read_error", path, "%s",
                            strerror(errno));
                break;
            }
            if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
                continue;
            char p[PATH_MAX];
            if (kc_path(p, path, e->d_name))
                baseline_add(w, p, depth + 1);
            else
                kc_emit(w->c, KC_GAP, "integrity.path_too_long", path,
                        "Child path exceeds PATH_MAX.");
        }
        closedir(d);
        return;
    }
    char real[PATH_MAX];
    if (!realpath(path, real) || stat(real, &st) < 0) {
        kc_emit(w->c, KC_GAP, "integrity.path_unavailable", path, "%s", strerror(errno));
        return;
    }
    if (!S_ISREG(st.st_mode)) {
        if (!depth || S_ISDIR(st.st_mode))
            kc_emit(w->c, KC_GAP, "integrity.unsupported_path", path,
                    "Non-regular files and directory symlinks are not hashed.");
        return;
    }
    struct stat report;
    if ((st.st_dev == w->manifest_dev && st.st_ino == w->manifest_ino) ||
        (fstat(w->c->report_fd, &report) == 0 && st.st_dev == report.st_dev &&
         st.st_ino == report.st_ino))
        return;
    uint64_t key = kc_hash_bytes(real, strlen(real));
    if (kc_map_get(&w->seen, key, NULL))
        return;
    if (!kc_map_put(&w->seen, key, 1)) {
        kc_stop = 1;
        return;
    }
    char hash[65], why[256];
    uint64_t bytes, limit = w->c->cfg.max_total_bytes - w->bytes;
    if (limit > w->c->cfg.max_file_bytes)
        limit = w->c->cfg.max_file_bytes;
    if (!kc_sha256_limited(real, limit, &bytes, hash, why, sizeof(why))) {
        w->bytes += bytes;
        kc_emit(w->c, KC_GAP, "integrity.hash_unavailable", real, "%s", why);
        return;
    }
    char *encoded = path_encode(real);
    if (!encoded) {
        kc_stop = 1;
        return;
    }
    if (fprintf(w->out, "%s\t%s\n", hash, encoded) < 0)
        kc_stop = 1;
    free(encoded);
    ++w->files;
    w->bytes += bytes;
}
int kc_baseline(struct kc_context *c, bool create) {
    const char *manifest = create ? c->cfg.baseline_create : c->cfg.baseline_check;
    int fd = open(manifest,
                  create ? (O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW)
                         : (O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW),
                  0600);
    if (fd < 0) {
        kc_emit(c, KC_GAP, "integrity.manifest_unavailable", manifest, "%s", strerror(errno));
        return 2;
    }
    struct stat st;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) ||
        (!create && st.st_size > 64 * (off_t)KC_MIB)) {
        close(fd);
        kc_emit(c, KC_GAP, "integrity.invalid_manifest", manifest,
                "Manifest must be a regular file of at most 64 MiB.");
        return 2;
    }
    FILE *f = fdopen(fd, create ? "w" : "r");
    if (!f) {
        close(fd);
        return 2;
    }
    if (create) {
        struct baseline_walk w = {
            .c = c, .out = f, .manifest_dev = st.st_dev, .manifest_ino = st.st_ino};
        uint64_t previous_gaps = c->stats.gaps;
        if (!kc_map_init(&w.seen, 128)) {
            fclose(f);
            return 2;
        }
        fputs("# KaalClam SHA256 baseline v2; paths are hex-encoded bytes\n", f);
        for (size_t i = 0; i < c->cfg.scan_path_count; ++i)
            baseline_add(&w, c->cfg.scan_paths[i], 0);
        if (!w.files)
            kc_emit(c, KC_GAP, "integrity.empty_scope", manifest,
                    "No regular files were hashed; baseline is incomplete.");
        bool complete = c->stats.gaps == previous_gaps && !kc_stop;
        if (complete)
            fprintf(f, "# KaalClam baseline complete files=%u\n", w.files);
        else
            fputs("# KaalClam baseline incomplete\n", f);
        bool good = !ferror(f) && fflush(f) == 0 && fsync(fd) == 0;
        int close_result = fclose(f);
        kc_map_destroy(&w.seen);
        kc_emit(c, good && close_result == 0 ? KC_INFO : KC_GAP, "integrity.baseline_created",
                manifest,
                "files=%u hashed_bytes=%llu. This captures current state, not known-good state. "
                "Preserve a trusted offline copy before using it as an integrity baseline.",
                w.files, (unsigned long long)w.bytes);
        return good && close_result == 0 && complete ? 0 : 2;
    }
    char line[PATH_MAX * 2 + 100];
    unsigned checked = 0, changed = 0, unavailable = 0, invalid = 0, rows = 0;
    uint64_t bytes = 0, declared = 0;
    bool header = false, footer = false;
    while (!kc_stop && fgets(line, sizeof(line), f)) {
        if (++rows > (uint64_t)c->cfg.max_files + 16) {
            ++unavailable;
            kc_emit(c, KC_GAP, "integrity.record_limit", manifest,
                    "Manifest record budget exhausted.");
            break;
        }
        size_t n = strlen(line);
        if (!n || line[n - 1] != '\n') {
            ++invalid;
            int ch;
            while ((ch = fgetc(f)) != '\n' && ch != EOF) {
            }
            if (feof(f) || ferror(f))
                break;
            continue;
        }
        line[--n] = 0;
        if (line[0] == '#') {
            const char *prefix = "# KaalClam baseline complete files=";
            if (rows == 1 &&
                !strcmp(line, "# KaalClam SHA256 baseline v2; paths are hex-encoded bytes"))
                header = true;
            else if (!footer && !strncmp(line, prefix, strlen(prefix)) &&
                     kc_number(line + strlen(prefix), 1, c->cfg.max_files, &declared))
                footer = true;
            else
                ++invalid;
            continue;
        }
        if (footer || !header) {
            ++invalid;
            continue;
        }
        if (checked + unavailable >= c->cfg.max_files) {
            kc_emit(c, KC_GAP, "integrity.check_limit", manifest,
                    "Manifest check file-count limit reached.");
            ++unavailable;
            break;
        }
        if (n < 66 || line[64] != '\t') {
            ++invalid;
            continue;
        }
        bool valid = true;
        for (unsigned i = 0; i < 64; ++i)
            if (unhex((unsigned char)line[i]) < 0)
                valid = false;
        if (!valid) {
            ++invalid;
            continue;
        }
        line[64] = 0;
        char *path = path_decode(line + 65);
        if (!path) {
            ++invalid;
            continue;
        }
        char actual[65], why[256];
        uint64_t hashed, limit = c->cfg.max_total_bytes - bytes;
        if (limit > c->cfg.max_file_bytes)
            limit = c->cfg.max_file_bytes;
        bool ok = kc_sha256_limited(path, limit, &hashed, actual, why, sizeof(why));
        bytes += hashed;
        if (!ok) {
            ++unavailable;
            kc_emit(c, KC_GAP, "integrity.file_unavailable", path, "%s", why);
        } else {
            ++checked;
            if (strcmp(line, actual)) {
                ++changed;
                kc_emit(c, KC_REVIEW, "integrity.hash_changed", path,
                        "expected_sha256=%s observed_sha256=%s. Updates or tampering can change "
                        "files; establish baseline provenance.",
                        line, actual);
            }
        }
        free(path);
    }
    if (ferror(f))
        ++unavailable;
    fclose(f);
    if (!header || !footer || declared != (uint64_t)checked + unavailable) {
        ++invalid;
        kc_emit(c, KC_GAP, "integrity.incomplete_manifest", manifest,
                "Expected a v2 header and completion record matching the entry count. "
                "Partial or legacy baselines cannot establish complete coverage.");
    }
    if (invalid)
        kc_emit(c, KC_GAP, "integrity.malformed_records", manifest, "invalid_records=%u", invalid);
    if (!checked && !unavailable && !invalid) {
        ++invalid;
        kc_emit(c, KC_GAP, "integrity.empty_manifest", manifest,
                "No usable baseline entries; integrity was not verified.");
    }
    kc_emit(
        c, KC_INFO, "integrity.summary", manifest,
        "checked=%u changed=%u unavailable=%u malformed=%u. Changes are not automatically malware.",
        checked, changed, unavailable, invalid);
    return unavailable || invalid || kc_stop ? 2 : changed ? 3 : 0;
}
