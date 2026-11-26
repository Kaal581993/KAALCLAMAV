/* SPDX-License-Identifier: GPL-2.0-or-later
 * Read-only Arch Linux package-file comparison. This does not authenticate
 * the local package database or prove that matching software is harmless. */
#include "kaalclam.h"
#include <alpm.h>
#include <archive.h>
#include <archive_entry.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void show(const char *status, const char *path, const char *package, const char *detail) {
    char *p = kc_json_escape(path), *n = kc_json_escape(package), *d = kc_json_escape(detail);
    if (!p || !n || !d) {
        fprintf(stderr, "Package check: allocation failure.\n");
        free(p);
        free(n);
        free(d);
        exit(2);
    }
    printf("%s | %s | package=%s | %s\n", status, p, n, d);
    free(p);
    free(n);
    free(d);
}

static bool expected_hash(alpm_pkg_t *package, const char *relative, char hex[65]) {
    struct archive *mtree = alpm_pkg_mtree_open(package);
    if (!mtree)
        return false;
    struct archive_entry *entry = NULL;
    bool found = false;
    unsigned entries = 0;
    while (++entries <= 1000000 && alpm_pkg_mtree_next(package, mtree, &entry) == 0) {
        const char *name = archive_entry_pathname(entry);
        if (!name)
            continue;
        if (!strncmp(name, "./", 2))
            name += 2;
        if (strcmp(name, relative))
            continue;
        const unsigned char *digest = archive_entry_digest(entry, ARCHIVE_ENTRY_DIGEST_SHA256);
        if (archive_entry_filetype(entry) == AE_IFREG && digest) {
            static const char digits[] = "0123456789abcdef";
            for (unsigned i = 0; i < 32; ++i) {
                hex[2 * i] = digits[digest[i] >> 4];
                hex[2 * i + 1] = digits[digest[i] & 15];
            }
            hex[64] = 0;
            found = true;
        }
        break;
    }
    if (alpm_pkg_mtree_close(package, mtree) != 0)
        found = false;
    return found;
}

int main(int argc, char **argv) {
    if (argc < 2 || argc > KC_MAX_PATHS + 1) {
        fputs("Usage: kaalclam-package-check FILE [FILE ...] (maximum 128 paths)\n"
              "Compares SHA256 with Arch's local package mtree, up to 256 MiB per file.\n"
              "Read-only. The local database is a reference, not independent authentication.\n"
              "Exit: 0=all matched, 2=unverified/error, 3=different file contents.\n",
              stderr);
        return 2;
    }
    alpm_errno_t error;
    alpm_handle_t *handle = alpm_initialize("/", "/var/lib/pacman/", &error);
    if (!handle) {
        fprintf(stderr, "Cannot open local Arch package database: %s\n", alpm_strerror(error));
        return 2;
    }
    alpm_db_t *database = alpm_get_localdb(handle);
    alpm_list_t *packages = database ? alpm_db_get_pkgcache(database) : NULL;
    if (!packages || alpm_errno(handle) != ALPM_ERR_OK) {
        fputs("Local package inventory unavailable; no files verified.\n", stderr);
        alpm_release(handle);
        return 2;
    }
    unsigned matched = 0, different = 0, unavailable = 0;
    uint64_t total = 0;
    puts("Reference: local pacman database; a matching hash does not prove a program is safe.");
    for (int i = 1; i < argc; ++i) {
        char path[PATH_MAX];
        if (!realpath(argv[i], path)) {
            show("UNVERIFIED", argv[i], "unknown", strerror(errno));
            ++unavailable;
            continue;
        }
        alpm_pkg_t *owner = NULL;
        for (alpm_list_t *p = packages; p; p = p->next) {
            alpm_pkg_t *candidate = p->data;
            alpm_filelist_t *files = alpm_pkg_get_files(candidate);
            if (files && alpm_filelist_contains(files, path + 1)) {
                owner = candidate;
                break;
            }
        }
        if (!owner) {
            show("UNVERIFIED", path, "none",
                 "No package owns this path; locally installed tools may be legitimate.");
            ++unavailable;
            continue;
        }
        char package[512];
        snprintf(package, sizeof(package), "%s %s", alpm_pkg_get_name(owner),
                 alpm_pkg_get_version(owner));
        char expected[65], actual[65], why[256];
        if (!expected_hash(owner, path + 1, expected)) {
            show("UNVERIFIED", path, package, "No usable SHA256 in the package mtree.");
            ++unavailable;
            continue;
        }
        uint64_t bytes, limit = 1024 * KC_MIB - total;
        if (limit > 256 * KC_MIB)
            limit = 256 * KC_MIB;
        bool good = kc_sha256_limited(path, limit, &bytes, actual, why, sizeof(why));
        total += bytes;
        if (!good) {
            show("UNVERIFIED", path, package, why);
            ++unavailable;
            continue;
        }
        char detail[512];
        if (strcmp(expected, actual)) {
            snprintf(detail, sizeof(detail),
                     "expected_sha256=%s actual_sha256=%s; updates/local edits/tampering need "
                     "differentiation. This is not automatically malware.",
                     expected, actual);
            show("DIFFERENT", path, package, detail);
            ++different;
        } else {
            snprintf(detail, sizeof(detail), "SHA256 matches local package record: %s", actual);
            show("MATCH", path, package, detail);
            ++matched;
        }
    }
    printf("Matched: %u | Different: %u | Unverified: %u | Hashed bytes: %llu\n", matched,
           different, unavailable, (unsigned long long)total);
    puts("Changed or compromised package metadata can defeat this comparison. "
         "Trusted offline references provide stronger evidence.");
    bool release_failed = alpm_release(handle) != 0;
    return different ? 3 : unavailable || release_failed ? 2 : 0;
}
