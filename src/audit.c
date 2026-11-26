/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "kaalclam.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>

static void trim(char *s) {
    size_t n = strlen(s);
    while (n && (s[n - 1] == '\n' || s[n - 1] == '\r'))
        s[--n] = 0;
}
static bool numeric(const char *s) {
    uint64_t n;
    return kc_number(s, 1, INT_MAX, &n);
}

void kc_audit_environment(struct kc_context *c) {
    struct utsname u;
    if (uname(&u) == 0)
        kc_emit(c, KC_INFO, "environment.kernel", u.release, "system=%s machine=%s build=%s",
                u.sysname, u.machine, u.version);
    char *uidmap = kc_read_text("/proc/self/uid_map", 2048, NULL);
    char *pid1 = kc_read_text("/proc/1/comm", 256, NULL);
    unsigned long inside = 0, outside = 0, count = 0;
    bool remapped = uidmap && sscanf(uidmap, "%lu %lu %lu", &inside, &outside, &count) == 3 &&
                    !(inside == 0 && outside == 0 && count >= 4294967294UL);
    if (pid1)
        trim(pid1);
    if (remapped || (pid1 && strcmp(pid1, "systemd") && strcmp(pid1, "init"))) {
        c->namespace_limited = true;
        kc_emit(c, KC_GAP, "coverage.namespaces", "/proc/self/uid_map",
                "Restricted/container namespace is possible: pid1=%s uid_map=%s. Process and "
                "network results cover only this namespace, not necessarily the host.",
                pid1 ? pid1 : "unreadable", uidmap ? uidmap : "unreadable");
    }
    kc_emit(c, KC_INFO, "environment.identity", "KaalClam",
            "uid=%lu euid=%lu desktop_uid=%lu; no kernel modules are loaded and no system settings "
            "are changed.",
            (unsigned long)getuid(), (unsigned long)geteuid(), (unsigned long)c->cfg.desktop_uid);
    free(uidmap);
    free(pid1);
    static const char *paths[] = {
        "/proc/sys/kernel/dmesg_restrict",    "/proc/sys/kernel/kptr_restrict",
        "/proc/sys/kernel/modules_disabled",  "/proc/sys/kernel/unprivileged_bpf_disabled",
        "/proc/sys/kernel/yama/ptrace_scope", "/sys/kernel/security/lockdown"};
    for (size_t i = 0; i < sizeof(paths) / sizeof(*paths); ++i) {
        char *s = kc_read_text(paths[i], 1024, NULL);
        if (s) {
            trim(s);
            kc_emit(c, KC_INFO, "kernel.policy", paths[i], "%s", s);
            free(s);
        } else
            kc_emit(c, KC_GAP, "kernel.policy_unavailable", paths[i], "%s", strerror(errno));
    }
}

struct socket_row {
    uint64_t inode;
    char protocol[8], local[96], remote[96];
    unsigned state;
};
bool kc_net_endpoint(const char *s, bool ipv6, char out[96]) {
    const char *colon = strrchr(s, ':');
    if (!colon)
        return false;
    size_t addrlen = (size_t)(colon - s);
    if (addrlen != (ipv6 ? 32U : 8U) || strlen(colon + 1) != 4)
        return false;
    for (const char *p = s; *p; ++p)
        if (p != colon && !isxdigit((unsigned char)*p))
            return false;
    unsigned port;
    if (sscanf(colon + 1, "%x", &port) != 1 || port > 65535)
        return false;
    char ip[INET6_ADDRSTRLEN];
    if (ipv6) {
        unsigned words[4];
        if ((size_t)(colon - s) != 32 ||
            sscanf(s, "%8x%8x%8x%8x", &words[0], &words[1], &words[2], &words[3]) != 4)
            return false;
        if (!inet_ntop(AF_INET6, words, ip, sizeof(ip)))
            return false;
        snprintf(out, 96, "[%s]:%u", ip, port);
    } else {
        unsigned word;
        if ((size_t)(colon - s) != 8 || sscanf(s, "%8x", &word) != 1)
            return false;
        if (!inet_ntop(AF_INET, &word, ip, sizeof(ip)))
            return false;
        snprintf(out, 96, "%s:%u", ip, port);
    }
    return true;
}
static void sockets_read(struct kc_context *c, struct socket_row **rows, size_t *n,
                         struct kc_map *index) {
    const char *names[] = {"tcp", "tcp6", "udp", "udp6"};
    size_t cap = 0;
    for (unsigned k = 0; k < 4; ++k) {
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "/proc/net/%s", names[k]);
        FILE *f = fopen(path, "re");
        if (!f) {
            kc_emit_once(c, KC_GAP, "network.table_unavailable", path, "%s", strerror(errno));
            continue;
        }
        char line[4096];
        if (!fgets(line, sizeof(line), f)) {
            kc_emit_once(c, KC_GAP, "network.table_header_unavailable", path,
                         "Socket table header could not be read; coverage is incomplete.");
            fclose(f);
            continue;
        }
        while (*n < 100000 && fgets(line, sizeof(line), f)) {
            char *fields[16];
            size_t count = 0;
            char *save = NULL;
            for (char *s = strtok_r(line, " \t\n", &save); s && count < 16;
                 s = strtok_r(NULL, " \t\n", &save))
                fields[count++] = s;
            if (count < 10)
                continue;
            uint64_t inode;
            if (!kc_number(fields[9], 1, UINT64_MAX, &inode))
                continue;
            struct socket_row row = {.inode = inode};
            if (!kc_net_endpoint(fields[1], k % 2 != 0, row.local) ||
                !kc_net_endpoint(fields[2], k % 2 != 0, row.remote))
                continue;
            row.state = (unsigned)strtoul(fields[3], NULL, 16);
            snprintf(row.protocol, sizeof(row.protocol), "%s", names[k]);
            if (*n == cap) {
                size_t next = cap ? cap * 2 : 128;
                void *p = realloc(*rows, next * sizeof(**rows));
                if (!p) {
                    kc_stop = 1;
                    break;
                }
                *rows = p;
                cap = next;
            }
            (*rows)[*n] = row;
            if (!kc_map_put(index, inode, *n + 1)) {
                kc_stop = 1;
                break;
            }
            ++*n;
        }
        if (ferror(f))
            kc_emit_once(c, KC_GAP, "network.table_read_error", path, "%s", strerror(errno));
        fclose(f);
    }
    if (*n >= 100000)
        kc_emit(c, KC_GAP, "network.table_limit", "/proc/net",
                "100000-socket inventory cap reached.");
}

void kc_audit_processes(struct kc_context *c) {
    struct kc_map sockets = {0};
    struct socket_row *rows = NULL;
    size_t nrows = 0;
    if (!kc_map_init(&sockets, 256)) {
        kc_stop = 1;
        return;
    }
    sockets_read(c, &rows, &nrows, &sockets);
    DIR *d = opendir("/proc");
    if (!d) {
        kc_emit(c, KC_GAP, "process.inventory_unavailable", "/proc", "%s", strerror(errno));
        goto done;
    }
    struct dirent *e;
    unsigned processes = 0, fd_denied = 0, maps_denied = 0, exited = 0;
    uint64_t fd_count = 0;
    char self_net[128];
    bool own_net = kc_readlink("/proc/self/ns/net", self_net, sizeof(self_net)) >= 0;
    while ((e = readdir(d)) && !kc_stop) {
        if (!numeric(e->d_name))
            continue;
        ++processes;
        char base[PATH_MAX], path[PATH_MAX], comm[256] = "?", exe[PATH_MAX] = "[unavailable]";
        snprintf(base, sizeof(base), "/proc/%s", e->d_name);
        kc_path(path, base, "comm");
        char *t = kc_read_text(path, sizeof(comm) - 1, NULL);
        if (t) {
            trim(t);
            snprintf(comm, sizeof(comm), "%s", t);
            free(t);
        }
        kc_path(path, base, "exe");
        bool exe_ok = kc_readlink(path, exe, sizeof(exe)) >= 0;
        bool deleted = exe_ok && strstr(exe, " (deleted)"), memfd = exe_ok && strstr(exe, "memfd:");
        bool temporary = exe_ok && (!strncmp(exe, "/tmp/", 5) || !strncmp(exe, "/dev/shm/", 9) ||
                                    !strncmp(exe, "/var/tmp/", 9));
        bool writable_exec = false;
        unsigned anon_exec = 0, rwx = 0, connections = 0, input_writers = 0;
        unsigned flags = kc_ac_flags(&c->matcher, comm, strlen(comm)) |
                         kc_ac_flags(&c->matcher, exe, strlen(exe));
        kc_path(path, base, "cmdline");
        size_t arglen = 0;
        char *args = kc_read_text(path, 65536, &arglen);
        if (args) {
            for (size_t i = 0; i < arglen; ++i)
                if (!args[i])
                    args[i] = ' ';
            flags |= kc_ac_flags(&c->matcher, args, arglen);
            free(args);
        }
        kc_path(path, base, "maps");
        size_t maplen = 0;
        char *maps = kc_read_text(path, 2 * KC_MIB, &maplen);
        if (!maps) {
            if (errno != ENOENT && errno != ESRCH)
                ++maps_denied;
        } else {
            char *save = NULL;
            for (char *line = strtok_r(maps, "\n", &save); line;
                 line = strtok_r(NULL, "\n", &save)) {
                unsigned long long start, end, offset, inode;
                unsigned maj, min;
                char perms[5];
                int at = 0;
                if (sscanf(line, "%llx-%llx %4s %llx %x:%x %llu %n", &start, &end, perms, &offset,
                           &maj, &min, &inode, &at) < 7)
                    continue;
                if (perms[2] == 'x') {
                    const char *name = line + at;
                    while (*name == ' ')
                        ++name;
                    if (!*name || strstr(name, "memfd:") || !strncmp(name, "[anon", 5))
                        ++anon_exec;
                    if (perms[1] == 'w') {
                        ++rwx;
                        writable_exec = true;
                    }
                }
            }
            if (maplen == 2 * KC_MIB)
                kc_emit_once(c, KC_GAP, "process.maps_limit", base,
                             "maps inventory reached 2 MiB; incomplete.");
            free(maps);
        }
        kc_path(path, base, "fd");
        DIR *fds = opendir(path);
        if (!fds) {
            if (errno == ENOENT || errno == ESRCH)
                ++exited;
            else
                ++fd_denied;
        } else {
            struct dirent *fe;
            unsigned seen = 0;
            while ((fe = readdir(fds))) {
                uint64_t fdnum;
                if (!kc_number(fe->d_name, 0, INT_MAX, &fdnum))
                    continue;
                if (++seen > 8192) {
                    kc_emit_once(c, KC_GAP, "process.fd_limit", base, "8192-fd cap reached.");
                    break;
                }
                ++fd_count;
                char fp[PATH_MAX], target[PATH_MAX];
                if (!kc_path(fp, path, fe->d_name) || kc_readlink(fp, target, sizeof(target)) < 0)
                    continue;
                uint64_t inode = 0, index;
                unsigned long long parsed = 0;
                if (sscanf(target, "socket:[%llu]", &parsed) == 1) {
                    inode = (uint64_t)parsed;
                    if (kc_map_get(&sockets, inode, &index) && index && index <= nrows) {
                        struct socket_row *r = &rows[index - 1];
                        if ((!strncmp(r->protocol, "tcp", 3) && r->state == 1))
                            ++connections;
                        char subject[256];
                        snprintf(subject, sizeof(subject), "pid=%.10s inode=%llu", e->d_name,
                                 (unsigned long long)inode);
                        kc_emit_once(c, KC_INFO, "network.socket_owner", subject,
                                     "process=%s executable=%s protocol=%s local=%s remote=%s "
                                     "state=0x%x; snapshot, not a maliciousness verdict.",
                                     comm, exe, r->protocol, r->local, r->remote, r->state);
                    }
                }
                bool ui = !strcmp(target, "/dev/uinput") || !strcmp(target, "/dev/input/uinput");
                bool ev = !strncmp(target, "/dev/input/event", 16);
                if (ui || ev) {
                    char fi[PATH_MAX], leaf[128];
                    snprintf(leaf, sizeof(leaf), "fdinfo/%llu", (unsigned long long)fdnum);
                    kc_path(fi, base, leaf);
                    char *info = kc_read_text(fi, 16384, NULL);
                    unsigned long access = 0;
                    bool known = false;
                    if (info) {
                        char *p = strstr(info, "flags:");
                        if (p && sscanf(p, "flags:\t%lo", &access) == 1)
                            known = true;
                        free(info);
                    }
                    bool writeable = known && ((access & O_ACCMODE) != O_RDONLY);
                    if (writeable)
                        ++input_writers;
                    char subject[512];
                    snprintf(subject, sizeof(subject), "pid=%.10s fd=%llu", e->d_name,
                             (unsigned long long)fdnum);
                    kc_emit_once(
                        c, writeable ? KC_REVIEW : KC_INFO,
                        writeable ? "input.write_handle" : "input.read_handle", subject,
                        "process=%s executable=%s device=%s access=%s. Writable uinput/evdev "
                        "handles can inject events; legitimate desktop and accessibility "
                        "tools also use them. This is not proof of malware.",
                        comm, exe, target,
                        known ? (writeable ? "write-capable" : "read-only") : "unknown");
                }
            }
            closedir(fds);
        }
        kc_path(path, base, "ns/net");
        char other_net[128];
        if (own_net && kc_readlink(path, other_net, sizeof(other_net)) >= 0 &&
            strcmp(self_net, other_net))
            kc_emit_once(c, KC_GAP, "network.other_namespace", other_net,
                         "At least one process has another network namespace; its sockets are not "
                         "represented in /proc/net here.");
        char subject[512];
        snprintf(subject, sizeof(subject), "pid=%.10s %s", e->d_name, comm);
        if (flags & (KC_REMOTE | KC_INJECT | KC_SHELL | KC_ROOTKIT_NAME))
            kc_emit_once(c, (flags & (KC_SHELL | KC_ROOTKIT_NAME)) ? KC_REVIEW : KC_INFO,
                         "process.indicator", subject,
                         "executable=%s indicator_flags=0x%x; name/argument heuristic only. "
                         "Commands, environment, and memory contents are not saved.",
                         exe, flags);
        if (deleted || memfd || temporary || rwx || anon_exec) {
            bool combined =
                (connections || input_writers) && (deleted || memfd || temporary || writable_exec);
            kc_emit_once(c, combined ? KC_REVIEW : KC_INFO, "process.execution_metadata", subject,
                         "executable=%s deleted=%d memfd=%d temporary_path=%d "
                         "anonymous_executable_mappings=%u writable_executable_mappings=%u "
                         "established_tcp_sockets=%u input_write_handles=%u. Updates and JIT "
                         "runtimes can explain these properties; verify provenance.",
                         exe, deleted, memfd, temporary, anon_exec, rwx, connections,
                         input_writers);
        }
    }
    closedir(d);
    kc_emit(c, KC_INFO, "process.snapshot_summary", "/proc",
            "processes=%u inspected_fds=%llu socket_rows=%zu transient_exits=%u "
            "fd_directories_denied=%u maps_denied=%u",
            processes, (unsigned long long)fd_count, nrows, exited, fd_denied, maps_denied);
    if (fd_denied || maps_denied)
        kc_emit_once(c, KC_GAP, "process.partial_permissions", "/proc",
                     "Some process descriptors/maps cannot be inspected; fd_denied=%u "
                     "maps_denied=%u. A host root run may improve coverage.",
                     fd_denied, maps_denied);
done:
    kc_map_destroy(&sockets);
    free(rows);
}

static bool module_in_list(const char *text, const char *name) {
    size_t len = strlen(name);
    const char *p = text;
    while (p && *p) {
        if (!strncmp(p, name, len) && p[len] == ' ')
            return true;
        p = strchr(p, '\n');
        if (p)
            ++p;
    }
    return false;
}
static void bpf_inventory(struct kc_context *c) {
#ifdef __NR_bpf
    unsigned last = 0, count = 0;
    for (; count < 4096; ++count) {
        union bpf_attr a;
        memset(&a, 0, sizeof(a));
        a.start_id = last;
        if (syscall(__NR_bpf, BPF_PROG_GET_NEXT_ID, &a, sizeof(a)) < 0) {
            if (errno != ENOENT)
                kc_emit_once(c, KC_GAP, "kernel.bpf_inventory_unavailable", "bpf()",
                             "%s; this does not mean no BPF programs are loaded.", strerror(errno));
            break;
        }
        unsigned id = a.next_id;
        last = id;
        memset(&a, 0, sizeof(a));
        a.prog_id = id;
        int fd = (int)syscall(__NR_bpf, BPF_PROG_GET_FD_BY_ID, &a, sizeof(a));
        if (fd < 0) {
            kc_emit_once(c, KC_GAP, "kernel.bpf_program_unreadable", "bpf()",
                         "Cannot open program IDs: %s", strerror(errno));
            continue;
        }
        struct bpf_prog_info info;
        memset(&info, 0, sizeof(info));
        memset(&a, 0, sizeof(a));
        a.info.bpf_fd = (uint32_t)fd;
        a.info.info_len = sizeof(info);
        a.info.info = (uint64_t)(uintptr_t)&info;
        if (syscall(__NR_bpf, BPF_OBJ_GET_INFO_BY_FD, &a, sizeof(a)) == 0) {
            info.name[BPF_OBJ_NAME_LEN - 1] = 0;
            char subject[128];
            snprintf(subject, sizeof(subject), "id=%u %s", id, info.name);
            kc_emit_once(
                c, KC_INFO, "kernel.bpf_program", subject,
                "type=%u creator_uid=%u translated_bytes=%u; legitimate networking/security "
                "software commonly loads BPF. Enumeration alone does not establish integrity.",
                info.type, info.created_by_uid, info.xlated_prog_len);
        }
        close(fd);
    }
    if (count == 4096)
        kc_emit(c, KC_GAP, "kernel.bpf_limit", "bpf()", "4096-program inventory cap reached.");
#else
    kc_emit(c, KC_GAP, "kernel.bpf_unavailable", "build",
            "No bpf syscall number in build headers.");
#endif
}
void kc_audit_kernel(struct kc_context *c) {
    char *t = kc_read_text("/proc/sys/kernel/tainted", 128, NULL);
    if (t) {
        uint64_t taint = strtoull(t, NULL, 10);
        free(t);
        kc_emit(
            c,
            taint & ((1ULL << 4) | (1ULL << 5) | (1ULL << 7) | (1ULL << 9) | (1ULL << 14))
                ? KC_REVIEW
                : KC_INFO,
            "kernel.taint", "/proc/sys/kernel/tainted",
            "value=%llu proprietary=%d forced_module=%d machine_check=%d bad_page=%d oops=%d "
            "warning=%d out_of_tree=%d unsigned=%d soft_lockup=%d. Taint is diagnostic context, "
            "not a malware verdict; NVIDIA commonly sets proprietary/out-of-tree/unsigned flags.",
            (unsigned long long)taint, (int)!!(taint & 1), (int)!!(taint & 2), (int)!!(taint & 16),
            (int)!!(taint & 32), (int)!!(taint & 128), (int)!!(taint & 512), (int)!!(taint & 4096),
            (int)!!(taint & 8192), (int)!!(taint & 16384));
    } else
        kc_emit(c, KC_GAP, "kernel.taint_unavailable", "/proc/sys/kernel/tainted", "%s",
                strerror(errno));
    size_t length = 0;
    char *modules = kc_read_text("/proc/modules", 4 * KC_MIB, &length);
    if (!modules) {
        kc_emit(c, KC_GAP, "kernel.modules_unavailable", "/proc/modules", "%s", strerror(errno));
        bpf_inventory(c);
        return;
    }
    if (length == 4 * KC_MIB)
        kc_emit(c, KC_GAP, "kernel.module_list_limit", "/proc/modules",
                "Module list reached read limit; comparison is incomplete.");
    char *copy = strdup(modules);
    unsigned count = 0;
    if (copy) {
        char *save = NULL;
        for (char *line = strtok_r(copy, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
            char name[256], state[64];
            unsigned long size, refs;
            char dependencies[2048];
            if (sscanf(line, "%255s %lu %lu %2047s %63s", name, &size, &refs, dependencies, state) <
                5)
                continue;
            ++count;
            char path[PATH_MAX];
            snprintf(path, sizeof(path), "/sys/module/%s/taint", name);
            char *taint = kc_read_text(path, 256, NULL);
            if (taint)
                trim(taint);
            unsigned flags = kc_ac_flags(&c->matcher, name, strlen(name));
            kc_emit_once(c, flags & KC_ROOTKIT_NAME ? KC_REVIEW : KC_INFO, "kernel.module", name,
                         "state=%s size=%lu refcount=%lu taint=%s rootkit_name_heuristic=%d. A "
                         "matching name requires independent investigation.",
                         state, size, refs, taint ? taint : "unavailable",
                         !!(flags & KC_ROOTKIT_NAME));
            free(taint);
            snprintf(path, sizeof(path), "/sys/module/%s", name);
            struct stat st;
            if (stat(path, &st) < 0 && errno == ENOENT) {
                char *again = kc_read_text("/proc/modules", 4 * KC_MIB, NULL);
                if (again && module_in_list(again, name))
                    kc_emit_once(
                        c, KC_REVIEW, "kernel.module_crossview", name,
                        "Present in /proc/modules twice, absent from /sys/module. Module "
                        "transitions, namespaces, permissions, or tampering need differentiation.");
                free(again);
            }
        }
        free(copy);
    }
    DIR *d = opendir("/sys/module");
    if (!d)
        kc_emit(c, KC_GAP, "kernel.sysmodules_unavailable", "/sys/module", "%s", strerror(errno));
    else {
        struct dirent *e;
        while ((e = readdir(d))) {
            if (e->d_name[0] == '.' || module_in_list(modules, e->d_name))
                continue;
            char path[PATH_MAX];
            snprintf(path, sizeof(path), "/sys/module/%s/initstate", e->d_name);
            char *state = kc_read_text(path, 256, NULL);
            /* Built-in modules do not have initstate. Ignore them instead of labelling them hidden.
             */
            if (state) {
                trim(state);
                if (!strcmp(state, "live")) {
                    char *again = kc_read_text("/proc/modules", 4 * KC_MIB, NULL);
                    if (again && !module_in_list(again, e->d_name))
                        kc_emit_once(c, KC_REVIEW, "kernel.module_crossview", e->d_name,
                                     "Live loadable module in sysfs absent from two /proc/modules "
                                     "snapshots. This is an inconsistency to verify, not proof of "
                                     "a hidden rootkit.");
                    free(again);
                }
                free(state);
            }
        }
        closedir(d);
    }
    kc_emit(c, KC_INFO, "kernel.module_summary", "/proc/modules",
            "loadable_modules=%u; both views come from the running kernel and can be falsified by "
            "a compromised kernel.",
            count);
    free(modules);
    bpf_inventory(c);
}

static void persistence_file(struct kc_context *c, const char *path) {
    struct stat st;
    if (lstat(path, &st) < 0)
        return;
    if (S_ISLNK(st.st_mode)) {
        char dest[PATH_MAX];
        if (kc_readlink(path, dest, sizeof(dest)) >= 0)
            kc_emit_once(c, KC_INFO, "persistence.symlink", path, "target=%s", dest);
        return;
    }
    if (!S_ISREG(st.st_mode))
        return;
    if (st.st_mode & 0002)
        kc_emit_once(
            c, KC_REVIEW, "persistence.world_writable", path,
            "Startup/config file is writable by everyone; verify ownership and intended use.");
    if (st.st_size > 256 * 1024) {
        kc_emit_once(c, KC_GAP, "persistence.size_limit", path,
                     "Text inspection capped at 256 KiB; file not fully inspected.");
        return;
    }
    size_t n = 0;
    char *s = kc_read_text(path, 256 * 1024, &n);
    if (!s) {
        kc_emit_once(c, KC_GAP, "persistence.unreadable", path, "%s", strerror(errno));
        return;
    }
    if (memchr(s, 0, n)) {
        free(s);
        return;
    }
    char *save = NULL;
    unsigned line = 0;
    for (char *p = strtok_r(s, "\n", &save); p; p = strtok_r(NULL, "\n", &save)) {
        ++line;
        while (isspace((unsigned char)*p))
            ++p;
        if (!*p || *p == '#' || *p == ';')
            continue;
        unsigned flags = kc_ac_flags(&c->matcher, p, strlen(p));
        if (flags & (KC_REMOTE | KC_INJECT | KC_SHELL | KC_OBFUSCATED | KC_ROOTKIT_NAME)) {
            kc_emit_once(c, flags & (KC_SHELL | KC_ROOTKIT_NAME) ? KC_REVIEW : KC_INFO,
                         "persistence.indicator", path,
                         "non-comment line=%u indicator_flags=0x%x. Text/name heuristic only; file "
                         "contents are not included to avoid exposing credentials.",
                         line, flags);
        }
        if (strstr(p, "LD_PRELOAD") || strstr(p, "LD_AUDIT"))
            kc_emit_once(c, KC_REVIEW, "persistence.loader_environment", path,
                         "Dynamic-loader override on a non-comment line. It may be intentional; "
                         "inspect the referenced library and compare with a trusted baseline.");
    }
    free(s);
}
static void persistence_walk(struct kc_context *c, const char *path, unsigned depth,
                             unsigned *count) {
    if (depth > 8 || *count >= 10000 || kc_stop) {
        if (depth > 8)
            kc_emit_once(c, KC_GAP, "persistence.depth_limit", path,
                         "Startup inspection depth limit reached.");
        return;
    }
    struct stat st;
    if (lstat(path, &st) < 0) {
        if (errno != ENOENT)
            kc_emit_once(c, KC_GAP, "persistence.path_unavailable", path, "%s", strerror(errno));
        return;
    }
    if (!S_ISDIR(st.st_mode)) {
        ++*count;
        persistence_file(c, path);
        return;
    }
    DIR *d = opendir(path);
    if (!d) {
        kc_emit_once(c, KC_GAP, "persistence.directory_unavailable", path, "%s", strerror(errno));
        return;
    }
    struct dirent *e;
    while (*count < 10000 && !kc_stop && (e = readdir(d))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
            continue;
        char next[PATH_MAX];
        if (kc_path(next, path, e->d_name))
            persistence_walk(c, next, depth + 1, count);
    }
    closedir(d);
}
void kc_audit_persistence(struct kc_context *c) {
    unsigned count = 0;
    const char *system[] = {"/etc/systemd/system", "/etc/systemd/user",
                            "/etc/xdg/autostart",  "/etc/cron.d",
                            "/etc/cron.daily",     "/etc/cron.hourly",
                            "/etc/udev/rules.d",   "/etc/ld.so.conf.d",
                            "/etc/profile.d",      "/etc/NetworkManager/dispatcher.d",
                            "/etc/rc.local",       "/etc/crontab"};
    for (size_t i = 0; i < sizeof(system) / sizeof(*system); ++i)
        persistence_walk(c, system[i], 0, &count);
    const char *user[] = {".config/autostart",
                          ".config/autostart-scripts",
                          ".config/systemd/user",
                          ".local/share/systemd/user",
                          ".config/environment.d",
                          ".config/plasma-workspace/env",
                          ".config/fish/config.fish",
                          ".config/libinput-gestures.conf",
                          ".bashrc",
                          ".bash_profile",
                          ".profile",
                          ".zshrc",
                          ".zshenv",
                          ".zprofile",
                          ".xprofile",
                          ".xinitrc",
                          ".ssh/authorized_keys"};
    for (size_t i = 0; i < sizeof(user) / sizeof(*user); ++i) {
        char p[PATH_MAX];
        if (kc_path(p, c->cfg.home, user[i]))
            persistence_walk(c, p, 0, &count);
    }
    char *s = kc_read_text("/etc/ld.so.preload", 262144, NULL);
    if (s) {
        bool content = false;
        char *save = NULL;
        for (char *l = strtok_r(s, "\n", &save); l; l = strtok_r(NULL, "\n", &save)) {
            while (isspace((unsigned char)*l))
                ++l;
            if (*l && *l != '#') {
                content = true;
                break;
            }
        }
        kc_emit(c, content ? KC_REVIEW : KC_INFO, "persistence.global_preload",
                "/etc/ld.so.preload",
                "active_entries_present=%d; preload can be legitimate; inspect libraries "
                "independently.",
                content);
        free(s);
    } else if (errno != ENOENT)
        kc_emit(c, KC_GAP, "persistence.preload_unavailable", "/etc/ld.so.preload", "%s",
                strerror(errno));
    if (count >= 10000)
        kc_emit(c, KC_GAP, "persistence.count_limit", "startup locations",
                "10000-file inspection cap reached.");
    kc_emit(c, KC_INFO, "persistence.summary", "startup locations",
            "inspected_entries=%u; default inspection covers this user and selected system "
            "locations, not every account or every possible persistence mechanism.",
            count);
}
