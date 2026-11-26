/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "kaalclam.h"
#include <stdlib.h>
#include <string.h>

uint64_t kc_hash_bytes(const void *data, size_t n) {
    const unsigned char *p = data;
    uint64_t h = UINT64_C(14695981039346656037);
    for (size_t i = 0; i < n; ++i) {
        h ^= p[i];
        h *= UINT64_C(1099511628211);
    }
    return h;
}
static uint64_t mix(uint64_t x) {
    x ^= x >> 30;
    x *= UINT64_C(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x *= UINT64_C(0x94d049bb133111eb);
    return x ^ (x >> 31);
}
bool kc_map_init(struct kc_map *m, size_t requested) {
    memset(m, 0, sizeof(*m));
    size_t cap = 16;
    while (cap < requested) {
        if (cap > SIZE_MAX / 2)
            return false;
        cap *= 2;
    }
    m->entries = calloc(cap, sizeof(*m->entries));
    if (!m->entries)
        return false;
    m->capacity = cap;
    return true;
}
void kc_map_destroy(struct kc_map *m) {
    free(m->entries);
    memset(m, 0, sizeof(*m));
}
bool kc_map_get(const struct kc_map *m, uint64_t key, uint64_t *value) {
    if (!m->capacity)
        return false;
    size_t i = (size_t)mix(key) & (m->capacity - 1);
    for (size_t n = 0; n < m->capacity; ++n, i = (i + 1) & (m->capacity - 1)) {
        if (!m->entries[i].used)
            return false;
        if (m->entries[i].key == key) {
            if (value)
                *value = m->entries[i].value;
            return true;
        }
    }
    return false;
}
bool kc_map_put(struct kc_map *m, uint64_t key, uint64_t value) {
    if (!m->capacity && !kc_map_init(m, 16))
        return false;
    if (m->count >= m->capacity * 7 / 10) {
        struct kc_map grown;
        if (m->capacity > SIZE_MAX / 2 || !kc_map_init(&grown, m->capacity * 2))
            return false;
        for (size_t j = 0; j < m->capacity; ++j)
            if (m->entries[j].used && !kc_map_put(&grown, m->entries[j].key, m->entries[j].value)) {
                kc_map_destroy(&grown);
                return false;
            }
        kc_map_destroy(m);
        *m = grown;
    }
    size_t i = (size_t)mix(key) & (m->capacity - 1);
    while (m->entries[i].used && m->entries[i].key != key)
        i = (i + 1) & (m->capacity - 1);
    if (!m->entries[i].used) {
        m->entries[i].used = true;
        m->entries[i].key = key;
        ++m->count;
    }
    m->entries[i].value = value;
    return true;
}
static int ac_node(struct kc_ac *a) {
    if (a->count == a->capacity) {
        size_t cap = a->capacity ? a->capacity * 2 : 32;
        if (cap > SIZE_MAX / sizeof(*a->nodes))
            return -1;
        void *p = realloc(a->nodes, cap * sizeof(*a->nodes));
        if (!p)
            return -1;
        a->nodes = p;
        a->capacity = cap;
    }
    size_t n = a->count++;
    for (unsigned i = 0; i < 128; ++i)
        a->nodes[n].next[i] = -1;
    a->nodes[n].outputs = 0;
    a->nodes[n].fail = 0;
    return (int)n;
}
bool kc_ac_init(struct kc_ac *a) {
    memset(a, 0, sizeof(*a));
    return ac_node(a) == 0;
}
static unsigned fold(unsigned ch) {
    return ch >= 'A' && ch <= 'Z' ? ch + ('a' - 'A') : ch;
}
bool kc_ac_add(struct kc_ac *a, const char *text, unsigned flags) {
    if (a->built || !*text || a->pattern_count >= KC_MAX_PATTERNS)
        return false;
    int n = 0;
    for (const unsigned char *s = (const unsigned char *)text; *s; ++s) {
        unsigned ch = fold(*s);
        if (ch >= 128)
            return false;
        if (a->nodes[n].next[ch] < 0) {
            int child = ac_node(a);
            if (child < 0)
                return false;
            a->nodes[n].next[ch] = child;
        }
        n = a->nodes[n].next[ch];
    }
    a->nodes[n].outputs |= UINT64_C(1) << a->pattern_count;
    a->patterns[a->pattern_count++] = (struct kc_pattern){text, flags};
    return true;
}
bool kc_ac_build(struct kc_ac *a) {
    if (a->built || !a->count)
        return false;
    int *queue = malloc(a->count * sizeof(*queue));
    if (!queue)
        return false;
    size_t head = 0, tail = 0;
    for (unsigned c = 0; c < 128; ++c) {
        int n = a->nodes[0].next[c];
        if (n < 0)
            a->nodes[0].next[c] = 0;
        else {
            a->nodes[n].fail = 0;
            queue[tail++] = n;
        }
    }
    while (head < tail) {
        int n = queue[head++];
        for (unsigned c = 0; c < 128; ++c) {
            int child = a->nodes[n].next[c];
            int fallback = a->nodes[a->nodes[n].fail].next[c];
            if (child < 0)
                a->nodes[n].next[c] = fallback;
            else {
                a->nodes[child].fail = fallback;
                a->nodes[child].outputs |= a->nodes[fallback].outputs;
                queue[tail++] = child;
            }
        }
    }
    free(queue);
    a->built = true;
    return true;
}
uint64_t kc_ac_feed(const struct kc_ac *a, const void *data, size_t len, int *state) {
    if (!a->built)
        return 0;
    const unsigned char *s = data;
    int n = *state;
    uint64_t found = 0;
    if (n < 0 || (size_t)n >= a->count)
        n = 0;
    for (size_t i = 0; i < len; ++i) {
        unsigned c = fold(s[i]);
        n = c < 128 ? a->nodes[n].next[c] : 0;
        found |= a->nodes[n].outputs;
    }
    *state = n;
    return found;
}
unsigned kc_ac_flags(const struct kc_ac *a, const void *data, size_t len) {
    int state = 0;
    uint64_t mask = kc_ac_feed(a, data, len, &state);
    unsigned flags = 0;
    for (size_t i = 0; i < a->pattern_count; ++i)
        if (mask & (UINT64_C(1) << i))
            flags |= a->patterns[i].flags;
    return flags;
}
void kc_ac_destroy(struct kc_ac *a) {
    free(a->nodes);
    memset(a, 0, sizeof(*a));
}
bool kc_patterns_init(struct kc_ac *a) {
    static const struct kc_pattern p[] = {{"rustdesk", KC_REMOTE},
                                          {"anydesk", KC_REMOTE},
                                          {"teamviewer", KC_REMOTE},
                                          {"meshagent", KC_REMOTE},
                                          {"dwagent", KC_REMOTE},
                                          {"x11vnc", KC_REMOTE},
                                          {"wayvnc", KC_REMOTE},
                                          {"xrdp", KC_REMOTE},
                                          {"krdp", KC_REMOTE},
                                          {"krfb", KC_REMOTE},
                                          {"nxserver", KC_REMOTE},
                                          {"chrome-remote-desktop", KC_REMOTE},
                                          {"screenconnect", KC_REMOTE},
                                          {"sunshine", KC_REMOTE},
                                          {"kdeconnect", KC_REMOTE},
                                          {"input-leap", KC_REMOTE},
                                          {"xdotool", KC_INJECT},
                                          {"ydotool", KC_INJECT},
                                          {"autokey", KC_INJECT},
                                          {"pyautogui", KC_INJECT},
                                          {"pynput", KC_INJECT},
                                          {"libinput-gestures", KC_INJECT},
                                          {"/dev/uinput", KC_INJECT},
                                          {"/dev/tcp/", KC_SHELL},
                                          {"bash -i", KC_SHELL},
                                          {"nc -e ", KC_SHELL},
                                          {"ncat --exec", KC_SHELL},
                                          {"socat exec:", KC_SHELL},
                                          {"base64 -d", KC_OBFUSCATED},
                                          {"base64 --decode", KC_OBFUSCATED},
                                          {"diamorphine", KC_ROOTKIT_NAME},
                                          {"suterusu", KC_ROOTKIT_NAME},
                                          {"adore_ng", KC_ROOTKIT_NAME},
                                          {"reptile", KC_ROOTKIT_NAME},
                                          {"touch jump", KC_INPUT_FAULT},
                                          {"i2c_hid", KC_INPUT_FAULT},
                                          {"syn_dropped", KC_INPUT_FAULT},
                                          {"psmouse", KC_INPUT_FAULT},
                                          {"kernel bug", KC_KERNEL_FAULT},
                                          {"oops:", KC_KERNEL_FAULT},
                                          {"bug:", KC_KERNEL_FAULT},
                                          {"soft lockup", KC_KERNEL_FAULT},
                                          {"hardware error", KC_KERNEL_FAULT},
                                          {"warning: cpu:", KC_KERNEL_FAULT},
                                          {"accepted password", KC_AUTH},
                                          {"accepted publickey", KC_AUTH}};
    if (!kc_ac_init(a))
        return false;
    for (size_t i = 0; i < sizeof(p) / sizeof(*p); ++i)
        if (!kc_ac_add(a, p[i].text, p[i].flags))
            return false;
    return kc_ac_build(a);
}
