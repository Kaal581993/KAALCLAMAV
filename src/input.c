/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "kaalclam.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libinput.h>
#include <libudev.h>
#include <linux/input.h>
#include <math.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <systemd/sd-bus.h>
#include <time.h>
#include <unistd.h>

enum kc_button_result kc_button_step(struct kc_button_state *s, unsigned type, unsigned code,
                                     int value, uint64_t at) {
    if (type == EV_SYN && code == SYN_DROPPED) {
        s->desynchronized = true;
        s->known = false;
        return KC_BUTTON_GAP;
    }
    if (s->desynchronized) {
        if (type == EV_SYN && code == SYN_REPORT) {
            s->desynchronized = false;
            return KC_BUTTON_RESYNC;
        }
        return KC_BUTTON_NONE;
    }
    if (type != EV_KEY || code != BTN_LEFT)
        return KC_BUTTON_NONE;
    if (value != 0 && value != 1) {
        ++s->repeats;
        return KC_BUTTON_REPEAT;
    }
    bool down = value == 1;
    if (s->known && s->down == down) {
        ++s->repeats;
        return KC_BUTTON_REPEAT;
    }
    s->known = true;
    s->down = down;
    ++s->transitions;
    if (down) {
        ++s->presses;
        if (s->last_press_us && at > s->last_press_us) {
            double delta = (double)(at - s->last_press_us);
            ++s->interval_n;
            double diff = delta - s->mean_interval_us;
            s->mean_interval_us += diff / (double)s->interval_n;
            s->interval_m2 += diff * (delta - s->mean_interval_us);
        }
        s->last_press_us = at;
        return KC_BUTTON_PRESS;
    }
    ++s->releases;
    return KC_BUTTON_RELEASE;
}

struct point {
    int x, y, old_x, old_y;
    bool x_valid, y_valid, old_valid, dirty;
    uint64_t time;
};
struct input_device {
    int fd, enabled, tapping, disable_typing;
    bool used, touchpad, touchscreen, virtual_device, clock_monotonic;
    char sysname[64], name[256], physical[PATH_MAX], driver[128], node[PATH_MAX];
    struct kc_button_state left;
    uint64_t motions, contacts, frames, drops, interpreted_clicks, last_motion_report;
    struct libinput_device *li_device;
    struct point slots[32];
    int slot;
    double width, height;
};
struct kc_input {
    struct kc_context *c;
    struct input_device devices[KC_MAX_DEVICES];
    int epoll_fd;
    struct libinput *li;
    struct udev *udev;
    sd_bus *bus;
    uint64_t next_discovery, next_bus;
    unsigned count;
};

static bool bitmap_has(const char *path, unsigned bit) {
    char *s = kc_read_text(path, 16384, NULL);
    if (!s)
        return false;
    char *words[256];
    size_t n = 0;
    char *save = NULL;
    for (char *p = strtok_r(s, " \t\n", &save); p && n < 256; p = strtok_r(NULL, " \t\n", &save))
        words[n++] = p;
    unsigned width = sizeof(unsigned long) * 8;
    size_t word = bit / width;
    bool present = false;
    if (word < n) {
        char *end;
        errno = 0;
        unsigned long value = strtoul(words[n - 1 - word], &end, 16);
        if (!errno && !*end)
            present = !!(value & (1UL << (bit % width)));
    }
    free(s);
    return present;
}
static int li_open(const char *path, int flags, void *data) {
    (void)data;
    int fd = open(path, (flags & ~O_ACCMODE) | O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    return fd < 0 ? -errno : fd;
}
static void li_close(int fd, void *data) {
    (void)data;
    close(fd);
}
static const struct libinput_interface li_interface = {.open_restricted = li_open,
                                                       .close_restricted = li_close};
static void li_log(struct libinput *li, enum libinput_log_priority priority, const char *fmt,
                   va_list args) {
    struct kc_input *in = libinput_get_user_data(li);
    char message[2048];
    vsnprintf(message, sizeof(message), fmt, args);
    if (priority >= LIBINPUT_LOG_PRIORITY_ERROR)
        kc_emit_once(in->c, KC_REVIEW, "input.libinput_diagnostic", message,
                     "Independent libinput context: %s", message);
}
static void bus_open(struct kc_input *in) {
    uid_t original = geteuid();
    bool changed = false;
    if (original == 0 && in->c->cfg.desktop_uid != 0) {
        if (seteuid(in->c->cfg.desktop_uid) < 0) {
            kc_emit(in->c, KC_GAP, "desktop.bus_identity", "KWin",
                    "Cannot use desktop user's credentials: %s", strerror(errno));
            return;
        }
        changed = true;
    }
    int r = sd_bus_new(&in->bus);
    char address[160];
    snprintf(address, sizeof(address), "unix:path=/run/user/%lu/bus",
             (unsigned long)in->c->cfg.desktop_uid);
    if (r >= 0)
        r = sd_bus_set_address(in->bus, address);
    if (r >= 0)
        r = sd_bus_set_bus_client(in->bus, 1);
    if (r >= 0)
        r = sd_bus_set_method_call_timeout(in->bus, 250000);
    if (r >= 0)
        r = sd_bus_start(in->bus);
    if (changed && seteuid(original) < 0) {
        fprintf(stderr, "KaalClam: cannot restore effective uid\n");
        kc_stop = 1;
    }
    if (r < 0) {
        kc_emit(in->c, KC_GAP, "desktop.bus_unavailable", address,
                "%s; KWin runtime settings cannot be verified.", strerror(-r));
        in->bus = sd_bus_unref(in->bus);
    }
}
static void query_device(struct kc_input *in, struct input_device *d) {
    if (!in->bus)
        return;
    char path[256];
    snprintf(path, sizeof(path), "/org/kde/KWin/InputDevice/%s", d->sysname);
    sd_bus_message *m = NULL;
    sd_bus_error error = SD_BUS_ERROR_NULL;
    int r = sd_bus_call_method(in->bus, "org.kde.KWin", path, "org.freedesktop.DBus.Properties",
                               "GetAll", &error, &m, "s", "org.kde.KWin.InputDevice");
    if (r < 0) {
        kc_emit_once(in->c, KC_GAP, "desktop.device_state_unavailable", d->sysname,
                     "%s; saved config/defaults are not substituted for live state.",
                     error.message ? error.message : strerror(-r));
        goto done;
    }
    int enabled = -1, tap = -1, typing = -1, isvirtual = -1;
    r = sd_bus_message_enter_container(m, 'a', "{sv}");
    if (r < 0)
        goto done;
    while (sd_bus_message_enter_container(m, 'e', "sv") > 0) {
        const char *key = NULL;
        char type;
        const char *contents = NULL;
        if (sd_bus_message_read(m, "s", &key) < 0 ||
            sd_bus_message_peek_type(m, &type, &contents) < 0)
            break;
        if (type == 'v' && contents && !strcmp(contents, "b")) {
            int value = 0;
            if (sd_bus_message_enter_container(m, 'v', "b") < 0 ||
                sd_bus_message_read(m, "b", &value) < 0)
                break;
            if (!strcmp(key, "enabled"))
                enabled = value;
            else if (!strcmp(key, "tapToClick"))
                tap = value;
            else if (!strcmp(key, "disableWhileTyping"))
                typing = value;
            else if (!strcmp(key, "isVirtual"))
                isvirtual = value;
            if (sd_bus_message_exit_container(m) < 0)
                break;
        } else if (sd_bus_message_skip(m, "v") < 0)
            break;
        if (sd_bus_message_exit_container(m) < 0)
            break;
    }
    if (enabled != d->enabled || tap != d->tapping || typing != d->disable_typing) {
        d->enabled = enabled;
        d->tapping = tap;
        d->disable_typing = typing;
        kc_emit(in->c, KC_INFO, "desktop.device_state", d->sysname,
                "KWin enabled=%d tapToClick=%d disableWhileTyping=%d isVirtual=%d; -1 means "
                "unknown. These properties are read, never set.",
                enabled, tap, typing, isvirtual);
    }
    if (tap >= 0 && d->li_device)
        (void)libinput_device_config_tap_set_enabled(
            d->li_device, tap ? LIBINPUT_CONFIG_TAP_ENABLED : LIBINPUT_CONFIG_TAP_DISABLED);
done:
    sd_bus_error_free(&error);
    sd_bus_message_unref(m);
}
static void device_summary(struct kc_input *in, struct input_device *d) {
    kc_emit(in->c, KC_INFO, "input.device_summary", d->sysname,
            "name=%s physical=%s raw_left_presses=%llu raw_left_releases=%llu "
            "duplicate_or_repeat_events=%llu contacts=%llu motion_axis_events=%llu frames=%llu "
            "dropped_batches=%llu independent_libinput_presses=%llu KWin_enabled=%d. Raw activity "
            "from a disabled device does not prove the desktop accepted it.",
            d->name, d->physical, (unsigned long long)d->left.presses,
            (unsigned long long)d->left.releases, (unsigned long long)d->left.repeats,
            (unsigned long long)d->contacts, (unsigned long long)d->motions,
            (unsigned long long)d->frames, (unsigned long long)d->drops,
            (unsigned long long)d->interpreted_clicks, d->enabled);
}
static void remove_device(struct kc_input *in, struct input_device *d) {
    device_summary(in, d);
    if (d->fd >= 0) {
        epoll_ctl(in->epoll_fd, EPOLL_CTL_DEL, d->fd, NULL);
        close(d->fd);
        d->fd = -1;
    }
    if (d->li_device) {
        libinput_path_remove_device(d->li_device);
        libinput_device_unref(d->li_device);
        d->li_device = NULL;
    }
}
static void discover(struct kc_input *in) {
    DIR *dir = opendir("/sys/class/input");
    if (!dir) {
        kc_emit_once(in->c, KC_GAP, "input.sysfs_unavailable", "/sys/class/input", "%s",
                     strerror(errno));
        return;
    }
    struct dirent *e;
    while ((e = readdir(dir))) {
        uint64_t number;
        if (strncmp(e->d_name, "event", 5) || !kc_number(e->d_name + 5, 0, UINT_MAX, &number))
            continue;
        char path[PATH_MAX], keys[PATH_MAX], base[PATH_MAX], physical[PATH_MAX];
        snprintf(base, sizeof(base), "/sys/class/input/%s/device", e->d_name);
        kc_path(keys, base, "capabilities/key");
        if (!bitmap_has(keys, BTN_LEFT) && !bitmap_has(keys, BTN_TOUCH) &&
            !bitmap_has(keys, BTN_TOOL_PEN))
            continue;
        if (!realpath(base, physical)) {
            kc_emit_once(in->c, KC_GAP, "input.sysfs_path", base, "%s", strerror(errno));
            continue;
        }
        struct input_device *d = NULL;
        unsigned index = 0;
        for (unsigned i = 0; i < in->count; ++i)
            if (!strcmp(in->devices[i].sysname, e->d_name)) {
                d = &in->devices[i];
                index = i;
                break;
            }
        if (d && strcmp(d->physical, physical)) {
            remove_device(in, d);
            memset(d, 0, sizeof(*d));
            d->fd = -1;
            d->enabled = d->tapping = d->disable_typing = -1;
            d->used = false;
        }
        if (!d) {
            if (in->count >= KC_MAX_DEVICES) {
                kc_emit_once(in->c, KC_GAP, "input.device_limit", "/sys/class/input",
                             "128-pointer-device cap reached.");
                break;
            }
            index = in->count++;
            d = &in->devices[index];
            memset(d, 0, sizeof(*d));
            d->fd = -1;
            d->enabled = d->tapping = d->disable_typing = -1;
        }
        bool fresh = !d->used;
        d->used = true;
        snprintf(d->sysname, sizeof(d->sysname), "event%llu", (unsigned long long)number);
        snprintf(d->physical, sizeof(d->physical), "%s", physical);
        snprintf(d->node, sizeof(d->node), "/dev/input/%s", e->d_name);
        kc_path(path, base, "name");
        char *name = kc_read_text(path, sizeof(d->name) - 1, NULL);
        if (name) {
            size_t n = strlen(name);
            if (n && name[n - 1] == '\n')
                name[n - 1] = 0;
            snprintf(d->name, sizeof(d->name), "%s", name);
            free(name);
        }
        d->virtual_device = strstr(physical, "/devices/virtual/") != NULL;
        struct udev_device *ud =
            udev_device_new_from_subsystem_sysname(in->udev, "input", e->d_name);
        if (ud) {
            d->touchpad = udev_device_get_property_value(ud, "ID_INPUT_TOUCHPAD") != NULL;
            d->touchscreen = udev_device_get_property_value(ud, "ID_INPUT_TOUCHSCREEN") != NULL;
            for (struct udev_device *p = ud; p; p = udev_device_get_parent(p)) {
                const char *driver = udev_device_get_driver(p);
                if (driver) {
                    snprintf(d->driver, sizeof(d->driver), "%s", driver);
                    break;
                }
            }
            udev_device_unref(ud);
        }
        if (fresh) {
            kc_emit(in->c, d->virtual_device ? KC_REVIEW : KC_INFO, "input.device", d->sysname,
                    "name=%s node=%s sysfs=%s driver=%s touchpad=%d touchscreen=%d "
                    "virtual_path=%d. Multiple nodes may belong to one physical device. A virtual "
                    "path can be legitimate.",
                    d->name, d->node, d->physical, d->driver, d->touchpad, d->touchscreen,
                    d->virtual_device);
        }
        if (d->fd >= 0)
            continue;
        d->fd = open(d->node, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
        if (d->fd < 0) {
            kc_emit_once(in->c, KC_GAP, "input.node_unavailable", d->node,
                         "%s; this device is inventoried but not observed.", strerror(errno));
            continue;
        }
        int clockid = CLOCK_MONOTONIC;
        d->clock_monotonic = ioctl(d->fd, EVIOCSCLOCKID, &clockid) == 0;
        struct input_absinfo x, y;
        if (ioctl(d->fd, EVIOCGABS(ABS_MT_POSITION_X), &x) == 0 &&
            ioctl(d->fd, EVIOCGABS(ABS_MT_POSITION_Y), &y) == 0) {
            d->width = (double)x.maximum - x.minimum;
            d->height = (double)y.maximum - y.minimum;
        }
        struct epoll_event event = {.events = EPOLLIN | EPOLLERR | EPOLLHUP, .data.u32 = index + 1};
        if (epoll_ctl(in->epoll_fd, EPOLL_CTL_ADD, d->fd, &event) < 0) {
            kc_emit(in->c, KC_GAP, "input.epoll_failed", d->node, "%s", strerror(errno));
            close(d->fd);
            d->fd = -1;
            continue;
        }
        if (in->li) {
            struct libinput_device *ld = libinput_path_add_device(in->li, d->node);
            if (ld)
                d->li_device = libinput_device_ref(ld);
            else
                kc_emit_once(in->c, KC_GAP, "input.libinput_device_unavailable", d->sysname,
                             "Raw observation available; libinput could not add this device.");
        }
        query_device(in, d);
        kc_emit(in->c, KC_INFO, "input.observation_started", d->sysname,
                "Read-only raw evdev observation active. monotonic_timestamps=%d; keyboard key "
                "codes are not recorded.",
                d->clock_monotonic);
    }
    closedir(dir);
}
static void frame_points(struct kc_input *in, struct input_device *d, uint64_t at) {
    if (d->width <= 0 || d->height <= 0)
        return;
    for (unsigned i = 0; i < 32; ++i) {
        struct point *p = &d->slots[i];
        if (!p->dirty)
            continue;
        if (p->old_valid && p->x_valid && p->y_valid && at > p->time && at - p->time <= 40000) {
            double dx = ((double)p->x - p->old_x) / d->width,
                   dy = ((double)p->y - p->old_y) / d->height;
            if (dx * dx + dy * dy > 0.16) {
                char subject[256];
                snprintf(subject, sizeof(subject), "%s slot=%u", d->sysname, i);
                kc_emit_once(
                    in->c, KC_REVIEW, "input.coordinate_discontinuity", subject,
                    "A tracked touch moved more than 40%% of normalized pad diagonal scale within "
                    "%llu microseconds. Review firmware/driver, contact tracking and "
                    "electrical/hardware causes; this is a heuristic, not malware proof.",
                    (unsigned long long)(at - p->time));
            }
        }
        if (p->x_valid && p->y_valid) {
            p->old_x = p->x;
            p->old_y = p->y;
            p->old_valid = true;
            p->time = at;
        }
        p->dirty = false;
    }
}
static void raw_events(struct kc_input *in, struct input_device *d) {
    struct input_event events[128];
    for (unsigned batch = 0; batch < 64; ++batch) {
        ssize_t n = read(d->fd, events, sizeof(events));
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0 && errno == EAGAIN)
            return;
        if (n <= 0) {
            kc_emit(in->c, KC_GAP, "input.device_read_stopped", d->sysname, "%s",
                    n == 0 ? "device closed" : strerror(errno));
            remove_device(in, d);
            return;
        }
        if ((size_t)n % sizeof(*events)) {
            kc_emit(in->c, KC_GAP, "input.partial_record", d->sysname,
                    "Non-integral input_event record batch; data discarded.");
            return;
        }
        for (size_t i = 0; i < (size_t)n / sizeof(*events); ++i) {
            struct input_event *e = &events[i];
            uint64_t at = (uint64_t)e->input_event_sec * 1000000 + (uint64_t)e->input_event_usec;
            enum kc_button_result result = kc_button_step(&d->left, e->type, e->code, e->value, at);
            if (result == KC_BUTTON_GAP) {
                ++d->drops;
                memset(d->slots, 0, sizeof(d->slots));
                kc_emit(in->c, KC_GAP, "input.syn_dropped", d->sysname,
                        "Kernel input queue overflowed; events are missing. Ignore the gap until "
                        "SYN_REPORT, then resynchronize state.");
            }
            if (result == KC_BUTTON_RESYNC) {
                unsigned long
                    bits[(KEY_MAX + 8 * sizeof(unsigned long)) / (8 * sizeof(unsigned long))];
                memset(bits, 0, sizeof(bits));
                if (ioctl(d->fd, EVIOCGKEY(sizeof(bits)), bits) >= 0) {
                    d->left.down = !!(bits[BTN_LEFT / (8 * sizeof(unsigned long))] &
                                      (1UL << (BTN_LEFT % (8 * sizeof(unsigned long)))));
                    d->left.known = true;
                }
            }
            if (d->left.desynchronized)
                continue;
            if (result == KC_BUTTON_PRESS || result == KC_BUTTON_RELEASE) {
                kc_emit(in->c,
                        in->c->cfg.hands_off && result == KC_BUTTON_PRESS ? KC_REVIEW : KC_INFO,
                        "input.raw_left_button", d->sysname,
                        "state=%s kernel_time_us=%llu name=%s KWin_enabled=%d "
                        "hands_off_assumed=%d; source is this evdev endpoint. Correlate with "
                        "visible unwanted clicks; desktop acceptance is not measured.",
                        result == KC_BUTTON_PRESS ? "pressed" : "released", (unsigned long long)at,
                        d->name, d->enabled, in->c->cfg.hands_off);
                if (d->left.interval_n >= 20 && d->left.mean_interval_us > 0 &&
                    d->left.mean_interval_us < 200000) {
                    double variance = d->left.interval_m2 / (double)(d->left.interval_n - 1),
                           cv = sqrt(variance) / d->left.mean_interval_us;
                    if (cv < 0.02)
                        kc_emit_once(
                            in->c, in->c->cfg.hands_off ? KC_REVIEW : KC_INFO,
                            "input.regular_click_train", d->sysname,
                            "At least 20 inter-press intervals, mean_ms=%.3f "
                            "coefficient_of_variation=%.6f. Regularity is not sufficient to "
                            "distinguish automation, hardware, replay, or intentional input.",
                            d->left.mean_interval_us / 1000, cv);
                }
            } else if (result == KC_BUTTON_REPEAT)
                kc_emit_once(
                    in->c, KC_REVIEW, "input.repeated_button_state", d->sysname,
                    "Repeated/invalid left-button transition observed; startup and dropped-event "
                    "gaps are handled separately. Review input source; not a malware signature.");
            if (e->type == EV_KEY && (e->code == BTN_TOUCH || e->code == BTN_TOOL_FINGER)) {
                ++d->contacts;
                if (e->value)
                    kc_emit_once(in->c, in->c->cfg.hands_off ? KC_REVIEW : KC_INFO,
                                 "input.touch_contact", d->sysname,
                                 "Touch contact while hands_off_assumed=%d KWin_enabled=%d. Raw "
                                 "contact does not itself establish a desktop click.",
                                 in->c->cfg.hands_off, d->enabled);
            }
            if (e->type == EV_REL || e->type == EV_ABS)
                ++d->motions;
            if (e->type == EV_ABS) {
                if (e->code == ABS_MT_SLOT) {
                    d->slot = e->value >= 0 && e->value < 32 ? e->value : -1;
                } else if (d->slot >= 0) {
                    struct point *p = &d->slots[d->slot];
                    if (e->code == ABS_MT_TRACKING_ID) {
                        memset(p, 0, sizeof(*p));
                    } else if (e->code == ABS_MT_POSITION_X) {
                        p->x = e->value;
                        p->x_valid = true;
                        p->dirty = true;
                    } else if (e->code == ABS_MT_POSITION_Y) {
                        p->y = e->value;
                        p->y_valid = true;
                        p->dirty = true;
                    }
                }
            }
            if (e->type == EV_SYN && e->code == SYN_REPORT) {
                ++d->frames;
                frame_points(in, d, at);
            }
        }
    }
    kc_emit_once(in->c, KC_GAP, "input.read_budget", d->sysname,
                 "Per-tick input read budget reached; observation may lag during an event flood.");
}
static void interpreted(struct kc_input *in) {
    if (!in->li)
        return;
    if (libinput_dispatch(in->li) < 0) {
        kc_emit_once(in->c, KC_GAP, "input.libinput_dispatch", "libinput", "Dispatch failed.");
        return;
    }
    struct libinput_event *e;
    while ((e = libinput_get_event(in->li))) {
        enum libinput_event_type type = libinput_event_get_type(e);
        struct libinput_device *device = libinput_event_get_device(e);
        const char *sysname = libinput_device_get_sysname(device);
        struct input_device *d = NULL;
        for (unsigned i = 0; i < in->count; ++i)
            if (!strcmp(in->devices[i].sysname, sysname)) {
                d = &in->devices[i];
                break;
            }
        if (type == LIBINPUT_EVENT_POINTER_BUTTON) {
            struct libinput_event_pointer *p = libinput_event_get_pointer_event(e);
            if (libinput_event_pointer_get_button(p) == BTN_LEFT) {
                bool down =
                    libinput_event_pointer_get_button_state(p) == LIBINPUT_BUTTON_STATE_PRESSED;
                if (d && down)
                    ++d->interpreted_clicks;
                kc_emit(in->c, in->c->cfg.hands_off && down ? KC_REVIEW : KC_INFO,
                        "input.interpreted_left_button", sysname,
                        "state=%s time_us=%llu KWin_enabled=%d. This is KaalClam's independent "
                        "libinput interpretation, not proof of delivery to the desktop. Tap "
                        "setting follows queried KWin state where available.",
                        down ? "pressed" : "released",
                        (unsigned long long)libinput_event_pointer_get_time_usec(p),
                        d ? d->enabled : -1);
            }
        } else if (type == LIBINPUT_EVENT_GESTURE_SWIPE_BEGIN ||
                   type == LIBINPUT_EVENT_GESTURE_PINCH_BEGIN ||
                   type == LIBINPUT_EVENT_GESTURE_HOLD_BEGIN) {
            struct libinput_event_gesture *g = libinput_event_get_gesture_event(e);
            kc_emit(in->c, in->c->cfg.hands_off ? KC_REVIEW : KC_INFO, "input.gesture", sysname,
                    "independent_context_type=%d fingers=%d hands_off_assumed=%d; separate gesture "
                    "readers may react even when compositor input is disabled.",
                    type, libinput_event_gesture_get_finger_count(g), in->c->cfg.hands_off);
        }
        libinput_event_destroy(e);
    }
}
struct kc_input *kc_input_open(struct kc_context *c) {
    struct kc_input *in = calloc(1, sizeof(*in));
    if (!in)
        return NULL;
    in->c = c;
    in->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    in->udev = udev_new();
    if (in->epoll_fd < 0 || !in->udev) {
        kc_emit(c, KC_GAP, "input.initialization", "input", "%s", strerror(errno));
        kc_input_close(in);
        return NULL;
    }
    in->li = libinput_path_create_context(&li_interface, in);
    if (in->li) {
        libinput_log_set_handler(in->li, li_log);
        libinput_log_set_priority(in->li, LIBINPUT_LOG_PRIORITY_ERROR);
        struct epoll_event event = {.events = EPOLLIN, .data.u32 = UINT32_C(0x10000)};
        if (epoll_ctl(in->epoll_fd, EPOLL_CTL_ADD, libinput_get_fd(in->li), &event) < 0) {
            kc_emit(c, KC_GAP, "input.libinput_epoll", "libinput", "%s", strerror(errno));
            in->li = libinput_unref(in->li);
        }
    } else
        kc_emit(c, KC_GAP, "input.libinput_unavailable", "libinput",
                "Independent tap/gesture interpretation unavailable.");
    bus_open(in);
    discover(in);
    in->next_discovery = kc_mono_ms() + 5000;
    in->next_bus = kc_mono_ms() + 10000;
    if (!in->count)
        kc_emit(c, KC_GAP, "input.no_pointer_devices", "/sys/class/input",
                "No pointer/touch candidates visible; this is not evidence of no input sources.");
    return in;
}
void kc_input_tick(struct kc_input *in, int wait_ms) {
    if (!in)
        return;
    struct epoll_event events[32];
    int n = epoll_wait(in->epoll_fd, events, 32, wait_ms);
    if (n < 0 && errno != EINTR) {
        kc_emit_once(in->c, KC_GAP, "input.epoll_wait", "input", "%s", strerror(errno));
        return;
    }
    for (int i = 0; i < n; ++i) {
        unsigned index = events[i].data.u32;
        if (index == UINT32_C(0x10000)) {
            interpreted(in);
            continue;
        }
        if (index && index <= in->count) {
            struct input_device *d = &in->devices[index - 1];
            if (d->fd >= 0)
                raw_events(in, d);
        }
    }
    uint64_t now = kc_mono_ms();
    if (now >= in->next_discovery) {
        discover(in);
        in->next_discovery = now + 5000;
    }
    if (now >= in->next_bus) {
        for (unsigned i = 0; i < in->count; ++i)
            query_device(in, &in->devices[i]);
        in->next_bus = now + 10000;
    }
    for (unsigned i = 0; i < in->count; ++i) {
        struct input_device *d = &in->devices[i];
        if (d->motions && now - d->last_motion_report >= 10000) {
            kc_emit(in->c, KC_INFO, "input.motion_summary", d->sysname,
                    "cumulative_motion_axis_events=%llu frames=%llu KWin_enabled=%d",
                    (unsigned long long)d->motions, (unsigned long long)d->frames, d->enabled);
            d->last_motion_report = now;
        }
    }
    interpreted(in);
}
void kc_input_close(struct kc_input *in) {
    if (!in)
        return;
    for (unsigned i = 0; i < in->count; ++i)
        remove_device(in, &in->devices[i]);
    if (in->li)
        libinput_unref(in->li);
    if (in->udev)
        udev_unref(in->udev);
    sd_bus_unref(in->bus);
    if (in->epoll_fd >= 0)
        close(in->epoll_fd);
    free(in);
}
