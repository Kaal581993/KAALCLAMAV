# KaalClam is implemented entirely in C. Dependencies are system libraries.
CC ?= cc
PKG_CONFIG ?= pkg-config
PACKAGES = libsystemd libinput libudev libclamav openssl
CPPFLAGS += -D_GNU_SOURCE -D_FORTIFY_SOURCE=3 -Iinclude $(shell $(PKG_CONFIG) --cflags $(PACKAGES))
CFLAGS ?= -O2 -g
CFLAGS += -std=c17 -Wall -Wextra -Wpedantic -Wformat=2 -Wshadow -Wstrict-prototypes -fstack-protector-strong -fstack-clash-protection -fPIE
LDFLAGS += -pie -Wl,-z,relro,-z,now
LDLIBS += $(shell $(PKG_CONFIG) --libs $(PACKAGES)) -lm
SOURCES = src/main.c src/util.c src/algorithms.c src/input.c src/audit.c src/journal.c src/integrity.c src/antivirus.c
LIB_SOURCES = $(filter-out src/main.c,$(SOURCES))
OBJECTS = $(SOURCES:src/%.c=build/%.o)

.PHONY: all check sanitize clean install package-check dist
all: KaalClam

KaalClam: $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

build/%.o: src/%.c include/kaalclam.h | build
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@

build:
	mkdir -p build

build/test_kaalclam: tests/test_kaalclam.c $(LIB_SOURCES) include/kaalclam.h | build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ tests/test_kaalclam.c $(LIB_SOURCES) $(LDLIBS)

check: KaalClam build/test_kaalclam
	./build/test_kaalclam
	./KaalClam --help >/dev/null
	./KaalClam --self-test

ASAN_RUN_OPTIONS ?= detect_leaks=1:halt_on_error=1
sanitize: | build
	$(CC) $(CPPFLAGS) -std=c17 -O1 -g -Wall -Wextra -Wpedantic -fsanitize=address,undefined -fno-omit-frame-pointer -o build/test_sanitize tests/test_kaalclam.c $(LIB_SOURCES) $(LDLIBS)
	ASAN_OPTIONS=$(ASAN_RUN_OPTIONS) UBSAN_OPTIONS=halt_on_error=1 ./build/test_sanitize

# Optional Arch Linux helper; these extra libraries are not needed by KaalClam.
package-check: build/kaalclam-package-check

build/kaalclam-package-check: tools/package-check.c src/integrity.c src/util.c src/algorithms.c include/kaalclam.h | build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(shell $(PKG_CONFIG) --cflags libalpm libarchive) $(LDFLAGS) -o $@ tools/package-check.c src/integrity.c src/util.c src/algorithms.c $(LDLIBS) $(shell $(PKG_CONFIG) --libs libalpm libarchive)

dist: | build
	tar -czf build/KaalClam-0.1.1-source.tar.gz --transform='s,^,KaalClam-0.1.1/,' Makefile README.md LICENSE.md COPYING .clang-format .gitignore src include tests tools

# Optional installation; not performed by the default build.
PREFIX ?= /usr/local
install: KaalClam
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 KaalClam $(DESTDIR)$(PREFIX)/bin/KaalClam

clean:
	rm -rf build KaalClam

-include $(OBJECTS:.o=.d)
