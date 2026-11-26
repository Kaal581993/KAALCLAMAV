# KaalClam

KaalClam is a Linux diagnostic program written in C. It collects evidence about
unexpected pointer activity, accessible processes and sockets, startup entries,
kernel module inventories, journal messages, and ClamAV signature matches. It
does not determine that a remote access trojan is present just because the cursor
misbehaves. The local `FINDINGS.md` records this machine's investigation and is
kept out of the portable source archive.

## Build and check

Requires a C17 compiler, Make, pkg-config, and development files for libsystemd,
libinput, libudev, libclamav, and OpenSSL. Automatic updates use
`/usr/bin/freshclam`. This build was checked with ClamAV 1.5.4, libinput 1.32.0,
libsystemd 262, and OpenSSL 3.6.5.

```sh
cd /home/kaal/KaalClam
make
make check
make sanitize ASAN_RUN_OPTIONS=detect_leaks=0:halt_on_error=1
```

The sanitizer command disables LeakSanitizer because this development sandbox
blocks its process inspection. AddressSanitizer and UndefinedBehaviorSanitizer
remain enabled. On an unrestricted host, `make sanitize` also enables leak checks.
The native signature self-test uses a temporary inert marker and a temporary test
database; production scans use official databases.

## Open and close the monitor

Run in a normal host terminal to observe the host, rather than this development
sandbox's separate process/network namespace:

```sh
cd /home/kaal/KaalClam
sudo ./KaalClam --watch --live --interval 5
```

Press **Ctrl+C** in that terminal to close it. There is no installed background
service to stop. `--live` prints new socket ownership observations, indicator
findings, signature alerts, and unavailable checks as they are reported.
All records also go to the new private JSONL report whose path is printed at
startup. A socket line identifies the accessible owning process, executable,
protocol, endpoints, and state; it is not a backdoor verdict.

Polling is a snapshot: connections that start and finish between polls can be
missed. The monitor does not capture traffic, show every socket closure, identify
every remote-control session, or prove that no hidden program exists. Root may
improve access but does not turn live kernel information into independent proof.
Starting the monitor does not disconnect or reconnect networking.

For a finite run with automatic updates and scanning:

```sh
./KaalClam --duration 60 --live
```

For a hardware/process snapshot without signature scanning:

```sh
./KaalClam --duration 0 --no-signatures --live
```

Add `--hands-off` only when nobody will touch the keyboard, touchpad, or other
input during the observation window. Otherwise ordinary activity could be
reported as unexpected. `--duration 0` still waits for an enabled signature scan
to finish; it only disables the input observation window.

## Scope and interpretation

- Input: inventories pointer/touch endpoints, reads accessible evdev events,
  queries KWin properties without setting them, and runs an independent libinput
  context. Keyboard keystrokes are not logged. Independent libinput events and
  raw events do not prove that KWin delivered a click to an application.
- Processes: inspects accessible executable paths, map metadata, descriptors,
  input write handles, and TCP/UDP socket ownership. Process arguments are matched
  in memory but not saved in the report. Memory contents are not dumped.
- Startup: examines selected system and current-user startup locations. Names
  associated with remote access or injection are leads, not proof. Startup
  symlinks are inventoried; text inspection does not follow their contents.
- Kernel: compares module views from procfs and sysfs and attempts BPF program
  inventory. Kernel taints, proprietary drivers, and cross-view differences
  require context. No kernel module is loaded by KaalClam.
- Journal: searches the accessible lookback, default 24 hours. Old touchpad-jump
  warnings are historical evidence and cannot explain every current symptom.
- Signatures: scans selected current-user startup files and local executables,
  `/usr/local/bin`, `/usr/local/sbin`, selected system startup locations,
  `/dev/shm`, `/tmp`, and accessible live executable file objects. This is not a
  whole-disk scan. Repeat `--scan PATH` to replace these defaults; use
  `--scan-processes` as well to retain live executable scanning.

Directory symlinks, special files, virtual filesystem trees other than
`/dev/shm`, the report itself, and signature state are excluded from signature
traversal. Regular-file symlinks may be resolved and scanned. Directory opens
reject a symlink at the last component, but moving trees and intermediate path
changes still make this a live, non-atomic snapshot. Unreadable paths and limits
are coverage gaps. An explicitly requested missing path is reported as a gap.

Defaults: 5,000 files, 256 MiB per input file, 1 GiB total input bytes, 32 levels
of directory recursion, a separate traversal budget, and a 64 MiB report limit.
The ClamAV per-file time budget defaults to 20 seconds; it is an engine budget,
not a hard deadline for every filesystem operation or database compilation.
The scanner runs in a separate low-priority process while input observation
continues. Signature-limit alerts are counted as gaps, not malware matches.

Linux distribution ISO images on an unmounted USB drive are not accessible to a
path scan. Once a filesystem is mounted and readable, explicitly select its
mount directory with `--scan`. Large ISOs may exceed file/byte limits, and a
signature scan does not authenticate a distribution image. Verify an ISO against
the distributor's trusted checksums and signatures when needed. KaalClam does
not mount drives or execute their contents.

## Signature updates

Automatic updates are enabled for signature runs. State lives at
`~/.local/share/kaalclam`, or `/var/lib/kaalclam` for a host root run. An existing
directory without the KaalClam marker is refused. Root mode requires a non-root
`clamav` account and safe root-owned parent directories. A new signature
directory may be seeded from installed official databases to avoid unnecessary
full downloads.

KaalClam generates its own FreshClam configuration using the official ClamAV
mirror, without execute callbacks. FreshClam runs with a minimal environment and
without privilege escalation; root mode drops it to the `clamav` account. The
configuration does not inherit proxy environment variables. The default updater
timeout is 120 seconds. A lock prevents concurrent refreshes. Successful
refreshes are throttled for the update interval (default four hours), failures
for 15 minutes, and FreshClam may also enforce its own CDN cooldown.

```sh
./KaalClam --update-only --live
./KaalClam --duration 0 --no-update --live
```

`--update-only` bypasses KaalClam's attempt backoff, but not FreshClam's CDN
policy. `--no-update` uses available databases without refreshing. If refresh
fails, available official databases may still be scanned and the failure is
reported; they are not represented as current. The FreshClam log is in the
state directory. Daily-database age beyond 48 hours, or a future date beyond the
clock tolerance, is a coverage gap.

## Optional SHA256 baselines

```sh
./KaalClam --baseline-create /home/kaal/example.baseline --scan /some/directory
./KaalClam --baseline-check /home/kaal/example.baseline
```

Creation refuses to overwrite an existing file. Baselines encode path bytes so
newlines cannot create extra entries, exclude their own manifest and report,
and include a v2 completion record. Incomplete/legacy manifests cannot establish
complete coverage. Both creation and checking enforce file/byte limits. Manifest
reading rejects FIFOs/symlinks and is limited to 64 MiB. The baseline must remain
outside the changing files you intend to compare.

This captures the current files, not known-good files. A check compares the
listed paths and does not detect newly added paths. Keep a trusted offline copy
for stronger assurance. A package being listed as an owner does not authenticate
its bytes.

## Optional Arch package hash comparison

This separate C helper compares selected file contents with SHA256 values from
the local pacman database. It needs the extra development libraries libalpm and
libarchive; the main KaalClam build does not require them.

```sh
make package-check
./build/kaalclam-package-check /usr/bin/kwin_wayland /usr/bin/kdeconnectd /usr/bin/xdotool
```

It prints `MATCH`, `DIFFERENT`, or `UNVERIFIED`, with a package and file path.
Limits are 128 paths, 256 MiB per file, and 1 GiB total. It reports files that
change while hashing as unavailable and does not modify files/package metadata.
There is no automatic verification of every installed package.

`MATCH` means agreement with this local reference. `DIFFERENT` can result from an
edit, update, or tampering. `UNVERIFIED` includes third-party tools without
package ownership and missing metadata. A compromised database or kernel can
defeat this comparison. Exit codes: 0=all matched, 2=unverified/error,
3=different contents. Matching a record does not prove safe behavior.

## Exit codes and artifacts

| Code | Meaning |
| --- | --- |
| 0 | Completed within requested scope without findings/gaps |
| 1 | Signature alert requiring investigation |
| 2 | Unavailable coverage, a limit, interruption, or another error |
| 3 | Review findings, including baseline changes and heuristic/PUA findings |

Signature alerts take precedence over other findings; otherwise coverage gaps
take precedence over review findings. A report sync failure returns 2. A stopped
watch run may return 2 because observation was interrupted. Nothing is deleted,
quarantined, disabled, installed as a service, or automatically removed in
response to findings. Signature state, fresh update logs, reports, and requested
baselines are the program's intended writes.

Source: `src/`, `include/`, and `tests/`. Build output: `build/` and `KaalClam`.
Reports can contain sensitive paths, process names, endpoints, and historical
journal text; share selected findings rather than an entire report. Reports
start with private permissions and never overwrite existing files.

`make dist` creates `build/KaalClam-0.1.1-source.tar.gz` with source, tests,
build instructions, and licensing, excluding private reports/signature state.

## License and upstream references

See [LICENSE.md](LICENSE.md) and [COPYING](COPYING). System libraries and the
signature databases keep their respective terms.

- [ClamAV signature updates](https://docs.clamav.net/manual/Usage/SignatureManagement.html)
- [ClamAV scan API and verdicts](https://github.com/Cisco-Talos/clamav/blob/main/libclamav/clamav.h)
- [libinput send-events configuration](https://wayland.freedesktop.org/libinput/doc/latest/api/group__config.html)
- [Linux virtual input devices](https://docs.kernel.org/input/uinput.html)

These describe capabilities and interfaces, not evidence that this machine has
malware. A compromised kernel can falsify procfs, sysfs, device events, and logs;
trusted offline comparison is required for stronger integrity evidence.
