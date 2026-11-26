# Findings — 1 November 2026

No backdoor has been confirmed. The automatic clicks remain unexplained. This
restricted investigation cannot establish that the host is free of malware.

| Check | Result and meaning |
| --- | --- |
| Signature scan | 212 files / 706,681,768 input bytes scanned using 3,628,233 loaded signatures; zero signature matches. Selected paths, not the whole disk. |
| Scan coverage | Four engine-limit findings, two oversized executable objects skipped, and other inaccessible/transient paths. Overall exit 2; 30 unavailable/limited findings. Limits are not malware detections. |
| Automatic refresh | FreshClam attempted; exit 11 after DNS lookup failures for the official server. The installed daily database, version 28167, was about four days old. Signatures were not refreshed. |
| Package hashes | Ten selected input, desktop, network, and remote-access program/library files matched SHA256 records in the local pacman database. This does not authenticate that database or prove safe behavior. |
| Gesture utility | `libinput-gestures` is configured to autostart separately from KWin and run desktop/browser shortcuts. Its configuration contains no left-click command. It does not explain all reported clicks. |
| Historical logs | Four records report discarded touchpad jumps from KWin and `libinput-gestures`. These show earlier faults, not the cause of every symptom, particularly with the touchpad disabled. |
| Startup entries | KDE Connect has an autostart entry. Custom Kaal services reference local model-router/Ollama tools, including a loopback Ollama address. These are not evidence of an unauthorized remote session; runtime state is unavailable here. |
| USB/display | PNY `154b:6000` exposes a storage interface, with no USB keyboard/mouse interface shown for it. Its partitions are unmounted, so the reported Linux ISOs were not scanned. The user reports an HDMI TV without internet and no external mouse; no collected evidence ties it to the clicks. |

The ten hash comparisons covered `libinput-gestures`, `xdotool`, `kdeconnectd`,
`kwin_wayland`, `ssh`, `sshd`, `NetworkManager`, and the resolved libinput,
libsystemd, and libc libraries. Metadata checks reported only UID/GID differences:
this user namespace maps host system owners to `nobody`. These warnings cannot
be interpreted here as tampering evidence.

This environment exposes its own small process/network namespace. Netlink,
KWin D-Bus, and BPF inspection were restricted; `/dev/input` was unavailable.
Zero observed host connections/events here therefore cannot rule out activity.
Collect the missing runtime evidence in a normal host terminal:

```sh
sudo /home/kaal/KaalClam/KaalClam --watch --live --interval 5
```

Press **Ctrl+C** to close it. It prints the report path. Socket lines show
observable ownership, not automatic RAT identifications. Polling can miss brief
connections. If symptoms return, record their time and actual KWin disabled
state for correlation; do not presume the old jump warnings explain everything.

Evidence: `reports/full-run-20261101.jsonl`,
`reports/resumed-evidence-20261101.jsonl`,
`reports/package-hashes-20261101.txt`, and
`reports/package-metadata-20261101.txt`.

Validation: 60,749 C checks and native engine self-tests passed. ASan/UBSan passed
with leak detection disabled because of sandbox restrictions. Final Clang
analysis produced no findings for the main program or optional helper. An
unsafe-state regression preserved a hard-linked config's target and prevented
the updater from starting. Helper positive, missing/unowned-file, and sanitizer
checks passed. Logs are in `reports/` with the corresponding names.

Full C source is under `/home/kaal/KaalClam`. No background service, timer,
firewall change, quarantine, removal of suspected files, or kernel module was
installed. Private signature state was created at
`/home/kaal/.local/share/kaalclam`.
