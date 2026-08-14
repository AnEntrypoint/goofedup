# goofedup

Cross-platform structural-anomaly watcher: catches malware by **shape**, not signature.

Born from a real incident: a legitimate app's small bootstrap file (should be ~40 bytes) was silently overwritten with a 270KB obfuscated payload, the original preserved next to it as a `.orig` backup, and it launched an obfuscated `node -e "..."` process talking to a hardcoded C2 IP. No signature database had any of this — every one of those facts is a **structural** anomaly a host can detect on its own, without ever having seen this exact malware before.

## What it watches

All watchers run concurrently, are **alert-only** (nothing is ever killed, deleted, or blocked automatically — every actionable alert prints the exact command to run yourself), and work identically on Windows, macOS, and Linux:

- **Bootstrap tampering** — a known-tiny entry-point file suddenly huge, plus a fully generic detector (no app name required) for *any* small script file that balloons 10x+ past its own baseline size.
- **Backup-sibling files** — a `.orig`/`.bak`/`.inz`/`.old` file appearing next to a real one, the tell an infector leaves behind to preserve the original.
- **Obfuscated process command lines** — scored on Shannon entropy, embedded IP/URL literals, long encoded-blob runs, and symbol density. Not a signature list: proven to catch unrelated shapes (Node/XOR C2, Python/base64 reverse shells, PowerShell `-EncodedCommand`) while never flagging an ordinary long command line.
- **Denied / unusual / masquerading process paths** — instant flag for anything executing from a Recycle Bin/Trash path, a softer flag for anything outside a known-good allowlist, and detection of 25+ commonly-impersonated system process names (`svchost.exe`, `launchd`, `systemd`, etc.) running from the wrong location.
- **Weird process names** — zero-width characters, RTL-override tricks, and Cyrillic/Greek homoglyph lookalikes used to visually disguise a process in a listing.
- **New persistence registrations** — services, scheduled tasks / launchd / systemd / cron, and login items, diffed against a baseline so only genuinely *new* entries alert.
- **Mass file-read bursts** — a process reading an unusual amount of file data in one poll interval, either an absolute burst or a spike versus its own recent average. The tell-tale shape of drive scanning/harvesting.
- **Network scanning** — a process opening connections to an unusual number of distinct ports or hosts in a short window.
- **Firewall silently going dark** — a common malware self-defense move.

## Known false-positive classes (read this before you panic)

This tool is alert-only for exactly this reason: structural detection catches real novel threats, but the same shapes sometimes appear in legitimate tooling. Two worth knowing about specifically:

- **`-EncodedCommand`/`-enc` PowerShell invocations from automation tooling.** Many legitimate remote-management, CI, and AI-assistant harnesses (including the one used to build this very tool) pass complex scripts to PowerShell as base64 to sidestep shell-escaping — the exact same shape a real attacker's living-off-the-land technique uses. If you see this and don't recognize the parent process/tool as something you run, investigate; if it's your own automation, it's expected noise.
- **A legitimate backup/indexer/AV scanner reading a large volume of files quickly.** The file-read-burst detector will flag it — that's correct, since the *shape* really is indistinguishable from harvesting without more context. Recognize your own backup software by name/path and move on.

Neither of these is a bug — a tool that silently special-cased "trust anything named like known automation" would have missed the real incident it was built to catch, since the real payload was ALSO disguised as trusted automation. The alert-only design means the cost of a false positive is a few seconds of your attention, never an unwanted action.

## Install

Download the binary for your platform from the [latest release](https://github.com/AnEntrypoint/goofedup/releases/latest). No install, no dependencies — a single static binary.

## Run

```sh
./goofedup
```

Ctrl+C to stop. Logs to `~/.goofedup/goofedup.log` (and stdout).

```sh
./goofedup --show-config   # print the resolved watch list and thresholds, then exit
```

## Build from source

```sh
cargo build --release
```

## Test

Every test is a **live witness** against real files, real spawned processes, and the real `notify`/`sysinfo`-driven watch loops — no mocks, no fixtures standing in for the real thing.

```sh
cargo test
```
