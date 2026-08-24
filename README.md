# goofedup

![you done goofed](https://media.giphy.com/media/XyIBLhXPveD8k/giphy.gif)

Cross-platform structural-anomaly watcher: catches malware by **shape**, not signature.

We done goofed. Somebody's Discord bootstrap file — a 40-byte one-liner that should read `module.exports = require('./core.asar')` and nothing else — quietly ballooned into a 270KB wall of obfuscated garbage, kept the original as a polite `.orig` backup like it was doing us a favor, and then popped an obfuscated `node -e "..."` shell that phoned home to a C2 IP like it had somewhere to be. Meanwhile the Recycle Bin was moonlighting as a warehouse for 21,000 mystery Go and JS files with names like a cat walked across a keyboard.

Nobody signed anything. No antivirus signature file had ever heard of this exact flavor of nonsense. It just... looked wrong, the way a stranger wearing your coworker's badge looks wrong. So `goofedup` was born to notice *wrong shapes*, not memorized fingerprints — because next time we'd rather not have to goof up before we wisen up.

## What it watches

All watchers run concurrently, are **alert-only** (nothing is ever killed, deleted, or blocked automatically, and no remedy is prescribed — every alert is a report so you can judge for yourself whether it's suspicious), and work identically on Windows, macOS, and Linux:

- **Bootstrap tampering** — a known-tiny entry-point file suddenly huge, plus a fully generic detector (no app name required) for *any* small script file that balloons 10x+ past its own baseline size.
- **Backup-sibling files** — a `.orig`/`.bak`/`.inz`/`.old` file appearing next to a real one, the tell an infector leaves behind to preserve the original.
- **Obfuscated process command lines** — scored on Shannon entropy, embedded IP/URL literals, long encoded-blob runs, and symbol density. Not a signature list: proven to catch unrelated shapes (Node/XOR C2, Python/base64 reverse shells, PowerShell `-EncodedCommand`) while never flagging an ordinary long command line.
- **Denied / unusual / masquerading process paths** — instant flag for anything executing from a Recycle Bin/Trash path, a softer flag for anything outside a known-good allowlist, and detection of 25+ commonly-impersonated system process names (`svchost.exe`, `launchd`, `systemd`, etc.) running from the wrong location.
- **Weird process names** — zero-width characters, RTL-override tricks, and Cyrillic/Greek homoglyph lookalikes used to visually disguise a process in a listing.
- **New persistence registrations** — services, scheduled tasks / launchd / systemd / cron, and login items, diffed against a baseline so only genuinely *new* entries alert.
- **Mass file-read bursts** — a process reading an unusual amount of file data in one poll interval, either an absolute burst or a spike versus its own recent average. The tell-tale shape of drive scanning/harvesting.
- **Network scanning** — a process opening connections to an unusual number of distinct ports or hosts in a short window.
- **Firewall silently going dark** — a common malware self-defense move.
- **Alert-triggered content audit** — when any Warn/Critical alert names an app, its install tree is automatically scanned (including inside Electron `.asar` archives) for `\uXXXX`-hidden ASCII identifiers; alerts naming a high-value target (Discord, Adobe, Slack, Teams) widen the scan to that product's whole tree.

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

## Windows GUI (goofedup-gui.exe)

For everyday use on Windows, `goofedup-gui.exe` runs the same watchers with no
console window and a system-tray icon instead:

- **First launch** — a friendly welcome toast explains what's about to happen
  before any watcher fires an alert, so a new user is never left wondering if
  the app is actually doing anything.
- **Tray icon** — a shield glyph, cyan while quiet, gray while paused, red the
  moment an unacknowledged Critical alert lands.
- **Live tooltip** — hover the tray icon for an at-a-glance status ("watching,
  all clear", "3 warning(s) today", "PAUSED", or a call to attention when a
  Critical alert needs you) instead of a static string.
- **Double-click the tray icon** to jump straight to recent alerts — the
  same shortcut every other tray app uses, no menu required.
- **Toast notifications** — every Warn/Critical alert pops a native Windows
  toast; **click the toast itself** to open the alert history directly,
  instead of just dismissing it.
- **Right-click menu:**
  - *Open Recent Alerts* — opens a native alert history window: a scrollable
    feed of severity-colored cards (red for Critical, amber for Warn), each
    with a headline, timestamp, and click-to-expand evidence, and clears the
    red-icon flag. Repeated alerts sharing the same activity — the same
    process for file-read-burst, or the same obfuscation shape for
    c2-shaped-process — bundle into one card with a count badge instead of
    flooding the feed with duplicates. A group card has a **Mark safe**
    button: clicking it downgrades that exact group's visual prominence
    (never deletes it) without affecting any other process, category, or
    group — a different detection stays fully visible even if it happens to
    share a process name.
  - *Show Config* — opens the resolved watch list/thresholds as a sectioned
    list with bold group headers and a plain-language description of what
    each section means, grouped by category.
  - *Pause Alerts* — a checkable item that silences new alerts on demand
    (the tray icon goes gray, the tooltip says PAUSED) without killing the
    app or its watcher threads, for known maintenance windows.
  - *Start with Windows* — a checkable item toggling launch-at-login via the
    per-user registry Run key (no admin rights needed).
  - *Quit* — stops every watcher thread cleanly and exits.
- Launching a second copy while one is already running just exits — no
  duplicate watchers.

Download `goofedup-gui.exe` from the [latest release](https://github.com/AnEntrypoint/goofedup/releases/latest)
alongside the CLI binary, or build it yourself (see below).

## Build from source

```sh
cargo build --release                          # CLI binary (goofedup)
cargo build --release --features gui --bin goofedup-gui   # Windows tray GUI
```

## Verification

No standing test suite. Every change is verified by live-witnessing the real code path against real files, real spawned processes, and the real `notify`/`sysinfo`-driven watch loops -- no mocks, no fixtures standing in for the real thing.
