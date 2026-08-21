// Process watcher: cross-platform via `sysinfo` polling. A push-based native
// API (WMI process-creation events on Windows, kqueue EVFILT_PROC on macOS,
// netlink proc connector on Linux) would be lower-latency, but each is a
// separate per-OS implementation for a modest win over a short poll
// interval -- polling every few seconds via one cross-platform crate is the
// pragmatic tradeoff for a tool that has to build and run identically on
// three OSes from one codebase.

use crate::alert::AlertSink;
use crate::config::Config;
use crate::heuristics::{is_denied_exec_path, is_unlisted_exec_path, score_command_line, score_process_name};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use sysinfo::{Pid, System};

/// Per-process read-rate tracking state for the file-read-burst (mass
/// scanning / harvesting) detector below.
struct ReadTracker {
    last_total_read: u64,
    /// Running average of the per-poll read delta, EMA-smoothed so one
    /// legitimate burst (a real build, a real backup job starting) doesn't
    /// permanently poison the baseline as "normal" nor get immediately
    /// re-flagged as a fresh burst on the very next poll.
    avg_delta: f64,
    alerted_this_burst: bool,
    /// How many of the last WINDOW_SIZE polls (a fixed-size sliding window,
    /// not strict back-to-back consecutiveness) scored as a relative spike.
    /// A real drive-scanning/harvesting process sustains elevated reads
    /// across a short window; a legitimate app's burst (a page load, a
    /// cache write, an update check) is characteristically one-shot.
    /// Live-witnessed false positives (firefox.exe, Discord.exe) were both
    /// single-poll spikes; requiring persistence within a window eliminates
    /// that shape. A STRICT back-to-back-with-no-gap requirement was tried
    /// first and live-witnessed to fail: a real process whose own read
    /// rounds are separated by even one intervening near-zero-delta poll
    /// (a genuinely common shape -- disk I/O is bursty, not perfectly
    /// uniform, even for a real scanner) never accumulates past 1 under
    /// strict consecutiveness, since a single zero-delta poll resets the
    /// count to 0 and erases all prior progress. A sliding window tolerates
    /// that gap while still requiring genuine persistence, not one sample.
    relative_spike_window: [bool; Self::WINDOW_SIZE],
    /// Same windowed-persistence requirement as relative_spike_window, but
    /// for the absolute-burst path. Live-witnessed: this path originally
    /// had no baseline/persistence gating at all, so a legitimate dev tool
    /// loading a large plugin file on a single poll (agentplug-runner.exe
    /// reading hundreds of MB of WASM) alerted immediately every time,
    /// bypassing the relative path's persistence fix entirely.
    absolute_burst_window: [bool; Self::WINDOW_SIZE],
    window_pos: usize,
}

impl ReadTracker {
    const WINDOW_SIZE: usize = 4;
    const REQUIRED_SPIKES_IN_WINDOW: usize = 2;

    fn new(seed_total_read: u64) -> Self {
        Self {
            last_total_read: seed_total_read,
            avg_delta: 0.0,
            alerted_this_burst: false,
            relative_spike_window: [false; Self::WINDOW_SIZE],
            absolute_burst_window: [false; Self::WINDOW_SIZE],
            window_pos: 0,
        }
    }

    fn record_poll(&mut self, was_relative_spike: bool, was_absolute_burst: bool) {
        self.relative_spike_window[self.window_pos] = was_relative_spike;
        self.absolute_burst_window[self.window_pos] = was_absolute_burst;
        self.window_pos = (self.window_pos + 1) % Self::WINDOW_SIZE;
    }

    fn relative_spike_count_in_window(&self) -> usize {
        self.relative_spike_window.iter().filter(|&&x| x).count()
    }

    fn absolute_burst_count_in_window(&self) -> usize {
        self.absolute_burst_window.iter().filter(|&&x| x).count()
    }
}

pub fn run(cfg: Arc<Config>, alerts: Arc<AlertSink>, running: Arc<AtomicBool>) {
    alerts.info(
        "process",
        format!(
            "watching new processes (poll every {}s) for: obfuscated inline payloads, unusual/denied exec paths, masquerading names",
            cfg.poll_interval_secs
        ),
    );
    alerts.info(
        "file-read-burst",
        format!(
            "watching ALL running processes for mass file-read bursts: {}+ bytes/poll absolute, or {}x+ a process's own recent average",
            format_bytes(cfg.file_read_burst_absolute_bytes_per_poll),
            cfg.file_read_burst_relative_multiplier
        ),
    );

    let mut read_trackers: HashMap<Pid, ReadTracker> = HashMap::new();
    let mut warned_unlisted_paths: HashSet<String> = HashSet::new();

    // A fresh System::new_all() is built EVERY poll cycle rather than reused
    // via refresh_processes on one long-lived instance -- a real bug hit and
    // fixed while building this: on Windows, sysinfo 0.33's
    // refresh_processes(All, ...) on an already-populated System silently
    // drops each process's cmd() on the SECOND and later refreshes (single
    // fresh System::new_all() + one refresh returns it correctly; reusing
    // the instance across repeated refresh calls returns an empty Vec from
    // the second call onward). Live-witnessed via a real spawned node
    // process and a real repeated-refresh reproduction before landing this
    // fix -- see tests/live_process_watch.rs. The command line is this
    // watcher's primary signal (the C2-shape heuristic reads it), so
    // silently losing it defeats the whole detector; the extra per-poll
    // enumeration cost is the correct tradeoff at a multi-second interval.
    let mut known: HashSet<Pid> = {
        let sys = System::new_all();
        sys.processes().keys().copied().collect()
    };

    while running.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_secs(cfg.poll_interval_secs));
        let sys = System::new_all();

        let current: HashSet<Pid> = sys.processes().keys().copied().collect();
        for pid in current.difference(&known) {
            if let Some(p) = sys.process(*pid) {
                inspect_new_process(&cfg, &alerts, &sys, p, &mut warned_unlisted_paths);
            }
        }

        // Runs against EVERY currently-running process, not just newly
        // spawned ones -- a mass-scanning process may already have been
        // running when goofedup started, or may sit quiet for a while
        // before its scan begins.
        for (pid, p) in sys.processes() {
            check_read_burst(&cfg, &alerts, *pid, p, &mut read_trackers);
        }
        read_trackers.retain(|pid, _| current.contains(pid));

        known = current;
    }
}

/// Linux's sysinfo disk_usage() surfaces /proc/[pid]/io's `read_bytes`,
/// which counts actual block-device I/O only -- reads served from page
/// cache or tmpfs (the common case for a container/VM with warm cache, or
/// for a scanning process re-reading recently-touched files) report 0
/// there and the detector never trips. `rchar` counts every byte passed to
/// read()-family syscalls regardless of cache, which is what a mass
/// scanning/harvesting process actually produces -- read directly since
/// sysinfo's DiskUsage does not expose it. Live-witnessed: this container's
/// own /proc/self/io reports read_bytes=0 for a real page-cache-served
/// read.
#[cfg(target_os = "linux")]
fn total_read_bytes(pid: Pid) -> u64 {
    let path = format!("/proc/{}/io", pid.as_u32());
    let Ok(contents) = std::fs::read_to_string(path) else {
        return 0;
    };
    for line in contents.lines() {
        if let Some(rest) = line.strip_prefix("rchar:") {
            return rest.trim().parse().unwrap_or(0);
        }
    }
    0
}

#[cfg(not(target_os = "linux"))]
fn total_read_bytes(_pid: Pid, p: &sysinfo::Process) -> u64 {
    p.disk_usage().total_read_bytes
}

/// Mass file-read (drive scanning / harvesting) detection -- see Config's
/// own doc comment for the two independent triggers (absolute burst,
/// relative spike vs a process's own EMA baseline).
fn check_read_burst(
    cfg: &Config,
    alerts: &AlertSink,
    pid: Pid,
    p: &sysinfo::Process,
    trackers: &mut HashMap<Pid, ReadTracker>,
) {
    #[cfg(target_os = "linux")]
    let total_read = total_read_bytes(pid);
    #[cfg(not(target_os = "linux"))]
    let total_read = total_read_bytes(pid, p);

    let tracker = trackers.entry(pid).or_insert_with(|| ReadTracker::new(total_read));

    // A process's disk_usage() can wrap or reset (e.g. genuinely restarted
    // under the same PID between polls on some platforms) -- treat a
    // decrease as "no delta this poll" rather than an underflow panic or a
    // bogus huge unsigned delta.
    let delta = total_read.saturating_sub(tracker.last_total_read);
    tracker.last_total_read = total_read;

    if delta == 0 {
        // Record a non-spike poll into the window rather than wiping the
        // tracker's whole history -- a real process's read rounds are
        // often separated by an intervening near-zero-delta poll (bursty
        // disk I/O, not perfectly uniform), live-witnessed via
        // _diag_syncthing_deltas.rs: a strict "any zero-delta poll erases
        // all prior progress" rule meant a real sustained multi-round
        // burst pattern never accumulated past a single spike, since each
        // round's own inter-round pause produced an intervening zero-delta
        // poll that reset the count every time.
        tracker.record_poll(false, false);
        if tracker.relative_spike_count_in_window() < ReadTracker::REQUIRED_SPIKES_IN_WINDOW
            && tracker.absolute_burst_count_in_window() < ReadTracker::REQUIRED_SPIKES_IN_WINDOW
        {
            tracker.alerted_this_burst = false;
        }
        return;
    }

    let name = p.name().to_string_lossy().to_string();
    let name_lower = name.to_lowercase();
    let is_known_high_throughput_tool =
        cfg.known_high_throughput_tool_names.iter().any(|n| n.to_lowercase() == name_lower);
    let effective_absolute_threshold = if is_known_high_throughput_tool {
        (cfg.file_read_burst_absolute_bytes_per_poll as f64 * cfg.known_high_throughput_tool_multiplier) as u64
    } else {
        cfg.file_read_burst_absolute_bytes_per_poll
    };

    // Live-witnessed: a process whose own baseline is already substantial
    // (python.exe reading 60MB against a 13-24MB/poll established average)
    // is not anomalous relative to ITSELF just because the raw byte count
    // clears the absolute floor -- the absolute check exists to catch a
    // scanner even on its very first observation (no baseline yet), not to
    // re-flag a consistently high-throughput process on every poll near its
    // own normal level. A read within a modest multiple of the process's
    // own established baseline is excluded from the absolute-burst check
    // even if it clears the raw threshold.
    const BASELINE_RELATIVE_TO_ABSOLUTE_EXEMPTION_MULTIPLIER: f64 = 3.0;
    let absolute_reading_is_within_own_established_baseline = tracker.avg_delta > 0.0
        && (delta as f64) < tracker.avg_delta * BASELINE_RELATIVE_TO_ABSOLUTE_EXEMPTION_MULTIPLIER;

    let single_poll_absolute_burst = delta >= effective_absolute_threshold
        && !absolute_reading_is_within_own_established_baseline;

    // A live-witnessed false-positive source: a low EMA baseline built up
    // during a genuinely quiet stretch (an idle browser tab) makes any
    // ordinary burst of real activity look like a huge relative spike.
    // BASELINE_WARM_UP_FLOOR requires the baseline itself to already
    // reflect a meaningful amount of steady-state activity before the
    // relative check even engages, not just "greater than noise."
    const BASELINE_WARM_UP_FLOOR: f64 = 512.0 * 1024.0;
    let single_poll_relative_spike = tracker.avg_delta > BASELINE_WARM_UP_FLOOR
        && (delta as f64) >= tracker.avg_delta * cfg.file_read_burst_relative_multiplier;

    tracker.record_poll(single_poll_relative_spike, single_poll_absolute_burst);

    // A real drive-scanning/harvesting process sustains its elevated read
    // rate across a short window; a legitimate app's burst (page load,
    // cache write, update check, a dev tool loading a large plugin file)
    // is characteristically one-shot. Requiring the spike to recur within
    // the last WINDOW_SIZE polls -- not a single sample, and not requiring
    // strict zero-gap consecutiveness -- is what actually distinguishes the
    // two shapes, live-witnessed against real recorded firefox.exe/
    // Discord.exe/agentplug-runner.exe/python.exe false positives (all
    // single-poll) while a genuine multi-round sustained burst (even with
    // an intervening quiet poll between rounds) still trips this. The
    // absolute path originally had no persistence requirement at all,
    // completely bypassing this protection -- both paths now require it.
    let is_relative_spike = tracker.relative_spike_count_in_window() >= ReadTracker::REQUIRED_SPIKES_IN_WINDOW;
    let is_absolute_burst = tracker.absolute_burst_count_in_window() >= ReadTracker::REQUIRED_SPIKES_IN_WINDOW;

    if (is_absolute_burst || is_relative_spike) && !tracker.alerted_this_burst {
        tracker.alerted_this_burst = true;
        let exe_path = p.exe().map(|e| e.to_string_lossy().to_string()).unwrap_or_default();
        let reason = if is_absolute_burst && is_relative_spike {
            "both an absolute burst and a sustained spike versus its own baseline"
        } else if is_absolute_burst {
            "an absolute burst"
        } else {
            "a sustained spike versus its own recent baseline"
        };
        alerts.critical(
            "file-read-burst",
            format!(
                "'{name}' (PID {}) read an unusual amount of file data -- {reason}, the tell-tale shape of drive scanning/harvesting",
                pid.as_u32()
            ),
            format!(
                "read {} in ~{}s (baseline avg ~{}/poll){}",
                format_bytes(delta),
                cfg.poll_interval_secs,
                format_bytes(tracker.avg_delta as u64),
                if exe_path.is_empty() { String::new() } else { format!(", exe={exe_path}") }
            ),
        );
    } else if !is_absolute_burst && !is_relative_spike {
        tracker.alerted_this_burst = false;
    }

    // EMA update AFTER scoring this poll -- a burst this poll must be
    // compared against the baseline BEFORE the burst itself pulls the
    // average up. A poll that itself scored as a spike (single-poll or
    // absolute) is excluded from the update entirely, not just deferred:
    // otherwise a SUSTAINED scan launders its own elevated read rate into
    // the baseline within 1-2 polls (live-witnessed: a real 3.6MB burst
    // pulled a ~150KB baseline up to ~700KB in two polls, so a second
    // identical 3.6MB burst right after no longer cleared the relative
    // threshold against its own inflated average) -- the baseline must stay
    // anchored to genuine steady-state activity for as long as the scan
    // itself continues, or a sustained scan becomes progressively HARDER to
    // detect the longer it runs, the opposite of the intended behavior.
    const EMA_ALPHA: f64 = 0.2;
    if !single_poll_relative_spike && !single_poll_absolute_burst {
        tracker.avg_delta = if tracker.avg_delta == 0.0 {
            delta as f64
        } else {
            EMA_ALPHA * (delta as f64) + (1.0 - EMA_ALPHA) * tracker.avg_delta
        };
    }
}

fn format_bytes(b: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    if b >= GB {
        format!("{:.1}GB", b as f64 / GB as f64)
    } else if b >= MB {
        format!("{:.1}MB", b as f64 / MB as f64)
    } else if b >= KB {
        format!("{:.1}KB", b as f64 / KB as f64)
    } else {
        format!("{b}B")
    }
}

fn inspect_new_process(
    cfg: &Config,
    alerts: &AlertSink,
    sys: &System,
    p: &sysinfo::Process,
    warned_unlisted_paths: &mut HashSet<String>,
) {
    let name = p.name().to_string_lossy().to_string();
    let exe_path = p
        .exe()
        .map(|e| e.to_string_lossy().to_string())
        .unwrap_or_default();
    let cmdline = p
        .cmd()
        .iter()
        .map(|s| s.to_string_lossy().to_string())
        .collect::<Vec<_>>()
        .join(" ");
    let pid = p.pid().as_u32();

    // 1. denied path -- instant CRITICAL regardless of process name.
    if !exe_path.is_empty() {
        if let Some(reason) = is_denied_exec_path(&exe_path, &cfg.deny_exec_path_fragments) {
            alerts.critical(
                "process-path",
                format!("'{name}' (PID {pid}) is executing from a location nothing legitimate runs from"),
                format!("exe={exe_path} ({reason})"),
            );
        } else if is_unlisted_exec_path(&exe_path, &cfg.allowed_exec_roots) {
            // The allowlist check itself stays exactly as sensitive as
            // before -- a system-wide install location or a user's own
            // tooling directory can still hold a compromised binary, so
            // WHICH paths get flagged never changes here. What changes is
            // re-alert volume: the SAME already-flagged path launching
            // again (e.g. a system Python interpreter invoked many times a
            // day) is not new information the second time, so it alerts
            // once per exact exe path per session run rather than once per
            // process launch. In-memory only -- a fresh session still
            // re-flags every path from scratch, since a path's trust
            // status could genuinely have changed since last run.
            if warned_unlisted_paths.insert(exe_path.clone()) {
                alerts.warn(
                    "process-path",
                    format!("'{name}' (PID {pid}) is running from a path outside the known-good allowlist"),
                    format!("exe={exe_path}"),
                );
            }
        }
    }

    // 2. masquerading name / suspicious characters.
    if let Some(v) = score_process_name(&name, &exe_path) {
        alerts.critical(
            "process-name",
            format!("'{name}' (PID {pid}) name looks suspicious"),
            format!("score={} reasons=[{}]", v.score, v.reasons.join("; ")),
        );
    }

    // 3. obfuscated inline-eval command line, only for watched interpreters
    //    (avoids false-positiving on e.g. a long git commit message passed
    //    as an argument to something unrelated).
    //
    // On Linux, sysinfo's p.name() is /proc/[pid]/comm -- for a
    // multi-threaded interpreter like node this is the per-thread name
    // (MainThread, V8Worker, ...), NOT the binary name, even for the PID
    // that IS the process itself. Matching against the exe basename too
    // catches the real interpreter regardless of what comm reports.
    // Live-witnessed: a real spawned `node -e <payload>` never matched on
    // name alone in this container.
    let name_lower = name.to_lowercase();
    let exe_basename_lower = std::path::Path::new(&exe_path)
        .file_name()
        .map(|f| f.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let is_watched_interp = cfg.watched_interpreters.iter().any(|i| {
        let i_lower = i.to_lowercase();
        i_lower == name_lower || i_lower == exe_basename_lower
    });
    if is_watched_interp {
        if let Some(v) = score_command_line(&cmdline) {
            let head: String = cmdline.chars().take(200).collect();
            // Severity stays CRITICAL unconditionally -- a c2-shaped command
            // line is a severe signal regardless of who spawned it, since a
            // real compromise could just as easily run under a parent name
            // that happens to match a trusted dispatcher. Ancestry is still
            // useful triage context, so it's appended to the evidence text
            // instead of ever changing severity: a known name is not the
            // same as a trusted actor, and the alert must never be quieter
            // for a payload that merely looks like it came from a familiar
            // process.
            let parent_is_known_automation = ancestor_names(sys, p, ANCESTOR_WALK_MAX_DEPTH)
                .iter()
                .any(|ancestor| {
                    let ancestor_lower = ancestor.to_lowercase();
                    cfg.known_automation_parent_names.iter().any(|n| n.to_lowercase() == ancestor_lower)
                });
            let parent_note = if parent_is_known_automation {
                "parent=recognized-dev-tool-ancestor"
            } else {
                "parent=unrecognized"
            };
            let evidence = format!("score={} reasons=[{}] {parent_note} cmdline_head={head}", v.score, v.reasons.join("; "));
            let message = format!("'{name}' (PID {pid}) spawned with a command line shaped like an obfuscated C2 payload");
            alerts.critical("c2-shaped-process", message, evidence);
        }
    }
}

// A live-witnessed real dispatch chain (this session's own AI-assistant
// tool-dispatch path) is bash.exe (nested 3 deep) <- claude.exe <- cmd.exe
// <- explorer.exe -- the immediate parent of a flagged interpreter is
// routinely an intermediate shell, not a directly-trusted top-level
// dispatcher, so checking only p.parent() (one level) almost never matches.
// Walk a small bounded number of ancestor levels instead; the bound exists
// so this stays cheap per-alert regardless of process-tree depth, not
// because a real Windows process tree could cycle.
const ANCESTOR_WALK_MAX_DEPTH: u32 = 4;

fn ancestor_names(sys: &System, p: &sysinfo::Process, max_depth: u32) -> Vec<String> {
    let mut names = Vec::new();
    let mut current_pid = p.pid();
    for _ in 0..max_depth {
        let Some(current) = sys.process(current_pid) else { break };
        let Some(parent_pid) = current.parent() else { break };
        let Some(parent) = sys.process(parent_pid) else { break };
        names.push(parent.name().to_string_lossy().to_string());
        current_pid = parent_pid;
    }
    names
}
