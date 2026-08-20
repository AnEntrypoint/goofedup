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
    /// Consecutive polls (excluding the current one) that already scored as
    /// a relative spike. A real drive-scanning/harvesting process sustains
    /// its elevated read rate poll after poll; a legitimate app's burst
    /// (a page load, a cache write, an update check) is characteristically
    /// one-shot. Live-witnessed false positives (firefox.exe, Discord.exe)
    /// were both single-poll spikes against a baseline the app itself had
    /// only just gone quiet enough to shrink -- requiring persistence
    /// eliminates that shape while a genuine sustained scan still trips
    /// this within a couple of poll intervals.
    consecutive_relative_spikes: u32,
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
                inspect_new_process(&cfg, &alerts, p, &mut warned_unlisted_paths);
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

    let tracker = trackers.entry(pid).or_insert_with(|| ReadTracker {
        last_total_read: total_read,
        avg_delta: 0.0,
        alerted_this_burst: false,
        consecutive_relative_spikes: 0,
    });

    // A process's disk_usage() can wrap or reset (e.g. genuinely restarted
    // under the same PID between polls on some platforms) -- treat a
    // decrease as "no delta this poll" rather than an underflow panic or a
    // bogus huge unsigned delta.
    let delta = total_read.saturating_sub(tracker.last_total_read);
    tracker.last_total_read = total_read;

    if delta == 0 {
        tracker.alerted_this_burst = false;
        tracker.consecutive_relative_spikes = 0;
        return;
    }

    let is_absolute_burst = delta >= cfg.file_read_burst_absolute_bytes_per_poll;

    // A live-witnessed false-positive source: a low EMA baseline built up
    // during a genuinely quiet stretch (an idle browser tab) makes any
    // ordinary burst of real activity look like a huge relative spike.
    // BASELINE_WARM_UP_FLOOR requires the baseline itself to already
    // reflect a meaningful amount of steady-state activity before the
    // relative check even engages, not just "greater than noise."
    const BASELINE_WARM_UP_FLOOR: f64 = 512.0 * 1024.0;
    let single_poll_relative_spike = tracker.avg_delta > BASELINE_WARM_UP_FLOOR
        && (delta as f64) >= tracker.avg_delta * cfg.file_read_burst_relative_multiplier;

    if single_poll_relative_spike {
        tracker.consecutive_relative_spikes += 1;
    } else {
        tracker.consecutive_relative_spikes = 0;
    }

    // A real drive-scanning/harvesting process sustains its elevated read
    // rate; a legitimate app's burst (page load, cache write, update check)
    // is characteristically one-shot. Requiring the spike to repeat on the
    // very next poll too -- not a single sample -- is what actually
    // distinguishes the two shapes, live-witnessed against real recorded
    // firefox.exe/Discord.exe false positives (both single-poll spikes).
    const REQUIRED_CONSECUTIVE_SPIKES: u32 = 2;
    let is_relative_spike = tracker.consecutive_relative_spikes >= REQUIRED_CONSECUTIVE_SPIKES;

    if (is_absolute_burst || is_relative_spike) && !tracker.alerted_this_burst {
        tracker.alerted_this_burst = true;
        let name = p.name().to_string_lossy().to_string();
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
    if !single_poll_relative_spike && !is_absolute_burst {
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
            alerts.critical(
                "c2-shaped-process",
                format!("'{name}' (PID {pid}) spawned with a command line shaped like an obfuscated C2 payload"),
                format!("score={} reasons=[{}] cmdline_head={head}", v.score, v.reasons.join("; ")),
            );
        }
    }
}
