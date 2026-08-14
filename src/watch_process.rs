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
                inspect_new_process(&cfg, &alerts, p);
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

/// Mass file-read (drive scanning / harvesting) detection via sysinfo's
/// per-process cumulative disk_usage() -- see Config's own doc comment for
/// the two independent triggers (absolute burst, relative spike vs a
/// process's own EMA baseline).
fn check_read_burst(
    cfg: &Config,
    alerts: &AlertSink,
    pid: Pid,
    p: &sysinfo::Process,
    trackers: &mut HashMap<Pid, ReadTracker>,
) {
    let total_read = p.disk_usage().total_read_bytes;

    let tracker = trackers.entry(pid).or_insert_with(|| ReadTracker {
        last_total_read: total_read,
        avg_delta: 0.0,
        alerted_this_burst: false,
    });

    // A process's disk_usage() can wrap or reset (e.g. genuinely restarted
    // under the same PID between polls on some platforms) -- treat a
    // decrease as "no delta this poll" rather than an underflow panic or a
    // bogus huge unsigned delta.
    let delta = total_read.saturating_sub(tracker.last_total_read);
    tracker.last_total_read = total_read;

    if delta == 0 {
        tracker.alerted_this_burst = false;
        return;
    }

    let is_absolute_burst = delta >= cfg.file_read_burst_absolute_bytes_per_poll;
    let is_relative_spike = tracker.avg_delta > 1024.0 * 64.0 // require a real established baseline first, not "0 -> anything" on process 2
        && (delta as f64) >= tracker.avg_delta * cfg.file_read_burst_relative_multiplier;

    if (is_absolute_burst || is_relative_spike) && !tracker.alerted_this_burst {
        tracker.alerted_this_burst = true;
        let name = p.name().to_string_lossy().to_string();
        let exe_path = p.exe().map(|e| e.to_string_lossy().to_string()).unwrap_or_default();
        let reason = if is_absolute_burst && is_relative_spike {
            "both an absolute burst and a spike versus its own baseline"
        } else if is_absolute_burst {
            "an absolute burst"
        } else {
            "a spike versus its own recent baseline"
        };
        alerts.critical(
            "file-read-burst",
            format!(
                "'{name}' (PID {}) read an unusual amount of file data in one poll interval -- {reason}, the tell-tale shape of drive scanning/harvesting",
                pid.as_u32()
            ),
            format!(
                "read {} in ~{}s (baseline avg ~{}/poll){}",
                format_bytes(delta),
                cfg.poll_interval_secs,
                format_bytes(tracker.avg_delta as u64),
                if exe_path.is_empty() { String::new() } else { format!(", exe={exe_path}") }
            ),
            Some(suggest_kill(pid.as_u32())),
        );
    } else if !is_absolute_burst && !is_relative_spike {
        tracker.alerted_this_burst = false;
    }

    // EMA update AFTER scoring this poll -- a burst this poll must be
    // compared against the baseline BEFORE the burst itself pulls the
    // average up, otherwise a sustained scan would only ever spike the
    // average and never trip the relative check past its first poll.
    const EMA_ALPHA: f64 = 0.2;
    tracker.avg_delta = if tracker.avg_delta == 0.0 {
        delta as f64
    } else {
        EMA_ALPHA * (delta as f64) + (1.0 - EMA_ALPHA) * tracker.avg_delta
    };
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

fn inspect_new_process(cfg: &Config, alerts: &AlertSink, p: &sysinfo::Process) {
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
                Some(suggest_kill(pid)),
            );
        } else if is_unlisted_exec_path(&exe_path, &cfg.allowed_exec_roots) {
            alerts.warn(
                "process-path",
                format!("'{name}' (PID {pid}) is running from a path outside the known-good allowlist"),
                format!("exe={exe_path}"),
            );
        }
    }

    // 2. masquerading name / suspicious characters.
    if let Some(v) = score_process_name(&name, &exe_path) {
        alerts.critical(
            "process-name",
            format!("'{name}' (PID {pid}) name looks suspicious"),
            format!("score={} reasons=[{}]", v.score, v.reasons.join("; ")),
            Some(suggest_kill(pid)),
        );
    }

    // 3. obfuscated inline-eval command line, only for watched interpreters
    //    (avoids false-positiving on e.g. a long git commit message passed
    //    as an argument to something unrelated).
    let name_lower = name.to_lowercase();
    let is_watched_interp = cfg
        .watched_interpreters
        .iter()
        .any(|i| i.to_lowercase() == name_lower);
    if is_watched_interp {
        if let Some(v) = score_command_line(&cmdline) {
            let head: String = cmdline.chars().take(200).collect();
            alerts.critical(
                "c2-shaped-process",
                format!("'{name}' (PID {pid}) spawned with a command line shaped like an obfuscated C2 payload"),
                format!("score={} reasons=[{}] cmdline_head={head}", v.score, v.reasons.join("; ")),
                Some(suggest_kill(pid)),
            );
        }
    }
}

#[cfg(windows)]
fn suggest_kill(pid: u32) -> String {
    format!("taskkill /PID {pid} /F   (verify first: tasklist /FI \"PID eq {pid}\")")
}

#[cfg(not(windows))]
fn suggest_kill(pid: u32) -> String {
    format!("kill -9 {pid}   (verify first: ps -p {pid} -o comm=,args=)")
}
