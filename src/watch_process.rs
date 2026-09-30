use crate::alert::AlertSink;
use crate::config::{Config, SharedConfig};
use crate::heuristics::{decode_encoded_command, is_denied_exec_path, is_unlisted_exec_path, score_command_line, score_process_name};
use crate::process_trust::{self, ProcessTrust};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use sysinfo::{Pid, System};

const CMDLINE_EVIDENCE_HEAD_CHARS: usize = 1200;
const DECODED_COMMAND_EVIDENCE_HEAD_CHARS: usize = 300;
const ANCESTOR_WALK_MAX_DEPTH: u32 = 4;

struct ReadTracker {
    last_total_read: u64,
    avg_delta: f64,
    alerted_this_burst: bool,
    relative_spike_window: Vec<bool>,
    absolute_burst_window: Vec<bool>,
    window_pos: usize,
}

impl ReadTracker {
    fn new(seed_total_read: u64, window_size: usize) -> Self {
        Self {
            last_total_read: seed_total_read,
            avg_delta: 0.0,
            alerted_this_burst: false,
            relative_spike_window: vec![false; window_size.max(1)],
            absolute_burst_window: vec![false; window_size.max(1)],
            window_pos: 0,
        }
    }

    fn record_poll(&mut self, was_relative_spike: bool, was_absolute_burst: bool) {
        self.relative_spike_window[self.window_pos] = was_relative_spike;
        self.absolute_burst_window[self.window_pos] = was_absolute_burst;
        self.window_pos = (self.window_pos + 1) % self.relative_spike_window.len();
    }

    fn relative_spike_count_in_window(&self) -> usize {
        self.relative_spike_window.iter().filter(|&&x| x).count()
    }

    fn absolute_burst_count_in_window(&self) -> usize {
        self.absolute_burst_window.iter().filter(|&&x| x).count()
    }
}

fn config_snapshot(cfg_shared: &SharedConfig) -> Arc<Config> {
    cfg_shared.read().unwrap_or_else(std::sync::PoisonError::into_inner).clone()
}

fn fresh_system_snapshot() -> System {
    System::new_all()
}

pub fn run(cfg_shared: SharedConfig, alerts: Arc<AlertSink>, running: Arc<AtomicBool>) {
    {
        let cfg = config_snapshot(&cfg_shared);
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
    }

    let mut read_trackers: HashMap<Pid, ReadTracker> = HashMap::new();
    let mut warned_unlisted_paths: HashSet<String> = HashSet::new();
    let mut trust_watch = ProcessTrust::new();

    let mut known: HashSet<Pid> = {
        let sys = fresh_system_snapshot();
        sys.processes().keys().copied().collect()
    };

    while running.load(Ordering::Relaxed) {
        let cfg = config_snapshot(&cfg_shared);
        std::thread::sleep(Duration::from_secs(cfg.poll_interval_secs));
        let sys = fresh_system_snapshot();

        let current: HashSet<Pid> = sys.processes().keys().copied().collect();
        for pid in current.difference(&known) {
            if let Some(p) = sys.process(*pid) {
                inspect_new_process(&cfg, &alerts, &sys, p, &mut warned_unlisted_paths);
            }
        }
        trust_watch.observe(&cfg, &alerts, &sys, &known, &current);

        for (pid, p) in sys.processes() {
            check_read_burst(&cfg, &alerts, *pid, p, &mut read_trackers);
        }
        read_trackers.retain(|pid, _| current.contains(pid));

        known = current;
    }
}

#[cfg(target_os = "linux")]
fn total_read_bytes(pid: Pid) -> u64 {
    const PROC_IO_CHARS_READ_PREFIX: &str = "rchar:";
    let path = format!("/proc/{}/io", pid.as_u32());
    let Ok(contents) = std::fs::read_to_string(path) else {
        return 0;
    };
    for line in contents.lines() {
        if let Some(rest) = line.strip_prefix(PROC_IO_CHARS_READ_PREFIX) {
            return rest.trim().parse().unwrap_or(0);
        }
    }
    0
}

#[cfg(not(target_os = "linux"))]
fn total_read_bytes(_pid: Pid, p: &sysinfo::Process) -> u64 {
    p.disk_usage().total_read_bytes
}

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

    let tracker = trackers
        .entry(pid)
        .or_insert_with(|| ReadTracker::new(total_read, cfg.read_burst_window_size));

    let delta = total_read.saturating_sub(tracker.last_total_read);
    tracker.last_total_read = total_read;

    if delta == 0 {
        tracker.record_poll(false, false);
        if tracker.relative_spike_count_in_window() < cfg.read_burst_required_spikes_in_window
            && tracker.absolute_burst_count_in_window() < cfg.read_burst_required_spikes_in_window
        {
            tracker.alerted_this_burst = false;
        }
        return;
    }

    let name = p.name().to_string_lossy().to_string();
    let name_lower = name.to_lowercase();
    let is_known_high_throughput_tool =
        cfg.known_high_throughput_tool_names.iter().any(|n| n.to_lowercase() == name_lower);
    let exe_path_lower = p.exe().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
    let runs_from_os_vendor_root = !exe_path_lower.is_empty()
        && cfg.os_vendor_roots.iter().any(|root| {
            let root_str = root.to_string_lossy().to_lowercase();
            !root_str.is_empty() && exe_path_lower.starts_with(&root_str)
        });
    let is_locally_built_binary = !exe_path_lower.is_empty()
        && crate::process_trust::is_local_cargo_artifact(&p.exe().map(|e| e.to_string_lossy().to_string()).unwrap_or_default());
    let gets_high_throughput_relaxation = is_known_high_throughput_tool || runs_from_os_vendor_root || is_locally_built_binary;
    let effective_absolute_threshold = if gets_high_throughput_relaxation {
        ((cfg.file_read_burst_absolute_bytes_per_poll as f64 * cfg.known_high_throughput_tool_multiplier) as u64)
            .min(cfg.file_read_burst_uncorroborated_ceiling_bytes)
    } else {
        cfg.file_read_burst_absolute_bytes_per_poll
    };
    let effective_relative_multiplier = if gets_high_throughput_relaxation {
        cfg.file_read_burst_relative_multiplier * cfg.known_high_throughput_tool_multiplier
    } else {
        cfg.file_read_burst_relative_multiplier
    };

    let exe_path_raw = p.exe().map(|e| e.to_string_lossy().to_string()).unwrap_or_default();
    let path_is_corroborating = is_denied_exec_path(&exe_path_raw, &cfg.deny_exec_path_fragments).is_some()
        || (!is_locally_built_binary && is_unlisted_exec_path(&exe_path_raw, &cfg.allowed_exec_roots));
    let effective_absolute_threshold = if path_is_corroborating {
        ((effective_absolute_threshold as f64) * cfg.read_burst_corroborated_threshold_fraction) as u64
    } else {
        effective_absolute_threshold
    };

    let absolute_reading_is_within_own_established_baseline = tracker.avg_delta > 0.0
        && (delta as f64) < tracker.avg_delta * cfg.read_burst_baseline_exemption_multiplier;

    let single_poll_absolute_burst = delta >= effective_absolute_threshold
        && !absolute_reading_is_within_own_established_baseline;

    let relative_spike_needs_ceiling_check = gets_high_throughput_relaxation && !path_is_corroborating;
    let single_poll_relative_spike = tracker.avg_delta > cfg.read_burst_baseline_warm_up_floor_bytes
        && (delta as f64) >= tracker.avg_delta * effective_relative_multiplier
        && (!relative_spike_needs_ceiling_check
            || delta >= cfg.file_read_burst_uncorroborated_ceiling_bytes);

    tracker.record_poll(single_poll_relative_spike, single_poll_absolute_burst);

    let is_relative_spike = tracker.relative_spike_count_in_window() >= cfg.read_burst_required_spikes_in_window;
    let is_absolute_burst = tracker.absolute_burst_count_in_window() >= cfg.read_burst_required_spikes_in_window;

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

    if !single_poll_relative_spike && !single_poll_absolute_burst {
        tracker.avg_delta = if tracker.avg_delta == 0.0 {
            delta as f64
        } else {
            cfg.read_burst_ema_alpha * (delta as f64) + (1.0 - cfg.read_burst_ema_alpha) * tracker.avg_delta
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

    if !exe_path.is_empty() {
        if let Some(reason) = is_denied_exec_path(&exe_path, &cfg.deny_exec_path_fragments) {
            alerts.critical(
                "process-path",
                format!("'{name}' (PID {pid}) is executing from a location nothing legitimate runs from"),
                format!("exe={exe_path} ({reason})"),
            );
        } else if !process_trust::supersedes_path_allowlist(cfg) && is_unlisted_exec_path(&exe_path, &cfg.allowed_exec_roots) {
            if warned_unlisted_paths.insert(exe_path.clone()) {
                alerts.warn(
                    "process-path",
                    format!("'{name}' (PID {pid}) is running from a path outside the known-good allowlist"),
                    format!("exe={exe_path}"),
                );
            }
        }
    }

    if let Some(v) = score_process_name(&name, &exe_path) {
        alerts.critical(
            "process-name",
            format!("'{name}' (PID {pid}) name looks suspicious"),
            format!("score={} reasons=[{}]", v.score, v.reasons.join("; ")),
        );
    }

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
        if let Some(v) = score_command_line(&cmdline, cfg.c2_max_decode_depth) {
            let head: String = cmdline.chars().take(CMDLINE_EVIDENCE_HEAD_CHARS).collect();
            let decoded_head = decode_encoded_command(&cmdline, cfg.c2_max_decode_depth)
                .map(|d| d.chars().take(DECODED_COMMAND_EVIDENCE_HEAD_CHARS).collect::<String>());
            let ancestors = ancestor_names(sys, p, ANCESTOR_WALK_MAX_DEPTH);
            let parent_is_known_automation = ancestors.iter().any(|ancestor| {
                let ancestor_lower = ancestor.to_lowercase();
                cfg.known_automation_parent_names.iter().any(|n| n.to_lowercase() == ancestor_lower)
            });
            let parent_note = if parent_is_known_automation {
                "parent=recognized-dev-tool-ancestor"
            } else {
                "parent=unrecognized"
            };
            let ancestor_chain = if ancestors.is_empty() {
                String::new()
            } else {
                format!(" ancestor_chain=[{}]", ancestors.join(" <- "))
            };
            let decoded_note = decoded_head
                .map(|d| format!(" decoded_head={d}"))
                .unwrap_or_default();
            let evidence = format!(
                "score={} reasons=[{}] {parent_note}{ancestor_chain} cmdline_head={head}{decoded_note}",
                v.score,
                v.reasons.join("; ")
            );
            let message = format!("'{name}' (PID {pid}) spawned with a command line shaped like an obfuscated C2 payload");
            alerts.critical("c2-shaped-process", message, evidence);
        }
    }
}

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
