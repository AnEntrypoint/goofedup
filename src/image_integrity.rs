use crate::alert::AlertSink;
use std::collections::{HashMap, HashSet};
use std::io::ErrorKind;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use sysinfo::{Pid, System};

const START_TIME_TOLERANCE: Duration = Duration::from_secs(2);

type Fingerprint = (SystemTime, u64);

pub struct ImageWatch {
    baselines: HashMap<Pid, (u64, String, Fingerprint)>,
    reported: HashSet<(Pid, u64)>,
}

const UPDATER_RENAME_TOKENS: [&str; 10] = [
    "old",
    "prev",
    "previous",
    "backup",
    "bak",
    "selfupdated",
    "release",
    "pinned",
    "replaced",
    "superseded",
];

fn is_updater_rename(original_path: &str, moved_path: &str) -> bool {
    let original = std::path::Path::new(original_path);
    if !original.is_file() {
        return false;
    }
    let moved_name = moved_path.rsplit(['\\', '/']).next().unwrap_or("").to_lowercase();
    if moved_name.starts_with("old_") {
        return true;
    }
    if std::path::Path::new(moved_path).parent() != original.parent() {
        return false;
    }
    let Some(original_name) = original.file_name().map(|n| n.to_string_lossy().to_lowercase()) else {
        return false;
    };
    let Some(suffix) = moved_name.strip_prefix(&original_name) else {
        return false;
    };
    if !suffix.starts_with(['.', '-', '_']) {
        return false;
    }
    let tokens: Vec<&str> = suffix.split(|c: char| c == '.' || c == '-' || c == '_').filter(|t| !t.is_empty()).collect();
    tokens.iter().any(|t| UPDATER_RENAME_TOKENS.contains(t))
        || tokens.iter().any(|t| t.len() >= 6 && t.chars().all(|c| c.is_ascii_digit()))
}

fn format_time(t: SystemTime) -> String {
    chrono::DateTime::<chrono::Local>::from(t).format("%Y-%m-%d %H:%M:%S").to_string()
}

impl ImageWatch {
    pub fn new() -> Self {
        Self { baselines: HashMap::new(), reported: HashSet::new() }
    }

    pub fn poll(&mut self, alerts: &AlertSink, sys: &System) {
        for (pid, p) in sys.processes() {
            let Some(exe) = p.exe().filter(|e| !e.as_os_str().is_empty()) else { continue };
            let start_secs = p.start_time();
            let identity = (*pid, start_secs);
            if self.reported.contains(&identity) {
                continue;
            }
            let name = p.name().to_string_lossy().to_string();
            let exe_display = exe.to_string_lossy().to_string();

            let meta = match std::fs::metadata(exe) {
                Ok(meta) => meta,
                Err(e) if e.kind() == ErrorKind::NotFound => {
                    self.reported.insert(identity);
                    alerts.critical(
                        "image-replaced-after-start",
                        format!("'{name}' (PID {}) is running from an image file that no longer exists on disk", pid.as_u32()),
                        format!("exe={exe_display} (deleted or moved after the process started)"),
                    );
                    continue;
                }
                Err(_) => continue,
            };
            let Ok(modified) = meta.modified() else { continue };
            let fingerprint: Fingerprint = (modified, meta.len());
            let started = UNIX_EPOCH + Duration::from_secs(start_secs);

            let baseline = self.baselines.get(pid).filter(|(baseline_start, _, _)| *baseline_start == start_secs).cloned();
            let reason = match &baseline {
                Some((_, seen_path, _)) if *seen_path != exe_display => Some(format!(
                    "the image file was moved while the process was running (started as {seen_path}), the classic first step of replacing a running image in place"
                )),
                Some((_, _, seen)) if *seen != fingerprint => Some(format!(
                    "the image file changed while the process was running (was {} bytes modified {}, now {} bytes modified {})",
                    seen.1,
                    format_time(seen.0),
                    fingerprint.1,
                    format_time(fingerprint.0)
                )),
                Some(_) => None,
                None => modified.duration_since(started).ok().filter(|gap| *gap > START_TIME_TOLERANCE).map(|gap| {
                    format!(
                        "the image file was modified {}s after the process started (file modified {}, process started {})",
                        gap.as_secs(),
                        format_time(modified),
                        format_time(started)
                    )
                }),
            };
            if baseline.is_none() {
                self.baselines.insert(*pid, (start_secs, exe_display.clone(), fingerprint));
            }

            if let Some(reason) = reason {
                self.reported.insert(identity);
                let message = format!("'{name}' (PID {}) is running code that no longer matches its image on disk", pid.as_u32());
                let evidence = format!("exe={exe_display} {reason}");
                match baseline.as_ref().filter(|(_, seen_path, _)| is_updater_rename(seen_path, &exe_display)) {
                    Some(_) => alerts.warn("image-replaced-after-start", format!("{message} (updater-shaped rename: original path repopulated)"), evidence),
                    None => alerts.critical("image-replaced-after-start", message, evidence),
                }
            }
        }
        self.baselines.retain(|pid, _| sys.process(*pid).is_some());
        self.reported.retain(|(pid, _)| sys.process(*pid).is_some());
    }
}

impl Default for ImageWatch {
    fn default() -> Self {
        Self::new()
    }
}
