// File watcher: native OS filesystem-change events on all three platforms
// via the `notify` crate (ReadDirectoryChangesW on Windows, FSEvents on
// macOS, inotify on Linux) -- genuinely event-driven, no polling.

use crate::alert::AlertSink;
use crate::config::Config;
use notify::{Event, EventKind, RecursiveMode, Watcher};
use regex::Regex;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::mpsc::channel;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;

fn backup_suffix_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\.(orig|bak|inz|original|old)(\.[A-Za-z0-9]+)?$").unwrap())
}

/// Script-file extensions worth baselining. Not tied to any one app/runtime
/// -- covers the interpreted-language entry-point shape a "small bootstrap
/// file overwritten with a huge payload" attack needs (compiled binaries
/// don't fit this exact tell the same way; a giant .exe growing is a
/// different, much noisier signal not worth tracking the same way here).
fn is_watched_script_ext(path: &std::path::Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()).map(|e| e.to_lowercase()).as_deref(),
        Some("js" | "mjs" | "cjs" | "py" | "rb" | "php" | "pl" | "ps1" | "sh")
    )
}

const BASELINE_SMALL_CEILING: u64 = 5 * 1024;
const GROWTH_ABSOLUTE_FLOOR: u64 = 20 * 1024;
const GROWTH_RATIO_THRESHOLD: f64 = 10.0;

/// Path segments that mark a package-manager cache/staging directory --
/// files here are written incrementally during a normal install/extract
/// (small stub, then filled with real content), so "small baseline that
/// later balloons" is the expected shape of every ordinary `npm install`/
/// `npx`, not tampering. Live-witnessed: 229 of 239 unusual-growth CRITICALs
/// in one session were npm's own `_cacache`/`_npx` staging dirs, 0 of them
/// real. Never a payload's *final resting place* for this attack class
/// either -- a real bootstrap-hijack targets a package's already-installed,
/// long-lived entry point, not a directory that gets wiped and rewritten on
/// every install.
const CACHE_STAGING_DIR_SEGMENTS: &[&str] = &["_cacache", "_npx", "node_modules/.cache", ".cache"];

fn is_cache_staging_path(path: &std::path::Path) -> bool {
    let path_lower = path.to_string_lossy().to_lowercase();
    CACHE_STAGING_DIR_SEGMENTS.iter().any(|seg| {
        let seg_lower = seg.to_lowercase();
        path_lower.contains(&format!("\\{seg_lower}\\"))
            || path_lower.contains(&format!("/{seg_lower}/"))
    })
}

pub fn run(cfg: Arc<Config>, alerts: Arc<AlertSink>) {
    // First-seen size per path, for the generic "known-small file just got
    // huge" detector below -- this is the general form of what the explicit
    // bootstrap_watch entries in Config hand-name for specific known apps:
    // no app name required, any small script anywhere under a watched root
    // that later balloons in size is worth a look. Populated lazily as
    // events arrive rather than pre-scanned, so it costs nothing on files
    // that never change.
    let baselines: Arc<Mutex<HashMap<PathBuf, u64>>> = Arc::new(Mutex::new(HashMap::new()));
    let (tx, rx) = channel::<notify::Result<Event>>();
    let mut watcher = match notify::recommended_watcher(move |res| {
        let _ = tx.send(res);
    }) {
        Ok(w) => w,
        Err(e) => {
            alerts.warn("file", "could not initialize filesystem watcher", e.to_string());
            return;
        }
    };

    let mut watched_any = false;
    for entry in &cfg.bootstrap_watch {
        if entry.search_root.exists() {
            if watcher
                .watch(&entry.search_root, RecursiveMode::Recursive)
                .is_ok()
            {
                watched_any = true;
                alerts.info(
                    "file",
                    format!(
                        "watching {} for {} > {} bytes",
                        entry.search_root.display(),
                        entry.file_name,
                        entry.max_bytes
                    ),
                );
            }
        }
    }
    for root in &cfg.backup_sibling_roots {
        if root.exists() {
            if watcher.watch(root, RecursiveMode::Recursive).is_ok() {
                watched_any = true;
                alerts.info("file", format!("watching {} for backup-suffix siblings", root.display()));
            }
        }
    }

    if !watched_any {
        alerts.warn("file", "no filesystem roots to watch existed on this system", "check config.rs's per-platform defaults");
        return;
    }

    alerts.info(
        "file",
        format!(
            "generic growth watch active: any script file first seen <{} bytes that later exceeds {} bytes AND grows {}x+ will be flagged",
            BASELINE_SMALL_CEILING, GROWTH_ABSOLUTE_FLOOR, GROWTH_RATIO_THRESHOLD as u32
        ),
    );

    for res in rx {
        let Ok(event) = res else { continue };
        if !matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) {
            continue;
        }
        for path in &event.paths {
            check_bootstrap_size(&cfg, &alerts, path);
            check_backup_sibling(&cfg, &alerts, path);
            check_unusual_growth(&alerts, &baselines, path);
        }
    }
}

/// Generic counterpart to check_bootstrap_size: no hardcoded app/file name
/// required. Tracks the first-seen size of any watched script file; if a
/// later size crosses BOTH the absolute floor and the growth-ratio
/// threshold versus its own baseline, that's the same underlying tell (a
/// small trusted entry point silently ballooning) without needing to know
/// in advance which specific app/file it will be.
fn check_unusual_growth(
    alerts: &AlertSink,
    baselines: &Mutex<HashMap<PathBuf, u64>>,
    path: &std::path::Path,
) {
    if !is_watched_script_ext(path) || is_cache_staging_path(path) {
        return;
    }
    let Ok(meta) = std::fs::metadata(path) else {
        return;
    };
    let current = meta.len();
    let mut map = baselines.lock().unwrap();
    let entry = map.entry(path.to_path_buf());
    match entry {
        std::collections::hash_map::Entry::Vacant(v) => {
            v.insert(current);
        }
        std::collections::hash_map::Entry::Occupied(mut o) => {
            let baseline = *o.get();
            if baseline > 0 && baseline < BASELINE_SMALL_CEILING && current > GROWTH_ABSOLUTE_FLOOR {
                let ratio = current as f64 / baseline as f64;
                if ratio >= GROWTH_RATIO_THRESHOLD {
                    alerts.critical(
                        "unusual-growth",
                        format!(
                            "a small script file grew {ratio:.0}x past its own baseline size -- the general shape of a trusted entry point being overwritten with a payload: {}",
                            path.display()
                        ),
                        format!("baseline={baseline} bytes, current={current} bytes"),
                    );
                }
            }
            // Baseline tracks the SMALLEST size ever seen, not the latest --
            // once a file is confirmed to have legitimately grown (a real
            // update), re-alerting on every subsequent edit would be noise;
            // the smallest-seen value stays the reference point for "was
            // this ever a tiny trusted bootstrap file."
            if current < baseline {
                o.insert(current);
            }
        }
    }
}

pub fn check_bootstrap_size(cfg: &Config, alerts: &AlertSink, path: &std::path::Path) {
    let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
        return;
    };
    let path_str = path.to_string_lossy();
    for entry in &cfg.bootstrap_watch {
        if file_name != entry.file_name || !path_str.contains(entry.path_must_contain) {
            continue;
        }
        let Ok(meta) = std::fs::metadata(path) else {
            continue;
        };
        if meta.len() > entry.max_bytes {
            alerts.critical(
                "bootstrap-size",
                format!(
                    "known-tiny bootstrap file exceeded its sane size ceiling -- likely tampered: {}",
                    path.display()
                ),
                format!("size={} bytes, ceiling={} bytes", meta.len(), entry.max_bytes),
            );
        }
    }
}

pub fn check_backup_sibling(_cfg: &Config, alerts: &AlertSink, path: &std::path::Path) {
    let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
        return;
    };
    if backup_suffix_re().is_match(file_name) {
        alerts.critical(
            "backup-sibling",
            "a *.orig/*.bak/*.inz-style backup file appeared -- this is exactly the shape an infector leaves behind to preserve the original while it replaces the real file",
            path.display().to_string(),
        );
    }
}
