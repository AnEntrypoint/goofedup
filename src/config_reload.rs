// Loads, merges, and periodically re-checks the hot-reloadable config
// override file (~/.goofedup/goofedup.config.json). Kept separate from
// config.rs so that module stays pure data/merge-logic -- this is the "runs
// a thread" layer over it, matching the existing watch_*.rs / config.rs
// split elsewhere in this project.

use crate::alert::AlertSink;
use crate::config::{apply_overrides, apply_reload, Config, ConfigOverrides, SharedConfig};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

/// Reads and parses the override file. Returns `Ok(None)` if the file
/// simply doesn't exist yet (the expected, non-alarming first-run state --
/// never logged as a warning), `Ok(Some(overrides))` on a successful parse,
/// and `Err(message)` on a present-but-broken file (unreadable mid-write,
/// invalid JSON, a field with the wrong type) -- never panics on malformed
/// external input, matching this project's existing discipline for
/// anything reading OS/user-supplied data.
pub fn load_overrides_from_file(path: &Path) -> Result<Option<ConfigOverrides>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let overrides: ConfigOverrides = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    Ok(Some(overrides))
}

/// Builds the initial Config: platform defaults, with any overrides from
/// `path` merged on top. A missing file is silent (pure defaults); a
/// present-but-broken file at STARTUP falls back to pure defaults too --
/// nothing here is fatal, `default_for_platform()` alone is always a
/// complete, correct config on its own. Returns the resolved Config plus
/// the ConfigOverrides that were actually applied (an empty/default
/// ConfigOverrides if the file was absent or broken), so callers can show
/// which values are currently file-driven.
pub fn load_config_with_overrides(path: &Path) -> (Config, ConfigOverrides) {
    let base = Config::default_for_platform();
    match load_overrides_from_file(path) {
        Ok(Some(overrides)) => {
            let merged = apply_overrides(base, &overrides);
            (merged, overrides)
        }
        Ok(None) => (base, ConfigOverrides::default()),
        Err(_) => (base, ConfigOverrides::default()),
    }
}

/// Periodically re-checks the override file (mtime + size, not a dedicated
/// `notify` watcher -- see this module's own design rationale: reload
/// latency of "up to one poll interval" is irrelevant next to the
/// rebuild+restart cycle this whole mechanism replaces, and a second
/// filesystem watcher thread is unjustified complexity for a latency win
/// nobody needs at this cadence). On a successful reparse, swaps in the
/// newly-merged Config and updates the shared ConfigOverrides snapshot (so
/// the GUI/CLI config viewer can show current file-vs-default provenance).
/// On a parse failure, logs a WARN (not CRITICAL -- a typo mid-edit is an
/// expected, benign event during active tuning) and leaves the last-known-
/// good Config running untouched -- de-duplicated so a file left broken
/// across an extended edit session doesn't re-warn every poll, only when
/// the file changes again.
pub fn run(
    cfg_shared: SharedConfig,
    overrides_shared: Arc<RwLock<ConfigOverrides>>,
    path: std::path::PathBuf,
    alerts: Arc<AlertSink>,
    running: Arc<AtomicBool>,
) {
    let mut last_seen: Option<(std::time::SystemTime, u64)> = file_fingerprint(&path);
    let mut last_warned_fingerprint: Option<(std::time::SystemTime, u64)> = None;

    while running.load(Ordering::Relaxed) {
        let poll_secs = {
            let cfg = cfg_shared.read().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
            cfg.poll_interval_secs
        };
        std::thread::sleep(Duration::from_secs(poll_secs));

        let current = file_fingerprint(&path);
        if current == last_seen {
            continue;
        }
        last_seen = current;

        match load_overrides_from_file(&path) {
            Ok(Some(overrides)) => {
                let base = Config::default_for_platform();
                let merged = apply_overrides(base, &overrides);
                apply_reload(&cfg_shared, merged);
                *overrides_shared.write().unwrap_or_else(std::sync::PoisonError::into_inner) = overrides;
                alerts.info(
                    "config",
                    format!("reloaded config from {} -- picked up on next poll, no restart needed", path.display()),
                );
            }
            Ok(None) => {
                // File was deleted since last check -- revert to pure
                // defaults, same as a fresh first run with no file present.
                apply_reload(&cfg_shared, Config::default_for_platform());
                *overrides_shared.write().unwrap_or_else(std::sync::PoisonError::into_inner) = ConfigOverrides::default();
                alerts.info("config", format!("{} removed -- reverted to computed defaults", path.display()));
            }
            Err(reason) => {
                if last_warned_fingerprint != current {
                    last_warned_fingerprint = current;
                    alerts.warn(
                        "config",
                        "config file failed to parse -- continuing with last-known-good config",
                        format!("path={} error={reason}", path.display()),
                    );
                }
            }
        }
    }
}

fn file_fingerprint(path: &Path) -> Option<(std::time::SystemTime, u64)> {
    let meta = std::fs::metadata(path).ok()?;
    let modified = meta.modified().ok()?;
    Some((modified, meta.len()))
}
