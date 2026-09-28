use crate::alert::AlertSink;
use crate::config::{apply_overrides, apply_reload, Config, ConfigOverrides, SharedConfig};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

pub fn load_overrides_from_file(path: &Path) -> Result<Option<ConfigOverrides>, String> {
    if !path.exists() {
        return Ok(None);
    }
    if let Some(reason) = crate::self_protect::untrusted_override_reason(path) {
        return Err(reason);
    }
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let overrides: ConfigOverrides = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    Ok(Some(overrides))
}

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
