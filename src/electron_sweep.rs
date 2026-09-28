use crate::alert::AlertSink;
use crate::config::SharedConfig;
use crate::heuristics::is_backup_sibling_name;
use crate::scan_js;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use walkdir::WalkDir;

const DISCOVERY_MAX_DEPTH: usize = 6;
const SHUTDOWN_POLL_STEP: Duration = Duration::from_millis(500);

fn looks_like_electron_or_vscode_install(dir: &Path) -> bool {
    if dir.join("resources").join("app.asar").is_file() {
        return true;
    }
    if dir.join("node_modules").join("@vscode").is_dir() {
        return true;
    }
    if dir.join("resources").is_dir()
        && (dir.join("electron.exe").is_file() || dir.join("electron").is_file())
    {
        return true;
    }
    false
}

pub fn discover_installs(roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut seen: HashSet<PathBuf> = HashSet::new();
    for root in roots {
        if !root.exists() {
            continue;
        }
        for entry in WalkDir::new(root)
            .max_depth(DISCOVERY_MAX_DEPTH)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if !entry.file_type().is_dir() {
                continue;
            }
            let dir = entry.path();
            if looks_like_electron_or_vscode_install(dir) && seen.insert(dir.to_path_buf()) {
                found.push(dir.to_path_buf());
            }
        }
    }
    found
}

fn sweep_existing_backup_siblings(root: &Path, alerts: &AlertSink) {
    for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        let Some(name) = entry.file_name().to_str() else {
            continue;
        };
        if is_backup_sibling_name(name) {
            alerts.critical(
                "backup-sibling",
                "a *.orig/*.bak/*.inz-style backup file already exists inside a proactively-swept Electron/VSCode-family install -- this is exactly the shape an infector leaves behind to preserve the original while it replaces the real file",
                entry.path().display().to_string(),
            );
        }
    }
}

pub fn run(cfg_shared: SharedConfig, alerts: Arc<AlertSink>, running: Arc<AtomicBool>) {
    let mut already_reported: HashSet<PathBuf> = HashSet::new();
    let mut first_pass = true;

    while running.load(Ordering::Relaxed) {
        let cfg = cfg_shared.read().unwrap_or_else(std::sync::PoisonError::into_inner).clone();

        if first_pass {
            alerts.info(
                "electron-sweep",
                if cfg.electron_sweep_enabled {
                    format!(
                        "proactive Electron/VSCode-family sweep active: scanning {} root(s) for app installs by shape every {}s",
                        cfg.electron_sweep_roots.len(),
                        cfg.electron_sweep_interval_secs
                    )
                } else {
                    "proactive Electron/VSCode-family sweep disabled via config".to_string()
                },
            );
            first_pass = false;
        }

        if cfg.electron_sweep_enabled {
            let installs = discover_installs(&cfg.electron_sweep_roots);
            for install in &installs {
                if already_reported.insert(install.clone()) {
                    alerts.info(
                        "electron-sweep",
                        format!(
                            "discovered Electron/VSCode-family install by shape (app.asar / @vscode module tree / electron binary), not a hardcoded name list: {}",
                            install.display()
                        ),
                    );
                }
            }
            for install in &installs {
                if !running.load(Ordering::Relaxed) {
                    return;
                }
                scan_js::scan_project(install, &alerts);
                sweep_existing_backup_siblings(install, &alerts);
            }
        }

        sleep_in_chunks(cfg.electron_sweep_interval_secs, &running);
    }
}

fn sleep_in_chunks(total_secs: u64, running: &AtomicBool) {
    let mut remaining = Duration::from_secs(total_secs);
    while remaining > Duration::ZERO {
        if !running.load(Ordering::Relaxed) {
            return;
        }
        let chunk = remaining.min(SHUTDOWN_POLL_STEP);
        std::thread::sleep(chunk);
        remaining -= chunk;
    }
}
