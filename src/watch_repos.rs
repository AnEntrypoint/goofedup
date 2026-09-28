use crate::alert::AlertSink;
use crate::scan_repo;
use notify::{Event, EventKind, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, RecvTimeoutError};
use std::sync::Arc;
use std::time::{Duration, Instant};

const SETTLE_DELAY: Duration = Duration::from_millis(250);
const POLL_STEP: Duration = Duration::from_millis(100);

fn outermost_existing_roots(roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut existing: Vec<PathBuf> = roots.iter().filter(|r| r.is_dir()).cloned().collect();
    existing.sort();
    existing.dedup();
    let all = existing.clone();
    existing.retain(|root| !all.iter().any(|other| other != root && root.starts_with(other)));
    existing
}

pub fn run(roots: Vec<PathBuf>, alerts: Arc<AlertSink>, running: Arc<AtomicBool>) {
    let (tx, rx) = channel::<notify::Result<Event>>();
    let mut watcher = match notify::recommended_watcher(move |res| {
        let _ = tx.send(res);
    }) {
        Ok(w) => w,
        Err(e) => {
            alerts.warn("repo-watch", "could not initialize the repo filesystem watcher", e.to_string());
            return;
        }
    };

    let mut watched = 0usize;
    for root in outermost_existing_roots(&roots) {
        match watcher.watch(&root, RecursiveMode::Recursive) {
            Ok(()) => {
                watched += 1;
                alerts.info(
                    "repo-watch",
                    format!(
                        "watching {} for .vscode/tasks.json, settings.json, .gitignore, package.json, *.config.*, workflows, git hooks and disguised assets",
                        root.display()
                    ),
                );
            }
            Err(e) => alerts.warn("repo-watch", format!("could not watch {}", root.display()), e.to_string()),
        }
    }
    if watched == 0 {
        alerts.warn(
            "repo-watch",
            "no repo_watch_roots exist on this system",
            "set repo_watch_roots in ~/.goofedup/goofedup.config.json or pass paths after --watch-repos",
        );
        return;
    }

    let mut settling: HashMap<PathBuf, Instant> = HashMap::new();
    while running.load(Ordering::Relaxed) {
        match rx.recv_timeout(POLL_STEP) {
            Ok(Ok(event)) if matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) => {
                for path in event.paths.into_iter().filter(|p| scan_repo::is_watch_candidate(p)) {
                    settling.insert(path, Instant::now() + SETTLE_DELAY);
                }
            }
            Ok(_) => {}
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
        let now = Instant::now();
        let ready: Vec<PathBuf> = settling
            .iter()
            .filter(|(_, due)| **due <= now)
            .map(|(path, _)| path.clone())
            .collect();
        for path in ready {
            settling.remove(&path);
            if path.is_file() {
                scan_repo::check_changed_file(&path, &alerts);
            }
        }
    }
}
