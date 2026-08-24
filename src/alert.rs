// Single alert channel every detector writes through. Alert-only by design:
// no detector in this codebase kills a process, deletes a file, or blocks a
// connection, and none of them prescribes what to do about it either -- the
// job here is reporting what looks suspicious, not deciding a remedy.

use chrono::Local;
use std::fmt;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// Every lock in this module guards a plain data structure (an Option, a
/// unit "are we mid-write" token) with no user code running while it is
/// held, except the registered GUI callback in `emit` -- if that callback
/// ever panicked it must not take every future alert down with it via a
/// poisoned mutex, since a dropped notification is a real, named degraded
/// behavior but a watcher thread that can no longer emit alerts at all is
/// the actual failure this tool exists to catch.
fn lock_recovering<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Level {
    Info,
    Warn,
    Critical,
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Level::Info => write!(f, "INFO"),
            Level::Warn => write!(f, "WARN"),
            Level::Critical => write!(f, "CRITICAL"),
        }
    }
}

pub struct Alert {
    pub level: Level,
    pub category: &'static str,
    pub message: String,
    pub evidence: Option<String>,
}

pub struct AlertSink {
    log_path: PathBuf,
    lock: Mutex<()>,
    on_alert: Mutex<Vec<Arc<dyn Fn(&Alert) + Send + Sync>>>,
}

impl AlertSink {
    pub fn new(log_path: PathBuf) -> Self {
        Self {
            log_path,
            lock: Mutex::new(()),
            on_alert: Mutex::new(Vec::new()),
        }
    }

    /// Registers a callback invoked with every emitted Alert, in addition to
    /// the existing console+file output -- the GUI's toast/history hook and
    /// the scan_js alert-response hook. More than one consumer may register.
    pub fn add_on_alert(&self, cb: impl Fn(&Alert) + Send + Sync + 'static) {
        lock_recovering(&self.on_alert).push(Arc::new(cb));
    }

    pub fn emit(&self, a: Alert) {
        // Clone the Arcs and drop the on_alert lock before invoking the
        // callbacks -- calling out to arbitrary code (which may itself call
        // back into emit, the real shape once the GUI's own alerting paths
        // grow) while still holding this lock is a same-thread self-deadlock
        // on a non-reentrant Mutex, witnessed live via a nested-emit probe.
        let cbs = lock_recovering(&self.on_alert).clone();
        for cb in &cbs {
            cb(&a);
        }
        let _guard = lock_recovering(&self.lock);
        let ts = Local::now().format("%Y-%m-%d %H:%M:%S");
        let color = match a.level {
            Level::Critical => "\x1b[31m",
            Level::Warn => "\x1b[33m",
            Level::Info => "\x1b[36m",
        };
        let reset = "\x1b[0m";
        let head = format!("[{ts}] [{}] [{}] {}", a.level, a.category, a.message);
        println!("{color}{head}{reset}");
        let mut log_lines = vec![head];
        if let Some(ev) = &a.evidence {
            println!("    evidence: {ev}");
            log_lines.push(format!("    evidence: {ev}"));
        }
        if let Ok(mut f) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
        {
            for l in &log_lines {
                let _ = writeln!(f, "{l}");
            }
        }
    }

    pub fn info(&self, category: &'static str, message: impl Into<String>) {
        self.emit(Alert {
            level: Level::Info,
            category,
            message: message.into(),
            evidence: None,
        });
    }

    pub fn warn(&self, category: &'static str, message: impl Into<String>, evidence: impl Into<String>) {
        self.emit(Alert {
            level: Level::Warn,
            category,
            message: message.into(),
            evidence: Some(evidence.into()),
        });
    }

    pub fn critical(&self, category: &'static str, message: impl Into<String>, evidence: impl Into<String>) {
        self.emit(Alert {
            level: Level::Critical,
            category,
            message: message.into(),
            evidence: Some(evidence.into()),
        });
    }
}
