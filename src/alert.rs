use chrono::Local;
use std::fmt;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

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

    pub fn add_on_alert(&self, cb: impl Fn(&Alert) + Send + Sync + 'static) {
        lock_recovering(&self.on_alert).push(Arc::new(cb));
    }

    pub fn emit(&self, a: Alert) {
        let callbacks_snapshot = lock_recovering(&self.on_alert).clone();
        for callback in &callbacks_snapshot {
            callback(&a);
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
