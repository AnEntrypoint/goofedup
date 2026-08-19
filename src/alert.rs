// Single alert channel every detector writes through. Alert-only by design:
// no detector in this codebase kills a process, deletes a file, or blocks a
// connection on its own -- the strongest action any of them takes is
// printing the exact command a human would run to do that, so a false
// positive can never cause damage on its own.

use chrono::Local;
use std::fmt;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

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
    pub suggested_action: Option<String>,
}

pub struct AlertSink {
    log_path: PathBuf,
    lock: Mutex<()>,
    on_alert: Mutex<Option<Box<dyn Fn(&Alert) + Send + Sync>>>,
}

impl AlertSink {
    pub fn new(log_path: PathBuf) -> Self {
        Self {
            log_path,
            lock: Mutex::new(()),
            on_alert: Mutex::new(None),
        }
    }

    /// Registers a callback invoked with every emitted Alert, in addition to
    /// the existing console+file output -- the GUI's toast/history hook.
    pub fn set_on_alert(&self, cb: impl Fn(&Alert) + Send + Sync + 'static) {
        *self.on_alert.lock().unwrap() = Some(Box::new(cb));
    }

    pub fn emit(&self, a: Alert) {
        if let Some(cb) = self.on_alert.lock().unwrap().as_ref() {
            cb(&a);
        }
        let _guard = self.lock.lock().unwrap();
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
        if let Some(action) = &a.suggested_action {
            println!("    suggested action: {action}");
            log_lines.push(format!("    suggested action: {action}"));
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
            suggested_action: None,
        });
    }

    pub fn warn(&self, category: &'static str, message: impl Into<String>, evidence: impl Into<String>) {
        self.emit(Alert {
            level: Level::Warn,
            category,
            message: message.into(),
            evidence: Some(evidence.into()),
            suggested_action: None,
        });
    }

    pub fn critical(
        &self,
        category: &'static str,
        message: impl Into<String>,
        evidence: impl Into<String>,
        suggested_action: Option<String>,
    ) {
        self.emit(Alert {
            level: Level::Critical,
            category,
            message: message.into(),
            evidence: Some(evidence.into()),
            suggested_action,
        });
    }
}
