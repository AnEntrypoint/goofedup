// Bounded in-memory alert history for the tray app's "Show recent alerts"
// window -- newest first, capped so a noisy session can't grow unbounded.

use crate::alert::{Alert, Level};
use std::sync::Mutex;

const CAP: usize = 200;

pub struct Entry {
    pub ts: String,
    pub level: Level,
    pub category: &'static str,
    pub message: String,
    pub evidence: Option<String>,
    pub suggested_action: Option<String>,
}

pub struct History {
    entries: Mutex<Vec<Entry>>,
}

impl History {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
        }
    }

    pub fn push(&self, a: &Alert) {
        let mut entries = self.entries.lock().unwrap();
        entries.insert(
            0,
            Entry {
                ts: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                level: a.level,
                category: a.category,
                message: a.message.clone(),
                evidence: a.evidence.clone(),
                suggested_action: a.suggested_action.clone(),
            },
        );
        entries.truncate(CAP);
    }

    pub fn has_unacknowledged_critical(&self) -> bool {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .any(|e| e.level == Level::Critical)
    }

    pub fn clear_critical_flag(&self) {
        // Acknowledgement drops severity to Warn in the retained view so the
        // tray icon reverts without discarding history.
        let mut entries = self.entries.lock().unwrap();
        for e in entries.iter_mut() {
            if e.level == Level::Critical {
                e.level = Level::Warn;
            }
        }
    }

    pub fn render_text(&self) -> String {
        let entries = self.entries.lock().unwrap();
        if entries.is_empty() {
            return "No alerts yet.".to_string();
        }
        let mut out = String::new();
        for e in entries.iter() {
            out.push_str(&format!("[{}] [{}] [{}] {}\n", e.ts, e.level, e.category, e.message));
            if let Some(ev) = &e.evidence {
                out.push_str(&format!("    evidence: {ev}\n"));
            }
            if let Some(action) = &e.suggested_action {
                out.push_str(&format!("    suggested action: {action}\n"));
            }
        }
        out
    }
}
