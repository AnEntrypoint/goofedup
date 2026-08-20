// Bounded in-memory alert history for the tray app's "Show recent alerts"
// window -- newest first, capped so a noisy session can't grow unbounded.

use crate::alert::{Alert, Level};
use std::sync::{Mutex, MutexGuard, PoisonError};

const CAP: usize = 200;

pub struct Entry {
    pub ts: String,
    pub level: Level,
    pub category: &'static str,
    pub message: String,
    pub evidence: Option<String>,
    pub suggested_action: Option<String>,
}

#[derive(Clone)]
pub struct EntrySnapshot {
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

/// The only critical sections held on this mutex are plain Vec
/// operations with no user code that can panic mid-lock, so a poison can
/// only happen from an unrelated crash elsewhere in the process -- in
/// that case the alert history is best-effort observability, not a
/// correctness-critical store, so recovering the guard and continuing is
/// the correct degraded behavior rather than cascading the panic into
/// every future history read/write.
fn lock_recovering<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl History {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
        }
    }

    pub fn push(&self, a: &Alert) {
        let mut entries = lock_recovering(&self.entries);
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
        lock_recovering(&self.entries)
            .iter()
            .any(|e| e.level == Level::Critical)
    }

    /// (critical_count, warn_count) across the retained history -- used for
    /// the tray tooltip's at-a-glance status text. "Today" in name only:
    /// the bounded 200-entry retention window is a reasonable proxy for
    /// "recent" without tracking a separate day boundary.
    pub fn counts_today(&self) -> (usize, usize) {
        let entries = lock_recovering(&self.entries);
        let critical = entries.iter().filter(|e| e.level == Level::Critical).count();
        let warn = entries.iter().filter(|e| e.level == Level::Warn).count();
        (critical, warn)
    }

    pub fn clear_critical_flag(&self) {
        // Acknowledgement drops severity to Warn in the retained view so the
        // tray icon reverts without discarding history.
        let mut entries = lock_recovering(&self.entries);
        for e in entries.iter_mut() {
            if e.level == Level::Critical {
                e.level = Level::Warn;
            }
        }
    }

    pub fn entries_snapshot(&self) -> Vec<EntrySnapshot> {
        lock_recovering(&self.entries)
            .iter()
            .map(|e| EntrySnapshot {
                ts: e.ts.clone(),
                level: e.level,
                category: e.category,
                message: e.message.clone(),
                evidence: e.evidence.clone(),
                suggested_action: e.suggested_action.clone(),
            })
            .collect()
    }
}
