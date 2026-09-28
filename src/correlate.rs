use crate::alert::{Alert, AlertSink};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const CORRELATION_WINDOW: Duration = Duration::from_secs(60);

#[derive(Clone)]
struct Seen {
    at: Instant,
    category: &'static str,
    message: String,
    evidence: String,
}

pub struct Correlator {
    last_process_signal: Mutex<Option<Seen>>,
    last_file_signal: Mutex<Option<Seen>>,
}

impl Correlator {
    pub fn new() -> Self {
        Self {
            last_process_signal: Mutex::new(None),
            last_file_signal: Mutex::new(None),
        }
    }

    pub fn on_alert(&self, a: &Alert, sink: &AlertSink) {
        let is_process_signal = a.category == "c2-shaped-process";
        let is_file_signal = a.category == "backup-sibling" || a.category == "bootstrap-size";
        if !is_process_signal && !is_file_signal {
            return;
        }

        let this_seen = Seen {
            at: Instant::now(),
            category: a.category,
            message: a.message.clone(),
            evidence: a.evidence.clone().unwrap_or_default(),
        };

        if is_process_signal {
            let other = self.recent_within_window(&self.last_file_signal);
            if let Some(file_seen) = other {
                emit_confirmed_compromise(sink, &this_seen, &file_seen);
            }
            self.store(&self.last_process_signal, this_seen);
        } else {
            let other = self.recent_within_window(&self.last_process_signal);
            if let Some(process_seen) = other {
                emit_confirmed_compromise(sink, &process_seen, &this_seen);
            }
            self.store(&self.last_file_signal, this_seen);
        }
    }

    fn recent_within_window(&self, slot: &Mutex<Option<Seen>>) -> Option<Seen> {
        let guard = slot.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        guard
            .as_ref()
            .filter(|s| s.at.elapsed() <= CORRELATION_WINDOW)
            .cloned()
    }

    fn store(&self, slot: &Mutex<Option<Seen>>, seen: Seen) {
        *slot.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(seen);
    }
}

impl Default for Correlator {
    fn default() -> Self {
        Self::new()
    }
}

fn emit_confirmed_compromise(sink: &AlertSink, process: &Seen, file: &Seen) {
    sink.critical(
        "CONFIRMED-COMPROMISE",
        format!(
            "a c2-shaped-process alert and a {} alert fired within {}s of each other -- almost certainly the same event, not two coincidences: {} AND {}",
            file.category,
            CORRELATION_WINDOW.as_secs(),
            process.message,
            file.message
        ),
        format!(
            "process[{}]: {} || file[{}]: {}",
            process.category, process.evidence, file.category, file.evidence
        ),
    );
}
