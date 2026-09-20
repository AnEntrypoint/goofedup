// Cross-detector correlation: on a real live catch, the process-level tell
// (c2-shaped-process -- score, embedded IP, cmdline) and the file-level tell
// that follows a few seconds later (backup-sibling / bootstrap-size -- the
// tampered bootstrap path) are today two entirely separate, uncorrelated log
// lines. Live-witnessed cost of that: reconstructing that the 2026-08-24 and
// 2026-09-04 Discord hits were ONE event required a human manually grepping
// timestamps and eyeballing the sequence. Both detectors already work --
// this module just recognizes that a c2-shaped-process alert and a
// backup-sibling/bootstrap-size alert arriving within a short window of each
// other are almost certainly the same real compromise, and says so in one
// combined, higher-severity line that carries both halves of the evidence
// (process PID/cmdline/embedded IP AND the tampered file path) together.
// Still alert-only: this never changes what the underlying detectors do,
// only adds one more alert that references two that already fired.

use crate::alert::{Alert, AlertSink};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How close together (either order) a c2-shaped-process alert and a
/// backup-sibling/bootstrap-size alert must fire to be treated as the same
/// event. Matches the live-witnessed real gap between the two halves of the
/// 2026-08-24/2026-09-04 Discord catches ("seconds later" per incident
/// notes) with generous headroom for a slower disk/notify latency.
const CORRELATION_WINDOW: Duration = Duration::from_secs(60);

#[derive(Clone)]
struct Seen {
    at: Instant,
    category: &'static str,
    message: String,
    evidence: String,
}

/// Tracks the most recent alert of each half of the pair (process-level,
/// file-level) so that whichever one arrives SECOND can look back and find
/// the other one still inside the correlation window, regardless of which
/// order they actually fire in on a given machine.
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

    /// Callback body for AlertSink. Only c2-shaped-process, backup-sibling,
    /// and bootstrap-size alerts are inspected; everything else (including
    /// this module's own CONFIRMED-COMPROMISE output, which shares neither
    /// category name) passes through untouched -- no risk of the combined
    /// alert re-triggering itself.
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
