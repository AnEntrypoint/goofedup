use crate::alert::{AlertSink, Level};
use crate::audit_win::{self, Finding, Tier};
use crate::config::SharedConfig;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

const CATEGORY: &str = "tamper";
const COLLAPSED_POLLS_BEFORE_ACCEPTED: u8 = 2;
const DISABLED_RECHECK_SECS: u64 = 30;

struct Tracked {
    category: &'static str,
    fingerprint: String,
}

struct Baseline {
    label: &'static str,
    known: Option<HashMap<String, Tracked>>,
    collapsed_polls: HashMap<&'static str, u8>,
}

fn count_by_category(categories: impl Iterator<Item = &'static str>) -> HashMap<&'static str, usize> {
    let mut counts = HashMap::new();
    for category in categories {
        *counts.entry(category).or_insert(0) += 1;
    }
    counts
}

impl Baseline {
    fn new(label: &'static str) -> Self {
        Self { label, known: None, collapsed_polls: HashMap::new() }
    }

    fn capture(&mut self, current: &[Finding], alerts: &AlertSink) {
        let critical = current.iter().filter(|f| f.level == Level::Critical).count();
        let warn = current.iter().filter(|f| f.level == Level::Warn).count();
        alerts.info(
            CATEGORY,
            format!(
                "{} baseline captured: {} findings ({critical} critical, {warn} warn) -- only NEW or CHANGED findings alert from here; run `goofedup --audit` for the full report",
                self.label,
                current.len()
            ),
        );
        self.known = Some(
            current
                .iter()
                .map(|f| (f.key.clone(), Tracked { category: f.category, fingerprint: f.fingerprint() }))
                .collect(),
        );
    }

    fn categories_with_suspicious_collapse(&mut self, current: &[Finding]) -> HashSet<&'static str> {
        let Some(known) = self.known.as_ref() else { return HashSet::new() };
        let before = count_by_category(known.values().map(|t| t.category));
        let now = count_by_category(current.iter().map(|f| f.category));
        let mut guarded = HashSet::new();
        for (category, was) in before {
            let is_now = now.get(category).copied().unwrap_or(0);
            if is_now * 2 >= was {
                self.collapsed_polls.remove(category);
                continue;
            }
            let streak = self.collapsed_polls.entry(category).or_insert(0);
            *streak += 1;
            if *streak < COLLAPSED_POLLS_BEFORE_ACCEPTED {
                guarded.insert(category);
            } else {
                self.collapsed_polls.remove(category);
            }
        }
        guarded
    }

    fn observe(&mut self, current: Vec<Finding>, alerts: &AlertSink) {
        if self.known.is_none() {
            self.capture(&current, alerts);
            return;
        }
        let guarded = self.categories_with_suspicious_collapse(&current);
        let Some(known) = self.known.as_mut() else { return };
        let seen: HashSet<&str> = current.iter().map(|f| f.key.as_str()).collect();
        for finding in &current {
            let fingerprint = finding.fingerprint();
            let verdict = match known.get(&finding.key) {
                None => Some("new"),
                Some(previous) if previous.fingerprint != fingerprint => Some("changed"),
                Some(_) => None,
            };
            if let (Some(what), true) = (verdict, finding.worth_alerting()) {
                emit(alerts, what, finding);
            }
            known.insert(finding.key.clone(), Tracked { category: finding.category, fingerprint });
        }
        known.retain(|key, tracked| seen.contains(key.as_str()) || guarded.contains(tracked.category));
    }
}

fn emit(alerts: &AlertSink, what: &str, finding: &Finding) {
    let message = format!("{what}: {}", finding.title);
    match finding.level {
        Level::Critical => alerts.critical(finding.category, message, finding.evidence.clone()),
        _ => alerts.warn(finding.category, message, finding.evidence.clone()),
    }
}

fn sleep_while_running(running: &AtomicBool, secs: u64) {
    for _ in 0..secs {
        if !running.load(Ordering::Relaxed) {
            return;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

pub fn run(cfg_shared: SharedConfig, alerts: Arc<AlertSink>, running: Arc<AtomicBool>) {
    alerts.info(
        CATEGORY,
        "auditing portproxy rules, exposed listeners, inbound firewall allows, SYSTEM tasks/services, Defender, root certs, hosts, local admins, credential files and autoruns for new or changed findings",
    );
    let mut native = Baseline::new("posture");
    let mut shell = Baseline::new("shell-backed posture (Defender status, WMI subscriptions)");
    let mut poll: u32 = 0;

    while running.load(Ordering::Relaxed) {
        let cfg = cfg_shared.read().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
        if !cfg.tamper.enabled {
            sleep_while_running(&running, DISABLED_RECHECK_SECS);
            continue;
        }
        native.observe(audit_win::collect(Tier::Native, &cfg.tamper), &alerts);
        if poll % cfg.tamper.shell_scan_every_polls == 0 {
            shell.observe(audit_win::collect(Tier::Shell, &cfg.tamper), &alerts);
        }
        poll = poll.wrapping_add(1);
        sleep_while_running(&running, cfg.poll_interval_secs * cfg.tamper.poll_multiplier);
    }
}
