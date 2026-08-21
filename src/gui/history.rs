// Bounded in-memory alert history for the tray app's "Show recent alerts"
// window -- newest first, capped so a noisy session can't grow unbounded.

use crate::alert::{Alert, Level};
use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, MutexGuard, PoisonError};

const CAP: usize = 200;

pub struct Entry {
    pub ts: String,
    pub level: Level,
    pub category: &'static str,
    pub message: String,
    pub evidence: Option<String>,
}

#[derive(Clone)]
pub struct EntrySnapshot {
    pub ts: String,
    pub level: Level,
    pub category: &'static str,
    pub message: String,
    pub evidence: Option<String>,
}

pub enum GroupedEntry {
    Single(EntrySnapshot),
    Group {
        category: &'static str,
        key: String,
        representative_message: String,
        count: usize,
        members: Vec<EntrySnapshot>,
        acknowledged: bool,
    },
}

fn most_severe_level(levels: impl Iterator<Item = Level>) -> Level {
    levels
        .max_by_key(|l| match l {
            Level::Info => 0,
            Level::Warn => 1,
            Level::Critical => 2,
        })
        .unwrap_or(Level::Info)
}

impl GroupedEntry {
    pub fn level(&self) -> Level {
        match self {
            GroupedEntry::Single(e) => e.level,
            GroupedEntry::Group { members, .. } => most_severe_level(members.iter().map(|m| m.level)),
        }
    }

    pub fn category(&self) -> &'static str {
        match self {
            GroupedEntry::Single(e) => e.category,
            GroupedEntry::Group { category, .. } => category,
        }
    }

    pub fn newest_member_ts(&self) -> &str {
        match self {
            GroupedEntry::Single(e) => &e.ts,
            GroupedEntry::Group { members, .. } => members.first().map(|m| m.ts.as_str()).unwrap_or(""),
        }
    }

    pub fn headline(&self) -> String {
        match self {
            GroupedEntry::Single(e) => e.message.clone(),
            GroupedEntry::Group { category, count, representative_message, .. } => {
                format!("{category} \u{d7}{count} -- {representative_message}")
            }
        }
    }

    pub fn is_group(&self) -> bool {
        matches!(self, GroupedEntry::Group { .. })
    }

    pub fn is_acknowledged_group(&self) -> bool {
        matches!(self, GroupedEntry::Group { acknowledged: true, .. })
    }

    pub fn acknowledgeable_group_identity(&self) -> Option<(&'static str, &str)> {
        match self {
            GroupedEntry::Group { category, key, .. } => Some((category, key.as_str())),
            GroupedEntry::Single(_) => None,
        }
    }

    pub fn detail_text(&self) -> String {
        match self {
            GroupedEntry::Single(e) => e.evidence.clone().unwrap_or_else(no_evidence_placeholder),
            GroupedEntry::Group { members, .. } => members
                .iter()
                .map(|m| format!("[{}] {}", m.ts, m.evidence.as_deref().unwrap_or(NO_EVIDENCE_PLACEHOLDER)))
                .collect::<Vec<_>>()
                .join("\r\n\r\n"),
        }
    }
}

const NO_EVIDENCE_PLACEHOLDER: &str = "No further evidence recorded.";

fn no_evidence_placeholder() -> String {
    NO_EVIDENCE_PLACEHOLDER.to_string()
}

fn quoted_process_name(message: &str) -> Option<String> {
    let rest = message.strip_prefix('\'')?;
    let end = rest.find('\'')?;
    Some(rest[..end].to_string())
}

fn strip_measurement_parenthetical(text: &str) -> &str {
    match text.rfind('(') {
        Some(i) => text[..i].trim(),
        None => text.trim(),
    }
}

fn stable_reason_label(reason: &str) -> String {
    match reason.find(": ") {
        Some(i) => {
            let label = &reason[..i];
            let detail_list = &reason[i + ": ".len()..];
            format!("{}: {}", strip_measurement_parenthetical(label), detail_list.trim())
        }
        None => strip_measurement_parenthetical(reason).to_string(),
    }
}

fn reasons_label_signature(evidence: Option<&str>) -> String {
    let reasons_block = evidence.and_then(|ev| {
        let start = ev.find("reasons=[")? + "reasons=[".len();
        let end = ev[start..].find(']')? + start;
        Some(&ev[start..end])
    });
    match reasons_block {
        Some(reasons) => reasons
            .split("; ")
            .map(stable_reason_label)
            .collect::<Vec<_>>()
            .join("; "),
        None => String::new(),
    }
}

fn extract_group_key(e: &EntrySnapshot) -> Option<String> {
    let process_name = quoted_process_name(&e.message)?;
    match e.category {
        "file-read-burst" | "process-path" => Some(process_name),
        "c2-shaped-process" => {
            let reasons_signature = reasons_label_signature(e.evidence.as_deref());
            Some(format!("{process_name}\u{1}{reasons_signature}"))
        }
        _ => None,
    }
}

fn keys_with_multiple_members(entries: &[EntrySnapshot]) -> HashMap<(&'static str, String), usize> {
    let mut key_counts: HashMap<(&'static str, String), usize> = HashMap::new();
    for e in entries {
        if let Some(k) = extract_group_key(e) {
            *key_counts.entry((e.category, k)).or_insert(0) += 1;
        }
    }
    key_counts.into_iter().filter(|(_, count)| *count >= 2).collect()
}

fn group_entries(entries: Vec<EntrySnapshot>, acknowledged: &HashSet<(String, String)>) -> Vec<GroupedEntry> {
    let multi_member_keys = keys_with_multiple_members(&entries);

    let mut out: Vec<GroupedEntry> = Vec::new();
    let mut group_index_by_key: HashMap<(&'static str, String), usize> = HashMap::new();

    for e in entries {
        let multi_member_key = extract_group_key(&e)
            .filter(|k| multi_member_keys.contains_key(&(e.category, k.clone())));

        let Some(k) = multi_member_key else {
            out.push(GroupedEntry::Single(e));
            continue;
        };

        match group_index_by_key.get(&(e.category, k.clone())) {
            Some(&idx) => {
                if let Some(GroupedEntry::Group { count, members, .. }) = out.get_mut(idx) {
                    members.push(e);
                    *count += 1;
                }
            }
            None => {
                let category = e.category;
                let ack = acknowledged.contains(&(category.to_string(), k.clone()));
                let representative_message = e.message.clone();
                let idx = out.len();
                out.push(GroupedEntry::Group {
                    category,
                    key: k.clone(),
                    representative_message,
                    count: 1,
                    members: vec![e],
                    acknowledged: ack,
                });
                group_index_by_key.insert((category, k), idx);
            }
        }
    }
    out
}

pub struct History {
    entries: Mutex<Vec<Entry>>,
    acknowledged_groups: Mutex<Vec<(String, String)>>,
}

fn lock_recovering<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn currently_groupable_keys(entries: &[Entry]) -> HashSet<(&'static str, String)> {
    entries
        .iter()
        .filter_map(|e| {
            let snapshot = EntrySnapshot {
                ts: e.ts.clone(),
                level: e.level,
                category: e.category,
                message: e.message.clone(),
                evidence: e.evidence.clone(),
            };
            extract_group_key(&snapshot).map(|k| (e.category, k))
        })
        .collect()
}

impl History {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            acknowledged_groups: Mutex::new(Vec::new()),
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
            },
        );
        entries.truncate(CAP);
        let still_relevant = currently_groupable_keys(&entries);
        drop(entries);
        let mut acknowledged = lock_recovering(&self.acknowledged_groups);
        acknowledged.retain(|(category, key)| {
            still_relevant.contains(&(category.as_str(), key.clone()))
        });
    }

    pub fn has_unacknowledged_critical(&self) -> bool {
        lock_recovering(&self.entries)
            .iter()
            .any(|e| e.level == Level::Critical)
    }

    pub fn counts_today(&self) -> (usize, usize) {
        let entries = lock_recovering(&self.entries);
        let critical = entries.iter().filter(|e| e.level == Level::Critical).count();
        let warn = entries.iter().filter(|e| e.level == Level::Warn).count();
        (critical, warn)
    }

    pub fn clear_critical_flag(&self) {
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
            })
            .collect()
    }

    pub fn acknowledge_group(&self, category: &'static str, key: &str) {
        let mut acknowledged = lock_recovering(&self.acknowledged_groups);
        let tuple = (category.to_string(), key.to_string());
        if !acknowledged.contains(&tuple) {
            acknowledged.push(tuple);
        }
    }

    pub fn grouped_snapshot(&self) -> Vec<GroupedEntry> {
        let entries = self.entries_snapshot();
        let acknowledged: HashSet<(String, String)> =
            lock_recovering(&self.acknowledged_groups).iter().cloned().collect();
        group_entries(entries, &acknowledged)
    }
}
