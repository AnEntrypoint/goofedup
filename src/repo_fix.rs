use crate::alert::{AlertSink, Level};
use crate::jsonc;
use crate::scan_repo::{analyze_file, walk_files, Remedy, Scope};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[derive(Default)]
struct Plan {
    files: BTreeSet<PathBuf>,
    dirs: BTreeSet<PathBuf>,
    strips: BTreeMap<PathBuf, BTreeSet<String>>,
}

fn plan_for(root: &Path) -> Plan {
    let mut plan = Plan::default();
    for path in walk_files(root) {
        for finding in analyze_file(&path, Scope::Live) {
            if finding.level != Level::Critical {
                continue;
            }
            match finding.remedy {
                Some(Remedy::QuarantineFile(file)) => {
                    plan.files.insert(file);
                }
                Some(Remedy::QuarantineDir(dir)) => {
                    plan.dirs.insert(dir);
                }
                Some(Remedy::StripSettingsKeys { path, keys }) => {
                    plan.strips.entry(path).or_default().extend(keys);
                }
                None => {}
            }
        }
    }
    let dirs = plan.dirs.clone();
    plan.files.retain(|file| !dirs.iter().any(|dir| file.starts_with(dir)));
    plan
}

fn quarantine_destination(original: &Path) -> Result<PathBuf, String> {
    let dir = crate::config::dirs_home().join(".goofedup").join("quarantine");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S%.3f");
    let flattened = original.to_string_lossy().replace(['\\', '/', ':'], "_");
    Ok(dir.join(format!("{flattened}.{stamp}")))
}

fn copy_recursively(from: &Path, to: &Path) -> std::io::Result<()> {
    if from.is_dir() {
        std::fs::create_dir_all(to)?;
        for entry in std::fs::read_dir(from)? {
            let entry = entry?;
            copy_recursively(&entry.path(), &to.join(entry.file_name()))?;
        }
        Ok(())
    } else {
        std::fs::copy(from, to).map(|_| ())
    }
}

fn remove_original(path: &Path) -> std::io::Result<()> {
    if path.is_dir() {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    }
}

fn quarantine(original: &Path) -> Result<PathBuf, String> {
    let destination = quarantine_destination(original)?;
    if std::fs::rename(original, &destination).is_ok() {
        return Ok(destination);
    }
    copy_recursively(original, &destination).map_err(|e| e.to_string())?;
    remove_original(original).map_err(|e| e.to_string())?;
    Ok(destination)
}

fn strip_settings_keys(path: &Path, keys: &BTreeSet<String>) -> Result<PathBuf, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let key_refs: Vec<&str> = keys.iter().map(String::as_str).collect();
    let stripped = jsonc::remove_top_level_keys(&text, &key_refs)
        .ok_or("keys are not top-level members this tool can isolate; edit by hand")?;
    if jsonc::parse(&stripped).is_none() {
        return Err("stripped result would not parse; left untouched".to_string());
    }
    let backup = quarantine_destination(path)?;
    std::fs::copy(path, &backup).map_err(|e| e.to_string())?;
    let staging = path.with_extension("json.goofedup-tmp");
    std::fs::write(&staging, stripped).map_err(|e| e.to_string())?;
    std::fs::rename(&staging, path).map_err(|e| e.to_string())?;
    Ok(backup)
}

fn announce(alerts: &AlertSink, apply: bool, action: String) {
    alerts.warn(
        "repo-fix",
        format!("{} {action}", if apply { "about to" } else { "would" }),
        if apply {
            "originals move to ~/.goofedup/quarantine and are never deleted"
        } else {
            "originals would move to ~/.goofedup/quarantine, never deleted -- pass --fix to apply"
        },
    );
}

fn report_outcome(alerts: &AlertSink, done: String, outcome: Result<PathBuf, String>) {
    match outcome {
        Ok(kept_at) => alerts.critical(
            "repo-fix",
            format!("{done} -- original preserved (not deleted) at '{}'", kept_at.display()),
            String::new(),
        ),
        Err(e) => alerts.critical("repo-fix", format!("FAILED: {done} -- left untouched"), e),
    }
}

pub fn remediate_tree(root: &Path, alerts: &AlertSink, apply: bool) -> usize {
    let plan = plan_for(root);
    let total = plan.files.len() + plan.dirs.len() + plan.strips.len();
    if total == 0 {
        alerts.info("repo-fix", format!("no quarantinable repo-compromise findings under {}", root.display()));
        return 0;
    }
    for dir in &plan.dirs {
        let done = format!("quarantined decoy directory '{}'", dir.display());
        announce(alerts, apply, format!("quarantine decoy directory '{}'", dir.display()));
        if apply {
            report_outcome(alerts, done, quarantine(dir));
        }
    }
    for file in &plan.files {
        let done = format!("quarantined '{}'", file.display());
        announce(alerts, apply, format!("quarantine '{}'", file.display()));
        if apply {
            report_outcome(alerts, done, quarantine(file));
        }
    }
    for (path, keys) in &plan.strips {
        let listed = keys.iter().cloned().collect::<Vec<_>>().join(", ");
        let done = format!("removed injected key(s) [{listed}] from '{}'", path.display());
        announce(alerts, apply, format!("remove injected key(s) [{listed}] from '{}', keeping every other setting", path.display()));
        if apply {
            report_outcome(alerts, done, strip_settings_keys(path, keys));
        }
    }
    if apply {
        let remaining = walk_files(root)
            .flat_map(|path| analyze_file(&path, Scope::Live))
            .filter(|f| f.level == Level::Critical && f.remedy.is_some())
            .count();
        alerts.info("repo-fix", format!("re-scan after fix: {remaining} quarantinable critical finding(s) remain"));
    }
    total
}
