// Persistence audit: services, scheduled tasks/cron, and login-item
// autostart entries. This is the layer that would have caught the real
// incident fastest -- a malicious payload that respawns needs to register
// SOMEWHERE durable, and every OS's durable-registration surfaces are a
// short, enumerable list. Runs a full audit at startup, then re-audits on
// the same poll interval as the process watcher and diffs against the
// previous snapshot so a NEWLY REGISTERED entry (not just "any entry exists,
// noisy on first run") is what actually triggers an alert.

use crate::alert::AlertSink;
use crate::config::Config;
use crate::heuristics::{is_denied_exec_path, score_command_line};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PersistenceEntry {
    pub kind: &'static str, // "service" | "scheduled-task" | "login-item" | "cron" | "launchd"
    pub name: String,
    pub command: String,
}

pub fn run(cfg: Arc<Config>, alerts: Arc<AlertSink>, running: Arc<AtomicBool>) {
    alerts.info(
        "persistence",
        "auditing services / scheduled tasks / login items for new or suspicious registrations",
    );

    let mut known: HashMap<PersistenceEntry, ()> = HashMap::new();
    let mut first_pass = true;

    while running.load(Ordering::Relaxed) {
        let current = enumerate();
        let mut current_map = HashMap::new();
        for entry in current {
            if !first_pass && !known.contains_key(&entry) {
                inspect_new_entry(&cfg, &alerts, &entry);
            }
            current_map.insert(entry, ());
        }
        if first_pass {
            alerts.info(
                "persistence",
                format!("baseline captured: {} persistence entries -- future NEW registrations will alert", current_map.len()),
            );
        }
        known = current_map;
        first_pass = false;

        std::thread::sleep(Duration::from_secs(cfg.poll_interval_secs * 10));
    }
}

fn inspect_new_entry(cfg: &Config, alerts: &AlertSink, entry: &PersistenceEntry) {
    let mut reasons = Vec::new();

    if let Some(reason) = is_denied_exec_path(&entry.command, &cfg.deny_exec_path_fragments) {
        reasons.push(format!("command references a denied path: {reason}"));
    }
    if let Some(v) = score_command_line(&entry.command) {
        reasons.push(format!(
            "command shaped like obfuscated payload (score={}, {})",
            v.score,
            v.reasons.join("; ")
        ));
    }

    let level_critical = !reasons.is_empty();
    let message = format!("new {} registered: '{}'", entry.kind, entry.name);
    let evidence = format!(
        "command={}{}",
        entry.command,
        if reasons.is_empty() {
            String::new()
        } else {
            format!("  [{}]", reasons.join(" | "))
        }
    );

    if level_critical {
        alerts.critical(
            "persistence-new",
            message,
            evidence,
            Some(suggest_review(entry)),
        );
    } else {
        // Any new persistence registration is worth a human glance even
        // without a matched heuristic -- most are legitimate installs, but
        // this is exactly the surface a quiet implant abuses, so it stays
        // WARN rather than silent.
        alerts.warn("persistence-new", message, evidence);
    }
}

fn suggest_review(entry: &PersistenceEntry) -> String {
    match entry.kind {
        #[cfg(windows)]
        "service" => format!("sc.exe qc \"{}\"   then: sc.exe delete \"{}\"", entry.name, entry.name),
        #[cfg(windows)]
        "scheduled-task" => format!(
            "schtasks /Query /TN \"{}\" /V /FO LIST   then: schtasks /Delete /TN \"{}\" /F",
            entry.name, entry.name
        ),
        #[cfg(windows)]
        "login-item" => "review HKCU/HKLM ...\\CurrentVersion\\Run and remove the offending value".to_string(),
        #[cfg(target_os = "macos")]
        "launchd" => format!("launchctl list | grep \"{}\"   then: launchctl bootout ...", entry.name),
        #[cfg(target_os = "linux")]
        "systemd" => format!("systemctl status \"{}\"   then: systemctl disable --now \"{}\"", entry.name, entry.name),
        #[cfg(target_os = "linux")]
        "cron" => "review crontab -l / /etc/cron.d and remove the offending line".to_string(),
        _ => "review and remove this persistence entry manually".to_string(),
    }
}

fn enumerate() -> Vec<PersistenceEntry> {
    #[cfg(windows)]
    {
        windows_impl::enumerate()
    }
    #[cfg(target_os = "macos")]
    {
        macos_impl::enumerate()
    }
    #[cfg(target_os = "linux")]
    {
        linux_impl::enumerate()
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        Vec::new()
    }
}

#[cfg(windows)]
mod windows_impl {
    use super::PersistenceEntry;
    use std::process::Command;

    pub fn enumerate() -> Vec<PersistenceEntry> {
        let mut out = Vec::new();
        out.extend(services());
        out.extend(scheduled_tasks());
        out.extend(run_keys());
        out
    }

    fn services() -> Vec<PersistenceEntry> {
        // `sc query` lists names only; the binary path needs a per-service
        // qc call which is expensive at scale, so services are tracked by
        // name+state here -- a NEW service name is itself the signal; a
        // human reviewing the alert runs the suggested `sc qc` for the path.
        let out = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "Get-CimInstance Win32_Service | Select-Object -Property Name,PathName | ConvertTo-Json -Compress",
            ])
            .output();
        parse_ps_json_list(out, "service", "Name", "PathName")
    }

    fn scheduled_tasks() -> Vec<PersistenceEntry> {
        let out = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "Get-ScheduledTask | ForEach-Object { $a = ($_.Actions | Select-Object -First 1); [PSCustomObject]@{ Name = $_.TaskName; PathName = \"$($a.Execute) $($a.Arguments)\" } } | ConvertTo-Json -Compress",
            ])
            .output();
        parse_ps_json_list(out, "scheduled-task", "Name", "PathName")
    }

    fn run_keys() -> Vec<PersistenceEntry> {
        let mut out = Vec::new();
        for hive_path in [
            "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        ] {
            let cmd = format!(
                "Get-ItemProperty '{hive_path}' -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty PS* | ConvertTo-Json -Compress"
            );
            let res = Command::new("powershell")
                .args(["-NoProfile", "-Command", &cmd])
                .output();
            if let Ok(o) = res {
                if let Ok(text) = String::from_utf8(o.stdout) {
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&text) {
                        if let serde_json::Value::Object(map) = val {
                            for (k, v) in map {
                                if let Some(cmd_str) = v.as_str() {
                                    out.push(PersistenceEntry {
                                        kind: "login-item",
                                        name: k,
                                        command: cmd_str.to_string(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        out
    }

    fn parse_ps_json_list(
        res: std::io::Result<std::process::Output>,
        kind: &'static str,
        name_field: &str,
        cmd_field: &str,
    ) -> Vec<PersistenceEntry> {
        let mut out = Vec::new();
        let Ok(o) = res else { return out };
        let Ok(text) = String::from_utf8(o.stdout) else {
            return out;
        };
        let Ok(val) = serde_json::from_str::<serde_json::Value>(&text) else {
            return out;
        };
        let items: Vec<&serde_json::Value> = match &val {
            serde_json::Value::Array(a) => a.iter().collect(),
            serde_json::Value::Object(_) => vec![&val],
            _ => vec![],
        };
        for item in items {
            let name = item
                .get(name_field)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let command = item
                .get(cmd_field)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if !name.is_empty() {
                out.push(PersistenceEntry { kind, name, command });
            }
        }
        out
    }
}

#[cfg(target_os = "macos")]
mod macos_impl {
    use super::PersistenceEntry;
    use std::fs;
    use std::process::Command;

    pub fn enumerate() -> Vec<PersistenceEntry> {
        let mut out = Vec::new();
        for dir in [
            "/Library/LaunchAgents",
            "/Library/LaunchDaemons",
            "/System/Library/LaunchAgents",
            "/System/Library/LaunchDaemons",
        ] {
            out.extend(scan_plist_dir(dir));
        }
        if let Ok(home) = std::env::var("HOME") {
            out.extend(scan_plist_dir(&format!("{home}/Library/LaunchAgents")));
        }
        out.extend(login_items());
        out
    }

    fn scan_plist_dir(dir: &str) -> Vec<PersistenceEntry> {
        let mut out = Vec::new();
        let Ok(entries) = fs::read_dir(dir) else {
            return out;
        };
        for e in entries.flatten() {
            let path = e.path();
            if path.extension().and_then(|s| s.to_str()) != Some("plist") {
                continue;
            }
            let name = path
                .file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            let command = fs::read_to_string(&path)
                .ok()
                .and_then(|content| {
                    // Cheap extraction, not a real plist parser: pull the
                    // first <string> after ProgramArguments as a best-effort
                    // command summary for the alert evidence -- good enough
                    // to show a human what's registered without pulling in
                    // a plist crate for a summary field.
                    content
                        .find("ProgramArguments")
                        .and_then(|i| content[i..].find("<string>").map(|j| i + j))
                        .and_then(|i| {
                            let rest = &content[i + 8..];
                            rest.find("</string>").map(|j| rest[..j].to_string())
                        })
                })
                .unwrap_or_default();
            out.push(PersistenceEntry {
                kind: "launchd",
                name,
                command,
            });
        }
        out
    }

    fn login_items() -> Vec<PersistenceEntry> {
        let res = Command::new("osascript")
            .args(["-e", "tell application \"System Events\" to get the name of every login item"])
            .output();
        let mut out = Vec::new();
        if let Ok(o) = res {
            if let Ok(text) = String::from_utf8(o.stdout) {
                for name in text.trim().split(", ") {
                    if !name.is_empty() {
                        out.push(PersistenceEntry {
                            kind: "login-item",
                            name: name.to_string(),
                            command: String::new(),
                        });
                    }
                }
            }
        }
        out
    }
}

#[cfg(target_os = "linux")]
mod linux_impl {
    use super::PersistenceEntry;
    use std::fs;
    use std::process::Command;

    pub fn enumerate() -> Vec<PersistenceEntry> {
        let mut out = Vec::new();
        out.extend(systemd_units());
        out.extend(cron_entries());
        out
    }

    fn systemd_units() -> Vec<PersistenceEntry> {
        let mut out = Vec::new();
        let res = Command::new("systemctl")
            .args(["list-unit-files", "--type=service", "--state=enabled", "--no-legend", "--no-pager"])
            .output();
        if let Ok(o) = res {
            if let Ok(text) = String::from_utf8(o.stdout) {
                for line in text.lines() {
                    if let Some(name) = line.split_whitespace().next() {
                        let exec_start = Command::new("systemctl")
                            .args(["show", name, "-p", "ExecStart", "--no-pager"])
                            .output()
                            .ok()
                            .and_then(|o2| String::from_utf8(o2.stdout).ok())
                            .unwrap_or_default();
                        out.push(PersistenceEntry {
                            kind: "systemd",
                            name: name.to_string(),
                            command: exec_start.trim().to_string(),
                        });
                    }
                }
            }
        }
        out
    }

    fn cron_entries() -> Vec<PersistenceEntry> {
        let mut out = Vec::new();
        if let Ok(o) = Command::new("crontab").args(["-l"]).output() {
            if let Ok(text) = String::from_utf8(o.stdout) {
                for (i, line) in text.lines().enumerate() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    out.push(PersistenceEntry {
                        kind: "cron",
                        name: format!("crontab-line-{i}"),
                        command: line.to_string(),
                    });
                }
            }
        }
        for dir in ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly"] {
            if let Ok(entries) = fs::read_dir(dir) {
                for e in entries.flatten() {
                    let name = e.file_name().to_string_lossy().to_string();
                    let command = fs::read_to_string(e.path()).unwrap_or_default();
                    out.push(PersistenceEntry {
                        kind: "cron",
                        name: format!("{dir}/{name}"),
                        command,
                    });
                }
            }
        }
        out
    }
}
