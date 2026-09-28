use crate::alert::{Alert, AlertSink, Level};
use crate::config::{apply_overrides, Config, SharedConfig};
use crate::config_reload::{load_config_with_overrides, load_overrides_from_file};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::hash::Hasher;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const TRUST_LISTS: [&str; 5] = [
    "allowed_exec_roots",
    "os_vendor_roots",
    "known_high_throughput_tool_names",
    "known_automation_parent_names",
    "known_benign_event_sources",
];

const DETECTION_LISTS: [&str; 4] = [
    "watched_interpreters",
    "deny_exec_path_fragments",
    "backup_sibling_roots",
    "bootstrap_watch",
];

const LOOSER_WHEN_HIGHER: [&str; 11] = [
    "poll_interval_secs",
    "scan_distinct_ports_threshold",
    "scan_distinct_hosts_threshold",
    "file_read_burst_absolute_bytes_per_poll",
    "file_read_burst_relative_multiplier",
    "file_read_burst_uncorroborated_ceiling_bytes",
    "known_high_throughput_tool_multiplier",
    "read_burst_required_spikes_in_window",
    "read_burst_baseline_exemption_multiplier",
    "read_burst_baseline_warm_up_floor_bytes",
    "read_burst_corroborated_threshold_fraction",
];

const LOOSER_WHEN_LOWER: [&str; 1] = ["c2_max_decode_depth"];

#[derive(Serialize, Deserialize, Default, Clone, PartialEq)]
struct Snapshot {
    version: String,
    lists: BTreeMap<String, Vec<String>>,
    numbers: BTreeMap<String, f64>,
    log_path: String,
}

fn snapshot(cfg: &Config) -> Snapshot {
    let paths = |v: &[PathBuf]| v.iter().map(|p| p.display().to_string()).collect::<Vec<_>>();
    let lists = BTreeMap::from([
        ("allowed_exec_roots".to_string(), paths(&cfg.allowed_exec_roots)),
        ("os_vendor_roots".to_string(), paths(&cfg.os_vendor_roots)),
        ("known_high_throughput_tool_names".to_string(), cfg.known_high_throughput_tool_names.clone()),
        ("known_automation_parent_names".to_string(), cfg.known_automation_parent_names.clone()),
        ("known_benign_event_sources".to_string(), cfg.known_benign_event_sources.clone()),
        ("watched_interpreters".to_string(), cfg.watched_interpreters.clone()),
        ("deny_exec_path_fragments".to_string(), cfg.deny_exec_path_fragments.clone()),
        ("backup_sibling_roots".to_string(), paths(&cfg.backup_sibling_roots)),
        (
            "bootstrap_watch".to_string(),
            cfg.bootstrap_watch
                .iter()
                .map(|e| format!("{}|{}|{}|max={}", e.search_root.display(), e.file_name, e.path_must_contain, e.max_bytes))
                .collect(),
        ),
    ]);
    let numbers = BTreeMap::from([
        ("poll_interval_secs".to_string(), cfg.poll_interval_secs as f64),
        ("scan_distinct_ports_threshold".to_string(), cfg.scan_distinct_ports_threshold as f64),
        ("scan_distinct_hosts_threshold".to_string(), cfg.scan_distinct_hosts_threshold as f64),
        ("file_read_burst_absolute_bytes_per_poll".to_string(), cfg.file_read_burst_absolute_bytes_per_poll as f64),
        ("file_read_burst_relative_multiplier".to_string(), cfg.file_read_burst_relative_multiplier),
        ("file_read_burst_uncorroborated_ceiling_bytes".to_string(), cfg.file_read_burst_uncorroborated_ceiling_bytes as f64),
        ("known_high_throughput_tool_multiplier".to_string(), cfg.known_high_throughput_tool_multiplier),
        ("read_burst_required_spikes_in_window".to_string(), cfg.read_burst_required_spikes_in_window as f64),
        ("read_burst_baseline_exemption_multiplier".to_string(), cfg.read_burst_baseline_exemption_multiplier),
        ("read_burst_baseline_warm_up_floor_bytes".to_string(), cfg.read_burst_baseline_warm_up_floor_bytes),
        ("read_burst_corroborated_threshold_fraction".to_string(), cfg.read_burst_corroborated_threshold_fraction),
        ("c2_max_decode_depth".to_string(), cfg.c2_max_decode_depth as f64),
    ]);
    Snapshot {
        version: env!("CARGO_PKG_VERSION").to_string(),
        lists,
        numbers,
        log_path: cfg.log_path.display().to_string(),
    }
}

struct ConfigDiff {
    lines: Vec<String>,
    list_loosened: bool,
    number_loosened: bool,
    log_path_changed: bool,
}

fn diff_snapshots(before: &Snapshot, after: &Snapshot) -> ConfigDiff {
    let mut d = ConfigDiff { lines: Vec::new(), list_loosened: false, number_loosened: false, log_path_changed: false };
    for (name, now) in &after.lists {
        let old = before.lists.get(name).cloned().unwrap_or_default();
        let old_set: BTreeSet<_> = old.iter().collect();
        let now_set: BTreeSet<_> = now.iter().collect();
        let added: Vec<_> = now_set.difference(&old_set).map(|s| s.to_string()).collect();
        let removed: Vec<_> = old_set.difference(&now_set).map(|s| s.to_string()).collect();
        if added.is_empty() && removed.is_empty() {
            continue;
        }
        d.list_loosened |= (TRUST_LISTS.contains(&name.as_str()) && !added.is_empty())
            || (DETECTION_LISTS.contains(&name.as_str()) && !removed.is_empty());
        d.lines.push(format!("{name} +[{}] -[{}]", added.join(", "), removed.join(", ")));
    }
    for (name, now) in &after.numbers {
        let old = before.numbers.get(name).copied().unwrap_or(*now);
        if (old - now).abs() < f64::EPSILON {
            continue;
        }
        d.number_loosened |= (LOOSER_WHEN_HIGHER.contains(&name.as_str()) && *now > old)
            || (LOOSER_WHEN_LOWER.contains(&name.as_str()) && *now < old);
        d.lines.push(format!("{name} {old}->{now}"));
    }
    if before.log_path != after.log_path {
        d.log_path_changed = true;
        d.lines.push(format!("log_path {}->{}", before.log_path, after.log_path));
    }
    d
}

fn report_config_change(alerts: &AlertSink, path: &Path, d: &ConfigDiff, context: &str) {
    if d.lines.is_empty() {
        return;
    }
    let (level, verdict) = if d.list_loosened {
        (Level::Critical, "trust LOOSENED (allowlist grew or a detection list shrank)")
    } else if d.number_loosened || d.log_path_changed {
        (Level::Warn, "detector thresholds loosened or log redirected")
    } else {
        (Level::Info, "tightened or neutral")
    };
    alerts.emit(Alert {
        level,
        category: "self-protect-config",
        message: format!("override file {} {context}: {verdict}", path.display()),
        evidence: Some(d.lines.join(" ; ")),
    });
}

fn baseline_path(override_file: &Path) -> PathBuf {
    override_file.with_file_name("config.baseline.json")
}

fn write_atomically(path: &Path, text: &str) {
    let staging = path.with_extension("tmp");
    if std::fs::write(&staging, text).is_ok() {
        let _ = std::fs::rename(&staging, path);
    }
}

fn save_baseline(override_file: &Path, snap: &Snapshot) {
    if let Ok(text) = serde_json::to_string_pretty(snap) {
        write_atomically(&baseline_path(override_file), &text);
    }
}

fn load_baseline(override_file: &Path) -> Option<Snapshot> {
    let text = std::fs::read_to_string(baseline_path(override_file)).ok()?;
    serde_json::from_str(&text).ok()
}

fn unix_ms() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)
}

fn write_heartbeat(path: &Path, poll_secs: u64, state: &str) {
    let body = format!(
        "{{\"pid\":{},\"unix_ms\":{},\"poll_interval_secs\":{poll_secs},\"state\":\"{state}\"}}",
        std::process::id(),
        unix_ms()
    );
    write_atomically(path, &body);
}

#[derive(Clone, PartialEq)]
struct FileIdentity {
    len: u64,
    created: Option<SystemTime>,
}

fn file_identity(path: &Path) -> Option<FileIdentity> {
    let meta = std::fs::metadata(path).ok()?;
    Some(FileIdentity { len: meta.len(), created: meta.created().ok() })
}

fn check_log_file(alerts: &AlertSink, path: &Path, previous: &mut Option<FileIdentity>) {
    let current = file_identity(path);
    match (&*previous, &current) {
        (Some(_), None) => alerts.critical(
            "self-protect-log",
            format!("goofedup log file was deleted: {}", path.display()),
            "the alert history on disk is gone; this alert starts the new file",
        ),
        (Some(before), Some(now)) if now.len < before.len => alerts.critical(
            "self-protect-log",
            format!("goofedup log file was truncated: {}", path.display()),
            format!("length {} -> {} bytes", before.len, now.len),
        ),
        (Some(before), Some(now)) if before.created.is_some() && now.created != before.created => alerts.critical(
            "self-protect-log",
            format!("goofedup log file was replaced by a different file: {}", path.display()),
            format!("creation time changed; length {} -> {} bytes", before.len, now.len),
        ),
        _ => {}
    }
    *previous = file_identity(path);
}

struct BinaryState {
    path: PathBuf,
    len: u64,
    modified: Option<SystemTime>,
    digest: u64,
    alerted: bool,
}

fn content_digest(path: &Path) -> Option<u64> {
    let bytes = std::fs::read(path).ok()?;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    hasher.write(&bytes);
    Some(hasher.finish())
}

impl BinaryState {
    fn capture() -> Option<Self> {
        let path = std::env::current_exe().ok()?;
        let meta = std::fs::metadata(&path).ok()?;
        Some(Self {
            digest: content_digest(&path)?,
            len: meta.len(),
            modified: meta.modified().ok(),
            path,
            alerted: false,
        })
    }

    fn check(&mut self, alerts: &AlertSink) {
        let Ok(meta) = std::fs::metadata(&self.path) else {
            if !self.alerted {
                self.alerted = true;
                alerts.critical(
                    "self-protect-binary",
                    format!("goofedup's own binary is gone from {} (renamed or deleted after start)", self.path.display()),
                    "the running process keeps executing the old image",
                );
            }
            return;
        };
        if meta.len() == self.len && meta.modified().ok() == self.modified {
            return;
        }
        self.len = meta.len();
        self.modified = meta.modified().ok();
        let replaced = content_digest(&self.path).is_some_and(|d| d != self.digest);
        if replaced {
            self.alerted = true;
            alerts.critical(
                "self-protect-binary",
                format!("goofedup's own binary was replaced on disk after start: {}", self.path.display()),
                format!("length now {} bytes; the running process is still the old image", meta.len()),
            );
        }
    }
}

#[cfg(windows)]
mod acl {
    use crate::win_identity::{self, sid_to_string};
    use std::ffi::c_void;
    use std::path::Path;
    use windows::core::HSTRING;
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows::Win32::Security::{
        AclSizeInformation, GetAce, GetAclInformation, ACL, ACL_SIZE_INFORMATION,
        DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    };

    const WRITE_MASK: u32 = 0x2 | 0x4 | 0x40 | 0x10000 | 0x40000 | 0x80000 | 0x1000_0000 | 0x4000_0000;
    const ACE_INHERIT_ONLY: u8 = 0x08;
    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
    const ACCESS_ALLOWED_CALLBACK_ACE_TYPE: u8 = 9;

    pub struct Descriptor {
        pub owner: Option<String>,
        pub writers: Vec<String>,
        pub null_dacl: bool,
    }

    pub fn read(path: &Path) -> Result<Descriptor, String> {
        unsafe {
            let mut owner = PSID::default();
            let mut dacl: *mut ACL = std::ptr::null_mut();
            let mut descriptor = PSECURITY_DESCRIPTOR::default();
            GetNamedSecurityInfoW(
                &HSTRING::from(path.to_string_lossy().as_ref()),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                Some(&mut owner),
                None,
                Some(&mut dacl),
                None,
                &mut descriptor,
            )
            .ok()
            .map_err(|e| e.to_string())?;
            let result = collect(owner, dacl);
            let _ = LocalFree(HLOCAL(descriptor.0));
            result
        }
    }

    unsafe fn collect(owner: PSID, dacl: *mut ACL) -> Result<Descriptor, String> {
        let owner = sid_to_string(owner);
        if dacl.is_null() {
            return Ok(Descriptor { owner, writers: Vec::new(), null_dacl: true });
        }
        let mut info = ACL_SIZE_INFORMATION::default();
        GetAclInformation(
            dacl,
            &mut info as *mut _ as *mut c_void,
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
        .map_err(|e| e.to_string())?;
        let mut writers = Vec::new();
        for index in 0..info.AceCount {
            let mut ace: *mut c_void = std::ptr::null_mut();
            if GetAce(dacl, index, &mut ace).is_err() {
                continue;
            }
            let bytes = ace as *const u8;
            let ace_type = *bytes;
            let flags = *bytes.add(1);
            let allows = ace_type == ACCESS_ALLOWED_ACE_TYPE || ace_type == ACCESS_ALLOWED_CALLBACK_ACE_TYPE;
            if !allows || flags & ACE_INHERIT_ONLY != 0 {
                continue;
            }
            let mask = *(bytes.add(4) as *const u32);
            if mask & WRITE_MASK == 0 {
                continue;
            }
            if let Some(sid) = sid_to_string(PSID(bytes.add(8) as *mut c_void)) {
                writers.push(sid);
            }
        }
        Ok(Descriptor { owner, writers, null_dacl: false })
    }

    pub fn trusted_writer_sids(descriptor: &Descriptor) -> Vec<String> {
        let mut trusted = vec![
            win_identity::SID_SYSTEM.to_string(),
            win_identity::SID_ADMINISTRATORS.to_string(),
            win_identity::SID_CREATOR_OWNER.to_string(),
            win_identity::SID_TRUSTED_INSTALLER.to_string(),
        ];
        trusted.extend(descriptor.owner.clone());
        trusted.extend(win_identity::current_user_sid());
        trusted
    }

    pub fn friendly(sid: &str) -> String {
        match sid {
            win_identity::SID_EVERYONE => "Everyone".to_string(),
            win_identity::SID_AUTHENTICATED_USERS => "Authenticated Users".to_string(),
            win_identity::SID_USERS => "BUILTIN\\Users".to_string(),
            other => win_identity::account_name(other).unwrap_or_else(|| other.to_string()),
        }
    }
}

#[cfg(windows)]
pub fn untrusted_writers(path: &Path) -> Result<Vec<String>, String> {
    let descriptor = acl::read(path)?;
    if descriptor.null_dacl {
        return Ok(vec!["Everyone (NULL DACL)".to_string()]);
    }
    let trusted = acl::trusted_writer_sids(&descriptor);
    let mut offenders: Vec<String> = descriptor
        .writers
        .iter()
        .filter(|sid| !trusted.contains(sid))
        .map(|sid| acl::friendly(sid))
        .collect();
    offenders.sort();
    offenders.dedup();
    Ok(offenders)
}

#[cfg(windows)]
pub fn writable_by_current_user(path: &Path) -> bool {
    let Ok(descriptor) = acl::read(path) else { return false };
    let Some(me) = crate::win_identity::current_user_sid() else { return false };
    descriptor.null_dacl
        || descriptor.writers.iter().any(|sid| {
            *sid == me
                || sid == crate::win_identity::SID_EVERYONE
                || sid == crate::win_identity::SID_AUTHENTICATED_USERS
                || sid == crate::win_identity::SID_USERS
        })
}

#[cfg(not(windows))]
pub fn untrusted_writers(path: &Path) -> Result<Vec<String>, String> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path).map_err(|e| e.to_string())?.permissions().mode();
    Ok(if mode & 0o022 != 0 { vec![format!("group/other write bits (mode {:o})", mode & 0o777)] } else { Vec::new() })
}

#[cfg(not(windows))]
pub fn writable_by_current_user(_path: &Path) -> bool {
    true
}

pub fn untrusted_override_reason(path: &Path) -> Option<String> {
    if !path.exists() {
        return None;
    }
    match untrusted_writers(path) {
        Ok(offenders) if !offenders.is_empty() => Some(format!(
            "override file is writable by other principals ({}) so it is not trusted; tighten its ACL to load it",
            offenders.join(", ")
        )),
        Ok(_) => None,
        Err(reason) => Some(format!("override file ACL could not be verified ({reason}); not trusted")),
    }
}

fn override_fingerprint(path: &Path) -> Option<(SystemTime, u64)> {
    let meta = std::fs::metadata(path).ok()?;
    Some((meta.modified().ok()?, meta.len()))
}

fn report_hardening_state(alerts: &AlertSink, dir: &Path) {
    match untrusted_writers(dir) {
        Ok(offenders) if !offenders.is_empty() => alerts.warn(
            "self-protect-acl",
            format!("{} is writable by other principals", dir.display()),
            offenders.join(", "),
        ),
        _ if writable_by_current_user(dir) => alerts.info(
            "self-protect-acl",
            format!(
                "{} is writable by user-level processes, so user-level malware can alter goofedup's config, log and heartbeat -- run 'goofedup-gui --install-hardened' from an elevated prompt to lock it down",
                dir.display()
            ),
        ),
        _ => {}
    }
}

pub fn run(cfg: SharedConfig, alerts: Arc<AlertSink>, running: Arc<AtomicBool>, override_file: PathBuf) {
    let dir = override_file.parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."));
    let heartbeat = dir.join("heartbeat");
    report_hardening_state(&alerts, &dir);

    let (initial_cfg, _) = load_config_with_overrides(&override_file);
    let mut current = snapshot(&initial_cfg);
    match load_baseline(&override_file) {
        Some(baseline) if baseline.version == current.version => {
            report_config_change(&alerts, &override_file, &diff_snapshots(&baseline, &current), "changed while goofedup was not running");
        }
        _ => {}
    }
    save_baseline(&override_file, &current);

    let mut override_seen = override_fingerprint(&override_file);
    if let Some(reason) = untrusted_override_reason(&override_file) {
        alerts.warn("self-protect-acl", "refusing to trust the config override file", reason);
    }
    let mut log_state = file_identity(&initial_cfg.log_path);
    let mut watched_log = initial_cfg.log_path.clone();
    let mut binary = BinaryState::capture();

    while running.load(Ordering::Relaxed) {
        let (poll_secs, log_path) = {
            let cfg_now = cfg.read().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
            (cfg_now.poll_interval_secs, cfg_now.log_path.clone())
        };
        write_heartbeat(&heartbeat, poll_secs, "running");

        if log_path != watched_log {
            watched_log = log_path.clone();
            log_state = file_identity(&log_path);
        }
        check_log_file(&alerts, &log_path, &mut log_state);
        if let Some(b) = binary.as_mut() {
            b.check(&alerts);
        }

        let seen_now = override_fingerprint(&override_file);
        if seen_now != override_seen {
            override_seen = seen_now;
            let refusal = untrusted_override_reason(&override_file);
            if let Some(reason) = &refusal {
                alerts.warn("self-protect-acl", "refusing to trust the config override file", reason.clone());
            }
            let next = match load_overrides_from_file(&override_file) {
                Ok(Some(o)) => Some(snapshot(&apply_overrides(Config::default_for_platform(), &o))),
                Ok(None) => Some(snapshot(&Config::default_for_platform())),
                Err(_) => None,
            };
            if let Some(next) = next {
                report_config_change(&alerts, &override_file, &diff_snapshots(&current, &next), "was edited");
                save_baseline(&override_file, &next);
                current = next;
            }
        }
        std::thread::sleep(Duration::from_secs(poll_secs));
    }
    write_heartbeat(&heartbeat, 0, "stopped");
}
