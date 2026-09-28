use crate::alert::{AlertSink, Level};
use crate::config::Config;
use crate::heuristics::{is_compiler_build_artifact_path, is_denied_exec_path, score_command_line, score_process_name};
use crate::image_integrity::ImageWatch;
use crate::lineage::{self, Finding};
use crate::trust::{self, ImageKey, ImageRecord, Trust, UnsignedMode};
use crate::watch_network::Connection;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};
use sysinfo::{Pid, Process, System};

const DEFERRAL_LIMIT: Duration = Duration::from_secs(30);

const MASQUERADE_PRONE_SYSTEM_NAMES: &[&str] = &[
    "svchost", "lsass", "csrss", "services", "winlogon", "wininit", "smss", "explorer", "spoolsv", "dllhost", "rundll32",
    "regsvr32", "taskhost", "taskhostw", "conhost", "lsm", "searchindexer", "runtimebroker", "sihost", "ctfmon", "dwm",
    "fontdrvhost", "wmiprvse", "audiodg", "cmd", "powershell", "wscript", "cscript", "mshta",
];

#[derive(Clone)]
struct TrackedImage {
    name: String,
    exe_path: String,
    key: ImageKey,
    sha256: Option<String>,
}

struct Shared {
    tracked: HashMap<u32, TrackedImage>,
    public_connections: HashMap<u32, String>,
    escalated_images: HashSet<ImageKey>,
}

fn shared() -> MutexGuard<'static, Shared> {
    static SHARED: OnceLock<Mutex<Shared>> = OnceLock::new();
    SHARED
        .get_or_init(|| {
            Mutex::new(Shared { tracked: HashMap::new(), public_connections: HashMap::new(), escalated_images: HashSet::new() })
        })
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

pub fn supersedes_path_allowlist(cfg: &Config) -> bool {
    trust::verification_available() && cfg.unsigned_user_writable_policy.mode != UnsignedMode::Off
}

fn signature_word(trust: &Trust) -> &'static str {
    match trust {
        Trust::Invalid => "invalid-signature",
        _ => "unsigned",
    }
}

fn describe_image(exe_path: &str, trust: &Trust, sha256: &Option<String>) -> String {
    format!(
        "exe={exe_path} signature={}{}",
        signature_word(trust),
        sha256.as_ref().map(|h| format!(" sha256={h}")).unwrap_or_default()
    )
}

pub fn on_connections(alerts: &AlertSink, connections: &[Connection]) {
    let mut public: HashMap<u32, String> = HashMap::new();
    for c in connections {
        if trust::is_public_ip(&c.remote_ip) {
            public.entry(c.pid).or_insert_with(|| format!("{}:{}", c.remote_ip, c.remote_port));
        }
    }
    let mut escalations: Vec<(u32, TrackedImage, String)> = Vec::new();
    {
        let mut state = shared();
        for (pid, remote) in &public {
            if let Some(image) = state.tracked.get(pid) {
                if !state.escalated_images.contains(&image.key) {
                    escalations.push((*pid, image.clone(), remote.clone()));
                }
            }
        }
        for (_, image, _) in &escalations {
            state.escalated_images.insert(image.key.clone());
        }
        state.public_connections = public;
    }
    for (pid, image, remote) in escalations {
        alerts.critical(
            "unsigned-in-user-writable",
            format!(
                "'{}' (PID {pid}) is an unsigned image in a user-writable location and now has an outbound public network connection",
                image.name
            ),
            format!(
                "exe={} signature=unsigned{} remote={remote}",
                image.exe_path,
                image.sha256.as_ref().map(|h| format!(" sha256={h}")).unwrap_or_default()
            ),
        );
    }
}

struct ImageJob {
    pid: u32,
    name: String,
    exe_path: String,
    cmdline: String,
}

struct ParentJob {
    child_name: String,
    child_pid: u32,
    parent_name: String,
    parent_pid: u32,
    parent_exe: String,
}

enum Job {
    Image(ImageJob),
    Parent(ParentJob),
}

impl Job {
    fn image_path(&self) -> &str {
        match self {
            Job::Image(j) => &j.exe_path,
            Job::Parent(j) => &j.parent_exe,
        }
    }
}

struct Deferred {
    since: Instant,
    job: Job,
}

pub struct ProcessTrust {
    swept_existing: bool,
    deferred: Vec<Deferred>,
    warned_images: HashSet<ImageKey>,
    seen_publishers: HashSet<String>,
    reported_lineage: HashSet<(String, String)>,
    image_watch: ImageWatch,
}

impl Default for ProcessTrust {
    fn default() -> Self {
        Self::new()
    }
}

fn emit_finding(alerts: &AlertSink, finding: Finding) {
    match finding.level {
        Level::Critical => alerts.critical("process-lineage", finding.message, finding.evidence),
        _ => alerts.warn("process-lineage", finding.message, finding.evidence),
    }
}

fn exe_of(p: &Process) -> String {
    p.exe().map(|e| e.to_string_lossy().to_string()).unwrap_or_default()
}

fn is_local_cargo_artifact(exe_path: &str) -> bool {
    let components: Vec<_> = Path::new(exe_path).components().collect();
    components.iter().enumerate().any(|(i, component)| {
        component.as_os_str().eq_ignore_ascii_case("target")
            && components[i + 1..]
                .iter()
                .take(2)
                .any(|next| next.as_os_str().eq_ignore_ascii_case("debug") || next.as_os_str().eq_ignore_ascii_case("release"))
            && components[..i].iter().collect::<std::path::PathBuf>().join("Cargo.toml").is_file()
    })
}

fn is_locally_built_artifact(exe_path: &str) -> bool {
    is_compiler_build_artifact_path(&exe_path.to_lowercase()) || is_local_cargo_artifact(exe_path)
}

fn is_masquerade_prone(name: &str) -> bool {
    MASQUERADE_PRONE_SYSTEM_NAMES.contains(&lineage::normalized_name(name).as_str())
}

impl ProcessTrust {
    pub fn new() -> Self {
        Self {
            swept_existing: false,
            deferred: Vec::new(),
            warned_images: HashSet::new(),
            seen_publishers: HashSet::new(),
            reported_lineage: HashSet::new(),
            image_watch: ImageWatch::new(),
        }
    }

    pub fn observe(&mut self, cfg: &Config, alerts: &AlertSink, sys: &System, known: &HashSet<Pid>, current: &HashSet<Pid>) {
        let first_observation = !self.swept_existing;
        self.swept_existing = true;
        for pid in current {
            if first_observation || !known.contains(pid) {
                if let Some(p) = sys.process(*pid) {
                    self.inspect(cfg, alerts, sys, p);
                }
            }
        }
        self.resolve_deferred(cfg, alerts);
        self.image_watch.poll(alerts, sys);
        shared().tracked.retain(|pid, _| current.contains(&Pid::from_u32(*pid)));
    }

    fn inspect(&mut self, cfg: &Config, alerts: &AlertSink, sys: &System, p: &Process) {
        for finding in lineage::immediate_findings(sys, p) {
            let first_report = finding.dedupe_key.as_ref().map(|key| self.reported_lineage.insert(key.clone())).unwrap_or(true);
            if first_report {
                emit_finding(alerts, finding);
            }
        }
        if !supersedes_path_allowlist(cfg) || p.pid().as_u32() == std::process::id() {
            return;
        }
        let exe_path = exe_of(p);
        if exe_path.is_empty() || is_denied_exec_path(&exe_path, &cfg.deny_exec_path_fragments).is_some() {
            return;
        }
        let name = p.name().to_string_lossy().to_string();
        let cmdline = p.cmd().iter().map(|s| s.to_string_lossy().to_string()).collect::<Vec<_>>().join(" ");
        self.resolve(cfg, alerts, Job::Image(ImageJob { pid: p.pid().as_u32(), name: name.clone(), exe_path, cmdline }));

        if lineage::is_shell_child(&name) {
            if let Some(parent) = lineage::parent_of(sys, p) {
                let parent_exe = exe_of(parent);
                if !parent_exe.is_empty() && parent.pid().as_u32() != std::process::id() {
                    self.resolve(
                        cfg,
                        alerts,
                        Job::Parent(ParentJob {
                            child_name: name,
                            child_pid: p.pid().as_u32(),
                            parent_name: parent.name().to_string_lossy().to_string(),
                            parent_pid: parent.pid().as_u32(),
                            parent_exe,
                        }),
                    );
                }
            }
        }
    }

    fn resolve(&mut self, cfg: &Config, alerts: &AlertSink, job: Job) {
        match trust::lookup(Path::new(job.image_path())) {
            Some(record) => self.decide(cfg, alerts, job, &record),
            None => self.deferred.push(Deferred { since: Instant::now(), job }),
        }
    }

    fn resolve_deferred(&mut self, cfg: &Config, alerts: &AlertSink) {
        for deferred in std::mem::take(&mut self.deferred) {
            match trust::lookup(Path::new(deferred.job.image_path())) {
                Some(record) => self.decide(cfg, alerts, deferred.job, &record),
                None if deferred.since.elapsed() < DEFERRAL_LIMIT => self.deferred.push(deferred),
                None => {}
            }
        }
    }

    fn decide(&mut self, cfg: &Config, alerts: &AlertSink, job: Job, record: &ImageRecord) {
        match job {
            Job::Image(job) => self.decide_image(cfg, alerts, &job, record),
            Job::Parent(job) => self.decide_parent(cfg, alerts, &job, record),
        }
    }

    fn decide_image(&mut self, cfg: &Config, alerts: &AlertSink, job: &ImageJob, record: &ImageRecord) {
        if trust::is_under_admin_only_root(cfg, &job.exe_path) {
            self.decide_vendor_image(alerts, job, record);
            return;
        }
        match &record.trust {
            Trust::Unknown => {}
            Trust::Valid(publisher) => {
                if !trust::publisher_is_trusted(publisher, &cfg.trusted_publishers) && self.seen_publishers.insert(publisher.clone()) {
                    alerts.info(
                        "publisher-in-user-writable",
                        format!(
                            "'{}' (PID {}) runs from a user-writable location, validly signed by '{publisher}' (not in trusted_publishers)",
                            job.name, job.pid
                        ),
                    );
                }
            }
            Trust::Unsigned | Trust::Invalid => self.decide_unsigned(cfg, alerts, job, record),
        }
    }

    fn decide_vendor_image(&mut self, alerts: &AlertSink, job: &ImageJob, record: &ImageRecord) {
        if !is_masquerade_prone(&job.name) {
            return;
        }
        let genuine = match &record.trust {
            Trust::Valid(publisher) => publisher.to_lowercase().starts_with("microsoft"),
            Trust::Unknown => true,
            Trust::Unsigned | Trust::Invalid => false,
        };
        if !genuine {
            alerts.critical(
                "system-process-signature",
                format!(
                    "'{}' (PID {}) carries a system-process name but its image is not validly signed by Microsoft",
                    job.name, job.pid
                ),
                describe_image(&job.exe_path, &record.trust, &record.sha256),
            );
        }
    }

    fn decide_unsigned(&mut self, cfg: &Config, alerts: &AlertSink, job: &ImageJob, record: &ImageRecord) {
        let policy = &cfg.unsigned_user_writable_policy;
        if trust::hash_is_pinned(record, policy) {
            return;
        }
        let build_artifact = is_locally_built_artifact(&job.exe_path);

        let mut strong_reasons = Vec::new();
        if let Some(verdict) = score_command_line(&job.cmdline, cfg.c2_max_decode_depth) {
            strong_reasons.push(format!("obfuscated command line (score={})", verdict.score));
        }
        if let Some(verdict) = score_process_name(&job.name, &job.exe_path) {
            strong_reasons.push(format!("suspicious process name ({})", verdict.reasons.join("; ")));
        }

        let mut state = shared();
        let mut reasons = strong_reasons.clone();
        if build_artifact && reasons.is_empty() {
            return;
        }
        if !build_artifact {
            if let Some(remote) = state.public_connections.get(&job.pid) {
                reasons.push(format!("outbound public connection to {remote}"));
            }
            state.tracked.insert(
                job.pid,
                TrackedImage {
                    name: job.name.clone(),
                    exe_path: job.exe_path.clone(),
                    key: record.key.clone(),
                    sha256: record.sha256.clone(),
                },
            );
        }

        let critical = !reasons.is_empty() || policy.mode == UnsignedMode::Critical;
        let first_escalation = critical && state.escalated_images.insert(record.key.clone());
        drop(state);

        let evidence = describe_image(&job.exe_path, &record.trust, &record.sha256);
        if critical {
            if first_escalation || !strong_reasons.is_empty() {
                let corroboration = if reasons.is_empty() {
                    "policy mode is critical".to_string()
                } else {
                    reasons.join("; ")
                };
                alerts.critical(
                    "unsigned-in-user-writable",
                    format!(
                        "'{}' (PID {}) is an unsigned image in a user-writable location, corroborated by: {corroboration}",
                        job.name, job.pid
                    ),
                    evidence,
                );
            }
        } else if self.warned_images.insert(record.key.clone()) {
            alerts.warn(
                "unsigned-in-user-writable",
                format!(
                    "'{}' (PID {}) is running from a user-writable location with no publisher identity to trust ({})",
                    job.name,
                    job.pid,
                    signature_word(&record.trust)
                ),
                evidence,
            );
        }
    }

    fn decide_parent(&mut self, cfg: &Config, alerts: &AlertSink, job: &ParentJob, record: &ImageRecord) {
        if !matches!(record.trust, Trust::Unsigned | Trust::Invalid) {
            return;
        }
        if trust::hash_is_pinned(record, &cfg.unsigned_user_writable_policy)
            || trust::is_under_admin_only_root(cfg, &job.parent_exe)
            || is_locally_built_artifact(&job.parent_exe)
        {
            return;
        }
        let parent_normalized = lineage::normalized_name(&job.parent_name);
        if cfg.known_automation_parent_names.iter().any(|n| lineage::normalized_name(n) == parent_normalized) {
            return;
        }
        let key = (job.parent_exe.to_lowercase(), lineage::normalized_name(&job.child_name));
        if !self.reported_lineage.insert(key) {
            return;
        }
        alerts.warn(
            "process-lineage",
            format!(
                "'{}' (PID {}) was spawned by '{}' (PID {}), an unsigned image in a user-writable location",
                job.child_name, job.child_pid, job.parent_name, job.parent_pid
            ),
            describe_image(&job.parent_exe, &record.trust, &record.sha256),
        );
    }
}
