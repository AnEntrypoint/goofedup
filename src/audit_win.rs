use crate::alert::Level;
use crate::tamper_config::TamperConfig;

#[cfg(windows)]
mod accounts;
#[cfg(windows)]
mod acl;
#[cfg(windows)]
mod autoruns;
#[cfg(windows)]
mod certs;
#[cfg(windows)]
mod credentials;
#[cfg(windows)]
mod defender;
#[cfg(windows)]
mod firewall;
#[cfg(windows)]
mod hosts_file;
#[cfg(windows)]
mod net_exposure;
#[cfg(windows)]
mod pathing;
#[cfg(windows)]
mod registry;
#[cfg(windows)]
mod services;
#[cfg(windows)]
mod shell;
#[cfg(windows)]
mod tasks;
#[cfg(windows)]
mod wmi;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tier {
    Native,
    Shell,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub level: Level,
    pub category: &'static str,
    pub key: String,
    pub title: String,
    pub evidence: String,
    pub alert_on_change: bool,
}

impl Finding {
    pub fn new(
        level: Level,
        category: &'static str,
        key: impl Into<String>,
        title: impl Into<String>,
        evidence: impl Into<String>,
    ) -> Self {
        Self {
            level,
            category,
            key: key.into(),
            title: title.into(),
            evidence: evidence.into(),
            alert_on_change: false,
        }
    }

    pub fn tracked(mut self) -> Self {
        self.alert_on_change = true;
        self
    }

    pub fn limited_visibility(category: &'static str, what: impl Into<String>) -> Self {
        Self::new(
            Level::Info,
            category,
            format!("{category}:limited-visibility"),
            "limited visibility: needs elevation",
            what,
        )
    }

    pub fn is_limited_visibility(&self) -> bool {
        self.key.ends_with(":limited-visibility")
    }

    pub fn fingerprint(&self) -> String {
        format!("{}|{}|{}", self.level, self.title, self.evidence)
    }

    pub fn worth_alerting(&self) -> bool {
        !self.is_limited_visibility() && (self.level >= Level::Warn || self.alert_on_change)
    }
}

pub fn collect(tier: Tier, cfg: &TamperConfig) -> Vec<Finding> {
    let mut findings = collect_platform(tier, cfg);
    findings.retain(|f| !cfg.ignored_finding_keys.iter().any(|prefix| f.key.starts_with(prefix.as_str())));
    findings.sort_by(|a, b| b.level.cmp(&a.level).then(a.category.cmp(b.category)).then(a.key.cmp(&b.key)));
    findings
}

#[cfg(windows)]
fn collect_platform(tier: Tier, cfg: &TamperConfig) -> Vec<Finding> {
    let ctx = pathing::Context::new(cfg);
    let collectors: Vec<fn(&pathing::Context) -> Vec<Finding>> = match tier {
        Tier::Native => vec![
            net_exposure::portproxy,
            net_exposure::listeners,
            firewall::inbound_rules,
            hosts_file::entries,
            tasks::privileged_tasks,
            services::autostart_services,
            defender::registry_state,
            certs::root_stores,
            accounts::local_accounts,
            credentials::plaintext_stores,
            autoruns::autorun_locations,
        ],
        Tier::Shell => vec![defender::status_via_powershell, wmi::event_subscriptions],
    };
    std::thread::scope(|scope| {
        let handles: Vec<_> = collectors.iter().map(|c| scope.spawn(|| c(&ctx))).collect();
        handles.into_iter().flat_map(|h| h.join().unwrap_or_default()).collect()
    })
}

#[cfg(not(windows))]
fn collect_platform(_tier: Tier, _cfg: &TamperConfig) -> Vec<Finding> {
    vec![Finding::new(
        Level::Info,
        "tamper-platform",
        "platform:unsupported",
        format!("posture collectors are Windows-only; {} has none", std::env::consts::OS),
        String::new(),
    )]
}

#[cfg(windows)]
pub fn is_elevated() -> bool {
    use std::ffi::c_void;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut TOKEN_ELEVATION as *mut c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
        .is_ok();
        let _ = CloseHandle(token);
        ok && elevation.TokenIsElevated != 0
    }
}

#[cfg(not(windows))]
pub fn is_elevated() -> bool {
    false
}

const PER_CATEGORY_LINE_CAP: usize = 12;

pub fn render_report(findings: &[Finding], show_everything: bool) -> String {
    let mut out = String::new();
    let count = |level: Level| findings.iter().filter(|f| f.level == level).count();
    out.push_str(&format!(
        "goofedup posture audit -- {} -- elevated: {}\n",
        std::env::consts::OS,
        if is_elevated() { "yes" } else { "no" }
    ));
    out.push_str(&format!(
        "{} critical, {} warn, {} info\n\n",
        count(Level::Critical),
        count(Level::Warn),
        count(Level::Info)
    ));

    let mut printed: std::collections::BTreeMap<(Level, &'static str), usize> = std::collections::BTreeMap::new();
    let mut hidden: std::collections::BTreeMap<(Level, &'static str), usize> = std::collections::BTreeMap::new();
    for f in findings {
        let visible_by_level = show_everything || f.level >= Level::Warn || f.is_limited_visibility();
        let slot = printed.entry((f.level, f.category)).or_insert(0);
        let capped = !show_everything && f.level != Level::Critical && *slot >= PER_CATEGORY_LINE_CAP;
        if !visible_by_level || capped {
            *hidden.entry((f.level, f.category)).or_insert(0) += 1;
            continue;
        }
        *slot += 1;
        let color = match f.level {
            Level::Critical => "\x1b[31m",
            Level::Warn => "\x1b[33m",
            Level::Info => "\x1b[36m",
        };
        out.push_str(&format!("{color}[{}] [{}] {}\x1b[0m\n", f.level, f.category, f.title));
        if !f.evidence.is_empty() {
            out.push_str(&format!("    {}\n", f.evidence));
        }
        out.push_str(&format!("    key: {}\n", f.key));
    }
    if !hidden.is_empty() {
        out.push('\n');
        for ((level, category), n) in &hidden {
            out.push_str(&format!("({n} more {level} in {category} not shown -- rerun with --audit-all)\n"));
        }
    }
    out
}

pub fn run_cli(cfg: &TamperConfig, show_everything: bool) -> i32 {
    let mut findings = collect(Tier::Native, cfg);
    findings.extend(collect(Tier::Shell, cfg));
    findings.sort_by(|a, b| b.level.cmp(&a.level).then(a.category.cmp(b.category)).then(a.key.cmp(&b.key)));
    let mut seen_keys = std::collections::HashSet::new();
    findings.retain(|f| seen_keys.insert(f.key.clone()));
    print!("{}", render_report(&findings, show_everything));
    if findings.iter().any(|f| f.level == Level::Critical) {
        1
    } else {
        0
    }
}
