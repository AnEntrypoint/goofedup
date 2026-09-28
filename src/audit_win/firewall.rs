use super::acl::Exposure;
use super::pathing::{describe_exposure, expand_env, Context};
use super::registry::{self, OpenError};
use super::Finding;
use crate::alert::Level;
use std::path::PathBuf;
use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;

const CATEGORY: &str = "tamper-firewall";
const RULES_PATH: &str = "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules";

#[derive(Default)]
struct Rule {
    id: String,
    name: String,
    allow: bool,
    active: bool,
    inbound: bool,
    protocol: Option<String>,
    profiles: Vec<String>,
    local_ports: Vec<String>,
    remote_restricted: bool,
    program: Option<String>,
    service: Option<String>,
    is_store_app: bool,
}

fn parse_rule(id: &str, raw: &str) -> Rule {
    let mut rule = Rule { id: id.to_string(), ..Default::default() };
    for part in raw.split('|') {
        let Some((field, value)) = part.split_once('=') else { continue };
        match field {
            "Action" => rule.allow = value.eq_ignore_ascii_case("Allow"),
            "Active" => rule.active = value.eq_ignore_ascii_case("TRUE"),
            "Dir" => rule.inbound = value.eq_ignore_ascii_case("In"),
            "Protocol" => rule.protocol = Some(value.to_string()),
            "Profile" => rule.profiles.push(value.to_string()),
            "App" => rule.program = Some(value.to_string()),
            "Svc" => rule.service = Some(value.to_string()),
            "Name" => rule.name = value.to_string(),
            "AppPkgId" => rule.is_store_app = true,
            f if f.starts_with("LPort") => rule.local_ports.push(value.to_string()),
            f if f.starts_with("RA4") || f.starts_with("RA6") || f == "RMauth" || f == "RUAuth" => {
                rule.remote_restricted = true
            }
            _ => {}
        }
    }
    rule
}

fn port_ranges(rule: &Rule) -> Vec<(u16, u16)> {
    rule.local_ports
        .iter()
        .filter_map(|text| match text.split_once('-') {
            Some((low, high)) => Some((low.parse().ok()?, high.parse().ok()?)),
            None => text.parse().ok().map(|p| (p, p)),
        })
        .collect()
}

fn ports_hit(ranges: &[(u16, u16)], watched: &[u16]) -> Vec<u16> {
    let mut hit: Vec<u16> = watched.iter().copied().filter(|p| ranges.iter().any(|(lo, hi)| lo <= p && p <= hi)).collect();
    hit.sort_unstable();
    hit
}

fn is_windows_shipped(rule: &Rule) -> bool {
    rule.name.starts_with('@')
}

pub fn inbound_rules(ctx: &Context) -> Vec<Finding> {
    let key = match registry::open(HKEY_LOCAL_MACHINE, RULES_PATH) {
        Ok(key) => key,
        Err(OpenError::Denied) => {
            return vec![Finding::limited_visibility(CATEGORY, format!("HKLM\\{RULES_PATH} is not readable"))]
        }
        Err(OpenError::Missing) => return Vec::new(),
    };
    let mut findings = Vec::new();
    for (id, value) in key.values() {
        let Some(raw) = value.text() else { continue };
        let rule = parse_rule(&id, raw);
        if !rule.allow || !rule.active || !rule.inbound || rule.is_store_app || is_windows_shipped(&rule) {
            continue;
        }
        let udp_only = rule.protocol.as_deref() == Some("17");
        let ranges = port_ranges(&rule);
        let critical_hits = if udp_only { Vec::new() } else { ports_hit(&ranges, &ctx.cfg.critical_exposure_ports) };
        let admin_hits = if udp_only { Vec::new() } else { ports_hit(&ranges, &ctx.cfg.admin_exposure_ports) };
        let broad_profile = rule.profiles.is_empty() || rule.profiles.iter().any(|p| p == "Public");
        let broad = broad_profile && !rule.remote_restricted;

        let mut problems: Vec<String> = Vec::new();
        let mut level = Level::Info;
        if !critical_hits.is_empty() {
            problems.push(format!("opens debugger/service port(s) {critical_hits:?}"));
            level = if broad { Level::Critical } else { Level::Warn };
        }
        if !admin_hits.is_empty() && broad {
            problems.push(format!("opens remote-admin port(s) {admin_hits:?} to any remote address"));
            level = level.max(Level::Warn);
        }
        let program_path = rule
            .program
            .as_deref()
            .filter(|p| !p.eq_ignore_ascii_case("System") && !p.contains('*'))
            .map(|p| PathBuf::from(expand_env(p)));
        if let Some(program) = &program_path {
            let by_fragment = ctx.user_writable_fragment(&program.to_string_lossy());
            match ctx.exposure(program) {
                Exposure::Missing | Exposure::Plantable { .. } => {
                    problems.push("program is missing on disk (stale rule)".to_string());
                    if broad {
                        level = level.max(Level::Warn);
                    }
                }
                exposure @ Exposure::Writable { .. } => {
                    problems.push(format!("program {}", describe_exposure(&exposure)));
                    if broad {
                        level = level.max(Level::Warn);
                    }
                }
                _ => {}
            }
            if let Some(fragment) = by_fragment {
                problems.push(format!("program lives under user-writable location '{fragment}'"));
                if broad {
                    level = level.max(Level::Warn);
                }
            }
        }
        let profiles = if rule.profiles.is_empty() { "Any".to_string() } else { rule.profiles.join("+") };
        let scope = format!(
            "profile={profiles} remote={}",
            if rule.remote_restricted { "restricted" } else { "Any" }
        );
        let title = if problems.is_empty() {
            format!("inbound allow rule '{}' ({scope})", rule.name)
        } else {
            format!("inbound allow rule '{}' ({scope}): {}", rule.name, problems.join("; "))
        };
        let evidence = format!(
            "program={} service={} ports={} protocol={}",
            rule.program.as_deref().unwrap_or("-"),
            rule.service.as_deref().unwrap_or("-"),
            if rule.local_ports.is_empty() { "-".to_string() } else { rule.local_ports.join(",") },
            rule.protocol.as_deref().unwrap_or("Any")
        );
        findings.push(Finding::new(level, CATEGORY, format!("firewall:{}", rule.id), title, evidence).tracked());
    }
    findings
}
