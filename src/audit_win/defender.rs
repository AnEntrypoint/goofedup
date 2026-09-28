use super::pathing::{expand_env, Context};
use super::registry::{self, OpenError};
use super::shell::{json_items, powershell_json};
use super::Finding;
use crate::alert::Level;
use std::path::Path;
use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;

const CATEGORY: &str = "tamper-defender";
const DEFENDER: &str = "SOFTWARE\\Microsoft\\Windows Defender";
const DEFENDER_POLICY: &str = "SOFTWARE\\Policies\\Microsoft\\Windows Defender";
const EXCLUSION_KINDS: [&str; 4] = ["Paths", "Extensions", "Processes", "IpAddresses"];
const RISKY_EXTENSIONS: [&str; 10] = ["exe", "dll", "ps1", "bat", "cmd", "js", "vbs", "jar", "com", "scr"];

fn number_at(path: &str, name: &str) -> Option<u32> {
    registry::read_value(HKEY_LOCAL_MACHINE, path, name)?.number()
}

fn is_broad_path(path: &str) -> bool {
    let normalized = path.trim_end_matches('\\').to_lowercase();
    let profile = std::env::var("USERPROFILE").unwrap_or_default().to_lowercase();
    normalized.len() <= 2
        || normalized == "c:\\users"
        || normalized == "c:\\windows"
        || normalized == "c:\\program files"
        || (!profile.is_empty() && normalized == profile)
}

fn exclusion_findings(ctx: &Context, base: &str, source: &str, findings: &mut Vec<Finding>) {
    for kind in EXCLUSION_KINDS {
        let path = format!("{base}\\Exclusions\\{kind}");
        let key = match registry::open(HKEY_LOCAL_MACHINE, &path) {
            Ok(key) => key,
            Err(OpenError::Denied) => {
                findings.push(Finding::limited_visibility(
                    CATEGORY,
                    format!("Defender exclusions (HKLM\\{base}\\Exclusions) are hidden from non-administrators"),
                ));
                return;
            }
            Err(OpenError::Missing) => continue,
        };
        for (entry, _) in key.values() {
            let expanded = expand_env(&entry);
            let (level, why) = match kind {
                "Paths" if is_broad_path(&expanded) => (Level::Critical, "excludes a whole drive or profile root from scanning".to_string()),
                "Paths" => match ctx.user_writable_fragment(&expanded) {
                    Some(fragment) => (Level::Warn, format!("path is user-writable ('{fragment}'), malware dropped there is never scanned")),
                    None if Path::new(&expanded).exists() => match ctx.exposure(Path::new(&expanded)) {
                        super::acl::Exposure::Writable { .. } => (Level::Warn, "path is writable by non-admin principals".to_string()),
                        _ => (Level::Info, "path exclusion".to_string()),
                    },
                    None => (Level::Info, "path exclusion".to_string()),
                },
                "Extensions" if RISKY_EXTENSIONS.contains(&entry.trim_start_matches('.').to_lowercase().as_str()) => {
                    (Level::Warn, "executable/script extension excluded from scanning".to_string())
                }
                _ => (Level::Info, format!("{} exclusion", kind.to_lowercase())),
            };
            findings.push(
                Finding::new(
                    level,
                    CATEGORY,
                    format!("defender:exclusion:{kind}:{}", entry.to_lowercase()),
                    format!("Defender {} exclusion '{entry}': {why}", kind.to_lowercase()),
                    format!("source={source}"),
                )
                .tracked(),
            );
        }
    }
}

pub fn registry_state(ctx: &Context) -> Vec<Finding> {
    let mut findings = Vec::new();
    exclusion_findings(ctx, DEFENDER, "local Defender configuration", &mut findings);
    exclusion_findings(ctx, DEFENDER_POLICY, "Defender policy", &mut findings);

    let disabled_switches = [
        (format!("{DEFENDER}\\Real-Time Protection"), "DisableRealtimeMonitoring", "real-time protection"),
        (format!("{DEFENDER}\\Real-Time Protection"), "DisableBehaviorMonitoring", "behavior monitoring"),
        (format!("{DEFENDER}\\Real-Time Protection"), "DisableIOAVProtection", "download/attachment scanning"),
        (format!("{DEFENDER}\\Real-Time Protection"), "DisableScriptScanning", "script scanning"),
        (DEFENDER.to_string(), "DisableAntiSpyware", "Defender antivirus"),
        (DEFENDER_POLICY.to_string(), "DisableAntiSpyware", "Defender antivirus (policy)"),
        (format!("{DEFENDER_POLICY}\\Real-Time Protection"), "DisableRealtimeMonitoring", "real-time protection (policy)"),
        (format!("{DEFENDER_POLICY}\\Real-Time Protection"), "DisableBehaviorMonitoring", "behavior monitoring (policy)"),
    ];
    for (path, name, label) in disabled_switches {
        if number_at(&path, name) == Some(1) {
            findings.push(
                Finding::new(
                    Level::Critical,
                    CATEGORY,
                    format!("defender:disabled:{path}:{name}"),
                    format!("Defender {label} is switched off"),
                    format!("HKLM\\{path} {name}=1"),
                )
                .tracked(),
            );
        }
    }
    if let Some(state) = number_at(&format!("{DEFENDER}\\Features"), "TamperProtection") {
        if state == 4 || state == 0 {
            findings.push(
                Finding::new(
                    Level::Warn,
                    CATEGORY,
                    "defender:tamper",
                    "Defender tamper protection is off",
                    format!("HKLM\\{DEFENDER}\\Features TamperProtection={state}"),
                )
                .tracked(),
            );
        }
    }
    findings
}

fn flag(value: &serde_json::Value, field: &str) -> Option<bool> {
    value.get(field).and_then(|v| v.as_bool())
}

pub fn status_via_powershell(_ctx: &Context) -> Vec<Finding> {
    let script = "$s = Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,IsTamperProtected,AntivirusEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,OnAccessProtectionEnabled,AntivirusSignatureAge; \
                  $p = Get-MpPreference | Select-Object MAPSReporting,EnableNetworkProtection,PUAProtection,AttackSurfaceReductionRules_Actions; \
                  [pscustomobject]@{status=$s;pref=$p} | ConvertTo-Json -Depth 4 -Compress";
    let Some(root) = powershell_json(script) else {
        return vec![Finding::limited_visibility(CATEGORY, "Get-MpComputerStatus/Get-MpPreference returned nothing (Defender absent, replaced by another AV, or blocked)")];
    };
    let status = root.get("status").cloned().unwrap_or_default();
    let pref = root.get("pref").cloned().unwrap_or_default();
    let mut findings = Vec::new();
    let mut add = |level: Level, key: &str, title: String, evidence: String| {
        findings.push(Finding::new(level, CATEGORY, format!("defender:{key}"), title, evidence).tracked());
    };

    let switches = [
        ("RealTimeProtectionEnabled", "realtime", "real-time protection", Level::Critical),
        ("AntivirusEnabled", "antivirus", "antivirus engine", Level::Critical),
        ("IsTamperProtected", "tamper", "tamper protection", Level::Warn),
        ("BehaviorMonitorEnabled", "behavior", "behavior monitoring", Level::Warn),
        ("IoavProtectionEnabled", "ioav", "download/attachment scanning", Level::Warn),
        ("OnAccessProtectionEnabled", "onaccess", "on-access protection", Level::Warn),
    ];
    for (field, key, label, level) in switches {
        if flag(&status, field) == Some(false) {
            add(level, key, format!("Defender {label} is OFF"), format!("Get-MpComputerStatus {field}=False"));
        }
    }
    if let Some(age) = status.get("AntivirusSignatureAge").and_then(|v| v.as_u64()) {
        if age > 7 {
            add(Level::Warn, "signature-age", format!("Defender signatures are {age} days old"), "Get-MpComputerStatus AntivirusSignatureAge".to_string());
        }
    }
    if pref.get("MAPSReporting").and_then(|v| v.as_u64()) == Some(0) {
        add(Level::Warn, "cloud", "Defender cloud-delivered protection (MAPS) is off".to_string(), "Get-MpPreference MAPSReporting=0".to_string());
    }
    let network_protection = pref.get("EnableNetworkProtection").and_then(|v| v.as_u64()).unwrap_or(0);
    if network_protection != 1 {
        let mode = if network_protection == 2 { "audit mode only" } else { "off" };
        add(Level::Warn, "network-protection", format!("Defender Network Protection is {mode}"), format!("Get-MpPreference EnableNetworkProtection={network_protection}"));
    }
    let asr_actions: Vec<&serde_json::Value> = pref.get("AttackSurfaceReductionRules_Actions").map(json_items).unwrap_or_default();
    let asr_blocking = asr_actions.iter().filter(|v| v.as_u64() == Some(1)).count();
    if asr_blocking == 0 {
        add(Level::Warn, "asr", "no Attack Surface Reduction rule is in block mode".to_string(), format!("{} ASR rule(s) configured, 0 blocking", asr_actions.len()));
    }
    if pref.get("PUAProtection").and_then(|v| v.as_u64()) == Some(0) {
        add(Level::Info, "pua", "Defender potentially-unwanted-app protection is off".to_string(), "Get-MpPreference PUAProtection=0".to_string());
    }
    findings
}
