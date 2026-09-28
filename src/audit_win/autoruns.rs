use super::acl::Exposure;
use super::pathing::{expand_env, extract_paths, fnv1a, system_root, Context};
use super::registry::{self, OpenError};
use super::Finding;
use crate::alert::Level;
use crate::heuristics::score_command_line;
use std::path::PathBuf;
use windows::Win32::System::Registry::{HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};

const CATEGORY: &str = "tamper-autorun";
const SCRIPT_EXTENSIONS: [&str; 12] = ["vbs", "vbe", "js", "jse", "wsf", "hta", "ps1", "bat", "cmd", "scr", "cpl", "jar"];
const STAGING_FRAGMENTS: [&str; 4] = ["\\temp\\", "\\downloads\\", "\\users\\public\\", "$recycle.bin"];
const DECODE_DEPTH: u32 = 4;
const RUN_LOCATIONS: [&str; 7] = [
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
    "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices",
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
];
const IFEO_PATHS: [&str; 2] = [
    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
    "SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
];
const APPINIT_PATHS: [&str; 2] = [
    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
    "SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
];

fn hive_label(hive: HKEY) -> &'static str {
    if hive == HKEY_CURRENT_USER {
        "HKCU"
    } else {
        "HKLM"
    }
}

fn tracked(level: Level, key: String, title: String, evidence: String) -> Finding {
    Finding::new(level, CATEGORY, key, title, evidence).tracked()
}

fn command_findings(ctx: &Context, key: String, location: &str, name: &str, command: &str) -> Finding {
    let lowered = command.to_lowercase().replace('/', "\\");
    let mut problems: Vec<String> = Vec::new();
    let mut level = Level::Info;
    if let Some(verdict) = score_command_line(command, DECODE_DEPTH) {
        problems.push(format!("command shaped like an obfuscated payload ({})", verdict.reasons.join("; ")));
        level = Level::Critical;
    }
    if let Some(fragment) = STAGING_FRAGMENTS.iter().find(|f| lowered.contains(**f)) {
        problems.push(format!("runs from staging-style location '{fragment}'"));
        level = level.max(Level::Warn);
    }
    for path in extract_paths(command) {
        match ctx.exposure(&path) {
            Exposure::Missing | Exposure::Plantable { .. } => {
                problems.push(format!("target {} is missing", path.display()));
                level = level.max(Level::Warn);
            }
            _ => {}
        }
    }
    let title = if problems.is_empty() {
        format!("autorun {location} '{name}'")
    } else {
        format!("autorun {location} '{name}': {}", problems.join("; "))
    };
    tracked(level, key, title, format!("command={command}"))
}

fn run_key_findings(ctx: &Context, findings: &mut Vec<Finding>) {
    for hive in [HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE] {
        for path in RUN_LOCATIONS {
            let Ok(key) = registry::open(hive, path) else { continue };
            for (name, value) in key.values() {
                let location = format!("{}\\{path}", hive_label(hive));
                findings.push(command_findings(
                    ctx,
                    format!("autorun:{}:{}", location.to_lowercase(), name.to_lowercase()),
                    &location,
                    &name,
                    &value.as_display(),
                ));
            }
        }
    }
}

fn winlogon_findings(findings: &mut Vec<Finding>) {
    let path = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
    let Ok(key) = registry::open(HKEY_LOCAL_MACHINE, path) else { return };
    let expectations: [(&str, &[&str]); 2] = [
        ("Shell", &["explorer.exe"]),
        ("Userinit", &["c:\\windows\\system32\\userinit.exe,", "c:\\windows\\system32\\userinit.exe"]),
    ];
    for (name, allowed) in expectations {
        if let Some(value) = key.value(name) {
            let text = value.as_display();
            if !allowed.contains(&text.trim().to_lowercase().as_str()) {
                findings.push(tracked(
                    Level::Critical,
                    format!("autorun:winlogon:{}", name.to_lowercase()),
                    format!("Winlogon {name} is not the Windows default: '{text}'"),
                    format!("HKLM\\{path} {name}"),
                ));
            }
        }
    }
    for name in ["Taskman", "AppSetup", "GinaDLL"] {
        if let Some(value) = key.value(name) {
            findings.push(tracked(
                Level::Critical,
                format!("autorun:winlogon:{}", name.to_lowercase()),
                format!("Winlogon {name} is set: '{}'", value.as_display()),
                format!("HKLM\\{path} {name}"),
            ));
        }
    }
    if let Ok(notify) = key.open_child("Notify") {
        for (name, value) in notify.values() {
            findings.push(tracked(
                Level::Critical,
                format!("autorun:winlogon-notify:{}", name.to_lowercase()),
                format!("Winlogon Notify package '{name}': {}", value.as_display()),
                format!("HKLM\\{path}\\Notify"),
            ));
        }
    }
}

fn ifeo_findings(findings: &mut Vec<Finding>) {
    for base in IFEO_PATHS {
        let Ok(root) = registry::open(HKEY_LOCAL_MACHINE, base) else { continue };
        for image in root.subkeys() {
            let Ok(entry) = root.open_child(&image) else { continue };
            if let Some(debugger) = entry.value("Debugger") {
                findings.push(tracked(
                    Level::Critical,
                    format!("autorun:ifeo-debugger:{}:{}", base.contains("WOW6432Node"), image.to_lowercase()),
                    format!("Image File Execution Options hijack: launching {image} runs '{}' instead", debugger.as_display()),
                    format!("HKLM\\{base}\\{image} Debugger"),
                ));
            }
            if let Some(monitor) = registry::read_value(HKEY_LOCAL_MACHINE, &format!("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\{image}"), "MonitorProcess") {
                findings.push(tracked(
                    Level::Critical,
                    format!("autorun:silent-process-exit:{}", image.to_lowercase()),
                    format!("SilentProcessExit monitor: when {image} exits '{}' runs", monitor.as_display()),
                    "HKLM SilentProcessExit MonitorProcess".to_string(),
                ));
            }
        }
    }
}

fn appinit_findings(findings: &mut Vec<Finding>) {
    for path in APPINIT_PATHS {
        let Ok(key) = registry::open(HKEY_LOCAL_MACHINE, path) else { continue };
        let dlls = key.value("AppInit_DLLs").map(|v| v.as_display()).unwrap_or_default();
        if dlls.trim().is_empty() {
            continue;
        }
        let load_enabled = key.value("LoadAppInit_DLLs").and_then(|v| v.number()) == Some(1);
        findings.push(tracked(
            if load_enabled { Level::Critical } else { Level::Warn },
            format!("autorun:appinit:{}", path.contains("WOW6432Node")),
            format!("AppInit_DLLs is set ({}): '{dlls}'", if load_enabled { "loading is ENABLED, injected into every GUI process" } else { "LoadAppInit_DLLs is off" }),
            format!("HKLM\\{path}"),
        ));
    }
    if let Ok(key) = registry::open(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls") {
        for (name, value) in key.values() {
            findings.push(tracked(
                Level::Critical,
                format!("autorun:appcert:{}", name.to_lowercase()),
                format!("AppCertDlls entry '{name}': {} is injected into every process using CreateProcess", value.as_display()),
                "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls".to_string(),
            ));
        }
    }
    if let Some(value) = registry::read_value(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Session Manager", "BootExecute") {
        let text = value.as_display();
        if text.trim().to_lowercase() != "autocheck autochk *" {
            findings.push(tracked(
                Level::Critical,
                "autorun:bootexecute".to_string(),
                format!("Session Manager BootExecute is not the Windows default: '{text}'"),
                "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager BootExecute".to_string(),
            ));
        }
    }
}

fn netsh_findings(findings: &mut Vec<Finding>) {
    let path = "SOFTWARE\\Microsoft\\NetSh";
    let Ok(key) = registry::open(HKEY_LOCAL_MACHINE, path) else { return };
    let system32 = system_root().join("System32");
    for (name, value) in key.values() {
        let dll = value.as_display();
        let expanded = PathBuf::from(expand_env(&dll));
        let resolved = if expanded.parent().map(|p| p.as_os_str().is_empty()).unwrap_or(true) { system32.join(&expanded) } else { expanded };
        let outside_system = !resolved.starts_with(&system32) || !resolved.exists();
        findings.push(tracked(
            if outside_system { Level::Critical } else { Level::Info },
            format!("autorun:netsh:{}", name.to_lowercase()),
            format!("netsh helper '{name}' -> {dll}{}", if outside_system { " (not an existing System32 DLL, loaded by every netsh run)" } else { "" }),
            format!("HKLM\\{path}"),
        ));
    }
}

fn startup_folder_findings(findings: &mut Vec<Finding>) {
    let mut folders: Vec<PathBuf> = Vec::new();
    if let Ok(appdata) = std::env::var("APPDATA") {
        folders.push(PathBuf::from(appdata).join("Microsoft\\Windows\\Start Menu\\Programs\\Startup"));
    }
    if let Ok(program_data) = std::env::var("ProgramData") {
        folders.push(PathBuf::from(program_data).join("Microsoft\\Windows\\Start Menu\\Programs\\Startup"));
    }
    for folder in folders {
        let Ok(entries) = std::fs::read_dir(&folder) else { continue };
        for entry in entries.flatten() {
            let file_name = entry.file_name().to_string_lossy().to_string();
            if file_name.eq_ignore_ascii_case("desktop.ini") {
                continue;
            }
            let extension = entry.path().extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
            let scripted = SCRIPT_EXTENSIONS.contains(&extension.as_str());
            findings.push(tracked(
                if scripted { Level::Warn } else { Level::Info },
                format!("autorun:startup-folder:{}", entry.path().display().to_string().to_lowercase()),
                format!("Startup folder item '{file_name}'{}", if scripted { " (script or scriptable payload)" } else { "" }),
                format!("{} ({} bytes)", entry.path().display(), entry.metadata().map(|m| m.len()).unwrap_or(0)),
            ));
        }
    }
}

fn documents_folders() -> Vec<PathBuf> {
    let mut folders = Vec::new();
    if let Some(personal) = registry::read_value(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders", "Personal") {
        folders.push(PathBuf::from(expand_env(&personal.as_display())));
    }
    if let Ok(profile) = std::env::var("USERPROFILE") {
        folders.push(PathBuf::from(profile).join("Documents"));
    }
    folders.dedup();
    folders
}

fn powershell_profile_findings(findings: &mut Vec<Finding>) {
    let mut profiles: Vec<PathBuf> = Vec::new();
    for documents in documents_folders() {
        for flavor in ["WindowsPowerShell", "PowerShell"] {
            profiles.push(documents.join(flavor).join("profile.ps1"));
            profiles.push(documents.join(flavor).join("Microsoft.PowerShell_profile.ps1"));
            profiles.push(documents.join(flavor).join("Microsoft.VSCode_profile.ps1"));
        }
    }
    let host_dir = system_root().join("System32\\WindowsPowerShell\\v1.0");
    profiles.push(host_dir.join("profile.ps1"));
    profiles.push(host_dir.join("Microsoft.PowerShell_profile.ps1"));
    if let Ok(program_files) = std::env::var("ProgramFiles") {
        profiles.push(PathBuf::from(program_files).join("PowerShell\\7\\profile.ps1"));
    }
    profiles.sort();
    profiles.dedup();
    for profile in profiles {
        let Ok(bytes) = std::fs::read(&profile) else { continue };
        findings.push(tracked(
            Level::Warn,
            format!("autorun:powershell-profile:{}", profile.display().to_string().to_lowercase()),
            format!("PowerShell profile script runs at every shell start: {}", profile.display()),
            format!("{} bytes, content digest {:016x}", bytes.len(), fnv1a(&bytes)),
        ));
    }
}

pub fn autorun_locations(ctx: &Context) -> Vec<Finding> {
    let mut findings = Vec::new();
    if let Err(OpenError::Denied) = registry::open(HKEY_LOCAL_MACHINE, IFEO_PATHS[0]) {
        findings.push(Finding::limited_visibility(CATEGORY, "Image File Execution Options is not readable"));
    }
    run_key_findings(ctx, &mut findings);
    winlogon_findings(&mut findings);
    ifeo_findings(&mut findings);
    appinit_findings(&mut findings);
    netsh_findings(&mut findings);
    startup_folder_findings(&mut findings);
    powershell_profile_findings(&mut findings);
    findings
}
