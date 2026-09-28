use crate::alert::Level;
use sysinfo::{Process, System};

pub struct Finding {
    pub level: Level,
    pub message: String,
    pub evidence: String,
    pub dedupe_key: Option<(String, String)>,
}

struct SystemRole {
    name: &'static str,
    expected_parents: &'static [&'static str],
    parent_may_be_gone: bool,
    session_zero_only: bool,
    singleton: bool,
}

const SYSTEM_ROLES: &[SystemRole] = &[
    SystemRole { name: "smss", expected_parents: &["system", "smss"], parent_may_be_gone: true, session_zero_only: true, singleton: false },
    SystemRole { name: "csrss", expected_parents: &["smss"], parent_may_be_gone: true, session_zero_only: false, singleton: false },
    SystemRole { name: "wininit", expected_parents: &["smss"], parent_may_be_gone: true, session_zero_only: true, singleton: true },
    SystemRole { name: "winlogon", expected_parents: &["smss"], parent_may_be_gone: true, session_zero_only: false, singleton: false },
    SystemRole { name: "services", expected_parents: &["wininit"], parent_may_be_gone: false, session_zero_only: true, singleton: true },
    SystemRole { name: "lsass", expected_parents: &["wininit"], parent_may_be_gone: false, session_zero_only: true, singleton: true },
    SystemRole { name: "svchost", expected_parents: &["services"], parent_may_be_gone: false, session_zero_only: false, singleton: false },
];

const SHELL_CHILDREN: &[&str] = &["cmd", "powershell", "pwsh", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "node"];
const OFFICE_PARENTS: &[&str] = &["winword", "excel", "powerpnt", "outlook", "onenote", "msaccess", "mspub", "visio", "winproj"];
const BROWSER_PARENTS: &[&str] = &["chrome", "msedge", "firefox", "brave", "opera", "vivaldi", "iexplore"];
const DISCORD_PARENTS: &[&str] = &["discord", "discordptb", "discordcanary"];

pub fn normalized_name(name: &str) -> String {
    let lower = name.to_lowercase();
    lower.strip_suffix(".exe").map(str::to_string).unwrap_or(lower)
}

pub fn is_shell_child(name: &str) -> bool {
    SHELL_CHILDREN.contains(&normalized_name(name).as_str())
}

pub fn parent_of<'a>(sys: &'a System, p: &Process) -> Option<&'a Process> {
    let parent = sys.process(p.parent()?)?;
    (parent.start_time() <= p.start_time()).then_some(parent)
}

fn command_line(p: &Process) -> String {
    p.cmd().iter().map(|s| s.to_string_lossy().to_string()).collect::<Vec<_>>().join(" ")
}

fn exe_string(p: &Process) -> String {
    p.exe().map(|e| e.to_string_lossy().to_string()).unwrap_or_default()
}

#[cfg(windows)]
fn session_of(pid: u32) -> Option<u32> {
    let mut session = 0u32;
    unsafe { windows::Win32::System::RemoteDesktop::ProcessIdToSessionId(pid, &mut session) }.ok()?;
    Some(session)
}

#[cfg(not(windows))]
fn session_of(_pid: u32) -> Option<u32> {
    None
}

fn is_older_instance_present(sys: &System, p: &Process, role_name: &str) -> bool {
    sys.processes().values().any(|other| {
        other.pid() != p.pid()
            && normalized_name(&other.name().to_string_lossy()) == role_name
            && (other.start_time(), other.pid().as_u32()) < (p.start_time(), p.pid().as_u32())
    })
}

fn system_process_findings(sys: &System, p: &Process) -> Vec<Finding> {
    let name = p.name().to_string_lossy().to_string();
    let normalized = normalized_name(&name);
    let Some(role) = SYSTEM_ROLES.iter().find(|r| r.name == normalized) else {
        return Vec::new();
    };
    let pid = p.pid().as_u32();
    let mut findings = Vec::new();

    match parent_of(sys, p) {
        Some(parent) => {
            let parent_name = parent.name().to_string_lossy().to_string();
            if !role.expected_parents.contains(&normalized_name(&parent_name).as_str()) {
                findings.push(Finding {
                    level: Level::Critical,
                    message: format!("'{name}' (PID {pid}) has parent '{parent_name}' (PID {}) -- a genuine {name} is only ever launched by {}", parent.pid().as_u32(), role.expected_parents.join("/")),
                    evidence: format!("exe={} parent_exe={}", exe_string(p), exe_string(parent)),
                    dedupe_key: None,
                });
            }
        }
        None if !role.parent_may_be_gone && p.parent().is_some() => {
            findings.push(Finding {
                level: Level::Warn,
                message: format!("'{name}' (PID {pid}) has no live parent -- a genuine {name} is only ever launched by {}, which stays running", role.expected_parents.join("/")),
                evidence: format!("exe={} recorded_parent_pid={}", exe_string(p), p.parent().map(|pp| pp.as_u32()).unwrap_or(0)),
                dedupe_key: None,
            });
        }
        None => {}
    }

    if role.session_zero_only {
        if let Some(session) = session_of(pid).filter(|s| *s != 0) {
            findings.push(Finding {
                level: Level::Critical,
                message: format!("'{name}' (PID {pid}) runs in interactive session {session} -- a genuine {name} only exists in session 0"),
                evidence: format!("exe={}", exe_string(p)),
                dedupe_key: None,
            });
        }
    }

    if role.singleton && is_older_instance_present(sys, p, role.name) {
        findings.push(Finding {
            level: Level::Critical,
            message: format!("'{name}' (PID {pid}) is a second instance of a process that only ever runs once per boot"),
            evidence: format!("exe={}", exe_string(p)),
            dedupe_key: None,
        });
    }

    findings
}

fn shell_spawn_finding(sys: &System, p: &Process) -> Option<Finding> {
    let name = p.name().to_string_lossy().to_string();
    if !is_shell_child(&name) {
        return None;
    }
    let parent = parent_of(sys, p)?;
    let parent_name = parent.name().to_string_lossy().to_string();
    let parent_normalized = normalized_name(&parent_name);
    let parent_cmdline = command_line(parent);

    let (level, parent_class) = if OFFICE_PARENTS.contains(&parent_normalized.as_str()) {
        (Level::Critical, "an Office application")
    } else if DISCORD_PARENTS.contains(&parent_normalized.as_str()) {
        (Level::Critical, "Discord")
    } else if parent_cmdline.contains("--type=renderer") {
        (Level::Critical, "a Chromium/Electron renderer process")
    } else if BROWSER_PARENTS.contains(&parent_normalized.as_str()) {
        (Level::Warn, "a web browser")
    } else {
        return None;
    };

    let parent_exe = exe_string(parent);
    let head: String = parent_cmdline.chars().take(200).collect();
    Some(Finding {
        level,
        message: format!(
            "'{name}' (PID {}) was spawned by {parent_class} '{parent_name}' (PID {}) -- not something that process legitimately launches",
            p.pid().as_u32(),
            parent.pid().as_u32()
        ),
        evidence: format!("parent_exe={parent_exe} parent_cmdline_head={head}"),
        dedupe_key: (level == Level::Warn).then(|| (parent_exe, normalized_name(&name))),
    })
}

pub fn immediate_findings(sys: &System, p: &Process) -> Vec<Finding> {
    let mut findings = system_process_findings(sys, p);
    findings.extend(shell_spawn_finding(sys, p));
    findings
}
