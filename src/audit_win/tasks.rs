use super::acl::Exposure;
use super::pathing::{describe_exposure, expand_env, extract_paths, resolve_command, system_root, Context};
use super::Finding;
use crate::alert::Level;
use regex::Regex;
use std::path::PathBuf;
use std::sync::OnceLock;
use walkdir::WalkDir;

const CATEGORY: &str = "tamper-task";

struct Regexes {
    principals: Regex,
    settings: Regex,
    user_id: Regex,
    group_id: Regex,
    run_level: Regex,
    exec: Regex,
    command: Regex,
    arguments: Regex,
}

fn regexes() -> &'static Regexes {
    static RE: OnceLock<Regexes> = OnceLock::new();
    RE.get_or_init(|| Regexes {
        principals: Regex::new(r"(?s)<Principals>(.*?)</Principals>").unwrap(),
        settings: Regex::new(r"(?s)<Settings>(.*?)</Settings>").unwrap(),
        user_id: Regex::new(r"<UserId>(.*?)</UserId>").unwrap(),
        group_id: Regex::new(r"<GroupId>(.*?)</GroupId>").unwrap(),
        run_level: Regex::new(r"<RunLevel>(.*?)</RunLevel>").unwrap(),
        exec: Regex::new(r"(?s)<Exec>(.*?)</Exec>").unwrap(),
        command: Regex::new(r"(?s)<Command>(.*?)</Command>").unwrap(),
        arguments: Regex::new(r"(?s)<Arguments>(.*?)</Arguments>").unwrap(),
    })
}

fn decode_task_xml(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xFF, 0xFE]) {
        let units: Vec<u16> = bytes[2..].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        String::from_utf16_lossy(&units)
    } else if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        String::from_utf8_lossy(&bytes[3..]).to_string()
    } else {
        String::from_utf8_lossy(bytes).to_string()
    }
}

fn unescape(text: &str) -> String {
    text.replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

fn capture(re: &Regex, text: &str) -> Option<String> {
    re.captures(text).and_then(|c| c.get(1)).map(|m| unescape(m.as_str().trim()))
}

fn is_system_principal(principal: &str) -> bool {
    matches!(
        principal.to_lowercase().as_str(),
        "s-1-5-18" | "system" | "nt authority\\system" | "localsystem"
    )
}

struct Action {
    command: String,
    arguments: String,
}

struct TaskDefinition {
    principal: String,
    highest: bool,
    disabled: bool,
    actions: Vec<Action>,
}

fn parse_task(xml: &str) -> TaskDefinition {
    let re = regexes();
    let principals = re.principals.captures(xml).and_then(|c| c.get(1)).map(|m| m.as_str()).unwrap_or("");
    let principal = capture(&re.user_id, principals)
        .or_else(|| capture(&re.group_id, principals))
        .unwrap_or_default();
    let highest = capture(&re.run_level, principals).map(|r| r.eq_ignore_ascii_case("HighestAvailable")).unwrap_or(false);
    let disabled = re
        .settings
        .captures(xml)
        .and_then(|c| c.get(1))
        .map(|s| s.as_str().contains("<Enabled>false</Enabled>"))
        .unwrap_or(false);
    let actions = re
        .exec
        .captures_iter(xml)
        .filter_map(|c| c.get(1))
        .map(|block| Action {
            command: capture(&re.command, block.as_str()).unwrap_or_default(),
            arguments: capture(&re.arguments, block.as_str()).unwrap_or_default(),
        })
        .collect();
    TaskDefinition { principal, highest, disabled, actions }
}

struct Target {
    path: PathBuf,
    role: &'static str,
}

fn targets_of(action: &Action) -> Vec<Target> {
    let mut targets = Vec::new();
    let command = expand_env(action.command.trim().trim_matches('"'));
    if !command.is_empty() {
        let resolved = resolve_command(&command).unwrap_or_else(|| PathBuf::from(&command));
        targets.push(Target { path: resolved, role: "program" });
    }
    for path in extract_paths(&action.arguments) {
        if !targets.iter().any(|t| t.path == path) {
            targets.push(Target { path, role: "referenced file" });
        }
    }
    targets
}

pub fn privileged_tasks(ctx: &Context) -> Vec<Finding> {
    let root = system_root().join("System32").join("Tasks");
    if std::fs::read_dir(&root).is_err() {
        return vec![Finding::limited_visibility(
            CATEGORY,
            format!("{} is not readable, scheduled task definitions cannot be audited", root.display()),
        )];
    }
    let mut findings = Vec::new();
    let mut unreadable = 0usize;
    for entry in WalkDir::new(&root).follow_links(false) {
        let Ok(entry) = entry else {
            unreadable += 1;
            continue;
        };
        if !entry.file_type().is_file() {
            continue;
        }
        let Ok(bytes) = std::fs::read(entry.path()) else {
            unreadable += 1;
            continue;
        };
        let relative = entry.path().strip_prefix(&root).unwrap_or(entry.path()).to_string_lossy().to_string();
        let task = parse_task(&decode_task_xml(&bytes));
        if !(is_system_principal(&task.principal) || task.highest) {
            continue;
        }
        findings.extend(task_findings(ctx, &relative, &task));
    }
    if unreadable > 0 {
        findings.push(Finding::limited_visibility(
            CATEGORY,
            format!("{unreadable} scheduled task definition(s) could not be read"),
        ));
    }
    findings
}

fn task_findings(ctx: &Context, relative: &str, task: &TaskDefinition) -> Vec<Finding> {
    let is_os_task = relative.to_lowercase().starts_with("microsoft\\windows\\");
    let run_as = format!(
        "{}{}",
        if task.principal.is_empty() { "?" } else { task.principal.as_str() },
        if task.highest { " (RunLevel Highest)" } else { "" }
    );
    let mut findings = Vec::new();
    for action in &task.actions {
        for target in targets_of(action) {
            let exposure = ctx.exposure(&target.path);
            let mut level = match &exposure {
                Exposure::Writable { .. } | Exposure::Plantable { .. } => Level::Critical,
                Exposure::Missing if !is_os_task => Level::Warn,
                Exposure::Unknown => match ctx.user_writable_fragment(&target.path.to_string_lossy()) {
                    Some(_) => Level::Warn,
                    None => continue,
                },
                _ => continue,
            };
            if task.disabled {
                level = level.min(Level::Warn);
            }
            findings.push(
                Finding::new(
                    level,
                    CATEGORY,
                    format!("task:{relative}:{}", target.path.display()),
                    format!("{}task '{relative}' runs as {run_as}; {} {} is {}", if task.disabled { "DISABLED " } else { "" }, target.role, target.path.display(), describe_exposure(&exposure)),
                    format!("command={} arguments={}", action.command, action.arguments),
                )
                .tracked(),
            );
        }
    }
    findings
}
