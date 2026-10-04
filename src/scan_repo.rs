use crate::alert::{AlertSink, Level};
use crate::command_shape::{self, NON_SOURCE_ASSET_EXTENSIONS};
use crate::heuristics::{
    find_appended_packed_payload, find_config_payload_disproportion,
    find_javascript_masquerading_as_asset,
};
use crate::jsonc;
use regex::Regex;
use serde_json::Value;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use walkdir::{DirEntry, WalkDir};

const SKIP_DIR_NAMES: &[&str] = &[".hg", ".svn", "target"];
const WATCH_NOISE_DIR_NAMES: &[&str] = &["node_modules", "target"];
const GIT_DIR: &str = ".git";
const GIT_HOOKS_DIR: &str = "hooks";
const LIFECYCLE_SCRIPTS: &[&str] = &[
    "preinstall",
    "install",
    "postinstall",
    "prepare",
    "prepublish",
    "prepublishOnly",
];
const HIDING_SCRIPT_EXTENSIONS: &[&str] = &["bat", "cmd", "ps1", "exe", "vbs", "scr"];
const JS_SOURCE_EXTENSIONS: &[&str] = &["js", "mjs", "cjs", "ts", "mts", "cts"];
const ENTRY_POINT_NAMES: &[&str] = &["index.js", "main.js", "index.mjs", "index.cjs"];
const KNOWN_PAYLOAD_SCRIPT_NAME: &str = "config.bat";
const FIRST_PARTY_ACTION_OWNERS: &[&str] = &["actions", "github"];
const DECOY_README_PHRASE: &str = "blockchain explorer";
const DECOY_DIR_NAMES: &[&str] = &["fonts", "font"];
const TEXT_READ_LIMIT: u64 = 8 * 1024 * 1024;
const ASSET_PREFIX_BYTES: u64 = 64 * 1024;
const TRAILING_PAYLOAD_MIN_BYTES: usize = 2000;
const TRAILING_PAYLOAD_MIN_OBFUSCATED_IDENTIFIERS: usize = 8;
const EVIDENCE_LIMIT: usize = 300;
const UNPINNED_ACTIONS_LISTED: usize = 5;
const AUTO_TASKS_SETTING: &str = "task.allowAutomaticTasks";

#[derive(Clone)]
pub enum Remedy {
    QuarantineFile(PathBuf),
    QuarantineDir(PathBuf),
    StripSettingsKeys { path: PathBuf, keys: Vec<String> },
}

pub struct Finding {
    pub level: Level,
    pub category: &'static str,
    pub message: String,
    pub evidence: String,
    pub remedy: Option<Remedy>,
}

impl Finding {
    fn new(level: Level, category: &'static str, message: String, evidence: String) -> Self {
        Self { level, category, message, evidence, remedy: None }
    }

    fn critical(category: &'static str, message: String, evidence: String) -> Self {
        Self::new(Level::Critical, category, message, evidence)
    }

    fn warn(category: &'static str, message: String, evidence: String) -> Self {
        Self::new(Level::Warn, category, message, evidence)
    }

    fn with_remedy(mut self, remedy: Remedy) -> Self {
        self.remedy = Some(remedy);
        self
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Tree,
    Live,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Tasks,
    Settings,
    Workspace,
    Gitignore,
    PackageJson,
    GitHook,
    Workflow,
    DecoyReadme,
    JsTail,
    Asset,
}

fn name_of(path: &Path) -> Option<String> {
    Some(path.file_name()?.to_str()?.to_ascii_lowercase())
}

fn parent_name_of(path: &Path) -> String {
    path.parent().and_then(name_of).unwrap_or_default()
}

fn extension_of(name: &str) -> &str {
    name.rsplit_once('.').map_or("", |(_, ext)| ext)
}

fn classify(path: &Path) -> Option<Kind> {
    let name = name_of(path)?;
    let parent = parent_name_of(path);
    let grandparent = path.parent().map(parent_name_of).unwrap_or_default();
    let ext = extension_of(&name);
    if parent == ".vscode" && name == "tasks.json" {
        Some(Kind::Tasks)
    } else if parent == ".vscode" && name == "settings.json" {
        Some(Kind::Settings)
    } else if name.ends_with(".code-workspace") {
        Some(Kind::Workspace)
    } else if name == ".gitignore" {
        Some(Kind::Gitignore)
    } else if name == "package.json" {
        Some(Kind::PackageJson)
    } else if parent == GIT_HOOKS_DIR && grandparent == GIT_DIR && !name.ends_with(".sample") {
        Some(Kind::GitHook)
    } else if parent == "workflows" && grandparent == ".github" && matches!(ext, "yml" | "yaml") {
        Some(Kind::Workflow)
    } else if name == "readme.md" && DECOY_DIR_NAMES.contains(&parent.as_str()) {
        Some(Kind::DecoyReadme)
    } else if JS_SOURCE_EXTENSIONS.contains(&ext)
        && (name.contains(".config.") || ENTRY_POINT_NAMES.contains(&name.as_str()))
    {
        Some(Kind::JsTail)
    } else if NON_SOURCE_ASSET_EXTENSIONS.contains(&ext) {
        Some(Kind::Asset)
    } else {
        None
    }
}

pub fn is_watch_candidate(path: &Path) -> bool {
    let Some(kind) = classify(path) else {
        return false;
    };
    let mut inside_git = false;
    for component in path.components() {
        let part = component.as_os_str().to_string_lossy();
        if WATCH_NOISE_DIR_NAMES.iter().any(|noise| part.eq_ignore_ascii_case(noise)) {
            return false;
        }
        inside_git |= part == GIT_DIR;
    }
    !inside_git || kind == Kind::GitHook
}

pub fn read_prefix(path: &Path, max_bytes: u64) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    std::fs::File::open(path).ok()?.take(max_bytes).read_to_end(&mut buf).ok()?;
    Some(buf)
}

fn read_text(path: &Path) -> Option<String> {
    let bytes = read_prefix(path, TEXT_READ_LIMIT)?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

fn clip(text: &str) -> String {
    text.chars().take(EVIDENCE_LIMIT).collect()
}

fn text_or_value(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Object(o)) => o.get("value").and_then(Value::as_str).unwrap_or_default().to_string(),
        _ => String::new(),
    }
}

fn platform_scopes(task: &Value) -> Vec<&Value> {
    [Some(task), task.get("windows"), task.get("linux"), task.get("osx")]
        .into_iter()
        .flatten()
        .collect()
}

fn command_text(scope: &Value) -> String {
    let command = text_or_value(scope.get("command"));
    let args = scope
        .get("args")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|item| text_or_value(Some(item)))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();
    format!("{command} {args}").trim().to_string()
}

fn compose_command(task: &Value) -> String {
    platform_scopes(task)
        .into_iter()
        .map(command_text)
        .filter(|text| !text.is_empty())
        .collect::<Vec<_>>()
        .join(" ; ")
}

fn is_hidden(task: &Value) -> bool {
    let scopes = platform_scopes(task);
    let reveals_never = scopes.iter().any(|scope| {
        scope
            .get("presentation")
            .and_then(|p| p.get("reveal"))
            .and_then(Value::as_str)
            .map_or(false, |reveal| reveal.eq_ignore_ascii_case("never"))
    });
    let concealed = scopes.iter().any(|scope| {
        scope.get("hide") == Some(&Value::Bool(true))
            || scope.get("isBackground") == Some(&Value::Bool(true))
    });
    reveals_never && concealed
}

fn runs_on_folder_open(task: &Value) -> bool {
    task.get("runOptions")
        .and_then(|options| options.get("runOn"))
        .and_then(Value::as_str)
        .map_or(false, |run_on| run_on.eq_ignore_ascii_case("folderOpen"))
}

fn task_entries(document: &Value) -> Vec<&Value> {
    let listed = match document.get("tasks") {
        Some(Value::Array(items)) => Some(items),
        Some(Value::Object(nested)) => nested.get("tasks").and_then(Value::as_array),
        _ => None,
    };
    listed.map(|items| items.iter().collect()).unwrap_or_default()
}

fn contains_folder_open(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.iter().any(|(key, inner)| {
            (key == "runOn"
                && inner.as_str().map_or(false, |v| v.eq_ignore_ascii_case("folderOpen")))
                || contains_folder_open(inner)
        }),
        Value::Array(items) => items.iter().any(contains_folder_open),
        _ => false,
    }
}

fn single_task_finding(path: &Path, task: &Value, quarantinable: bool) -> Option<Finding> {
    let label = task.get("label").and_then(Value::as_str).unwrap_or("(unnamed)");
    let command = compose_command(task);
    let shape = command_shape::analyze(&command);
    let mut reasons = shape.payload_reasons();
    if is_hidden(task) {
        reasons.push("is hidden (presentation.reveal=never with hide/isBackground)".to_string());
    }
    let evidence = format!("label={label:?} command={}", clip(&command));
    if !runs_on_folder_open(task) {
        return shape.executed_asset.map(|asset| {
            Finding::warn(
                "vscode-task-runs-asset",
                format!(
                    "'{}' task '{label}' executes non-source asset '{asset}' with an interpreter -- no legitimate build task runs a font/image/data file",
                    path.display()
                ),
                evidence,
            )
        });
    }
    if reasons.is_empty() {
        return Some(Finding::warn(
            "vscode-folderopen-task",
            format!(
                "'{}' task '{label}' runs automatically the moment the folder is opened in VS Code/Cursor/Windsurf/Antigravity -- confirm you wrote it",
                path.display()
            ),
            evidence,
        ));
    }
    let finding = Finding::critical(
        "vscode-autorun-task",
        format!(
            "'{}' task '{label}' auto-runs on folder open and {} -- the delivery vehicle of two confirmed repo compromises (opening the folder executes the payload)",
            path.display(),
            reasons.join(", ")
        ),
        evidence,
    );
    Some(if quarantinable {
        finding.with_remedy(Remedy::QuarantineFile(path.to_path_buf()))
    } else {
        finding
    })
}

fn task_findings(path: &Path, text: &str, quarantinable: bool) -> Vec<Finding> {
    let Some(document) = jsonc::parse(text) else {
        return unparseable_task_findings(path, text);
    };
    task_entries(&document)
        .into_iter()
        .filter_map(|task| single_task_finding(path, task, quarantinable))
        .collect()
}

fn unparseable_task_findings(path: &Path, text: &str) -> Vec<Finding> {
    if !text.to_ascii_lowercase().contains("folderopen") {
        return Vec::new();
    }
    let reasons = command_shape::analyze(text).payload_reasons();
    let evidence = "file does not parse as JSON-with-comments, so it was matched as raw text".to_string();
    if reasons.is_empty() {
        return vec![Finding::warn(
            "vscode-folderopen-task",
            format!("'{}' mentions folderOpen but cannot be parsed", path.display()),
            evidence,
        )];
    }
    vec![Finding::critical(
        "vscode-autorun-task",
        format!(
            "'{}' mentions folderOpen and {} but cannot be parsed",
            path.display(),
            reasons.join(", ")
        ),
        evidence,
    )
    .with_remedy(Remedy::QuarantineFile(path.to_path_buf()))]
}

fn automatic_tasks_enabled(value: &Value) -> bool {
    let enabled = |v: &Value| match v {
        Value::Bool(b) => *b,
        Value::String(s) => s.eq_ignore_ascii_case("on") || s.eq_ignore_ascii_case("true"),
        _ => false,
    };
    value.get(AUTO_TASKS_SETTING).map_or(false, enabled)
        || value
            .get("task")
            .and_then(|task| task.get("allowAutomaticTasks"))
            .map_or(false, enabled)
}

fn settings_findings(path: &Path, settings: &Value, strippable: bool) -> Vec<Finding> {
    let mut out = Vec::new();
    if automatic_tasks_enabled(settings) {
        let finding = Finding::critical(
            "vscode-auto-tasks-enabled",
            format!(
                "'{}' switches on {AUTO_TASKS_SETTING} -- it bypasses the prompt that stops folderOpen tasks running unattended; no legitimate workspace needs it",
                path.display()
            ),
            format!("{AUTO_TASKS_SETTING}={}", settings.get(AUTO_TASKS_SETTING).map_or("nested".to_string(), |v| v.to_string())),
        );
        out.push(if strippable && settings.get(AUTO_TASKS_SETTING).is_some() {
            finding.with_remedy(Remedy::StripSettingsKeys {
                path: path.to_path_buf(),
                keys: vec![AUTO_TASKS_SETTING.to_string()],
            })
        } else {
            finding
        });
    }
    if settings.get("tasks").map_or(false, contains_folder_open) {
        let finding = Finding::critical(
            "vscode-autorun-task",
            format!(
                "'{}' carries a bogus top-level \"tasks\" key with runOn=folderOpen -- settings.json has no such key, it exists only to look like an auto-run task",
                path.display()
            ),
            clip(&settings["tasks"].to_string()),
        );
        out.push(if strippable {
            finding.with_remedy(Remedy::StripSettingsKeys {
                path: path.to_path_buf(),
                keys: vec!["tasks".to_string()],
            })
        } else {
            finding
        });
    }
    out
}

fn workspace_findings(path: &Path, text: &str) -> Vec<Finding> {
    let mut out = task_findings(path, text, false);
    if let Some(settings) = jsonc::parse(text).and_then(|doc| doc.get("settings").cloned()) {
        out.extend(settings_findings(path, &settings, false));
    }
    out
}

fn vscode_settings_findings(path: &Path, text: &str) -> Vec<Finding> {
    jsonc::parse(text)
        .map(|settings| settings_findings(path, &settings, true))
        .unwrap_or_default()
}

fn has_autorun_task_beside(gitignore: &Path) -> bool {
    gitignore
        .parent()
        .map(|dir| dir.join(".vscode").join("tasks.json"))
        .and_then(|tasks| read_text(&tasks))
        .map_or(false, |text| text.to_ascii_lowercase().contains("folderopen"))
}

fn hides_script(pattern: &str) -> bool {
    HIDING_SCRIPT_EXTENSIONS.contains(&extension_of(pattern))
}

fn gitignore_findings(path: &Path, text: &str) -> Vec<Finding> {
    let autorun_beside = has_autorun_task_beside(path);
    let mut out = Vec::new();
    let mut previous_entry = String::new();
    for (index, raw) in text.lines().enumerate() {
        let entry = raw.trim();
        if entry.is_empty() || entry.starts_with('#') || entry.starts_with('!') {
            continue;
        }
        let pattern = entry.trim_start_matches('/').trim_start_matches("**/").to_ascii_lowercase();
        let follows_node_modules = previous_entry.trim_end_matches('/') == "node_modules";
        previous_entry = pattern.clone();
        let wildcard = pattern.contains('*');
        let hidden_script = hides_script(&pattern);
        let named_script = hidden_script && !wildcard && extension_of(&pattern) != "exe";
        let evidence = format!(
            "line {}: {entry:?}{}",
            index + 1,
            if follows_node_modules { " (directly after node_modules)" } else { "" }
        );
        if autorun_beside && hidden_script {
            out.push(Finding::critical(
                "gitignore-hides-payload",
                format!(
                    "'{}' ignores '{entry}' while a folderOpen task sits in the same tree -- the gitignore edit that hides the dropped payload from git status in the confirmed compromises",
                    path.display()
                ),
                evidence,
            ));
        } else if pattern == KNOWN_PAYLOAD_SCRIPT_NAME || named_script {
            out.push(Finding::warn(
                "gitignore-hides-payload",
                format!(
                    "'{}' ignores the script '{entry}' -- the compromises hid their dropped payload this way; confirm this file is yours",
                    path.display()
                ),
                evidence,
            ));
        }
    }
    out
}

fn lifecycle_findings(path: &Path, text: &str) -> Vec<Finding> {
    let Some(scripts) = jsonc::parse(text).and_then(|doc| doc.get("scripts").cloned()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for name in LIFECYCLE_SCRIPTS {
        let Some(script) = scripts.get(name).and_then(Value::as_str) else {
            continue;
        };
        let shape = command_shape::analyze(script);
        let reasons = shape.dropper_reasons();
        let evidence = format!("{name}={}", clip(script));
        if !reasons.is_empty() {
            out.push(Finding::critical(
                "package-lifecycle-dropper",
                format!(
                    "'{}' runs a {name} script that {} -- executes on every install, before anyone reads the code",
                    path.display(),
                    reasons.join(", ")
                ),
                evidence,
            ));
        } else if shape.inline_code {
            out.push(Finding::warn(
                "package-lifecycle-dropper",
                format!(
                    "'{}' runs inline code (node -e / python -c) from its {name} script -- executes on every install",
                    path.display()
                ),
                evidence,
            ));
        }
    }
    out
}

fn git_hook_findings(path: &Path, text: &str) -> Vec<Finding> {
    let reasons = command_shape::analyze(text).dropper_reasons();
    if reasons.is_empty() {
        return vec![Finding::warn(
            "git-hook",
            format!("'{}' is an active (non-sample) git hook -- it runs on git operations; confirm you installed it", path.display()),
            format!("{} bytes", text.len()),
        )];
    }
    vec![Finding::critical(
        "git-hook",
        format!("'{}' is an active git hook that {}", path.display(), reasons.join(", ")),
        clip(text.trim()),
    )]
}

fn head_checkout_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"github\.event\.pull_request\.head\.(sha|ref|repo)|github\.head_ref|refs/pull/").unwrap()
    })
}

fn action_use_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r##"(?m)^\s*-?\s*uses:\s*['"]?([A-Za-z0-9_.-]+)/([A-Za-z0-9_./-]+)@([^\s'"#]+)"##).unwrap()
    })
}

fn skip_ci_marker_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\[(skip ci|ci skip|no ci|skip actions|actions skip)\]").unwrap())
}

fn is_full_commit_sha(reference: &str) -> bool {
    reference.len() == 40 && reference.chars().all(|c| c.is_ascii_hexdigit())
}

fn workflow_findings(path: &Path, text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let pull_request_target = text.contains("pull_request_target");
    if pull_request_target && head_checkout_re().is_match(text) {
        out.push(Finding::critical(
            "workflow-risk",
            format!(
                "'{}' uses pull_request_target and references the pull request head -- untrusted fork code runs with the base repository's token and secrets",
                path.display()
            ),
            "pull_request_target + github.event.pull_request.head / github.head_ref / refs/pull".to_string(),
        ));
    } else if pull_request_target {
        out.push(Finding::warn(
            "workflow-risk",
            format!("'{}' triggers on pull_request_target -- it runs with base-repository secrets for fork PRs", path.display()),
            "pull_request_target".to_string(),
        ));
    }
    if command_shape::pipes_download_to_interpreter(text) {
        out.push(Finding::warn(
            "workflow-risk",
            format!("'{}' pipes a download straight into an interpreter (curl|bash shape) -- fine for a pinned first-party installer, dangerous for anything else", path.display()),
            "download piped into bash/sh/iex/node/python".to_string(),
        ));
    }
    let unpinned: Vec<String> = action_use_re()
        .captures_iter(text)
        .filter(|c| !FIRST_PARTY_ACTION_OWNERS.contains(&c[1].to_ascii_lowercase().as_str()))
        .filter(|c| !is_full_commit_sha(&c[3]))
        .map(|c| format!("{}/{}@{}", &c[1], &c[2], &c[3]))
        .collect();
    if !unpinned.is_empty() {
        out.push(Finding::warn(
            "workflow-risk",
            format!(
                "'{}' uses {} third-party action(s) pinned to a mutable tag/branch instead of a full commit SHA -- a retagged action runs attacker code in your CI",
                path.display(),
                unpinned.len()
            ),
            unpinned.iter().take(UNPINNED_ACTIONS_LISTED).cloned().collect::<Vec<_>>().join(", "),
        ));
    }
    if text.contains("git push") && skip_ci_marker_re().is_match(text) {
        out.push(Finding::warn(
            "workflow-risk",
            format!("'{}' pushes commits from CI marked [skip ci] -- unreviewed bot commits to the default branch that trigger no checks", path.display()),
            "git push + [skip ci]".to_string(),
        ));
    }
    out
}

fn asset_findings(path: &Path) -> Vec<Finding> {
    read_prefix(path, ASSET_PREFIX_BYTES)
        .and_then(|bytes| find_javascript_masquerading_as_asset(&bytes))
        .map(|verdict| {
            Finding::critical(
                "js-masquerading-as-asset",
                format!(
                    "'{}' claims a font/image/data extension but its first bytes are JavaScript -- HiddenSpawn-family delivery vehicle (real files of that type never start this way)",
                    path.display()
                ),
                verdict.reasons.join("; "),
            )
            .with_remedy(Remedy::QuarantineFile(path.to_path_buf()))
        })
        .into_iter()
        .collect()
}

fn decoy_readme_findings(path: &Path, text: &str) -> Vec<Finding> {
    if !text.to_ascii_lowercase().contains(DECOY_README_PHRASE) {
        return Vec::new();
    }
    let Some(dir) = path.parent() else {
        return Vec::new();
    };
    let carries_payload = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .any(|entry| !asset_findings(&entry.path()).is_empty());
    let evidence = format!("README mentions {DECOY_README_PHRASE:?}");
    if !carries_payload {
        return vec![Finding::warn(
            "decoy-fonts-dir",
            format!("'{}' is a fonts-directory README about a blockchain explorer -- the decoy the compromises used to explain the payload's presence", path.display()),
            evidence,
        )];
    }
    vec![Finding::critical(
        "decoy-fonts-dir",
        format!(
            "'{}' is a decoy README beside a JavaScript payload disguised as a font/image -- the whole directory exists to hide the dropper",
            dir.display()
        ),
        evidence,
    )
    .with_remedy(Remedy::QuarantineDir(dir.to_path_buf()))]
}

fn trailing_payload_reason(text: &str) -> Option<String> {
    static IDENTIFIER: OnceLock<Regex> = OnceLock::new();
    let identifier = IDENTIFIER.get_or_init(|| Regex::new(r"_0x[0-9a-fA-F]{3,6}").unwrap());
    let last = text.lines().rev().find(|line| !line.trim().is_empty())?;
    if last.len() < TRAILING_PAYLOAD_MIN_BYTES {
        return None;
    }
    let obfuscated = identifier.find_iter(last).count();
    let stamped = last.contains("global['!']") || last.contains("global[\"!\"]");
    (obfuscated >= TRAILING_PAYLOAD_MIN_OBFUSCATED_IDENTIFIERS || stamped).then(|| {
        format!(
            "last line is {} bytes carrying {obfuscated} obfuscator-style _0x identifiers{}",
            last.len(),
            if stamped { " and a global['!'] stamp" } else { "" }
        )
    })
}

fn js_tail_findings(path: &Path, text: &str, scope: Scope) -> Vec<Finding> {
    let is_config = name_of(path).map_or(false, |name| name.contains(".config."));
    let disproportion = if is_config { find_config_payload_disproportion(text) } else { None };
    let appended = find_appended_packed_payload(text);
    let mut out = Vec::new();
    if scope == Scope::Live {
        if let Some(verdict) = &disproportion {
            out.push(Finding::critical(
                "config-payload-disproportion",
                format!("'{}' is a build/config file whose byte size is out of proportion to its line count -- a payload appended as one long line", path.display()),
                verdict.reasons.join("; "),
            ));
        }
        if let Some(verdict) = &appended {
            out.push(Finding::critical(
                "appended-packed-payload",
                format!("'{}' contains a multi-kilobyte packed obfuscator.io IIFE on one line -- HiddenSpawn-family append", path.display()),
                verdict.reasons.join("; "),
            ));
        }
    }
    if disproportion.is_none() && appended.is_none() {
        if let Some(reason) = trailing_payload_reason(text) {
            out.push(Finding::critical(
                "trailing-packed-payload",
                format!("'{}' ends in a packed payload line -- HiddenSpawn-family append that line-based diffs never show", path.display()),
                reason,
            ));
        }
    }
    out
}

pub fn analyze_file(path: &Path, scope: Scope) -> Vec<Finding> {
    let Some(kind) = classify(path) else {
        return Vec::new();
    };
    if kind == Kind::Asset {
        return if scope == Scope::Live { asset_findings(path) } else { Vec::new() };
    }
    let Some(text) = read_text(path) else {
        return Vec::new();
    };
    match kind {
        Kind::Tasks => task_findings(path, &text, true),
        Kind::Settings => vscode_settings_findings(path, &text),
        Kind::Workspace => workspace_findings(path, &text),
        Kind::Gitignore => gitignore_findings(path, &text),
        Kind::PackageJson => lifecycle_findings(path, &text),
        Kind::GitHook => git_hook_findings(path, &text),
        Kind::Workflow => workflow_findings(path, &text),
        Kind::DecoyReadme => decoy_readme_findings(path, &text),
        Kind::JsTail => js_tail_findings(path, &text, scope),
        Kind::Asset => Vec::new(),
    }
}

pub fn emit(alerts: &AlertSink, finding: &Finding) {
    match finding.level {
        Level::Critical => alerts.critical(finding.category, finding.message.clone(), finding.evidence.clone()),
        Level::Warn => alerts.warn(finding.category, finding.message.clone(), finding.evidence.clone()),
        Level::Info => alerts.info(finding.category, finding.message.clone()),
    }
}

fn should_descend(entry: &DirEntry) -> bool {
    if entry.path().to_string_lossy().len() > crate::scan_js::MAX_SCAN_PATH_CHARS {
        return false;
    }
    if !entry.file_type().is_dir() {
        return true;
    }
    if entry.depth() > crate::scan_js::MAX_SCAN_DEPTH
        || crate::scan_js::is_stacked_node_modules(entry.path())
    {
        return false;
    }
    let name = entry.file_name().to_string_lossy();
    if SKIP_DIR_NAMES.iter().any(|skip| *skip == name) {
        return false;
    }
    let inside_git = entry.path().parent().and_then(Path::file_name).map_or(false, |parent| parent == GIT_DIR);
    !(inside_git && name != GIT_HOOKS_DIR)
}

pub fn walk_files(root: &Path) -> impl Iterator<Item = PathBuf> {
    WalkDir::new(root)
        .into_iter()
        .filter_entry(should_descend)
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_file())
        .map(DirEntry::into_path)
}

pub fn report_findings(alerts: &AlertSink, findings: &[Finding]) -> usize {
    findings
        .iter()
        .map(|finding| {
            emit(alerts, finding);
            usize::from(finding.level == Level::Critical)
        })
        .sum()
}

pub fn scan_tree(root: &Path, alerts: &AlertSink) -> usize {
    let mut inspected = 0usize;
    let mut critical = 0usize;
    for path in walk_files(root) {
        if matches!(classify(&path), None | Some(Kind::Asset)) {
            continue;
        }
        inspected += 1;
        critical += report_findings(alerts, &analyze_file(&path, Scope::Tree));
    }
    alerts.info(
        "repo-scan",
        format!(
            "inspected {inspected} repo-config file(s) under {}, {critical} critical",
            root.display()
        ),
    );
    critical
}

pub fn check_changed_file(path: &Path, alerts: &AlertSink) -> usize {
    report_findings(alerts, &analyze_file(path, Scope::Live))
}
