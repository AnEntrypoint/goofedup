use super::acl::{self, Exposure};
use crate::tamper_config::TamperConfig;
use regex::Regex;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

pub struct Context<'a> {
    pub cfg: &'a TamperConfig,
    exposure_cache: Mutex<HashMap<PathBuf, Exposure>>,
}

impl<'a> Context<'a> {
    pub fn new(cfg: &'a TamperConfig) -> Self {
        Self { cfg, exposure_cache: Mutex::new(HashMap::new()) }
    }

    pub fn exposure(&self, path: &Path) -> Exposure {
        let cached = self.exposure_cache.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(path).cloned();
        if let Some(found) = cached {
            return found;
        }
        let computed = acl::exposure(path);
        self.exposure_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(path.to_path_buf(), computed.clone());
        computed
    }

    pub fn user_writable_fragment(&self, path: &str) -> Option<&str> {
        let lowered = path.replace('/', "\\").to_lowercase();
        self.cfg
            .user_writable_fragments
            .iter()
            .find(|fragment| lowered.contains(&fragment.to_lowercase()))
            .map(String::as_str)
    }
}

pub fn expand_env(input: &str) -> String {
    let mut out = String::new();
    let mut rest = input;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%') {
            Some(end) => {
                let name = &after[..end];
                match std::env::var(name) {
                    Ok(value) if !name.is_empty() => out.push_str(&value),
                    _ => {
                        out.push('%');
                        out.push_str(name);
                        out.push('%');
                    }
                }
                rest = &after[end + 1..];
            }
            None => {
                out.push('%');
                out.push_str(after);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

pub fn system_root() -> PathBuf {
    PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string()))
}

fn path_token_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)"((?:[a-z]:|%[a-z0-9_()]+%)\\[^"]+)"|((?:[a-z]:|%[a-z0-9_()]+%)\\[^"<>|*?\r\n]*?\.(?:exe|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|py|dll|jar|msi|scr|cpl|lnk|sys|com))(?:\s|"|$)"#,
        )
        .unwrap()
    })
}

pub fn extract_paths(command_line: &str) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = Vec::new();
    for capture in path_token_re().captures_iter(command_line) {
        let raw = capture.get(1).or_else(|| capture.get(2)).map(|m| m.as_str()).unwrap_or("");
        let path = PathBuf::from(expand_env(raw.trim()));
        if !found.contains(&path) {
            found.push(path);
        }
    }
    found
}

pub fn resolve_command(command: &str) -> Option<PathBuf> {
    let cleaned = expand_env(command.trim().trim_matches('"'));
    let has_extension = Path::new(&cleaned).extension().is_some();
    let with_extension = |p: PathBuf| if has_extension { p } else { p.with_extension("exe") };
    if cleaned.contains('\\') || cleaned.contains('/') {
        let candidate = with_extension(PathBuf::from(&cleaned));
        return candidate.exists().then_some(candidate);
    }
    let root = system_root();
    let mut dirs = vec![root.join("System32"), root.clone()];
    if let Ok(path_var) = std::env::var("PATH") {
        dirs.extend(std::env::split_paths(&path_var));
    }
    dirs.into_iter().map(|d| with_extension(d.join(&cleaned))).find(|c| c.exists())
}

pub fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf29ce484222325u64, |hash, b| (hash ^ *b as u64).wrapping_mul(0x100000001b3))
}

pub fn describe_exposure(exposure: &Exposure) -> String {
    match exposure {
        Exposure::Writable { via, writers } => format!("writable via {via} by {}", writers.join(", ")),
        Exposure::Plantable { writers } => format!("missing, and a file can be planted there by {}", writers.join(", ")),
        Exposure::Missing => "missing on disk".to_string(),
        Exposure::Protected => "protected".to_string(),
        Exposure::Unknown => "ACL unreadable".to_string(),
    }
}
