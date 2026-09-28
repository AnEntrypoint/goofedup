use super::acl::Exposure;
use super::pathing::{describe_exposure, expand_env, system_root, Context};
use super::registry::{self, Key};
use super::Finding;
use crate::alert::Level;
use regex::Regex;
use std::path::PathBuf;
use std::sync::OnceLock;
use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;

const CATEGORY: &str = "tamper-service";
const SERVICES_PATH: &str = "SYSTEM\\CurrentControlSet\\Services";
const START_AUTO_OR_EARLIER: u32 = 2;

struct ParsedImage {
    executable: PathBuf,
    quoted: bool,
}

fn image_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^(.+?\.(?:exe|sys|dll|com|bat|cmd))(?:\s|$)").unwrap())
}

fn parse_image_path(raw: &str) -> Option<ParsedImage> {
    let mut text = expand_env(raw.trim());
    if let Some(stripped) = text.strip_prefix("\\??\\") {
        text = stripped.to_string();
    }
    let lowered = text.to_lowercase();
    if lowered.starts_with("\\systemroot\\") {
        text = format!("{}\\{}", system_root().display(), &text["\\systemroot\\".len()..]);
    } else if lowered.starts_with("system32\\") {
        text = format!("{}\\{}", system_root().display(), text);
    }
    if let Some(inner) = text.strip_prefix('"') {
        let end = inner.find('"')?;
        return Some(ParsedImage { executable: PathBuf::from(&inner[..end]), quoted: true });
    }
    if !text.contains('\\') && !text.contains('/') {
        let dir = if lowered.trim_end().ends_with(".sys") { "System32\\drivers" } else { "System32" };
        text = format!("{}\\{dir}\\{}", system_root().display(), text);
    }
    let executable = image_re()
        .captures(&text)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
        .unwrap_or_else(|| text.trim().to_string());
    if executable.is_empty() {
        return None;
    }
    Some(ParsedImage { executable: PathBuf::from(executable), quoted: false })
}

fn runs_as_system(object_name: Option<&str>) -> bool {
    match object_name.map(|n| n.trim().to_lowercase()) {
        None => true,
        Some(n) => n.is_empty() || n == "localsystem" || n == "nt authority\\system",
    }
}

fn service_dll(service_key: &Key) -> Option<PathBuf> {
    let parameters = service_key.open_child("Parameters").ok()?;
    let raw = parameters.value("ServiceDll")?;
    parse_image_path(raw.text()?).map(|p| p.executable)
}

pub fn autostart_services(ctx: &Context) -> Vec<Finding> {
    let Ok(root) = registry::open(HKEY_LOCAL_MACHINE, SERVICES_PATH) else { return Vec::new() };
    let mut findings = Vec::new();
    for name in root.subkeys() {
        let Ok(service) = root.open_child(&name) else { continue };
        let values = service.values();
        let value_of = |wanted: &str| values.iter().find(|(n, _)| n.eq_ignore_ascii_case(wanted)).map(|(_, v)| v);
        let Some(start) = value_of("Start").and_then(|v| v.number()) else { continue };
        if start > START_AUTO_OR_EARLIER {
            continue;
        }
        let Some(image) = value_of("ImagePath").and_then(|v| v.text()).and_then(parse_image_path) else { continue };
        let system_account = runs_as_system(value_of("ObjectName").and_then(|v| v.text()));

        let mut targets = vec![("service binary", image.executable.clone())];
        if let Some(dll) = service_dll(&service) {
            targets.push(("hosted ServiceDll", dll));
        }
        for (role, path) in targets {
            let exposure = ctx.exposure(&path);
            let level = match &exposure {
                Exposure::Writable { .. } | Exposure::Plantable { .. } if system_account => Level::Critical,
                Exposure::Writable { .. } | Exposure::Plantable { .. } => Level::Warn,
                Exposure::Missing => Level::Warn,
                _ => continue,
            };
            findings.push(
                Finding::new(
                    level,
                    CATEGORY,
                    format!("service:{name}:{}", path.display()),
                    format!(
                        "auto-start service '{name}' ({}) {role} {} is {}",
                        if system_account { "runs as SYSTEM" } else { "runs as a named account" },
                        path.display(),
                        describe_exposure(&exposure)
                    ),
                    format!("ImagePath={}", value_of("ImagePath").map(|v| v.as_display()).unwrap_or_default()),
                )
                .tracked(),
            );
        }

        let executable = image.executable.to_string_lossy().to_string();
        if !image.quoted && executable.contains(' ') {
            let plantable = executable
                .match_indices(' ')
                .map(|(idx, _)| PathBuf::from(format!("{}.exe", &executable[..idx])))
                .find(|candidate| matches!(ctx.exposure(candidate), Exposure::Plantable { .. }));
            let (level, detail) = match plantable {
                Some(candidate) => (Level::Critical, format!("a planted {} would run first", candidate.display())),
                None => (Level::Warn, "no writable hijack point found, hardening gap only".to_string()),
            };
            findings.push(
                Finding::new(
                    level,
                    CATEGORY,
                    format!("service:{name}:unquoted"),
                    format!("auto-start service '{name}' has an unquoted ImagePath with spaces: {detail}"),
                    format!("ImagePath={}", value_of("ImagePath").map(|v| v.as_display()).unwrap_or_default()),
                )
                .tracked(),
            );
        }
    }
    findings
}
