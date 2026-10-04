use super::pathing::Context;
use super::Finding;
use crate::alert::Level;
use std::path::{Path, PathBuf};

const CATEGORY: &str = "tamper-credential";

fn modified_stamp(path: &Path) -> String {
    let Ok(meta) = std::fs::metadata(path) else { return "unknown".to_string() };
    let secs = meta
        .modified()
        .ok()
        .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{} bytes, modified epoch {secs}", meta.len())
}

fn line_count(path: &Path) -> usize {
    std::fs::read(path).map(|bytes| bytes.iter().filter(|b| **b == b'\n').count().max(1)).unwrap_or(0)
}

fn has_config_key(path: &Path, key_suffix: &str) -> bool {
    let Ok(bytes) = std::fs::read(path) else { return false };
    String::from_utf8_lossy(&bytes).lines().any(|line| {
        let key = line.split(['=', ':']).next().unwrap_or("").trim();
        key.ends_with(key_suffix)
    })
}

fn git_has_store_helper(home: &Path, appdata: &Path) -> bool {
    [home.join(".gitconfig"), home.join(".config").join("git").join("config"), appdata.join("Git").join("config")]
        .iter()
        .any(|path| {
            std::fs::read_to_string(path)
                .map(|content| {
                    content.lines().any(|line| {
                        let (key, value) = line.split_once('=').unwrap_or(("", ""));
                        key.trim().ends_with("helper") && value.trim().starts_with("store")
                    })
                })
                .unwrap_or(false)
        })
}

fn report(path: &Path, what: &str, detail: String) -> Finding {
    Finding::new(
        Level::Warn,
        CATEGORY,
        format!("credential:{}", path.display().to_string().to_lowercase()),
        format!("plaintext credential store present: {what}"),
        format!("{} ({detail}); presence only, contents not reported", path.display()),
    )
    .tracked()
}

pub fn plaintext_stores(_ctx: &Context) -> Vec<Finding> {
    let home = PathBuf::from(std::env::var("USERPROFILE").unwrap_or_default());
    if home.as_os_str().is_empty() {
        return Vec::new();
    }
    let appdata = std::env::var("APPDATA").map(PathBuf::from).unwrap_or_else(|_| home.join("AppData\\Roaming"));
    let mut findings = Vec::new();

    let git_credentials = home.join(".git-credentials");
    if git_credentials.is_file() {
        let what = if git_has_store_helper(&home, &appdata) {
            "git credential helper 'store' file"
        } else {
            "git credentials file (no 'store' helper is configured, so git does not read it)"
        };
        findings.push(report(&git_credentials, what, format!("{} entries, {}", line_count(&git_credentials), modified_stamp(&git_credentials))));
    }
    let npmrc = home.join(".npmrc");
    if npmrc.is_file() && has_config_key(&npmrc, "_authToken") {
        findings.push(report(&npmrc, "npm registry auth token", modified_stamp(&npmrc)));
    }
    for hosts_yml in [appdata.join("GitHub CLI").join("hosts.yml"), home.join(".config").join("gh").join("hosts.yml")] {
        if hosts_yml.is_file() && has_config_key(&hosts_yml, "oauth_token") {
            findings.push(report(&hosts_yml, "GitHub CLI token", modified_stamp(&hosts_yml)));
        }
    }
    for (relative, what) in [
        (".aws\\credentials", "AWS access keys"),
        (".netrc", "netrc login"),
        ("_netrc", "netrc login"),
        (".pypirc", "PyPI upload credentials"),
        (".cargo\\credentials.toml", "crates.io token"),
        (".cargo\\credentials", "crates.io token"),
    ] {
        let path = home.join(relative);
        if path.is_file() {
            findings.push(report(&path, what, modified_stamp(&path)));
        }
    }
    findings
}
