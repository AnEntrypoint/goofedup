use super::pathing::{fnv1a, system_root, Context};
use super::Finding;
use crate::alert::Level;

const CATEGORY: &str = "tamper-hosts";

const WELL_KNOWN_DOMAINS: [&str; 40] = [
    "microsoft.com",
    "windowsupdate.com",
    "windows.com",
    "live.com",
    "office.com",
    "office365.com",
    "microsoftonline.com",
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "github.com",
    "githubusercontent.com",
    "npmjs.org",
    "npmjs.com",
    "pypi.org",
    "crates.io",
    "docker.com",
    "discord.com",
    "discordapp.com",
    "apple.com",
    "amazon.com",
    "amazonaws.com",
    "paypal.com",
    "facebook.com",
    "cloudflare.com",
    "mozilla.org",
    "mozilla.com",
    "anthropic.com",
    "openai.com",
    "kaspersky.com",
    "malwarebytes.com",
    "avast.com",
    "eset.com",
    "symantec.com",
    "mcafee.com",
    "sophos.com",
    "bitdefender.com",
    "virustotal.com",
    "digicert.com",
    "letsencrypt.org",
];

const SECURITY_UPDATE_DOMAINS: [&str; 11] = [
    "microsoft.com",
    "windowsupdate.com",
    "windows.com",
    "kaspersky.com",
    "malwarebytes.com",
    "avast.com",
    "eset.com",
    "symantec.com",
    "mcafee.com",
    "sophos.com",
    "bitdefender.com",
];

fn matches_domain(host: &str, domains: &[&str]) -> bool {
    domains.iter().any(|d| host == *d || host.ends_with(&format!(".{d}")))
}

fn is_blackhole(ip: &str) -> bool {
    ip == "0.0.0.0" || ip == "::" || ip.starts_with("127.") || ip == "::1"
}

pub fn entries(_ctx: &Context) -> Vec<Finding> {
    let path = system_root().join("System32").join("drivers").join("etc").join("hosts");
    let Ok(content) = std::fs::read_to_string(&path) else { return Vec::new() };
    let mut findings = Vec::new();
    let mut active_lines: Vec<String> = Vec::new();
    for line in content.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let mut parts = line.split_whitespace();
        let Some(ip) = parts.next() else { continue };
        let hosts: Vec<String> = parts.map(|h| h.to_lowercase()).collect();
        active_lines.push(format!("{ip} {}", hosts.join(" ")));
        for host in hosts {
            let redirected = !is_blackhole(ip);
            let (level, why) = if redirected && matches_domain(&host, &WELL_KNOWN_DOMAINS) {
                (Level::Critical, "well-known domain redirected to a non-loopback address")
            } else if is_blackhole(ip) && matches_domain(&host, &SECURITY_UPDATE_DOMAINS) {
                (Level::Warn, "security/update vendor domain blackholed")
            } else if redirected {
                (Level::Warn, "host pinned to a non-loopback, non-blocklist address")
            } else {
                continue;
            };
            findings.push(
                Finding::new(
                    level,
                    CATEGORY,
                    format!("hosts:{host}:{ip}"),
                    format!("hosts entry {ip} -> {host}: {why}"),
                    path.display().to_string(),
                )
                .tracked(),
            );
        }
    }
    let digest = fnv1a(active_lines.join("\n").as_bytes());
    findings.push(
        Finding::new(
            Level::Info,
            CATEGORY,
            "hosts:digest",
            format!("hosts file has {} active lines (content digest {digest:016x})", active_lines.len()),
            path.display().to_string(),
        )
        .tracked(),
    );
    findings
}
