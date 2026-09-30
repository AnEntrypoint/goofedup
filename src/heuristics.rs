use regex::Regex;
use std::sync::OnceLock;

pub struct Verdict {
    pub score: u32,
    pub reasons: Vec<String>,
}

const MIN_INLINE_PAYLOAD_CMDLINE_LEN: usize = 300;
const LONG_CMDLINE_LEN: usize = 600;
const VERY_LONG_CMDLINE_LEN: usize = 2000;
const LONG_ENCODED_BLOB_MIN_RUN: usize = 120;
const HIGH_SYMBOL_DENSITY_RATIO: f64 = 0.30;
const PACKED_ENTROPY_BITS_PER_CHAR: f64 = 5.2;
const ELEVATED_ENTROPY_BITS_PER_CHAR: f64 = 4.7;
const COMMAND_LINE_ALERT_SCORE: u32 = 3;

const MIN_ENCODED_ARGUMENT_LEN: usize = 8;
const UTF16_TEXT_MAX_NON_ASCII_RATIO: f64 = 0.2;
const ENCODED_COMMAND_PATTERNS: [&str; 4] = ["-EncodedCommand", "-enc ", "$EncodedCommand = '", "$EncodedCommand='"];

const HIDDEN_UNICODE_ESCAPE_MIN_RUN: usize = 4;
const HIDDEN_UNICODE_ESCAPE_SCORE: u32 = 5;

const PACKED_IIFE_SCORE_BASE: u32 = 8;
const CONFIG_PAYLOAD_SCORE_BASE: u32 = 6;
const JS_MASQUERADING_AS_ASSET_SCORE_BASE: u32 = 9;
const HIDDEN_SPAWN_MARKER_SCORE_BONUS: u32 = 4;
const ASSET_MIN_BYTES_FOR_JS_CHECK: usize = 32;
const ASSET_JS_PREVIEW_MAX_BYTES: usize = 48;
const UTF8_BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];

const ADOBE_CREATIVE_CLOUD_BUNDLED_NODE_HOME: &str = "\\adobe\\adobe creative cloud experience\\libs";

fn ip_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap())
}

fn is_non_routable_ip(ip: &str) -> bool {
    let octets: Vec<u8> = ip.split('.').filter_map(|p| p.parse().ok()).collect();
    let [a, b, ..] = octets[..] else { return false };
    a == 127 || a == 10 || (a == 172 && (16..=31).contains(&b)) || (a == 192 && b == 168) || (a == 169 && b == 254)
}

fn url_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"https?://[^\s'\x22]+").unwrap())
}

fn url_host_is_non_routable(url: &str) -> bool {
    let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let host_and_port = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    let host = host_and_port.rsplit_once(':').map(|(h, _)| h).unwrap_or(host_and_port);
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost") || is_non_routable_ip(host)
}

const OBFUSCATION_MARKERS: &[&str] = &[
    "eval(",
    "Function(",
    "fromCharCode",
    "atob(",
    "btoa(",
    "createDecipheriv",
    "createCipheriv",
    "XOR",
    "base64",
    "-EncodedCommand",
    "-enc ",
    "IEX ",
    "Invoke-Expression",
    "DownloadString",
    "WebClient",
    "Net.Sockets",
    "/dev/tcp/",
    "curl -s",
];

pub fn decode_encoded_command(cmdline: &str, max_decode_depth: u32) -> Option<String> {
    let first = decode_one_encoded_command(cmdline)?;
    let mut current = first;
    for _ in 0..max_decode_depth {
        match decode_one_encoded_command(&current) {
            Some(next) => current = next,
            None => break,
        }
    }
    Some(current)
}

fn decode_one_encoded_command(text: &str) -> Option<String> {
    let mut candidates: Vec<usize> = Vec::new();
    for pat in ENCODED_COMMAND_PATTERNS {
        let mut start = 0;
        while let Some(i) = text[start..].find(pat) {
            let abs = start + i;
            candidates.push(abs + pat.len());
            start = abs + pat.len();
        }
    }
    candidates.sort_unstable();

    for flag_pos in candidates {
        let rest = text[flag_pos..].trim_start();
        let b64: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
            .collect();
        if b64.len() < MIN_ENCODED_ARGUMENT_LEN {
            continue;
        }
        let Some(bytes) = base64_decode(&b64) else { continue };

        if bytes.len() >= 2 && bytes.len() % 2 == 0 {
            let utf16: Vec<u16> = bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            if let Ok(s) = String::from_utf16(&utf16) {
                let non_ascii_ratio =
                    s.chars().filter(|c| !c.is_ascii()).count() as f64 / s.chars().count().max(1) as f64;
                if non_ascii_ratio < UTF16_TEXT_MAX_NON_ASCII_RATIO {
                    return Some(s);
                }
            }
        }

        if let Ok(s) = String::from_utf8(bytes) {
            return Some(s);
        }
    }

    None
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let clean: Vec<u8> = input.bytes().filter(|&b| b != b'=').collect();
    let mut out = Vec::with_capacity(clean.len() * 3 / 4);
    for chunk in clean.chunks(4) {
        let vals: Vec<u8> = chunk.iter().map(|&b| val(b)).collect::<Option<Vec<_>>>()?;
        match vals.len() {
            4 => {
                out.push((vals[0] << 2) | (vals[1] >> 4));
                out.push((vals[1] << 4) | (vals[2] >> 2));
                out.push((vals[2] << 6) | vals[3]);
            }
            3 => {
                out.push((vals[0] << 2) | (vals[1] >> 4));
                out.push((vals[1] << 4) | (vals[2] >> 2));
            }
            2 => {
                out.push((vals[0] << 2) | (vals[1] >> 4));
            }
            _ => return None,
        }
    }
    Some(out)
}

fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    let mut total = 0u32;
    for b in s.bytes() {
        counts[b as usize] += 1;
        total += 1;
    }
    let total_f = total as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / total_f;
            -p * p.log2()
        })
        .sum()
}

fn has_long_encoded_blob(s: &str) -> Option<usize> {
    let mut best = 0usize;
    let mut cur = 0usize;
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' {
            cur += 1;
            if cur > best {
                best = cur;
            }
        } else {
            cur = 0;
        }
    }
    if best >= LONG_ENCODED_BLOB_MIN_RUN {
        Some(best)
    } else {
        None
    }
}

pub fn score_command_line(cmdline: &str, max_decode_depth: u32) -> Option<Verdict> {
    if cmdline.len() < MIN_INLINE_PAYLOAD_CMDLINE_LEN {
        return None;
    }
    let has_inline_flag = cmdline.contains("-e ")
        || cmdline.contains("-e\"")
        || cmdline.contains("-c ")
        || cmdline.contains("--eval")
        || cmdline.contains("-enc")
        || cmdline.contains("-EncodedCommand")
        || cmdline.contains("IEX");
    if !has_inline_flag {
        return None;
    }

    let scored_text = decode_encoded_command(cmdline, max_decode_depth).unwrap_or_else(|| cmdline.to_string());
    let scored: &str = &scored_text;

    let mut score = 0u32;
    let mut reasons = Vec::new();
    let mut has_strong_signal = false;

    if cmdline.len() > VERY_LONG_CMDLINE_LEN {
        score += 2;
        reasons.push(format!("very long command line ({} chars)", cmdline.len()));
    } else if cmdline.len() > LONG_CMDLINE_LEN {
        score += 1;
        reasons.push(format!("long command line ({} chars)", cmdline.len()));
    }

    if let Some(m) = ip_re().find_iter(scored).find(|m| !is_non_routable_ip(m.as_str())) {
        score += 2;
        reasons.push(format!("embedded IP literal ({})", m.as_str()));
        has_strong_signal = true;
    }
    if url_re().find_iter(scored).any(|m| !url_host_is_non_routable(m.as_str())) {
        score += 1;
        reasons.push("embedded URL literal".to_string());
        has_strong_signal = true;
    }

    if let Some(len) = has_long_encoded_blob(scored) {
        score += 2;
        reasons.push(format!("long contiguous encoded-looking blob ({len} chars, base64/hex-alphabet run)"));
        has_strong_signal = true;
    }

    let hits: Vec<&str> = OBFUSCATION_MARKERS
        .iter()
        .filter(|m| scored.contains(*m))
        .copied()
        .collect();
    if !hits.is_empty() {
        score += 1;
        reasons.push(format!("generic obfuscation/exfil marker(s): {}", hits.join(", ")));
        has_strong_signal = true;
    }

    let symbol_count = scored
        .chars()
        .filter(|c| !c.is_alphanumeric() && !c.is_whitespace())
        .count();
    let density = symbol_count as f64 / scored.len().max(1) as f64;
    if density > HIGH_SYMBOL_DENSITY_RATIO {
        score += 1;
        reasons.push(format!(
            "high symbol density ({:.0}%, obfuscated-code shape)",
            density * 100.0
        ));
        has_strong_signal = true;
    }

    let entropy = shannon_entropy(scored);
    if entropy > PACKED_ENTROPY_BITS_PER_CHAR && has_strong_signal {
        score += 3;
        reasons.push(format!("high content entropy ({entropy:.2} bits/char, packed/encrypted-looking)"));
    } else if entropy > ELEVATED_ENTROPY_BITS_PER_CHAR && has_strong_signal {
        score += 1;
        reasons.push(format!("elevated content entropy ({entropy:.2} bits/char)"));
    }

    if score >= COMMAND_LINE_ALERT_SCORE {
        Some(Verdict { score, reasons })
    } else {
        None
    }
}

pub fn find_hidden_unicode_escape_run(s: &str) -> Option<Verdict> {
    let bytes = s.as_bytes();
    let mut i = 0usize;
    let mut best: Option<(usize, String)> = None;

    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() && bytes[i + 1] == b'u' {
            let mut run_len = 0usize;
            let mut decoded = String::new();
            let mut j = i;
            while j + 5 < bytes.len() && bytes[j] == b'\\' && bytes[j + 1] == b'u' {
                let hex = &s[j + 2..j + 6];
                let Ok(code) = u32::from_str_radix(hex, 16) else {
                    break;
                };
                let Some(ch) = char::from_u32(code) else {
                    break;
                };
                if !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '$') {
                    break;
                }
                decoded.push(ch);
                run_len += 1;
                j += 6;
            }
            if run_len >= HIDDEN_UNICODE_ESCAPE_MIN_RUN {
                let starts_identifier_like = decoded
                    .chars()
                    .next()
                    .map(|c| c.is_ascii_alphabetic() || c == '_' || c == '$')
                    .unwrap_or(false);
                if starts_identifier_like {
                    let better = best.as_ref().map(|(len, _)| run_len > *len).unwrap_or(true);
                    if better {
                        best = Some((run_len, decoded.clone()));
                    }
                }
            }
            i = if run_len > 0 { j } else { i + 1 };
        } else {
            i += 1;
        }
    }

    best.map(|(run_len, decoded)| Verdict {
        score: HIDDEN_UNICODE_ESCAPE_SCORE,
        reasons: vec![format!(
            "{run_len} consecutive \\uXXXX escapes decode to plain-ASCII identifier \"{decoded}\" -- real code never spells an ASCII identifier this way; this is how malware hides module/function names from plain-text grep"
        )],
    })
}

const CONFIG_PAYLOAD_MIN_BYTES: usize = 3000;

const CONFIG_PAYLOAD_MAX_LINES: usize = 50;

const HIDDEN_SPAWN_MARKERS: &[&str] = &[
    "global['_t_s']",
    "global._t_s",
    "_0x1706(",
    "x-payload-",
    "createGunzip",
    "global['!']",
    "global[\"!\"]",
];

pub fn find_config_payload_disproportion(content: &str) -> Option<Verdict> {
    let bytes = content.len();
    if bytes < CONFIG_PAYLOAD_MIN_BYTES {
        return None;
    }
    let lines = content.lines().count().max(1);
    if lines > CONFIG_PAYLOAD_MAX_LINES {
        return None;
    }

    let mut reasons = vec![format!(
        "{bytes} bytes across only {lines} line(s) -- a build/config file this size normally has far more lines; a payload appended as one long padded line is invisible in normal diffs/editors"
    )];
    let mut score = CONFIG_PAYLOAD_SCORE_BASE;
    for marker in HIDDEN_SPAWN_MARKERS {
        if content.contains(marker) {
            reasons.push(format!("contains known HiddenSpawn-family runtime marker \"{marker}\""));
            score += HIDDEN_SPAWN_MARKER_SCORE_BONUS;
        }
    }
    Some(Verdict { score, reasons })
}

const APPENDED_PACKED_MIN_TAIL_BYTES: usize = 3000;

fn line_looks_like_packed_iife(line: &str) -> bool {
    if line.contains("global['!']") || line.contains("global[\"!\"]") {
        return true;
    }
    line.contains("var _0x") && (line.contains("(function(") || line.contains("(function ("))
}

pub fn find_appended_packed_payload(content: &str) -> Option<Verdict> {
    let (idx, line) = content
        .lines()
        .enumerate()
        .filter(|(_, l)| l.len() >= APPENDED_PACKED_MIN_TAIL_BYTES && line_looks_like_packed_iife(l))
        .max_by_key(|(_, l)| l.len())?;
    let mut reasons = vec![format!(
        "line {} is {} bytes of packed obfuscator.io-style IIFE -- HiddenSpawn-family append; invisible to line-based diffs",
        idx + 1,
        line.len()
    )];
    let mut score = PACKED_IIFE_SCORE_BASE;
    for marker in HIDDEN_SPAWN_MARKERS {
        if line.contains(marker) {
            reasons.push(format!("contains known HiddenSpawn-family runtime marker \"{marker}\""));
            score += HIDDEN_SPAWN_MARKER_SCORE_BONUS;
        }
    }
    Some(Verdict { score, reasons })
}

fn skip_utf8_bom_and_ws(data: &[u8]) -> &[u8] {
    let data = if data.starts_with(&UTF8_BOM) {
        &data[UTF8_BOM.len()..]
    } else {
        data
    };
    let n = data.iter().take_while(|b| matches!(*b, b' ' | b'\t' | b'\n' | b'\r')).count();
    &data[n..]
}

fn bytes_look_like_javascript(data: &[u8]) -> bool {
    let data = skip_utf8_bom_and_ws(data);
    const PREFIXES: &[&[u8]] = &[
        b"global[",
        b"global.",
        b"var _0x",
        b"const _0x",
        b"let _0x",
        b"(function(",
        b"(function (",
        b"(async function",
        b"(async()=>",
        b"(()=>",
        b"!function(",
        b"\"use strict\"",
        b"'use strict'",
        b"require(",
        b"module.exports",
        b"eval(",
        b"#!/usr/bin/env node",
        b"/*! For license information",
    ];
    PREFIXES.iter().any(|p| data.starts_with(p))
}

pub fn find_javascript_masquerading_as_asset(data: &[u8]) -> Option<Verdict> {
    if data.len() < ASSET_MIN_BYTES_FOR_JS_CHECK || !bytes_look_like_javascript(data) {
        return None;
    }
    let head = skip_utf8_bom_and_ws(data);
    let preview_len = head.len().min(ASSET_JS_PREVIEW_MAX_BYTES);
    let preview = String::from_utf8_lossy(&head[..preview_len]);
    let mut reasons = vec![format!(
        "asset/font/image bytes begin as JavaScript ({preview:?}) -- real woff2/ttf/png never start this way"
    )];
    let mut score = JS_MASQUERADING_AS_ASSET_SCORE_BASE;
    if let Ok(text) = std::str::from_utf8(data) {
        for marker in HIDDEN_SPAWN_MARKERS {
            if text.contains(marker) {
                reasons.push(format!("contains known HiddenSpawn-family runtime marker \"{marker}\""));
                score += HIDDEN_SPAWN_MARKER_SCORE_BONUS;
            }
        }
    }
    Some(Verdict { score, reasons })
}

fn backup_suffix_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\.(orig|bak|inz|original|old)(\.[A-Za-z0-9]+)?$").unwrap())
}

pub fn is_backup_sibling_name(file_name: &str) -> bool {
    backup_suffix_re().is_match(file_name)
}

const BACKUP_MARKER_SUFFIXES: &[&str] = &[".orig", ".bak", ".original", ".old", ".inz"];

pub fn strip_backup_markers(name: &str) -> String {
    let mut current = name.to_string();
    loop {
        let lower = current.to_lowercase();
        let hit = BACKUP_MARKER_SUFFIXES.iter().find(|marker| lower.ends_with(**marker));
        let Some(marker) = hit else { break };
        let new_len = current.len() - marker.len();
        current.truncate(new_len);
    }
    current
}

pub fn is_denied_exec_path(exe_path: &str, deny_fragments: &[String]) -> Option<&'static str> {
    for frag in deny_fragments {
        if exe_path.contains(frag.as_str()) {
            return Some("path contains a location nothing legitimate executes from");
        }
    }
    None
}

pub fn is_unlisted_exec_path(exe_path: &str, allowed_roots: &[std::path::PathBuf]) -> bool {
    let exe_lower = exe_path.to_lowercase();
    !allowed_roots.iter().any(|root| {
        let root_str = root.to_string_lossy().to_lowercase();
        !root_str.is_empty() && exe_lower.starts_with(&root_str)
    })
        && !is_compiler_build_artifact_path(&exe_lower)
}

pub fn is_compiler_build_artifact_path(exe_lower: &str) -> bool {
    let sep = if exe_lower.contains('\\') { '\\' } else { '/' };
    let segments: Vec<&str> = exe_lower.split(sep).collect();
    segments.windows(4).any(|w| {
        matches!(w[1], "debug" | "release")
            && matches!(w[2], "build" | "deps")
            && (w[0] == "target" || w[0].ends_with("-target") || w[0].ends_with("_target"))
    })
}

pub fn is_dev_toolchain_path(exe_lower: &str) -> bool {
    let normalized = exe_lower.replace('/', "\\");
    const TOOLCHAIN_FRAGMENTS: [&str; 5] = [
        "\\.cargo\\bin\\",
        "\\.rustup\\toolchains\\",
        "\\scoop\\apps\\",
        "\\programdata\\chocolatey\\",
        "\\node_modules\\@esbuild\\",
    ];
    let is_python_console_script = normalized.contains("\\python3") && normalized.contains("\\scripts\\");
    is_python_console_script || TOOLCHAIN_FRAGMENTS.iter().any(|f| normalized.contains(f))
}

const KNOWN_NAME_HOMES: &[(&str, &[&str])] = &[
    ("svchost.exe", &["\\windows\\system32", "\\windows\\syswow64"]),
    ("explorer.exe", &["\\windows"]),
    ("csrss.exe", &["\\windows\\system32"]),
    ("lsass.exe", &["\\windows\\system32"]),
    ("winlogon.exe", &["\\windows\\system32"]),
    ("services.exe", &["\\windows\\system32"]),
    ("smss.exe", &["\\windows\\system32"]),
    ("wininit.exe", &["\\windows\\system32"]),
    ("spoolsv.exe", &["\\windows\\system32"]),
    ("dllhost.exe", &["\\windows\\system32", "\\windows\\syswow64"]),
    ("rundll32.exe", &["\\windows\\system32", "\\windows\\syswow64"]),
    ("taskhost.exe", &["\\windows\\system32"]),
    ("taskhostw.exe", &["\\windows\\system32"]),
    ("conhost.exe", &["\\windows\\system32"]),
    ("lsm.exe", &["\\windows\\system32"]),
    ("searchindexer.exe", &["\\windows"]),
    (
        "node.exe",
        &[
            "\\nodejs",
            "\\program files\\nodejs",
            "appdata\\roaming\\nvm",
            "appdata\\local\\fnm",
            ADOBE_CREATIVE_CLOUD_BUNDLED_NODE_HOME,
        ],
    ),
    ("node", &["/usr/", "/opt/", "/.nvm/", "/.fnm/", "/.local/"]),
    ("python.exe", &["\\python", "\\program files"]),
    ("chrome.exe", &["\\google\\chrome", "\\program files"]),
    ("discord.exe", &["\\discord\\app-"]),
    ("launchd", &["/sbin/", "/usr/libexec/"]),
    ("kernel_task", &["/System/"]),
    ("windowserver", &["/system/library/"]),
    ("coreaudiod", &["/usr/sbin/"]),
    ("systemd", &["/usr/lib/systemd/", "/lib/systemd/", "/sbin/"]),
    ("init", &["/sbin/", "/usr/sbin/"]),
    ("sshd", &["/usr/sbin/", "/usr/bin/"]),
    ("cron", &["/usr/sbin/"]),
];

pub fn score_process_name(name: &str, exe_path: &str) -> Option<Verdict> {
    let mut score = 0u32;
    let mut reasons = Vec::new();

    if let Some(reason) = suspicious_name_chars(name) {
        score += 3;
        reasons.push(reason);
    }

    let name_lower = name.to_lowercase();
    let path_lower = exe_path.to_lowercase();
    for (known_name, homes) in KNOWN_NAME_HOMES {
        if name_lower == *known_name {
            let at_home = homes.iter().any(|h| path_lower.contains(h));
            if !at_home && !exe_path.is_empty() {
                score += 3;
                reasons.push(format!(
                    "process named '{known_name}' but not running from its usual location (running from: {exe_path})"
                ));
            }
            break;
        }
    }

    if score > 0 {
        Some(Verdict { score, reasons })
    } else {
        None
    }
}

fn suspicious_name_chars(name: &str) -> Option<String> {
    let mut has_zero_width = false;
    let mut has_control = false;
    let mut has_rtl_override = false;
    let mut has_non_ascii_letter = false;

    for c in name.chars() {
        match c {
            '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}' => has_zero_width = true,
            '\u{202E}' | '\u{202D}' | '\u{2066}'..='\u{2069}' => has_rtl_override = true,
            c if c.is_control() => has_control = true,
            c if !c.is_ascii() && c.is_alphabetic() => has_non_ascii_letter = true,
            _ => {}
        }
    }

    let mut hits = Vec::new();
    if has_zero_width {
        hits.push("zero-width character(s)");
    }
    if has_rtl_override {
        hits.push("right-to-left override character(s) (classic extension-spoofing trick)");
    }
    if has_control {
        hits.push("control character(s)");
    }
    if has_non_ascii_letter {
        hits.push("non-ASCII letter(s) (possible homoglyph/lookalike spoofing)");
    }

    if hits.is_empty() {
        None
    } else {
        Some(format!(
            "process name '{name}' contains suspicious characters: {}",
            hits.join(", ")
        ))
    }
}
