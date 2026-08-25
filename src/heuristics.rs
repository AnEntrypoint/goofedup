// Pure, host-independent heuristics. Every function here takes plain data
// (a command line string, a path string) and returns a verdict -- no OS
// calls, no side effects, so they're identical on every platform and cheap
// to reason about in isolation.

use regex::Regex;
use std::sync::OnceLock;

pub struct Verdict {
    pub score: u32,
    pub reasons: Vec<String>,
}

fn ip_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap())
}

fn url_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"https?://[^\s'\x22]+").unwrap())
}

/// Generic obfuscation/exfil tells that show up across many unrelated
/// malware families and toolchains (packers, stealers, loaders, C2
/// beacons), not specific to any one incident. Each is a small BONUS on top
/// of the structural signals below (length, entropy, IP/URL literals,
/// encoded-blob density) -- none of these alone should ever be the deciding
/// factor, since several appear in legitimate tooling too. Kept broad and
/// generic on purpose: a NEW, never-seen-before payload with none of these
/// exact tokens still has to score on shape alone.
const OBFUSCATION_MARKERS: &[&str] = &[
    "eval(",
    "Function(",
    "fromCharCode",
    "atob(",
    "btoa(",
    "child_process",
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

/// Extracts and decodes a PowerShell `-EncodedCommand`/`-enc` argument's
/// base64 payload (PowerShell's own documented format: base64 of UTF-16LE
/// text) so its DECODED content can be scored instead of the encoding
/// wrapper itself. Live-witnessed root cause of a real false-positive class:
/// `-EncodedCommand` is itself in OBFUSCATION_MARKERS, and any encoded
/// command of reasonable length trivially satisfies has_long_encoded_blob
/// too (that's definitionally what base64-encoding produces) -- so a
/// completely benign encoded command (decoded sample: `$EncodedCommand =
/// '...'; ... cd C:\dev\...`) and a genuinely malicious one both score
/// identically on the WRAPPER alone, before any actual content is examined.
/// Recurses (bounded to MAX_DECODE_DEPTH) into a `$EncodedCommand =
/// '<base64>'`-shaped assignment found in the decoded text -- live-
/// witnessed: this project's own automation harness nests a SECOND
/// -EncodedCommand-style layer inside the first (decodes to
/// `$EncodedCommand = 'Y2QgQzpc...'`), and without recursing, that inner
/// base64 string itself still trivially satisfies has_long_encoded_blob on
/// the one-layer-decoded text, reproducing the exact same false-positive
/// shape one level down. Returns None if no `-EncodedCommand`/`-enc` flag
/// is present, or if the argument after it doesn't decode as valid base64
/// UTF-16LE (a malformed argument is itself unusual but not this
/// function's concern -- the raw cmdline's other signals still apply
/// either way since the caller falls back to scoring the original string
/// when this returns None).
pub fn decode_encoded_command(cmdline: &str) -> Option<String> {
    const MAX_DECODE_DEPTH: u32 = 4;
    let first = decode_one_encoded_command(cmdline)?;
    let mut current = first;
    for _ in 0..MAX_DECODE_DEPTH {
        match decode_one_encoded_command(&current) {
            Some(next) => current = next,
            None => break,
        }
    }
    Some(current)
}

/// Single-layer decode: finds the first `-EncodedCommand`/`-enc <base64>`
/// or `$EncodedCommand = '<base64>'` shape in `text` and decodes it.
fn decode_one_encoded_command(text: &str) -> Option<String> {
    let flag_pos = text
        .find("-EncodedCommand")
        .map(|i| i + "-EncodedCommand".len())
        .or_else(|| text.find("-enc ").map(|i| i + "-enc".len()))
        .or_else(|| text.find("$EncodedCommand = '").map(|i| i + "$EncodedCommand = '".len()))
        .or_else(|| text.find("$EncodedCommand='").map(|i| i + "$EncodedCommand='".len()))?;
    let rest = text[flag_pos..].trim_start();
    let b64: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
        .collect();
    if b64.len() < 8 {
        return None;
    }
    let bytes = base64_decode(&b64)?;
    if bytes.len() < 2 || bytes.len() % 2 != 0 {
        return None;
    }
    let utf16: Vec<u16> = bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    String::from_utf16(&utf16).ok()
}

/// Minimal standard-alphabet base64 decoder (RFC 4648, with padding) --
/// avoids pulling in a dependency for the one narrow use above.
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

/// True if `s` contains a long contiguous run of base64/hex-alphabet
/// characters -- the generic signature of an embedded encoded payload
/// (staged shellcode, an encrypted config blob, a packed second stage),
/// regardless of what family produced it.
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
    if best >= 120 {
        Some(best)
    } else {
        None
    }
}

/// Shape-based detection of an obfuscated inline payload passed via
/// -e/-c/--eval/-enc to an interpreter. Structural, not a signature match:
/// scores on length, Shannon entropy (obfuscated/packed/encrypted content
/// reads at a distinctly higher bits-per-char than natural source code),
/// embedded IP/URL literals, a long encoded-blob run, and only a small
/// bonus for known generic markers -- a completely novel payload with none
/// of the marker strings can still score purely on shape.
pub fn score_command_line(cmdline: &str) -> Option<Verdict> {
    if cmdline.len() < 300 {
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

    // A successfully-decoded -EncodedCommand/-enc payload is scored on its
    // DECODED content, not the base64 wrapper -- see decode_encoded_command's
    // own doc comment for the false-positive class this closes (the wrapper
    // itself trivially satisfies both the obfuscation-marker check and the
    // long-encoded-blob check for EVERY encoded command regardless of what's
    // inside, since that's mechanically what base64-encoding produces; a
    // completely benign `cd C:\dev\...` and a real attacker's payload both
    // scored identically on the wrapper alone). Falls back to scoring the
    // raw cmdline when decoding fails (a malformed/partial argument, e.g.
    // this tool's own 200-char cmdline_head truncation cutting mid-base64)
    // so nothing goes unscored just because a real payload got cut off.
    let scored_text = decode_encoded_command(cmdline).unwrap_or_else(|| cmdline.to_string());
    let scored: &str = &scored_text;

    let mut score = 0u32;
    let mut reasons = Vec::new();
    // Tracks whether a signal harder to trigger by accident than either
    // length or entropy alone has fired -- see the entropy-gating comment
    // below for why length doesn't count.
    let mut has_strong_signal = false;

    if cmdline.len() > 2000 {
        score += 2;
        reasons.push(format!("very long command line ({} chars)", cmdline.len()));
    } else if cmdline.len() > 600 {
        score += 1;
        reasons.push(format!("long command line ({} chars)", cmdline.len()));
    }

    if let Some(m) = ip_re().find(scored) {
        score += 2;
        reasons.push(format!("embedded IP literal ({})", m.as_str()));
        has_strong_signal = true;
    }
    if url_re().is_match(scored) {
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
    if density > 0.30 {
        score += 1;
        reasons.push(format!(
            "high symbol density ({:.0}%, obfuscated-code shape)",
            density * 100.0
        ));
        has_strong_signal = true;
    }

    // Entropy is scored LAST and only counts toward the alert threshold if
    // at least one of the signals above already fired -- length alone does
    // NOT count as corroboration (has_strong_signal is never set by the
    // length check), since any legitimately verbose script clears 600
    // chars on its own. Live-witnessed false-positive class: ordinary
    // dense-but-harmless JS (this project's own `node -e` snippets reading/
    // parsing local .gm/exec-spool/*.json files) routinely crosses 5.2
    // bits/char on content alone -- 4 separate CRITICALs, all score=3,
    // entropy the ONLY reason, zero IP/URL/blob/marker/density
    // corroboration. The real Discord C2 incident this detector caught, by
    // contrast, always scored 10 with 5+ signals stacked (IP + URL +
    // entropy + eval/base64 markers + symbol density) -- entropy was never
    // the sole or deciding signal for the real attack, so requiring
    // corroboration here doesn't touch that detection at all, only closes
    // the entropy-alone false-positive gap. Nothing here changes severity:
    // anything that still crosses the score>=3 bar fires CRITICAL exactly
    // as before.
    let entropy = shannon_entropy(scored);
    if entropy > 5.2 && has_strong_signal {
        score += 3;
        reasons.push(format!("high content entropy ({entropy:.2} bits/char, packed/encrypted-looking)"));
    } else if entropy > 4.7 && has_strong_signal {
        score += 1;
        reasons.push(format!("elevated content entropy ({entropy:.2} bits/char)"));
    }

    if score >= 3 {
        Some(Verdict { score, reasons })
    } else {
        None
    }
}

/// True if `s` contains a run of 4 or more CONSECUTIVE `\uXXXX` escapes
/// (no other characters between them) that decode to plain ASCII
/// identifier-shaped characters (letters, digits, underscore/dollar --
/// i.e. what a JS identifier is actually made of). Real source code almost
/// never spells an ASCII identifier this way -- `requ`
/// decodes to "requ" and is dramatically harder to read/write/diff than
/// just typing `requ`, so nobody does it by hand and no legitimate
/// minifier/bundler emits it either (minifiers escape only what actually
/// needs escaping: non-ASCII, or ASCII that would break the string
/// literal). Malware hides module names this way specifically so a
/// plain-text grep for "require"/"child_process"/"process.env" etc. finds
/// nothing -- the identifier only exists as ASCII after JS's own runtime
/// unescapes it. Structural, not tied to any specific hidden module name:
/// a NEW hidden identifier this tool has never seen still gets caught on
/// shape alone.
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
                // Only count escapes decoding to a plain-ASCII identifier
                // character -- this is what distinguishes "hiding an
                // identifier" from ordinary internationalized string
                // content (a genuinely non-ASCII string legitimately
                // escaped, e.g. CJK/emoji, decodes to non-ASCII and never
                // triggers this).
                if !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '$') {
                    break;
                }
                decoded.push(ch);
                run_len += 1;
                j += 6;
            }
            if run_len >= 4 {
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
        score: 5,
        reasons: vec![format!(
            "{run_len} consecutive \\uXXXX escapes decode to plain-ASCII identifier \"{decoded}\" -- real code never spells an ASCII identifier this way; this is how malware hides module/function names from plain-text grep"
        )],
    })
}

/// True if `exe_path` sits under any deny fragment (e.g. Recycle Bin, Trash)
/// -- an instant, unconditional flag regardless of process name.
pub fn is_denied_exec_path(exe_path: &str, deny_fragments: &[String]) -> Option<&'static str> {
    for frag in deny_fragments {
        if exe_path.contains(frag.as_str()) {
            return Some("path contains a location nothing legitimate executes from");
        }
    }
    None
}

/// True if `exe_path` is NOT under any of the allowed roots. This is a
/// softer WARN-tier signal (a real allowlist will always have gaps for
/// unusual-but-legitimate install locations), unlike the deny check above.
pub fn is_unlisted_exec_path(exe_path: &str, allowed_roots: &[std::path::PathBuf]) -> bool {
    let exe_lower = exe_path.to_lowercase();
    !allowed_roots.iter().any(|root| {
        let root_str = root.to_string_lossy().to_lowercase();
        !root_str.is_empty() && exe_lower.starts_with(&root_str)
    })
        && !is_compiler_build_artifact_path(&exe_lower)
}

/// True if `exe_path` sits inside a Cargo/Rust build-output tree
/// (`target/{debug,release}/{build,deps}/...`) under ANY project directory
/// -- these can't be absolute-prefix allowlisted the way a fixed system
/// location can, since `target/` legitimately appears under every one of
/// a developer's many project directories. Live-witnessed: `cargo build`
/// generates a fresh, content-hashed binary name under `target/*/build/`
/// on every build (build-script-build.exe, and crate-name-<hash>.exe test
/// binaries under `target/*/deps/`) -- a real allowlist-by-exact-path can
/// never keep up with this, and it's the single most common WARN-tier
/// process-path noise source for anyone doing Rust development. Never a
/// meaningful hiding spot for real persistence either: `target/` is wiped
/// by `cargo clean` and regenerated by every build, the opposite of a
/// durable location an attacker would plant something in.
fn is_compiler_build_artifact_path(exe_lower: &str) -> bool {
    let target_marker = if exe_lower.contains('\\') { "\\target\\" } else { "/target/" };
    let Some(after_target) = exe_lower.split(target_marker).nth(1) else {
        return false;
    };
    let sep = if exe_lower.contains('\\') { '\\' } else { '/' };
    let mut segments = after_target.split(sep);
    let Some(profile) = segments.next() else { return false };
    if !matches!(profile, "debug" | "release") {
        return false;
    }
    matches!(segments.next(), Some("build" | "deps"))
}

/// Well-known process names and the path fragment their REAL binary always
/// lives under. A process claiming one of these exact names but running
/// from somewhere else is classic masquerading (naming a malicious binary
/// after a trusted system process so it blends into a process list at a
/// glance, while actually running from Temp/AppData/Downloads/a Recycle Bin
/// path). Covers the most commonly impersonated names across all three
/// platforms per public threat-intel reporting on this technique -- not
/// tied to any one runtime or app, general system-process masquerading.
const KNOWN_NAME_HOMES: &[(&str, &[&str])] = &[
    // Windows core system processes -- the classic masquerading targets.
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
    // Common third-party runtimes -- their real install roots.
    (
        "node.exe",
        &[
            "\\nodejs",
            "\\program files\\nodejs",
            "appdata\\roaming\\nvm",
            "appdata\\local\\fnm",
            // Adobe Creative Cloud Experience bundles its own signed
            // Node.js runtime for internal tooling at this exact path --
            // live-verified (Get-AuthenticodeSignature: Valid; a genuine
            // Node.js 18.20.2 binary, not a masquerade) after it recurred
            // at the identical time of day (09:32:02) on two different
            // days, matching a scheduled Adobe background task rather than
            // a one-off.
            "\\adobe\\adobe creative cloud experience\\libs",
        ],
    ),
    ("node", &["/usr/", "/opt/", "/.nvm/", "/.fnm/", "/.local/"]),
    ("python.exe", &["\\python", "\\program files"]),
    ("chrome.exe", &["\\google\\chrome", "\\program files"]),
    ("discord.exe", &["\\discord\\app-"]),
    // macOS system daemons.
    ("launchd", &["/sbin/", "/usr/libexec/"]),
    ("kernel_task", &["/System/"]),
    ("windowserver", &["/system/library/"]),
    ("coreaudiod", &["/usr/sbin/"]),
    // Linux init/system daemons.
    ("systemd", &["/usr/lib/systemd/", "/lib/systemd/", "/sbin/"]),
    ("init", &["/sbin/", "/usr/sbin/"]),
    ("sshd", &["/usr/sbin/", "/usr/bin/"]),
    ("cron", &["/usr/sbin/"]),
];

/// Detects both: (1) a well-known name running from an unexpected location,
/// and (2) "weird characters" in the process name -- non-ASCII confusables
/// (Cyrillic/Greek lookalikes for Latin letters), zero-width/control
/// characters, or RTL override marks, all real techniques for visually
/// disguising a malicious binary as something benign in a process listing.
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
