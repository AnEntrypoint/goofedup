// One-shot project scanner: walks a directory tree for JS-family source
// (and node_modules dependency content) and greps each file for the
// hidden-unicode-escape-identifier shape (see heuristics::find_hidden_unicode_escape_run).
// Separate from the live watchers in watch_*.rs -- this is deliberately a
// bounded, on-demand pass over file CONTENT (a project/dependency audit),
// not a continuous background signal like process/network/file-metadata
// watching.

use crate::alert::{Alert, AlertSink};
use crate::heuristics::{
    find_appended_packed_payload, find_config_payload_disproportion,
    find_hidden_unicode_escape_run, find_javascript_masquerading_as_asset, strip_backup_markers,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use walkdir::WalkDir;

const JS_EXTENSIONS: &[&str] = &["js", "mjs", "cjs", "jsx", "ts", "tsx"];

/// Asset extensions a real font/image uses. The 2026-09 HiddenSpawn wave
/// stuffed a packed IIFE into `fa-solid-400.woff2` (magic `glob` / ASCII
/// `global['!']` instead of woff2). A JS-only walk never opens these.
const ASSET_EXTENSIONS: &[&str] = &[
    "woff", "woff2", "ttf", "otf", "eot", "png", "jpg", "jpeg", "gif", "webp", "ico", "bmp",
];

/// Directory names never worth descending into for this scan: version
/// control internals (never shipped/executed), and common noise dirs whose
/// content is either not JS or is test/doc fixture data rather than a real
/// execution path -- kept narrow and named so a truly novel malicious
/// package under an unusual dir name is never silently skipped.
const SKIP_DIR_NAMES: &[&str] = &[".git", ".hg", ".svn", "target"];

fn is_js_file(path: &Path) -> bool {
    ext_is(path, JS_EXTENSIONS)
}

/// True for a filename shaped like a build/tooling config file (the
/// HiddenSpawn family's delivery vehicle -- see
/// heuristics::find_config_payload_disproportion). Matched on filename
/// suffix so vite.config.js, webpack.config.mjs, next.config.ts etc. all
/// match without enumerating every tool name.
fn is_config_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.contains(".config."))
        .unwrap_or(false)
}

fn ext_is(path: &Path, exts: &[&str]) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| exts.iter().any(|ext| ext.eq_ignore_ascii_case(e)))
        .unwrap_or(false)
}

/// Inner-file size cap when reading entries out of an .asar archive -- a
/// packed payload big enough to exceed this is not identifier-hiding source
/// worth parsing, and the cap bounds memory on adversarial headers.
const ASAR_MAX_ENTRY_BYTES: u64 = 50 * 1024 * 1024;

/// Scans one Electron .asar archive (the container Discord and other
/// Electron apps ship most of their real JavaScript inside -- a plain file
/// walk sees only a single opaque binary blob). Parses the archive's JSON
/// header, extracts every stored entry that parses as UTF-8 text, and runs
/// the same hidden-identifier check over each. Returns (scanned, flagged).
fn scan_asar(path: &Path, alerts: &AlertSink, check: &mut impl FnMut(&str) -> bool) -> (usize, usize) {
    let mut scanned = 0usize;
    let mut flagged = 0usize;

    let Ok(data) = std::fs::read(path) else {
        return (0, 0);
    };
    // Asar layout: u32@4 = header pickle size H; u32@12 = JSON length L;
    // JSON bytes at offset 16; entry data begins at 8 + H.
    let Some(hsize) = read_u32_le(&data[4..8]) else { return (0, 0) };
    let Some(json_len) = read_u32_le(&data[12..16]) else { return (0, 0) };
    let data_base = 8usize + hsize as usize;
    if data.len() < 16 + json_len as usize || data_base > data.len() {
        return (0, 0);
    }
    let Ok(header) = std::str::from_utf8(&data[16..16 + json_len as usize]) else {
        return (0, 0);
    };
    let Ok(tree) = serde_json::from_str::<serde_json::Value>(header) else {
        return (0, 0);
    };

    // Depth-first walk of {"files": {name: node}}; leaf nodes carry
    // "offset" (string, relative to data_base) and "size".
    let mut stack = vec![tree];
    while let Some(node) = stack.pop() {
        let Some(files) = node.get("files").and_then(|f| f.as_object()) else {
            continue;
        };
        for child in files.values() {
            if child.get("files").is_some() {
                stack.push(child.clone());
                continue;
            }
            let Some(size) = child.get("size").and_then(|s| s.as_u64()) else {
                continue;
            };
            let Some(offset) = child.get("offset").and_then(|o| o.as_str()) else {
                continue;
            };
            if size == 0 || size > ASAR_MAX_ENTRY_BYTES {
                continue;
            }
            let Ok(offset) = offset.parse::<usize>() else {
                continue;
            };
            let start = data_base.checked_add(offset);
            let Some(start) = start else { continue };
            let Some(end) = start.checked_add(size as usize) else { continue };
            if end > data.len() {
                continue;
            }
            let Ok(content) = std::str::from_utf8(&data[start..end]) else {
                continue;
            };
            scanned += 1;
            if check(content) {
                flagged += 1;
            }
        }
    }

    if scanned > 0 {
        alerts.info(
            "hidden-unicode-identifier",
            format!("inspected {scanned} entr(ies) inside asar archive {}", path.display()),
        );
    }
    (scanned, flagged)
}

fn read_u32_le(b: &[u8]) -> Option<u32> {
    if b.len() < 4 {
        return None;
    }
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Walks `root` (recursively, including any `node_modules` present) and
/// alerts on every file containing a 4+ run of `\uXXXX` escapes that decode
/// to a plain-ASCII identifier. Returns the number of files flagged.
pub fn scan_project(root: &Path, alerts: &AlertSink) -> usize {
    let mut total_flagged = 0usize;
    let mut total_scanned = 0usize;

    let walker = WalkDir::new(root).into_iter().filter_entry(|e| {
        if e.file_type().is_dir() {
            let name = e.file_name().to_string_lossy();
            !SKIP_DIR_NAMES.iter().any(|s| *s == name)
        } else {
            true
        }
    });

    for entry in walker.filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if ext_is(path, &["asar"]) {
            let mut emit = |content: &str| -> bool {
                find_hidden_unicode_escape_run(content).map_or(false, |v| {
                    alerts.critical(
                        "hidden-unicode-identifier",
                        format!(
                            "'{}' contains an obfuscated \\uXXXX-escaped identifier -- the shape malware uses to hide module/function names from plain-text grep",
                            path.display()
                        ),
                        v.reasons.join("; "),
                    );
                    true
                })
            };
            let (scanned, flagged) = scan_asar(path, alerts, &mut emit);
            total_scanned += scanned;
            total_flagged += flagged;
            continue;
        }
        if ext_is(path, ASSET_EXTENSIONS) {
            let Ok(bytes) = std::fs::read(path) else {
                continue;
            };
            total_scanned += 1;
            if let Some(v) = find_javascript_masquerading_as_asset(&bytes) {
                total_flagged += 1;
                alerts.critical(
                    "js-masquerading-as-asset",
                    format!(
                        "'{}' claims a font/image extension but its first bytes are JavaScript -- HiddenSpawn-family delivery vehicle (real woff2/ttf/png never start this way)",
                        path.display()
                    ),
                    v.reasons.join("; "),
                );
            }
            continue;
        }
        if !is_js_file(path) {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(path) else {
            continue;
        };
        total_scanned += 1;
        if let Some(v) = find_hidden_unicode_escape_run(&content) {
            total_flagged += 1;
            alerts.critical(
                "hidden-unicode-identifier",
                format!(
                    "'{}' contains an obfuscated \\uXXXX-escaped identifier -- the shape malware uses to hide module/function names from plain-text grep",
                    path.display()
                ),
                v.reasons.join("; "),
            );
        }
        if is_config_file(path) {
            if let Some(v) = find_config_payload_disproportion(&content) {
                total_flagged += 1;
                alerts.critical(
                    "config-payload-disproportion",
                    format!(
                        "'{}' is a build/config file with a byte-size-to-line-count disproportion consistent with an appended hidden payload (HiddenSpawn-family supply-chain malware pattern)",
                        path.display()
                    ),
                    v.reasons.join("; "),
                );
            }
        }
        if let Some(v) = find_appended_packed_payload(&content) {
            total_flagged += 1;
            alerts.critical(
                "appended-packed-payload",
                format!(
                    "'{}' contains a multi-kilobyte packed obfuscator.io IIFE on one line -- HiddenSpawn-family append that line-based diffs never show",
                    path.display()
                ),
                v.reasons.join("; "),
            );
        }
    }

    alerts.info(
        "hidden-unicode-identifier",
        format!("scanned {total_scanned} JS-family file(s) under {}, {total_flagged} flagged", root.display()),
    );

    total_flagged
}

/// How long after a scan of a given root before another alert involving the
/// same app triggers a rescan -- repeated alerts about one busy process must
/// not turn into a continuous disk-churning rescan loop.
const RESPONSE_COOLDOWN: Duration = Duration::from_secs(30 * 60);

/// Alert-triggered response: whenever a Warn/Critical alert fires, find the
/// app it is about (a filesystem path in the message/evidence), and run this
/// same content scan over that app's install directory. This closes the loop
/// the live watchers leave open -- they report a suspicious SHAPE about a
/// process; this follows the process home and inspects its actual files for
/// hidden-unicode identifiers, without prescribing any remedy (still
/// alert-only).
pub struct AlertResponse {
    /// Root -> last scan start time.
    recent: Mutex<HashMap<PathBuf, Instant>>,
}

impl AlertResponse {
    pub fn new() -> Self {
        Self {
            recent: Mutex::new(HashMap::new()),
        }
    }

    /// Callback body for AlertSink: extract an app path from the alert, and
    /// if it passes the cooldown check, spawn the scan on a background
    /// thread (the emitting watcher thread must never block on a disk walk).
    /// Returns true if a scan was dispatched.
    pub fn on_alert(self: &Arc<Self>, a: &Alert, sink: &Arc<AlertSink>) -> bool {
        // Never respond to our own scan output -- the scanner's findings and
        // summary would otherwise re-trigger scans of whatever path they
        // mention, forever.
        if a.category == "hidden-unicode-identifier" || a.category == "alert-response" {
            return false;
        }
        if !matches!(a.level, crate::alert::Level::Warn | crate::alert::Level::Critical) {
            return false;
        }
        let Some(root) =
            extract_app_root(&a.message).or_else(|| extract_app_root(a.evidence.as_deref().unwrap_or("")))
        else {
            return false;
        };
        // Apps known to be high-value infection targets (Electron messengers
        // shipping live JS in modules/asar trees, vendor tool suites bundling
        // their own runtimes) get scanned from the PRODUCT root, not just the
        // single directory the flagged file sits in -- an alert about one
        // module should audit the whole tree it belongs to.
        let root = widen_to_risky_app_root(&root).unwrap_or(root);

        // Cooldown check + reserve before spawning, so N simultaneous
        // alerts about the same process dispatch exactly one scan.
        {
            let mut recent = self.recent.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(t) = recent.get(&root) {
                if t.elapsed() < RESPONSE_COOLDOWN {
                    return false;
                }
            }
            recent.insert(root.clone(), Instant::now());
        }

        let response = self.clone();
        let sink_handle = sink.clone();
        std::thread::spawn(move || {
            response.scan_and_report(&root, &sink_handle);
        });
        true
    }

    fn scan_and_report(&self, root: &Path, sink: &AlertSink) {
        sink.info(
            "alert-response",
            format!(
                "alert involved an app under {} -- running the hidden-unicode-identifier content scan over its install tree",
                root.display()
            ),
        );
        scan_project(root, sink);
    }
}

impl Default for AlertResponse {
    fn default() -> Self {
        Self::new()
    }
}

/// Path segments that identify a high-value infection-target product root:
/// an alert naming any file under one of these widens the response scan to
/// the whole product tree (all versions, all module dirs). Matched on the
/// exact directory name, case-insensitively.
const RISKY_APP_DIR_NAMES: &[&str] = &["discord", "adobe", "slack", "teams", "electron"];

fn widen_to_risky_app_root(root: &Path) -> Option<PathBuf> {
    let mut acc = PathBuf::new();
    for comp in root.components() {
        let name = comp.as_os_str().to_string_lossy().to_lowercase();
        acc.push(comp);
        if RISKY_APP_DIR_NAMES.iter().any(|m| name == *m) {
            return Some(acc);
        }
    }
    None
}

/// Pulls a filesystem path out of free-form alert text and resolves it to
/// the app directory to scan: the parent directory of a mentioned file.
/// Handles the `exe=<path>` evidence shape the process watcher emits, plus a
/// bare absolute Windows/Unix path anywhere in the text.
fn extract_app_root(text: &str) -> Option<PathBuf> {
    let candidate = if let Some(pos) = text.find("exe=") {
        let rest = &text[pos + 4..];
        rest.split_whitespace().next()?
    } else {
        first_absolute_path(text)?
    };
    let p = PathBuf::from(candidate);
    if !p.is_file() {
        return None;
    }
    p.parent().map(|d| d.to_path_buf())
}

/// First token in `text` that looks like an absolute path to something that
/// exists. Deliberately conservative: only accepts tokens starting with a
/// drive letter or `/`, ending at whitespace or a quote.
fn first_absolute_path(text: &str) -> Option<&str> {
    for tok in text.split(|c: char| c.is_whitespace() || c == '"' || c == '\'') {
        let looks_absolute = tok.len() > 3
            && ((tok.as_bytes()[1] == b':' && tok.as_bytes()[0].is_ascii_alphabetic())
                || tok.starts_with('/'));
        if looks_absolute && Path::new(tok).is_file() {
            return Some(tok);
        }
    }
    None
}

// -- One-shot safe remediation for a miss the live watcher didn't catch --
//
// The live watcher, when it catches a backup-sibling event as it happens,
// already knows the file that just appeared IS the preserved original and
// the file it sits next to IS the live one that just got overwritten --
// that ordering is implicit in the event itself. `--scan-deps` runs after
// the fact with no such ordering information, only a snapshot of whatever
// is on disk, so it has to derive the same (live, preserved-original) pairing
// from filenames and content instead. This is exactly the operational gap
// live-witnessed during the Antigravity remediation: moving the malicious
// payload out of the way is not the same as restoring the live bootstrap
// file that was pointing at it, and doing the second step by hand, without
// double-checking the preserved original was actually clean, is exactly
// where a real mistake happened.

/// One safe-restore candidate: a live file with a preserved-original
/// sibling next to it (see `strip_backup_markers`) whose content differs
/// from the live file's, where the preserved original itself contains no
/// HiddenSpawn-family marker.
pub struct RemediationCandidate {
    pub live_path: PathBuf,
    pub orig_path: PathBuf,
}

/// Finds every safe-restore candidate under `root`: for each file whose
/// name carries a backup-marker suffix (*.orig, *.bak, *.inz, *.original,
/// *.old, or a doubled marker like *.inz.orig), strips the marker to get
/// the live file's name, and pairs them up ONLY when:
///   1. a file by that stripped name actually exists next to it, AND
///   2. its content differs from the marker-suffixed file's (nothing to
///      restore if they're identical), AND
///   3. the marker-suffixed (preserved-original) file itself contains no
///      HiddenSpawn-family marker -- refusing to "restore" FROM a file that
///      is itself tampered, which would just complete the compromise
///      instead of undoing it.
/// A marker-suffixed name that doesn't strip down to an existing sibling at
/// all (a real payload filename that merely contains "inz", e.g.
/// "index.inz.cjs" -- see strip_backup_markers's own doc comment) never
/// becomes a candidate in the first place.
pub fn find_remediation_candidates(root: &Path) -> Vec<RemediationCandidate> {
    let mut out = Vec::new();
    for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let stripped = strip_backup_markers(name);
        if stripped == name {
            continue;
        }
        let live_path = path.with_file_name(&stripped);
        if !live_path.is_file() {
            continue;
        }
        let (Ok(orig_bytes), Ok(live_bytes)) = (std::fs::read(path), std::fs::read(&live_path)) else {
            continue;
        };
        if orig_bytes == live_bytes {
            continue;
        }
        if let Ok(orig_text) = std::str::from_utf8(&orig_bytes) {
            if find_hidden_unicode_escape_run(orig_text).is_some()
                || find_appended_packed_payload(orig_text).is_some()
            {
                continue;
            }
        }
        out.push(RemediationCandidate {
            live_path,
            orig_path: path.to_path_buf(),
        });
    }
    out
}

/// Reports every safe-restore candidate under `root`, printing exactly what
/// it is about to do BEFORE doing it -- and, only when `apply` is true,
/// actually performs the restore. `apply=false` is a completely safe dry
/// run: every candidate is still reported, nothing on disk changes. Nothing
/// is ever deleted: the current (tampered) live file is moved into
/// `~/.goofedup/quarantine/` -- preserved as evidence, exactly the same
/// non-destructive posture this project already takes everywhere else --
/// before the verified-clean preserved original is copied into its place.
/// Returns the number of candidates found (restored or not).
pub fn remediate_project(root: &Path, alerts: &AlertSink, apply: bool) -> usize {
    let candidates = find_remediation_candidates(root);
    if candidates.is_empty() {
        alerts.info(
            "remediate",
            format!("no safe-restore candidates found under {}", root.display()),
        );
        return 0;
    }

    for c in &candidates {
        alerts.warn(
            "remediate",
            format!(
                "{} restore '{}' from verified-clean preserved original '{}'",
                if apply { "about to" } else { "would" },
                c.live_path.display(),
                c.orig_path.display()
            ),
            "orig contains no HiddenSpawn-family marker; live content differs from orig -- pass --fix to actually restore".to_string(),
        );
        if apply {
            match do_restore(c) {
                Ok(quarantine_path) => {
                    alerts.critical(
                        "remediate",
                        format!(
                            "restored '{}' from '{}' -- tampered version preserved (not deleted) at '{}'",
                            c.live_path.display(),
                            c.orig_path.display(),
                            quarantine_path.display()
                        ),
                        String::new(),
                    );
                }
                Err(e) => {
                    alerts.critical(
                        "remediate",
                        format!("FAILED to restore '{}' -- live file left untouched", c.live_path.display()),
                        e,
                    );
                }
            }
        }
    }

    if !apply {
        alerts.info(
            "remediate",
            format!(
                "{} candidate(s) found -- re-run with --scan-deps {} --fix to actually restore",
                candidates.len(),
                root.display()
            ),
        );
    }

    candidates.len()
}

/// Moves the current live file into `~/.goofedup/quarantine/` (never
/// deletes it) then copies the verified-clean preserved original into the
/// live file's place. Returns the quarantine path the tampered version now
/// lives at.
fn do_restore(c: &RemediationCandidate) -> Result<PathBuf, String> {
    let quarantine_dir = crate::config::dirs_home().join(".goofedup").join("quarantine");
    std::fs::create_dir_all(&quarantine_dir).map_err(|e| e.to_string())?;
    let ts = chrono::Local::now().format("%Y%m%d-%H%M%S%.3f");
    let safe_name = c
        .live_path
        .to_string_lossy()
        .replace(['\\', '/', ':'], "_");
    let quarantine_path = quarantine_dir.join(format!("{safe_name}.{ts}"));
    std::fs::rename(&c.live_path, &quarantine_path).map_err(|e| e.to_string())?;
    if let Err(e) = std::fs::copy(&c.orig_path, &c.live_path) {
        // Best-effort: put the tampered file back rather than leaving the
        // live path missing entirely if the copy step itself fails.
        let _ = std::fs::rename(&quarantine_path, &c.live_path);
        return Err(e.to_string());
    }
    Ok(quarantine_path)
}
