// One-shot project scanner: walks a directory tree for JS-family source
// (and node_modules dependency content) and greps each file for the
// hidden-unicode-escape-identifier shape (see heuristics::find_hidden_unicode_escape_run).
// Separate from the live watchers in watch_*.rs -- this is deliberately a
// bounded, on-demand pass over file CONTENT (a project/dependency audit),
// not a continuous background signal like process/network/file-metadata
// watching.

use crate::alert::{Alert, AlertSink};
use crate::heuristics::find_hidden_unicode_escape_run;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use walkdir::WalkDir;

const JS_EXTENSIONS: &[&str] = &["js", "mjs", "cjs", "jsx", "ts", "tsx"];

/// Directory names never worth descending into for this scan: version
/// control internals (never shipped/executed), and common noise dirs whose
/// content is either not JS or is test/doc fixture data rather than a real
/// execution path -- kept narrow and named so a truly novel malicious
/// package under an unusual dir name is never silently skipped.
const SKIP_DIR_NAMES: &[&str] = &[".git", ".hg", ".svn"];

fn is_js_file(path: &Path) -> bool {
    ext_is(path, JS_EXTENSIONS)
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
