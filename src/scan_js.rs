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

const ASSET_EXTENSIONS: &[&str] = crate::command_shape::NON_SOURCE_ASSET_EXTENSIONS;
const ASSET_PREFIX_BYTES: u64 = 64 * 1024;

const SKIP_DIR_NAMES: &[&str] = &[".git", ".hg", ".svn", "target"];
const NODE_MODULES_DIR_NAME: &str = "node_modules";
pub(crate) const MAX_SCAN_DEPTH: usize = 24;
#[cfg(windows)]
pub(crate) const MAX_SCAN_PATH_CHARS: usize = 240;
#[cfg(not(windows))]
pub(crate) const MAX_SCAN_PATH_CHARS: usize = 1024;
const CONFIG_FILE_NAME_INFIX: &str = ".config.";
const ASAR_HEADER_PICKLE_SIZE_OFFSET: usize = 4;
const ASAR_JSON_LENGTH_OFFSET: usize = 12;
const ASAR_JSON_START_OFFSET: usize = 16;
const ASAR_DATA_BASE_PREFIX_BYTES: usize = 8;
const U32_BYTES: usize = 4;
const ASAR_ENTRIES_KEY: &str = "files";
const EXE_EVIDENCE_PREFIX: &str = "exe=";
const MIN_ABSOLUTE_PATH_TOKEN_LEN: usize = 4;

fn is_js_file(path: &Path) -> bool {
    ext_is(path, JS_EXTENSIONS)
}

fn is_node_modules_dir(path: &Path) -> bool {
    path.file_name().map(|n| n.to_string_lossy() == NODE_MODULES_DIR_NAME).unwrap_or(false)
}

pub(crate) fn is_stacked_node_modules(path: &Path) -> bool {
    is_node_modules_dir(path) && path.parent().map(is_node_modules_dir).unwrap_or(false)
}

fn is_config_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.contains(CONFIG_FILE_NAME_INFIX))
        .unwrap_or(false)
}

fn ext_is(path: &Path, exts: &[&str]) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| exts.iter().any(|ext| ext.eq_ignore_ascii_case(e)))
        .unwrap_or(false)
}

const ASAR_MAX_ENTRY_BYTES: u64 = 50 * 1024 * 1024;

fn scan_asar(path: &Path, alerts: &AlertSink, check: &mut impl FnMut(&str) -> bool) -> (usize, usize) {
    let mut scanned = 0usize;
    let mut flagged = 0usize;

    let Ok(data) = std::fs::read(path) else {
        return (0, 0);
    };
    let Some(hsize) = read_u32_le(&data[ASAR_HEADER_PICKLE_SIZE_OFFSET..ASAR_HEADER_PICKLE_SIZE_OFFSET + U32_BYTES]) else { return (0, 0) };
    let Some(json_len) = read_u32_le(&data[ASAR_JSON_LENGTH_OFFSET..ASAR_JSON_LENGTH_OFFSET + U32_BYTES]) else { return (0, 0) };
    let data_base = ASAR_DATA_BASE_PREFIX_BYTES + hsize as usize;
    if data.len() < ASAR_JSON_START_OFFSET + json_len as usize || data_base > data.len() {
        return (0, 0);
    }
    let Ok(header) = std::str::from_utf8(&data[ASAR_JSON_START_OFFSET..ASAR_JSON_START_OFFSET + json_len as usize]) else {
        return (0, 0);
    };
    let Ok(tree) = serde_json::from_str::<serde_json::Value>(header) else {
        return (0, 0);
    };

    let mut stack = vec![tree];
    while let Some(node) = stack.pop() {
        let Some(files) = node.get(ASAR_ENTRIES_KEY).and_then(|f| f.as_object()) else {
            continue;
        };
        for child in files.values() {
            if child.get(ASAR_ENTRIES_KEY).is_some() {
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
    if b.len() < U32_BYTES {
        return None;
    }
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

pub fn scan_project(root: &Path, alerts: &AlertSink) -> usize {
    let mut total_flagged = 0usize;
    let mut total_scanned = 0usize;

    alerts.info("repo-scan", format!("starting dependency scan of {}", root.display()));

    let mut skipped_dirs = 0usize;
    let walker = WalkDir::new(root).into_iter().filter_entry(|e| {
        if e.path().to_string_lossy().len() > MAX_SCAN_PATH_CHARS {
            if e.file_type().is_dir() {
                skipped_dirs += 1;
            }
            return false;
        }
        if !e.file_type().is_dir() {
            return true;
        }
        if e.depth() > MAX_SCAN_DEPTH || is_stacked_node_modules(e.path()) {
            skipped_dirs += 1;
            return false;
        }
        let name = e.file_name().to_string_lossy();
        !SKIP_DIR_NAMES.iter().any(|s| *s == name)
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
            let Some(bytes) = crate::scan_repo::read_prefix(path, ASSET_PREFIX_BYTES) else {
                continue;
            };
            total_scanned += 1;
            if let Some(v) = find_javascript_masquerading_as_asset(&bytes).filter(|_| crate::command_shape::is_js_carrier(path)) {
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

    if skipped_dirs > 0 {
        alerts.warn(
            "repo-scan",
            format!(
                "left {skipped_dirs} director(ies) under {} uninspected: deeper than {MAX_SCAN_DEPTH} levels, a node_modules copy stacked inside another, or a path over {MAX_SCAN_PATH_CHARS} characters -- anything planted below those limits is not seen by this scan",
                root.display()
            ),
            format!("root={}", root.display()),
        );
    }

    alerts.info(
        "hidden-unicode-identifier",
        format!("scanned {total_scanned} JS-family file(s) under {}, {total_flagged} flagged", root.display()),
    );

    total_flagged
}

const RESPONSE_COOLDOWN: Duration = Duration::from_secs(120 * 60);

pub struct AlertResponse {
    last_scan_start_by_root: Mutex<HashMap<PathBuf, Instant>>,
}

impl AlertResponse {
    pub fn new() -> Self {
        Self {
            last_scan_start_by_root: Mutex::new(HashMap::new()),
        }
    }

    pub fn on_alert(self: &Arc<Self>, a: &Alert, sink: &Arc<AlertSink>) -> bool {
        if is_own_scan_output(a) {
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
        let root = widen_to_risky_app_root(&root).unwrap_or(root);

        if !self.reserve_scan_slot(&root) {
            return false;
        }

        let response = self.clone();
        let sink_handle = sink.clone();
        std::thread::spawn(move || {
            response.scan_and_report(&root, &sink_handle);
        });
        true
    }

    fn reserve_scan_slot(&self, root: &Path) -> bool {
        let mut last_scan_start_by_root = self
            .last_scan_start_by_root
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(t) = last_scan_start_by_root.get(root) {
            if t.elapsed() < RESPONSE_COOLDOWN {
                return false;
            }
        }
        last_scan_start_by_root.insert(root.to_path_buf(), Instant::now());
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

fn is_own_scan_output(a: &Alert) -> bool {
    a.category == "hidden-unicode-identifier" || a.category == "alert-response"
}

impl Default for AlertResponse {
    fn default() -> Self {
        Self::new()
    }
}

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

fn extract_app_root(text: &str) -> Option<PathBuf> {
    let candidate = if let Some(pos) = text.find(EXE_EVIDENCE_PREFIX) {
        let rest = &text[pos + EXE_EVIDENCE_PREFIX.len()..];
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

fn first_absolute_path(text: &str) -> Option<&str> {
    for tok in text.split(|c: char| c.is_whitespace() || c == '"' || c == '\'') {
        let looks_absolute = tok.len() >= MIN_ABSOLUTE_PATH_TOKEN_LEN
            && ((tok.as_bytes()[1] == b':' && tok.as_bytes()[0].is_ascii_alphabetic())
                || tok.starts_with('/'));
        if looks_absolute && Path::new(tok).is_file() {
            return Some(tok);
        }
    }
    None
}

pub struct RemediationCandidate {
    pub live_path: PathBuf,
    pub orig_path: PathBuf,
}

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
        let _ = std::fs::rename(&quarantine_path, &c.live_path);
        return Err(e.to_string());
    }
    Ok(quarantine_path)
}
