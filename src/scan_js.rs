// One-shot project scanner: walks a directory tree for JS-family source
// (and node_modules dependency content) and greps each file for the
// hidden-unicode-escape-identifier shape (see heuristics::find_hidden_unicode_escape_run).
// Separate from the live watchers in watch_*.rs -- this is deliberately a
// bounded, on-demand pass over file CONTENT (a project/dependency audit),
// not a continuous background signal like process/network/file-metadata
// watching.

use crate::alert::AlertSink;
use crate::heuristics::find_hidden_unicode_escape_run;
use std::path::Path;
use walkdir::WalkDir;

const JS_EXTENSIONS: &[&str] = &["js", "mjs", "cjs", "jsx", "ts", "tsx"];

/// Directory names never worth descending into for this scan: version
/// control internals (never shipped/executed), and common noise dirs whose
/// content is either not JS or is test/doc fixture data rather than a real
/// execution path -- kept narrow and named so a truly novel malicious
/// package under an unusual dir name is never silently skipped.
const SKIP_DIR_NAMES: &[&str] = &[".git", ".hg", ".svn"];

fn is_js_file(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| JS_EXTENSIONS.iter().any(|ext| ext.eq_ignore_ascii_case(e)))
        .unwrap_or(false)
}

/// Walks `root` (recursively, including any `node_modules` present) and
/// alerts on every file containing a 4+ run of `\uXXXX` escapes that decode
/// to a plain-ASCII identifier. Returns the number of files flagged.
pub fn scan_project(root: &Path, alerts: &AlertSink) -> usize {
    let mut flagged = 0usize;
    let mut scanned = 0usize;

    let walker = WalkDir::new(root).into_iter().filter_entry(|e| {
        if e.file_type().is_dir() {
            let name = e.file_name().to_string_lossy();
            !SKIP_DIR_NAMES.iter().any(|s| *s == name)
        } else {
            true
        }
    });

    for entry in walker.filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() || !is_js_file(entry.path()) {
            continue;
        }
        let path = entry.path();
        let Ok(content) = std::fs::read_to_string(path) else {
            continue;
        };
        scanned += 1;
        if let Some(v) = find_hidden_unicode_escape_run(&content) {
            flagged += 1;
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
        format!("scanned {scanned} JS-family file(s) under {}, {flagged} flagged", root.display()),
    );

    flagged
}
