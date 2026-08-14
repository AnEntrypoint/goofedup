// Test-only helper binary: reads every file in the given directory, one at a
// time, with a short pause between each -- built as a real Cargo [[bin]]
// (not a shell one-liner) specifically so tests/live_file_read_burst.rs has
// unambiguous control over exactly which process does the real file reads,
// with zero cross-shell exec/quoting surprises (Git Bash on Windows does
// NOT exec-replace itself for `bash -c "cmd"`, which made shell-based
// attempts at this attribute the read to the wrong PID).
//
// Usage: paced_reader <directory>

use std::fs;
use std::time::Duration;

fn main() {
    let dir = std::env::args().nth(1).expect("usage: paced_reader <directory>");
    let mut entries: Vec<_> = fs::read_dir(&dir)
        .expect("read_dir failed")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_file() {
            let _ = fs::read(&path);
            std::thread::sleep(Duration::from_millis(150));
        }
    }
}
