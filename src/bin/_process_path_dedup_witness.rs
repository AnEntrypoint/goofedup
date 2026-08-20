// One-shot live witness for p-reduce-process-path-warn-noise-without-weakening-detection.
// Spawns the SAME real binary from an unlisted (not-allowlisted) path
// multiple times in one session and confirms: (1) only ONE process-path WARN
// fires for that exact path across all launches (dedup working), and (2) a
// SECOND distinct unlisted path still gets its OWN warn (detection not
// weakened -- dedup is per-exact-path, not a blanket suppression). Built,
// run, and deleted same turn per gm no-standing-files discipline.

use goofedup::alert::AlertSink;
use goofedup::config::Config;
use goofedup::watch_process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn main() {
    // NOT std::env::temp_dir() -- on Windows that resolves under
    // %LOCALAPPDATA%\Temp, and LOCALAPPDATA is itself a default allowlist
    // root (Config::default_for_platform), so a copy placed there would be
    // silently trusted and never reach the unlisted-path check at all. The
    // project's own source tree is a real, unlisted (not-allowlisted)
    // location instead.
    let tmp = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("_gpp_witness_root");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();

    // Two distinct "unlisted" exe locations, each holding a copy of a real,
    // harmless, already-present system binary (cmd.exe on Windows) so a real
    // OS process really launches from a real path outside any allowlist
    // root.
    let path_a_dir = tmp.join("pathA");
    let path_b_dir = tmp.join("pathB");
    std::fs::create_dir_all(&path_a_dir).unwrap();
    std::fs::create_dir_all(&path_b_dir).unwrap();

    let system_cmd = std::env::var("COMSPEC").unwrap_or_else(|_| r"C:\Windows\System32\cmd.exe".to_string());
    let exe_a = path_a_dir.join("witness_a.exe");
    let exe_b = path_b_dir.join("witness_b.exe");
    std::fs::copy(&system_cmd, &exe_a).expect("copy cmd.exe to path A");
    std::fs::copy(&system_cmd, &exe_b).expect("copy cmd.exe to path B");

    let log_path = tmp.join("_gpp_witness.log");
    let mut cfg = Config::default_for_platform();
    cfg.poll_interval_secs = 1;
    cfg.log_path = log_path.clone();
    let cfg = Arc::new(cfg);

    let alerts = Arc::new(AlertSink::new(log_path.clone()));
    let warn_events: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    {
        let warn_events = warn_events.clone();
        alerts.set_on_alert(move |a| {
            if a.category == "process-path" && a.level == goofedup::alert::Level::Warn {
                warn_events.lock().unwrap().push(a.evidence.clone().unwrap_or_default());
            }
        });
    }

    let running = Arc::new(AtomicBool::new(true));
    {
        let cfg = cfg.clone();
        let alerts = alerts.clone();
        let running = running.clone();
        std::thread::spawn(move || watch_process::run(cfg, alerts, running));
    }

    // Launch path A 4 times (same exact exe path, repeated) -- must alert
    // ONCE total, not 4 times. `cmd /c exit` returns near-instantly (often
    // faster than the 1s poll interval can observe it as newly-seen), so
    // instead run a brief but poll-observable ping that exits on its own.
    for i in 0..4 {
        let mut c = std::process::Command::new(&exe_a)
            .args(["/c", "ping", "127.0.0.1", "-n", "3"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn witness_a");
        let _ = c.wait();
        println!("[witness] launched path A instance #{i}");
        std::thread::sleep(Duration::from_millis(1200));
    }

    // Then launch path B (a DIFFERENT unlisted path) twice -- must get its
    // OWN independent warn (dedup is per-exact-path, not global).
    for i in 0..2 {
        let mut c = std::process::Command::new(&exe_b)
            .args(["/c", "ping", "127.0.0.1", "-n", "3"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn witness_b");
        let _ = c.wait();
        println!("[witness] launched path B instance #{i}");
        std::thread::sleep(Duration::from_millis(1200));
    }

    std::thread::sleep(Duration::from_secs(2));
    running.store(false, Ordering::SeqCst);

    let events = warn_events.lock().unwrap();
    let a_str = exe_a.to_string_lossy().to_string();
    let b_str = exe_b.to_string_lossy().to_string();
    let count_a = events.iter().filter(|e| e.contains(&a_str)).count();
    let count_b = events.iter().filter(|e| e.contains(&b_str)).count();
    println!("[witness] total process-path WARNs captured: {}", events.len());
    for e in events.iter() {
        println!("[witness]   evidence: {e}");
    }
    println!("[witness] path A (4 launches, same exact path) warn_count={count_a} (expect 1)");
    println!("[witness] path B (2 launches, distinct path) warn_count={count_b} (expect 1)");

    drop(events);
    let _ = std::fs::remove_dir_all(&tmp);

    let pass = count_a == 1 && count_b == 1;
    println!("[witness] RESULT: {}", if pass { "PASS" } else { "FAIL" });
    std::process::exit(if pass { 0 } else { 1 });
}
