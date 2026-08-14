// Live-witness the REAL watch_process::run polling loop against a REAL
// spawned process reproducing the exact command-line shape of the incident
// (obfuscated node -e payload with a C2 IP marker). No mocked process list,
// no mocked sysinfo -- an actual child process is spawned, the actual
// watcher polls the actual OS process table and must find it.

use goofedup::alert::AlertSink;
use goofedup::config::Config;
use std::fs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[test]
fn real_spawned_c2_shaped_process_is_detected() {
    let dir = std::env::temp_dir().join(format!("goofedup-proc-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let log_path = dir.join("goofedup.log");

    let mut cfg = Config::default_for_platform();
    cfg.bootstrap_watch = vec![];
    cfg.backup_sibling_roots = vec![];
    cfg.poll_interval_secs = 1;
    cfg.log_path = log_path.clone();
    let cfg = Arc::new(cfg);
    let alerts = Arc::new(AlertSink::new(log_path.clone()));
    let running = Arc::new(AtomicBool::new(true));

    let cfg_for_thread = cfg.clone();
    let alerts_for_thread = alerts.clone();
    let running_for_thread = running.clone();
    let watcher = std::thread::spawn(move || {
        goofedup::watch_process::run(cfg_for_thread, alerts_for_thread, running_for_thread);
    });

    // Let the watcher take its baseline snapshot before the target process
    // exists, matching watch_process::run's real startup order.
    std::thread::sleep(Duration::from_millis(1200));

    // Same shape as the real incident: the entire -e argument IS the long,
    // dense, C2-marker-carrying payload (not a comment wrapping a harmless
    // script) -- harmless in effect (it just times out and exits), but the
    // COMMAND LINE itself is byte-for-byte the shape the detector must
    // score, exactly like the real malware's actual invocation.
    let mut junk = String::new();
    for i in 0..80 {
        junk.push_str(&format!("var q{i}={{a:{i},b:'{i}!@#$'}};"));
    }
    let payload = format!(
        "global['_t_s']='http://198.51.100.7:443';global['e']='NPM';{junk}function xorDecode(b){{return b}};xorDecode(Buffer.from('00','hex'));setTimeout(()=>process.exit(0),6000);"
    );
    let mut child = std::process::Command::new("node")
        .args(["-e", &payload])
        .spawn()
        .expect("node must be on PATH for this test");

    let deadline = Instant::now() + Duration::from_secs(8);
    let mut found = false;
    while Instant::now() < deadline {
        if log_path.exists() {
            let log = fs::read_to_string(&log_path).unwrap_or_default();
            if log.contains("c2-shaped-process") && log.contains("CRITICAL") {
                found = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    running.store(false, Ordering::Relaxed);
    let _ = child.kill();
    let _ = child.wait();
    let _ = watcher.join();

    assert!(
        found,
        "real watch_process::run did not detect the real spawned C2-shaped node process within 8s"
    );

    let _ = fs::remove_dir_all(&dir);
}

// Regression guard for a real bug found while building this: sysinfo 0.33
// on Windows silently drops a process's cmd() when refresh_processes is
// called repeatedly on an already-populated System, but returns it
// correctly from a fresh System::new_all(). watch_process::run was fixed to
// build a fresh System every poll cycle specifically because of this test.
#[test]
fn sysinfo_returns_real_cmdline_for_a_real_spawned_process() {
    use sysinfo::System;
    let mut child = std::process::Command::new("node")
        .args(["-e", "setTimeout(()=>{}, 4000);"])
        .spawn()
        .expect("node must be on PATH");
    std::thread::sleep(std::time::Duration::from_millis(800));

    let sys = System::new_all();
    let pid = sysinfo::Pid::from_u32(child.id());
    let found = sys.process(pid);
    let cmd: Vec<String> = found
        .map(|p| p.cmd().iter().map(|s| s.to_string_lossy().to_string()).collect())
        .unwrap_or_default();

    let _ = child.kill();
    let _ = child.wait();

    assert!(found.is_some(), "sysinfo did not find the spawned node process at all");
    assert!(!cmd.is_empty(), "sysinfo returned an empty cmd() for a real spawned process -- the exact bug this test guards against");
    assert!(cmd.iter().any(|s| s.contains("setTimeout")), "cmd content did not match what was spawned: {cmd:?}");
}
