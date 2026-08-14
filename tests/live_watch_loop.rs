// Live-witness the REAL watch_file::run event loop (notify-driven, not just
// the pure check functions) against a real scratch directory: spawn it on a
// thread, then perform the exact real-incident write (overwrite a known-tiny
// bootstrap file with a huge payload) and confirm the alert lands in the
// real log file within a bounded wait. This proves the actual wiring
// (notify watcher -> event dispatch -> check_bootstrap_size) works, not
// just the pure detection functions in isolation.

use goofedup::alert::AlertSink;
use goofedup::config::{BootstrapEntry, Config};
use std::fs;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[test]
fn full_notify_driven_loop_detects_tampered_bootstrap() {
    let dir = std::env::temp_dir().join(format!("goofedup-live-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let core_dir = dir
        .join("modules")
        .join("discord_desktop_core-1")
        .join("discord_desktop_core");
    fs::create_dir_all(&core_dir).unwrap();
    let index_path = core_dir.join("index.js");
    fs::write(&index_path, "module.exports = require('./core.asar');").unwrap();

    let log_path = dir.join("goofedup.log");
    let mut cfg = Config::default_for_platform();
    cfg.bootstrap_watch = vec![BootstrapEntry {
        search_root: dir.clone(),
        file_name: "index.js",
        path_must_contain: "discord_desktop_core",
        max_bytes: 2048,
    }];
    cfg.backup_sibling_roots = vec![];
    cfg.log_path = log_path.clone();
    let cfg = Arc::new(cfg);
    let alerts = Arc::new(AlertSink::new(log_path.clone()));

    let cfg_for_thread = cfg.clone();
    let alerts_for_thread = alerts.clone();
    std::thread::spawn(move || {
        goofedup::watch_file::run(cfg_for_thread, alerts_for_thread);
    });

    // Give the watcher a moment to register with the OS before writing --
    // this is the one real timing dependency of a live fs-event test.
    std::thread::sleep(Duration::from_millis(500));

    let payload = format!("/*obfuscated*/{}", "x".repeat(270_000));
    fs::write(&index_path, &payload).unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut found = false;
    while Instant::now() < deadline {
        if log_path.exists() {
            let log = fs::read_to_string(&log_path).unwrap_or_default();
            if log.contains("bootstrap-size") && log.contains("CRITICAL") {
                found = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    assert!(
        found,
        "real notify-driven watch_file::run did not detect the tampered bootstrap file within 10s"
    );

    let _ = fs::remove_dir_all(&dir);
}
