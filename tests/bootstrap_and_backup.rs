// Live-witness integration test: real filesystem writes, real Config/AlertSink,
// the SAME check_bootstrap_size / check_backup_sibling functions the running
// watch_file::run loop calls -- reproduces the shape of the real incident
// (a known-tiny bootstrap file blown up, a *.orig sibling appearing) and
// reads the real log file the sink wrote, not a mock.

use goofedup::alert::AlertSink;
use goofedup::config::{BootstrapEntry, Config};
use goofedup::watch_file::{check_backup_sibling, check_bootstrap_size};
use std::fs;
use std::path::PathBuf;

fn scratch_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("goofedup-test-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn test_config(bootstrap: Vec<BootstrapEntry>, log_path: PathBuf) -> Config {
    let mut cfg = Config::default_for_platform();
    cfg.bootstrap_watch = bootstrap;
    cfg.log_path = log_path;
    cfg
}

#[test]
fn tampered_bootstrap_file_triggers_critical_alert() {
    let dir = scratch_dir("bootstrap");
    let core_dir = dir.join("modules").join("discord_desktop_core-1").join("discord_desktop_core");
    fs::create_dir_all(&core_dir).unwrap();
    let index_path = core_dir.join("index.js");

    // Start clean, exactly like the real Discord bootstrap.
    fs::write(&index_path, "module.exports = require('./core.asar');").unwrap();

    let log_path = dir.join("goofedup.log");
    let cfg = test_config(
        vec![BootstrapEntry {
            search_root: dir.clone(),
            file_name: "index.js",
            path_must_contain: "discord_desktop_core",
            max_bytes: 2048,
        }],
        log_path.clone(),
    );
    let alerts = AlertSink::new(log_path.clone());

    // Clean file: must NOT alert.
    check_bootstrap_size(&cfg, &alerts, &index_path);
    assert!(!log_path.exists() || !fs::read_to_string(&log_path).unwrap().contains("bootstrap-size"));

    // Reproduce the real incident's shape: overwrite with a huge payload.
    let payload = format!("/*obfuscated*/{}", "x".repeat(270_000));
    fs::write(&index_path, &payload).unwrap();

    check_bootstrap_size(&cfg, &alerts, &index_path);

    let log = fs::read_to_string(&log_path).unwrap();
    assert!(log.contains("bootstrap-size"), "expected a bootstrap-size alert, log was:\n{log}");
    assert!(log.contains("CRITICAL"), "expected CRITICAL level, log was:\n{log}");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn backup_sibling_file_triggers_critical_alert() {
    let dir = scratch_dir("backup-sibling");
    let real_file = dir.join("index.js");
    let backup_file = dir.join("index.js.inz.orig");
    fs::write(&real_file, "real content").unwrap();
    fs::write(&backup_file, "module.exports = require('./core.asar');").unwrap();

    let log_path = dir.join("goofedup.log");
    let cfg = test_config(vec![], log_path.clone());
    let alerts = AlertSink::new(log_path.clone());

    check_backup_sibling(&cfg, &alerts, &backup_file);

    let log = fs::read_to_string(&log_path).unwrap();
    assert!(log.contains("backup-sibling"), "expected a backup-sibling alert, log was:\n{log}");
    assert!(log.contains("CRITICAL"));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn plain_file_does_not_trigger_backup_sibling_alert() {
    let dir = scratch_dir("backup-sibling-negative");
    let real_file = dir.join("index.js");
    fs::write(&real_file, "real content").unwrap();

    let log_path = dir.join("goofedup.log");
    let cfg = test_config(vec![], log_path.clone());
    let alerts = AlertSink::new(log_path.clone());

    check_backup_sibling(&cfg, &alerts, &real_file);

    assert!(!log_path.exists(), "a plain .js file must never trigger a backup-sibling alert");

    let _ = fs::remove_dir_all(&dir);
}
