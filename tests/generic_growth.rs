// Live-witness the generic (no hardcoded app name) small-file-balloons
// detector: a real .py file, not Discord's index.js and not in the
// bootstrap_watch config at all, starts small and later grows 10x+ past a
// real 20KB floor -- proves the detector generalizes beyond the one
// incident it was seeded from.

use goofedup::alert::AlertSink;
use goofedup::config::Config;
use std::fs;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[test]
fn unrelated_python_bootstrap_growth_is_detected_generically() {
    let dir = std::env::temp_dir().join(format!("goofedup-growth-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let script_path = dir.join("plugin_loader.py");

    // Genuinely tiny, genuinely unrelated to Discord/Node -- a Python
    // plugin loader, the kind of thing no bootstrap_watch entry names.
    fs::write(&script_path, "import importlib\nimportlib.import_module('plugin')\n").unwrap();

    let log_path = dir.join("goofedup.log");
    let mut cfg = Config::default_for_platform();
    cfg.bootstrap_watch = vec![]; // deliberately empty -- this file is unnamed anywhere in config
    // Registers the scratch dir for filesystem events (any registered root
    // works -- check_unusual_growth runs on every Create/Modify event
    // regardless of which list caused the watch registration); the file's
    // NAME is not listed anywhere, which is the actual thing under test.
    cfg.backup_sibling_roots = vec![dir.clone()];
    cfg.log_path = log_path.clone();
    let cfg = Arc::new(cfg);
    let alerts = Arc::new(AlertSink::new(log_path.clone()));

    let cfg_for_thread = cfg.clone();
    let alerts_for_thread = alerts.clone();
    std::thread::spawn(move || {
        goofedup::watch_file::run(cfg_for_thread, alerts_for_thread);
    });

    std::thread::sleep(Duration::from_millis(500));

    // First event establishes the baseline (tiny). Then grow it past both
    // the absolute floor and the 10x ratio.
    fs::write(&script_path, "import importlib\nimportlib.import_module('plugin')\n# still tiny\n").unwrap();
    std::thread::sleep(Duration::from_millis(300));

    let payload = format!("# payload\n{}\n", "x = 1\n".repeat(6000));
    fs::write(&script_path, &payload).unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut found = false;
    while Instant::now() < deadline {
        if log_path.exists() {
            let log = fs::read_to_string(&log_path).unwrap_or_default();
            if log.contains("unusual-growth") && log.contains("CRITICAL") {
                found = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    assert!(
        found,
        "the generic growth detector did not flag an unrelated .py file with no bootstrap_watch entry"
    );

    let _ = fs::remove_dir_all(&dir);
}
