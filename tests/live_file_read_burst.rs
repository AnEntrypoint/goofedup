// Live-witness the file-read-burst (mass scanning/harvesting) detector
// against a REAL process that actually reads a large amount of real file
// data quickly -- no mocked disk_usage(), the actual OS-reported per-process
// I/O counters via sysinfo.

use goofedup::alert::AlertSink;
use goofedup::config::Config;
use std::fs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[test]
fn real_bulk_file_read_triggers_burst_alert() {
    let dir = std::env::temp_dir().join(format!("goofedup-readburst-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();

    // A REAL, disclosed limitation of poll-based detection this test is
    // written around: a fast reader can complete and exit entirely between
    // two poll ticks, so sys.processes() never observes it mid-read at all
    // -- live-witnessed while building this test (a real `cat` process
    // reading 120MB in <1s was gone before a 1s-interval watcher ever
    // polled it). A real scanning/harvesting process reading a large real
    // dataset does NOT typically finish in under a second though -- this
    // test uses a large enough total (1GB) that even a fast disk takes
    // multiple seconds, giving the watcher's poll loop a genuine chance to
    // sample the process mid-read, matching realistic scanning behavior.
    let payload = vec![b'A'; 8 * 1024 * 1024]; // 8MB per file
    let file_count = 128; // 1GB total
    for i in 0..file_count {
        fs::write(dir.join(format!("blob-{i:03}.bin")), &payload).unwrap();
    }

    let log_path = dir.join("goofedup.log");
    let mut cfg = Config::default_for_platform();
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

    std::thread::sleep(Duration::from_millis(1200));

    // Reads via the real paced_reader helper binary (src/bin/paced_reader.rs)
    // instead of any shell wrapper: `cat`/native reads finish a 1GB payload
    // in ~250ms on modern NVMe/cache, well under the 1s poll interval, so a
    // plain fast reader exits before ever being sampled mid-read -- a REAL,
    // disclosed limitation of poll-based detection (see Config's own
    // file_read_burst_* doc comment), not something to paper over. Every
    // shell-based attempt at pacing this (bash -c, perl -e) hit real
    // cross-platform quoting/exec-replacement surprises; a real compiled
    // helper binary has none of that -- its own PID is unambiguously the
    // one doing the reads, paced by a real sleep between files.
    let paced_reader = env!("CARGO_BIN_EXE_paced_reader");
    let mut child = std::process::Command::new(paced_reader)
        .arg(&dir)
        .spawn()
        .expect("paced_reader helper binary must build (it's a normal [[bin]] target)");

    let child_pid = child.id();
    let pid_marker = format!("PID {child_pid})");

    let deadline = Instant::now() + Duration::from_secs(20);
    let mut found = false;
    while Instant::now() < deadline {
        if log_path.exists() {
            let log = fs::read_to_string(&log_path).unwrap_or_default();
            if log.contains("file-read-burst") && log.contains("CRITICAL") && log.contains(&pid_marker) {
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
        "real watch_process::run did not attribute a file-read-burst alert to the actual test cat process (PID {child_pid}) reading a real 120MB file within 20s"
    );

    let _ = fs::remove_dir_all(&dir);
}
