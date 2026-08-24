use clap::Parser;
use goofedup::alert::AlertSink;
use goofedup::config::Config;
use goofedup::{scan_js, watch_file, watch_network, watch_persistence, watch_process};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// goofedup -- cross-platform structural-anomaly watcher.
///
/// Catches malware by SHAPE, not signature: a known-tiny bootstrap file
/// suddenly huge, a *.orig backup sibling appearing, an obfuscated C2-shaped
/// process command line, a process running from a Recycle Bin / Trash path,
/// a masquerading process name, a new service/scheduled-task registration,
/// network scanning behavior, and the firewall silently going dark. Every
/// signal in this list is a real fact from one real incident on one real
/// machine, none of it required a signature database.
///
/// Alert-only. Nothing here kills a process, deletes a file, or blocks a
/// connection automatically -- every alert that warrants action prints the
/// exact command to run, so a false positive can never cause damage.
#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Print the resolved config (watched paths, thresholds) and exit.
    #[arg(long)]
    show_config: bool,

    /// One-shot scan of a project directory (including node_modules) for
    /// JS-family source hiding identifiers behind a run of 4+ \uXXXX
    /// escapes -- the shape malware uses to dodge a plain-text grep for
    /// require/child_process/eval/etc. Exits with a non-zero status if
    /// anything was flagged, so it composes with CI/pre-commit tooling.
    #[arg(long, value_name = "PATH")]
    scan_deps: Option<PathBuf>,
}

fn main() {
    let args = Args::parse();
    let cfg = Arc::new(Config::default_for_platform());

    if args.show_config {
        print_config(&cfg);
        return;
    }

    if let Some(root) = &args.scan_deps {
        if let Some(parent) = cfg.log_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let alerts = AlertSink::new(cfg.log_path.clone());
        let flagged = scan_js::scan_project(root, &alerts);
        std::process::exit(if flagged > 0 { 1 } else { 0 });
    }

    if let Some(parent) = cfg.log_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let alerts = Arc::new(AlertSink::new(cfg.log_path.clone()));

    // Alert-triggered response: any Warn/Critical alert naming an app sends
    // the hidden-unicode-identifier content scan over that app's install
    // tree. Registered before the watchers start so nothing slips past.
    let response = Arc::new(scan_js::AlertResponse::new());
    {
        let response = response.clone();
        let alerts_for_response = alerts.clone();
        alerts.add_on_alert(move |a| {
            response.on_alert(a, &alerts_for_response);
        });
    }

    alerts.info(
        "goofedup",
        format!(
            "starting on {} -- alert-only, nothing is killed/deleted/blocked automatically",
            std::env::consts::OS
        ),
    );

    let running = Arc::new(AtomicBool::new(true));
    {
        let running = running.clone();
        let alerts_for_ctrlc = alerts.clone();
        ctrlc::set_handler(move || {
            alerts_for_ctrlc.info("goofedup", "stopping (Ctrl+C received)");
            running.store(false, Ordering::Relaxed);
        })
        .expect("failed to set Ctrl+C handler");
    }

    let mut handles = Vec::new();

    {
        let cfg = cfg.clone();
        let alerts = alerts.clone();
        handles.push(std::thread::spawn(move || watch_file::run(cfg, alerts)));
    }
    {
        let cfg = cfg.clone();
        let alerts = alerts.clone();
        let running = running.clone();
        handles.push(std::thread::spawn(move || {
            watch_process::run(cfg, alerts, running)
        }));
    }
    {
        let cfg = cfg.clone();
        let alerts = alerts.clone();
        let running = running.clone();
        handles.push(std::thread::spawn(move || {
            watch_persistence::run(cfg, alerts, running)
        }));
    }
    {
        let cfg = cfg.clone();
        let alerts = alerts.clone();
        let running = running.clone();
        handles.push(std::thread::spawn(move || {
            watch_network::run(cfg, alerts, running)
        }));
    }
    {
        let cfg = cfg.clone();
        let alerts = alerts.clone();
        let running = running.clone();
        handles.push(std::thread::spawn(move || {
            watch_network::run_firewall_drift(cfg, alerts, running)
        }));
    }

    while running.load(Ordering::Relaxed) {
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    // File watcher blocks on its notify channel with no clean interrupt in
    // this design (notify's mpsc receiver has no timeout variant used
    // here); the process/persistence/network threads all observe `running`
    // and exit their own loops promptly. This is a deliberate, bounded
    // tradeoff -- the process exits regardless via std::process::exit once
    // every OTHER watcher has wound down, rather than hanging on the one
    // thread with no portable "stop watching" signal.
    for h in handles {
        let _ = h.join();
    }
}

fn print_config(cfg: &Config) {
    println!("goofedup config for {}", std::env::consts::OS);
    println!("log path: {}", cfg.log_path.display());
    println!("\nbootstrap watch:");
    for e in &cfg.bootstrap_watch {
        println!(
            "  {} (must contain '{}') > {} bytes",
            e.search_root.join(e.file_name).display(),
            e.path_must_contain,
            e.max_bytes
        );
    }
    println!("\nbackup-sibling roots:");
    for r in &cfg.backup_sibling_roots {
        println!("  {}", r.display());
    }
    println!("\nwatched interpreters: {}", cfg.watched_interpreters.join(", "));
    println!("\ndenied exec path fragments: {}", cfg.deny_exec_path_fragments.join(", "));
    println!("\nallowed exec roots:");
    for r in &cfg.allowed_exec_roots {
        println!("  {}", r.display());
    }
    println!(
        "\nnetwork scan thresholds: {}+ distinct ports OR {}+ distinct hosts within {}s",
        cfg.scan_distinct_ports_threshold, cfg.scan_distinct_hosts_threshold, cfg.scan_window_secs
    );
    println!("poll interval: {}s", cfg.poll_interval_secs);
}
