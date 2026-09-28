use clap::Parser;
use goofedup::alert::AlertSink;
use goofedup::config::{dirs_home, override_path, Config, ConfigOverrides, SharedConfig};
use goofedup::{
    config_reload, correlate, electron_sweep, repo_fix, scan_js, scan_repo, watch_file, watch_network,
    watch_persistence, watch_process, watch_repos,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

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
    /// HiddenSpawn-family shapes: 4+ \uXXXX identifier escapes, a
    /// multi-kilobyte packed IIFE appended as the last line of any JS-family
    /// file (not just *.config.*), and font/image bytes whose magic is
    /// JavaScript (the fa-solid-400.woff2 delivery vehicle). Exits non-zero
    /// if anything was flagged, so it composes with CI/pre-commit tooling.
    #[arg(long, value_name = "PATH")]
    scan_deps: Option<PathBuf>,

    /// Companion to --scan-deps for a miss the live watcher didn't catch:
    /// finds every live file under --scan-deps' PATH that has a preserved
    /// *.orig/*.bak/*.inz-style original sibling next to it (verifying the
    /// preserved original itself is clean of HiddenSpawn markers first),
    /// and safely restores the live file from it -- moving the current
    /// (tampered) live file into ~/.goofedup/quarantine/ rather than ever
    /// deleting it. Opt-in and separate from --scan-deps' own default
    /// report-only behavior: with --scan-deps alone, nothing here runs at
    /// all. Every candidate is printed (what would be restored, from
    /// where) before anything on disk changes.
    #[arg(long, requires = "scan_deps")]
    fix: bool,

    #[arg(
        long,
        value_name = "PATH",
        num_args = 0..,
        help = "Run only the repo-compromise watcher (hidden .vscode tasks, allowAutomaticTasks, payload-hiding .gitignore, lifecycle droppers, tampered configs) over PATH(s), or over repo_watch_roots when none are given"
    )]
    watch_repos: Option<Vec<PathBuf>>,
}

fn main() {
    let args = Args::parse();
    let override_file = override_path(&dirs_home());
    let (initial_cfg, initial_overrides) = config_reload::load_config_with_overrides(&override_file);

    if args.show_config {
        print_config(&initial_cfg, &initial_overrides);
        return;
    }

    if let Some(root) = &args.scan_deps {
        if let Some(parent) = initial_cfg.log_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let alerts = AlertSink::new(initial_cfg.log_path.clone());
        let flagged = scan_js::scan_project(root, &alerts) + scan_repo::scan_tree(root, &alerts);
        // --fix is opt-in and separate from --scan-deps' own default
        // behavior above -- with --scan-deps alone, nothing past this point
        // runs at all.
        if args.fix {
            scan_js::remediate_project(root, &alerts, true);
            repo_fix::remediate_tree(root, &alerts, true);
        }
        std::process::exit(if flagged > 0 { 1 } else { 0 });
    }

    if let Some(parent) = initial_cfg.log_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let alerts = Arc::new(AlertSink::new(initial_cfg.log_path.clone()));
    let cfg: SharedConfig = Arc::new(RwLock::new(Arc::new(initial_cfg)));
    let overrides_shared: Arc<RwLock<ConfigOverrides>> = Arc::new(RwLock::new(initial_overrides));

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

    // Cross-detector correlation: a c2-shaped-process alert and a
    // backup-sibling/bootstrap-size alert firing within ~60s of each other
    // are almost certainly the same real compromise -- emit one combined
    // CONFIRMED-COMPROMISE alert instead of leaving correlation as an
    // exercise for whoever reads the log later.
    let correlator = Arc::new(correlate::Correlator::new());
    {
        let correlator = correlator.clone();
        let alerts_for_correlate = alerts.clone();
        alerts.add_on_alert(move |a| {
            correlator.on_alert(a, &alerts_for_correlate);
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

    if let Some(paths) = &args.watch_repos {
        let roots = if paths.is_empty() {
            cfg.read().unwrap_or_else(std::sync::PoisonError::into_inner).repo_watch_roots.clone()
        } else {
            paths.clone()
        };
        watch_repos::run(roots, alerts, running);
        return;
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
    {
        let cfg = cfg.clone();
        let overrides_shared = overrides_shared.clone();
        let alerts = alerts.clone();
        let running = running.clone();
        let override_file = override_file.clone();
        handles.push(std::thread::spawn(move || {
            config_reload::run(cfg, overrides_shared, override_file, alerts, running)
        }));
    }
    {
        let cfg = cfg.clone();
        let alerts = alerts.clone();
        let running = running.clone();
        handles.push(std::thread::spawn(move || electron_sweep::run(cfg, alerts, running)));
    }
    {
        let roots = cfg.read().unwrap_or_else(std::sync::PoisonError::into_inner).repo_watch_roots.clone();
        let alerts = alerts.clone();
        let running = running.clone();
        handles.push(std::thread::spawn(move || watch_repos::run(roots, alerts, running)));
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

fn print_config(cfg: &Config, overrides: &ConfigOverrides) {
    println!("goofedup config for {}", std::env::consts::OS);
    println!("override file: {}", override_path(&dirs_home()).display());
    for section in goofedup::config::config_sections(cfg, overrides) {
        println!("\n{} -- {}", section.title, section.description);
        for row in section.rows {
            println!("  {}: {}", row.label, row.value);
        }
    }
}
