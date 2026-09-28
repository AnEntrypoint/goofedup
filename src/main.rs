use clap::Parser;
use goofedup::alert::AlertSink;
use goofedup::config::{dirs_home, override_path, Config, ConfigOverrides, SharedConfig};
use goofedup::{
    audit_win, config_reload, correlate, electron_sweep, repo_fix, scan_js, scan_repo, self_protect,
    sysmon_config, watch_events, watch_file, watch_network, watch_persistence, watch_process,
    watch_repos, watch_tamper,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

const LONG_ABOUT: &str = "goofedup -- cross-platform structural-anomaly watcher.\n\nCatches malware by SHAPE, not signature: a known-tiny bootstrap file suddenly huge, a *.orig backup sibling appearing, an obfuscated C2-shaped process command line, a process running from a Recycle Bin / Trash path, a masquerading process name, a new service/scheduled-task registration, network scanning behavior, and the firewall silently going dark. Every signal in this list is a real fact from one real incident on one real machine, none of it required a signature database.\n\nAlert-only. Nothing here kills a process, deletes a file, or blocks a connection automatically -- every alert that warrants action prints the exact command to run, so a false positive can never cause damage.";

#[derive(Parser)]
#[command(version, about, long_about = LONG_ABOUT)]
struct Args {
    #[arg(long, help = "Print the resolved config (watched paths, thresholds) and exit")]
    show_config: bool,

    #[arg(
        long,
        value_name = "PATH",
        help = "One-shot scan of a project directory (including node_modules) for HiddenSpawn-family shapes: 4+ \\uXXXX identifier escapes, a multi-kilobyte packed IIFE appended as the last line of any JS-family file (not just *.config.*), and font/image bytes whose magic is JavaScript (the fa-solid-400.woff2 delivery vehicle). Exits non-zero if anything was flagged, so it composes with CI/pre-commit tooling"
    )]
    scan_deps: Option<PathBuf>,

    #[arg(
        long,
        requires = "scan_deps",
        help = "Opt-in remediation over the --scan-deps PATH: restores live files from verified-clean *.orig/*.bak siblings and quarantines repo-compromise launchers (decoy dirs, payload files, injected settings keys). Every action is printed before anything changes; originals and tampered files move to ~/.goofedup/quarantine, never deleted"
    )]
    fix: bool,

    #[arg(
        long,
        help = "One-shot Windows posture audit: portproxy rules, exposed debugger/admin listeners, inbound firewall allows, SYSTEM tasks and services with missing or non-admin-writable binaries, Defender state, root certs, hosts file, local admins, plaintext credential files and autoruns. Exits non-zero if any Critical finding exists"
    )]
    audit: bool,

    #[arg(
        long,
        requires = "audit",
        help = "With --audit: list every finding including Info and lift the per-category line cap"
    )]
    audit_all: bool,
    #[arg(
        long,
        value_name = "PATH",
        num_args = 0..,
        help = "Run only the repo-compromise watcher (hidden .vscode tasks, allowAutomaticTasks, payload-hiding .gitignore, lifecycle droppers, tampered configs) over PATH(s), or over repo_watch_roots when none are given"
    )]
    watch_repos: Option<Vec<PathBuf>>,

    #[arg(
        long,
        value_name = "PATH",
        num_args = 0..=1,
        help = "Print the recommended Sysmon 15.x config (ATT&CK-tagged, minimal high-signal set) to stdout, or write it to PATH; never applies it"
    )]
    sysmon_config: Option<Option<PathBuf>>,
}

const PREVIEW_ONLY: bool = false;
const APPLY_CHANGES: bool = true;
const SHUTDOWN_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(200);

fn main() {
    let args = Args::parse();
    if let Some(target) = &args.sysmon_config {
        if let Err(e) = sysmon_config::emit(target.as_deref()) {
            eprintln!("sysmon config write failed: {e}");
            std::process::exit(1);
        }
        return;
    }

    let override_file = override_path(&dirs_home());
    let (initial_cfg, initial_overrides) = config_reload::load_config_with_overrides(&override_file);

    if args.show_config {
        print_config(&initial_cfg, &initial_overrides);
        return;
    }

    if args.audit {
        std::process::exit(audit_win::run_cli(&initial_cfg.tamper, args.audit_all));
    }

    if let Some(root) = &args.scan_deps {
        if let Some(parent) = initial_cfg.log_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let alerts = AlertSink::new(initial_cfg.log_path.clone());
        let flagged = scan_js::scan_project(root, &alerts) + scan_repo::scan_tree(root, &alerts);
        if args.fix {
            scan_js::remediate_project(root, &alerts, PREVIEW_ONLY);
            repo_fix::remediate_tree(root, &alerts, PREVIEW_ONLY);
            scan_js::remediate_project(root, &alerts, APPLY_CHANGES);
            repo_fix::remediate_tree(root, &alerts, APPLY_CHANGES);
        }
        std::process::exit(if flagged > 0 { 1 } else { 0 });
    }

    if let Some(parent) = initial_cfg.log_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let alerts = Arc::new(AlertSink::new(initial_cfg.log_path.clone()));
    let cfg: SharedConfig = Arc::new(RwLock::new(Arc::new(initial_cfg)));
    let overrides_shared: Arc<RwLock<ConfigOverrides>> = Arc::new(RwLock::new(initial_overrides));

    let response = Arc::new(scan_js::AlertResponse::new());
    {
        let response = response.clone();
        let alerts_for_response = alerts.clone();
        alerts.add_on_alert(move |a| {
            response.on_alert(a, &alerts_for_response);
        });
    }

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
        let alerts = alerts.clone();
        let running = running.clone();
        handles.push(std::thread::spawn(move || {
            watch_tamper::run(cfg, alerts, running)
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
    {
        let cfg = cfg.clone();
        let alerts = alerts.clone();
        let running = running.clone();
        handles.push(std::thread::spawn(move || watch_events::run(cfg, alerts, running)));
    }
    {
        let cfg = cfg.clone();
        let alerts = alerts.clone();
        let running = running.clone();
        let override_file = override_file.clone();
        handles.push(std::thread::spawn(move || {
            self_protect::run(cfg, alerts, running, override_file)
        }));
    }

    while running.load(Ordering::Relaxed) {
        std::thread::sleep(SHUTDOWN_POLL_INTERVAL);
    }

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
