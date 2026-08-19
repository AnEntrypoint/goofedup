#![windows_subsystem = "windows"]

// Windows system-tray GUI for goofedup: runs the same watcher threads as
// the CLI, but replaces console/log-only output with a tray icon that goes
// red on an unacknowledged Critical alert plus a native toast per Warn/
// Critical event, so "we done goofed" reaches the user without a terminal
// window open.

use goofedup::alert::{AlertSink, Level};
use goofedup::config::Config;
use goofedup::gui::{alert_window, autostart, history::History, icon, single_instance, toast};
use goofedup::{watch_file, watch_network, watch_persistence, watch_process};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::TrayIconBuilder;

fn main() {
    let Some(_instance_guard) = single_instance::acquire() else {
        return;
    };

    toast::init();

    let cfg = Arc::new(Config::default_for_platform());
    if let Some(parent) = cfg.log_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let alerts = Arc::new(AlertSink::new(cfg.log_path.clone()));
    let history = Arc::new(History::new());

    {
        let history = history.clone();
        alerts.set_on_alert(move |a| {
            history.push(a);
            if matches!(a.level, Level::Warn | Level::Critical) {
                toast::show(&format!("goofedup: {}", a.category), &a.message);
            }
        });
    }

    let running = Arc::new(AtomicBool::new(true));
    spawn_watchers(cfg.clone(), alerts.clone(), running.clone());

    let event_loop = EventLoopBuilder::new().build();

    let open_log = MenuItem::new("Open Recent Alerts", true, None);
    let show_config = MenuItem::new("Show Config", true, None);
    let autostart_item = MenuItem::new(autostart_label(), true, None);
    let quit = MenuItem::new("Quit", true, None);

    let menu = Menu::new();
    let _ = menu.append(&open_log);
    let _ = menu.append(&show_config);
    let _ = menu.append(&PredefinedMenuItem::separator());
    let _ = menu.append(&autostart_item);
    let _ = menu.append(&PredefinedMenuItem::separator());
    let _ = menu.append(&quit);

    let open_log_id = open_log.id().clone();
    let show_config_id = show_config.id().clone();
    let autostart_id = autostart_item.id().clone();
    let quit_id = quit.id().clone();

    let Some(idle_icon) = icon::render(false) else {
        alerts.critical(
            "goofedup-gui",
            "tray icon render failed at startup -- running watchers with no tray shell",
            "icon::render returned None",
            None,
        );
        run_watchers_headless(running);
        return;
    };

    let mut tray = match TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_icon(idle_icon)
        .with_tooltip("goofedup -- alert-only, nothing killed/deleted/blocked automatically")
        .build()
    {
        Ok(t) => Some(t),
        Err(e) => {
            alerts.critical(
                "goofedup-gui",
                "tray icon build failed at startup -- running watchers with no tray shell",
                e.to_string(),
                None,
            );
            run_watchers_headless(running);
            return;
        }
    };

    let menu_channel = MenuEvent::receiver();
    let running_for_loop = running.clone();

    event_loop.run(move |_event, _target, control_flow| {
        *control_flow = ControlFlow::WaitUntil(
            std::time::Instant::now() + std::time::Duration::from_millis(200),
        );

        if let Ok(event) = menu_channel.try_recv() {
            if event.id == open_log_id {
                history.clear_critical_flag();
                if let (Some(t), Some(icon)) = (tray.as_mut(), icon::render(false)) {
                    let _ = t.set_icon(Some(icon));
                }
                alert_window::show(&history.render_text());
            } else if event.id == show_config_id {
                alert_window::show(&render_config(&cfg));
            } else if event.id == autostart_id {
                if autostart::is_enabled() {
                    autostart::disable();
                } else {
                    autostart::enable();
                }
                autostart_item.set_text(autostart_label());
            } else if event.id == quit_id {
                running_for_loop.store(false, Ordering::Relaxed);
                tray.take();
                *control_flow = ControlFlow::Exit;
            }
        }

        if history.has_unacknowledged_critical() {
            if let (Some(t), Some(icon)) = (tray.as_mut(), icon::render(true)) {
                let _ = t.set_icon(Some(icon));
            }
        }
    });
}

fn run_watchers_headless(running: Arc<AtomicBool>) {
    while running.load(Ordering::Relaxed) {
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

fn autostart_label() -> String {
    if autostart::is_enabled() {
        "Disable Start with Windows".to_string()
    } else {
        "Start with Windows".to_string()
    }
}

fn render_config(cfg: &Config) -> String {
    let mut out = String::new();
    out.push_str(&format!("goofedup config for {}\n", std::env::consts::OS));
    out.push_str(&format!("log path: {}\n\n", cfg.log_path.display()));
    out.push_str("bootstrap watch:\n");
    for e in &cfg.bootstrap_watch {
        out.push_str(&format!(
            "  {} (must contain '{}') > {} bytes\n",
            e.search_root.join(e.file_name).display(),
            e.path_must_contain,
            e.max_bytes
        ));
    }
    out.push_str("\nbackup-sibling roots:\n");
    for r in &cfg.backup_sibling_roots {
        out.push_str(&format!("  {}\n", r.display()));
    }
    out.push_str(&format!("\nwatched interpreters: {}\n", cfg.watched_interpreters.join(", ")));
    out.push_str(&format!("\ndenied exec path fragments: {}\n", cfg.deny_exec_path_fragments.join(", ")));
    out.push_str("\nallowed exec roots:\n");
    for r in &cfg.allowed_exec_roots {
        out.push_str(&format!("  {}\n", r.display()));
    }
    out.push_str(&format!(
        "\nnetwork scan thresholds: {}+ distinct ports OR {}+ distinct hosts within {}s\n",
        cfg.scan_distinct_ports_threshold, cfg.scan_distinct_hosts_threshold, cfg.scan_window_secs
    ));
    out.push_str(&format!("poll interval: {}s\n", cfg.poll_interval_secs));
    out
}

fn spawn_watchers(cfg: Arc<Config>, alerts: Arc<AlertSink>, running: Arc<AtomicBool>) {
    alerts.info(
        "goofedup",
        format!(
            "starting on {} -- alert-only, nothing is killed/deleted/blocked automatically",
            std::env::consts::OS
        ),
    );

    {
        let cfg = cfg.clone();
        let alerts = alerts.clone();
        std::thread::spawn(move || watch_file::run(cfg, alerts));
    }
    {
        let cfg = cfg.clone();
        let alerts = alerts.clone();
        let running = running.clone();
        std::thread::spawn(move || watch_process::run(cfg, alerts, running));
    }
    {
        let cfg = cfg.clone();
        let alerts = alerts.clone();
        let running = running.clone();
        std::thread::spawn(move || watch_persistence::run(cfg, alerts, running));
    }
    {
        let cfg = cfg.clone();
        let alerts = alerts.clone();
        let running = running.clone();
        std::thread::spawn(move || watch_network::run(cfg, alerts, running));
    }
    {
        let cfg = cfg.clone();
        let alerts = alerts.clone();
        let running = running.clone();
        std::thread::spawn(move || watch_network::run_firewall_drift(cfg, alerts, running));
    }
}
