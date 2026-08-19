#![windows_subsystem = "windows"]

// Windows system-tray GUI for goofedup: runs the same watcher threads as
// the CLI, but replaces console/log-only output with a tray icon that goes
// red on an unacknowledged Critical alert plus a native toast per Warn/
// Critical event, so "we done goofed" reaches the user without a terminal
// window open.

use goofedup::alert::{AlertSink, Level};
use goofedup::config::Config;
use goofedup::gui::icon::IconState;
use goofedup::gui::{alert_window, autostart, history::History, icon, single_instance, toast};
use goofedup::{watch_file, watch_network, watch_persistence, watch_process};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tray_icon::menu::{CheckMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{TrayIconBuilder, TrayIconEvent};

fn main() {
    let Some(_instance_guard) = single_instance::acquire() else {
        return;
    };

    toast::init();

    let cfg = Arc::new(Config::default_for_platform());
    if let Some(parent) = cfg.log_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let is_first_run = !cfg.log_path.exists();

    let alerts = Arc::new(AlertSink::new(cfg.log_path.clone()));
    let history = Arc::new(History::new());
    let alerting_enabled = Arc::new(AtomicBool::new(true));

    {
        let history = history.clone();
        let alerting_enabled = alerting_enabled.clone();
        alerts.set_on_alert(move |a| {
            if !alerting_enabled.load(Ordering::Relaxed) {
                return;
            }
            history.push(a);
            if matches!(a.level, Level::Warn | Level::Critical) {
                toast::show(&format!("goofedup: {}", a.category), &a.message, open_history_request);
            }
        });
    }

    let running = Arc::new(AtomicBool::new(true));
    spawn_watchers(cfg.clone(), alerts.clone(), running.clone());

    if is_first_run {
        toast::show(
            "Welcome to goofedup",
            "Now watching for structural anomalies -- alert-only, nothing is ever killed, deleted, or blocked automatically. Right-click the tray icon any time to see recent alerts or settings.",
            || {},
        );
    }

    let event_loop = EventLoopBuilder::new().build();

    let open_log = MenuItem::new("Open Recent Alerts", true, None);
    let show_config = MenuItem::new("Show Config", true, None);
    let pause_item = CheckMenuItem::new("Pause Alerts", true, false, None);
    let autostart_item = CheckMenuItem::new("Start with Windows", true, autostart::is_enabled(), None);
    let quit = MenuItem::new("Quit", true, None);

    let menu = Menu::new();
    let _ = menu.append(&open_log);
    let _ = menu.append(&show_config);
    let _ = menu.append(&PredefinedMenuItem::separator());
    let _ = menu.append(&pause_item);
    let _ = menu.append(&autostart_item);
    let _ = menu.append(&PredefinedMenuItem::separator());
    let _ = menu.append(&quit);

    let open_log_id = open_log.id().clone();
    let show_config_id = show_config.id().clone();
    let pause_id = pause_item.id().clone();
    let autostart_id = autostart_item.id().clone();
    let quit_id = quit.id().clone();

    let idle_icon = icon::render(IconState::Idle);
    let Some(idle_icon) = idle_icon else {
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
        .with_tooltip(tooltip_text(&history, false))
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
    let tray_channel = TrayIconEvent::receiver();
    let running_for_loop = running.clone();
    let mut last_icon_state = IconStateKey::Idle;

    event_loop.run(move |_event, _target, control_flow| {
        *control_flow = ControlFlow::WaitUntil(
            std::time::Instant::now() + std::time::Duration::from_millis(200),
        );

        if let Ok(event) = tray_channel.try_recv() {
            if matches!(event, TrayIconEvent::DoubleClick { .. }) {
                history.clear_critical_flag();
                alert_window::show(&history.render_text());
            }
        }

        if OPEN_HISTORY_REQUESTED.swap(false, Ordering::Relaxed) {
            history.clear_critical_flag();
            alert_window::show(&history.render_text());
        }

        if let Ok(event) = menu_channel.try_recv() {
            if event.id == open_log_id {
                history.clear_critical_flag();
                alert_window::show(&history.render_text());
            } else if event.id == show_config_id {
                alert_window::show(&render_config(&cfg));
            } else if event.id == pause_id {
                let now_paused = pause_item.is_checked();
                alerting_enabled.store(!now_paused, Ordering::Relaxed);
                alerts.info(
                    "goofedup-gui",
                    if now_paused { "alerting paused by user" } else { "alerting resumed by user" },
                );
            } else if event.id == autostart_id {
                if autostart_item.is_checked() {
                    autostart::enable();
                } else {
                    autostart::disable();
                }
            } else if event.id == quit_id {
                running_for_loop.store(false, Ordering::Relaxed);
                tray.take();
                *control_flow = ControlFlow::Exit;
            }
        }

        let paused = !alerting_enabled.load(Ordering::Relaxed);
        let desired = if paused {
            IconStateKey::Paused
        } else if history.has_unacknowledged_critical() {
            IconStateKey::Critical
        } else {
            IconStateKey::Idle
        };
        if desired != last_icon_state {
            if let (Some(t), Some(icon)) = (tray.as_mut(), icon::render(desired.to_state())) {
                let _ = t.set_icon(Some(icon));
            }
            last_icon_state = desired;
        }
        if let Some(t) = tray.as_mut() {
            let _ = t.set_tooltip(Some(tooltip_text(&history, paused)));
        }
    });
}

#[derive(PartialEq, Clone, Copy)]
enum IconStateKey {
    Idle,
    Paused,
    Critical,
}

impl IconStateKey {
    fn to_state(self) -> IconState {
        match self {
            IconStateKey::Idle => IconState::Idle,
            IconStateKey::Paused => IconState::Paused,
            IconStateKey::Critical => IconState::Critical,
        }
    }
}

/// A toast's Activated handler runs on a WinRT callback thread, not the
/// event loop -- it cannot touch tray/menu state directly, so it just
/// flags the request and the event loop's own poll picks it up next tick.
static OPEN_HISTORY_REQUESTED: AtomicBool = AtomicBool::new(false);

fn open_history_request() {
    OPEN_HISTORY_REQUESTED.store(true, Ordering::Relaxed);
}

fn tooltip_text(history: &History, paused: bool) -> String {
    if paused {
        return "goofedup -- PAUSED (right-click to resume)".to_string();
    }
    let (critical, warn) = history.counts_today();
    if critical > 0 {
        format!("goofedup -- {critical} critical alert(s) need attention")
    } else if warn > 0 {
        format!("goofedup -- watching, {warn} warning(s) today")
    } else {
        "goofedup -- watching, all clear".to_string()
    }
}

fn run_watchers_headless(running: Arc<AtomicBool>) {
    while running.load(Ordering::Relaxed) {
        std::thread::sleep(std::time::Duration::from_millis(200));
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
