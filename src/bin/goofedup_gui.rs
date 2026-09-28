#![windows_subsystem = "windows"]

use goofedup::alert::{Alert, AlertSink, Level};
use goofedup::config::{dirs_home, override_path, ConfigOverrides, SharedConfig};
use goofedup::gui::icon::IconState;
use goofedup::gui::{alert_window, autostart, history::History, icon, single_instance, toast};
use goofedup::{
    config_reload, correlate, electron_sweep, scan_js, self_protect, watch_events, watch_file,
    watch_network, watch_persistence, watch_process, watch_repos, watch_tamper,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tray_icon::menu::{CheckMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{TrayIconBuilder, TrayIconEvent};

const PER_ALERT_IDENTITY_TOAST_COOLDOWN: Duration = Duration::from_secs(5 * 60);

fn toast_throttle_key(a: &Alert) -> String {
    let subject = a
        .message
        .strip_prefix('\'')
        .and_then(|rest| rest.find('\'').map(|end| rest[..end].to_string()))
        .unwrap_or_else(|| a.message.clone());
    format!("{}\u{1}{subject}", a.category)
}

fn should_pop_toast(last_toasted: &Mutex<HashMap<String, Instant>>, a: &Alert) -> bool {
    let key = toast_throttle_key(a);
    let mut map = last_toasted.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let now = Instant::now();
    let should_pop = match map.get(&key) {
        Some(last) => now.duration_since(*last) >= PER_ALERT_IDENTITY_TOAST_COOLDOWN,
        None => true,
    };
    if should_pop {
        map.insert(key, now);
    }
    should_pop
}

fn main() {
    let cli_args: Vec<String> = std::env::args().skip(1).collect();
    if let Some(exit_code) = goofedup::gui::hardened::run_cli(&cli_args) {
        std::process::exit(exit_code);
    }

    let Some(_instance_guard) = single_instance::acquire() else {
        return;
    };

    toast::init();
    goofedup::gui::shortcut::ensure_registered();

    let override_file = override_path(&dirs_home());
    let (initial_cfg, initial_overrides) = config_reload::load_config_with_overrides(&override_file);
    if let Some(parent) = initial_cfg.log_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let is_first_run = !initial_cfg.log_path.exists();

    let alerts = Arc::new(AlertSink::new(initial_cfg.log_path.clone()));
    let cfg: SharedConfig = Arc::new(RwLock::new(Arc::new(initial_cfg)));
    let overrides_shared: Arc<RwLock<ConfigOverrides>> = Arc::new(RwLock::new(initial_overrides));
    let history = Arc::new(History::new());
    let alerting_enabled = Arc::new(AtomicBool::new(true));

    let last_toasted: Arc<Mutex<HashMap<String, Instant>>> = Arc::new(Mutex::new(HashMap::new()));
    {
        let history = history.clone();
        let alerting_enabled = alerting_enabled.clone();
        let last_toasted = last_toasted.clone();
        alerts.add_on_alert(move |a| {
            if !alerting_enabled.load(Ordering::Relaxed) {
                return;
            }
            history.push(a);
            alert_window::notify_new_alert();
            if matches!(a.level, Level::Warn | Level::Critical) && should_pop_toast(&last_toasted, a) {
                toast::show(&format!("goofedup: {}", a.category), &a.message, open_history_request);
            }
        });
    }

    let hidden_unicode_scan_response = Arc::new(scan_js::AlertResponse::new());
    {
        let hidden_unicode_scan_response = hidden_unicode_scan_response.clone();
        let alerts_for_response = alerts.clone();
        alerts.add_on_alert(move |a| {
            hidden_unicode_scan_response.on_alert(a, &alerts_for_response);
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

    if is_first_run {
        let enabled = autostart::enable();
        alerts.info(
            "goofedup-gui",
            if enabled {
                "first run: enabled 'Start with Windows' automatically so the watcher can't silently go dark between sessions again -- toggle it off in the tray menu any time"
            } else {
                "first run: could not enable 'Start with Windows' automatically (registry write to HKCU Run failed) -- enable it manually from the tray menu"
            },
        );
    }

    let running = Arc::new(AtomicBool::new(true));
    spawn_watchers(
        cfg.clone(),
        overrides_shared.clone(),
        override_file,
        alerts.clone(),
        running.clone(),
    );

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
                open_alert_window(&alerts, "goofedup -- Recent Alerts", &history);
            }
        }

        if OPEN_HISTORY_REQUESTED.swap(false, Ordering::Relaxed) {
            history.clear_critical_flag();
            open_alert_window(&alerts, "goofedup -- Recent Alerts", &history);
        }

        if let Ok(event) = menu_channel.try_recv() {
            if event.id == open_log_id {
                history.clear_critical_flag();
                open_alert_window(&alerts, "goofedup -- Recent Alerts", &history);
            } else if event.id == show_config_id {
                open_config_window(&alerts, "goofedup -- Config", &cfg, &overrides_shared);
            } else if event.id == pause_id {
                let now_paused = pause_item.is_checked();
                alerting_enabled.store(!now_paused, Ordering::Relaxed);
                alerts.info(
                    "goofedup-gui",
                    if now_paused { "alerting paused by user" } else { "alerting resumed by user" },
                );
            } else if event.id == autostart_id {
                let ok = if autostart_item.is_checked() {
                    autostart::enable()
                } else {
                    autostart::disable()
                };
                if !ok {
                    autostart_item.set_checked(autostart::is_enabled());
                    alerts.critical(
                        "goofedup-gui",
                        "could not update Start with Windows -- the Run key write or the hardened scheduled task change failed (changing the hardened task needs an elevated run)",
                        format!("requested checked={}", autostart_item.is_checked()),
                    );
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

fn open_alert_window(alerts: &AlertSink, title: &str, history: &Arc<History>) {
    if let Err(reason) = alert_window::show_alerts(title, Arc::clone(history)) {
        alerts.critical(
            "goofedup-gui",
            "could not open the alert viewer",
            reason,
        );
    }
}

fn open_config_window(alerts: &AlertSink, title: &str, cfg: &SharedConfig, overrides: &Arc<RwLock<ConfigOverrides>>) {
    let cfg_snapshot = cfg.read().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
    let overrides_snapshot = overrides.read().unwrap_or_else(std::sync::PoisonError::into_inner);
    let sections = goofedup::config::config_sections(&cfg_snapshot, &overrides_snapshot);
    if let Err(reason) = alert_window::show_config(title, &sections) {
        alerts.critical(
            "goofedup-gui",
            "could not open the config viewer",
            reason,
        );
    }
}

fn run_watchers_headless(running: Arc<AtomicBool>) {
    while running.load(Ordering::Relaxed) {
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

fn spawn_watchers(
    cfg: SharedConfig,
    overrides_shared: Arc<RwLock<ConfigOverrides>>,
    override_file: std::path::PathBuf,
    alerts: Arc<AlertSink>,
    running: Arc<AtomicBool>,
) {
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
    {
        let cfg = cfg.clone();
        let alerts = alerts.clone();
        let running = running.clone();
        std::thread::spawn(move || watch_tamper::run(cfg, alerts, running));
    }
    {
        let cfg = cfg.clone();
        let alerts = alerts.clone();
        let running = running.clone();
        let override_file = override_file.clone();
        std::thread::spawn(move || config_reload::run(cfg, overrides_shared, override_file, alerts, running));
    }
    {
        let cfg = cfg.clone();
        let alerts = alerts.clone();
        let running = running.clone();
        std::thread::spawn(move || electron_sweep::run(cfg, alerts, running));
    }
    {
        let roots = cfg.read().unwrap_or_else(std::sync::PoisonError::into_inner).repo_watch_roots.clone();
        let alerts = alerts.clone();
        let running = running.clone();
        std::thread::spawn(move || watch_repos::run(roots, alerts, running));
    }
    {
        let cfg = cfg.clone();
        let alerts = alerts.clone();
        let running = running.clone();
        std::thread::spawn(move || watch_events::run(cfg, alerts, running));
    }
    {
        let cfg = cfg.clone();
        let alerts = alerts.clone();
        let running = running.clone();
        std::thread::spawn(move || self_protect::run(cfg, alerts, running, override_file));
    }
}
