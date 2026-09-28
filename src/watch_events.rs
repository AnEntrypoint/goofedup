use crate::alert::AlertSink;
use crate::config::SharedConfig;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

#[cfg(not(windows))]
pub fn run(_cfg: SharedConfig, _alerts: Arc<AlertSink>, _running: Arc<AtomicBool>) {}

#[cfg(windows)]
pub fn run(cfg: SharedConfig, alerts: Arc<AlertSink>, running: Arc<AtomicBool>) {
    windows_impl::run(cfg, alerts, running)
}

#[cfg(windows)]
mod windows_impl {
    use crate::alert::{Alert, AlertSink};
    use crate::config::{dirs_home, SharedConfig};
    use crate::event_rules::{self, ChannelSpec, Finding, RuleContext, CHANNELS};
    use regex::Regex;
    use std::collections::HashMap;
    use std::ffi::c_void;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
    use std::time::{Duration, Instant};
    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::EventLog::{
        EvtClose, EvtCreateBookmark, EvtNext, EvtQuery, EvtQueryChannelPath,
        EvtQueryReverseDirection, EvtRender, EvtRenderBookmark, EvtRenderEventXml,
        EvtSubscribe, EvtSubscribeActionDeliver, EvtSubscribeStartAfterBookmark,
        EvtSubscribeStartAtOldestRecord, EvtUpdateBookmark, EVT_HANDLE,
        EVT_SUBSCRIBE_NOTIFY_ACTION,
    };

    const LOOP_INTERVAL: Duration = Duration::from_secs(1);
    const RESUBSCRIBE_BACKOFF: Duration = Duration::from_secs(30);
    const ERROR_ACCESS_DENIED: u32 = 5;
    const ERROR_EVT_CHANNEL_NOT_FOUND: u32 = 15007;

    enum SubscribeFailure {
        AccessDenied,
        ChannelAbsent,
        Other(String),
    }

    fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
        m.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn win32_code(e: &windows::core::Error) -> u32 {
        (e.code().0 as u32) & 0xFFFF
    }

    struct ChannelState {
        spec: &'static ChannelSpec,
        cfg: SharedConfig,
        bookmark: Mutex<EVT_HANDLE>,
        pending: Mutex<Vec<Finding>>,
        broken_with: AtomicU32,
        bookmark_dirty: AtomicBool,
    }

    unsafe fn render(flags: u32, source: EVT_HANDLE) -> Option<String> {
        let mut used = 0u32;
        let mut properties = 0u32;
        let _ = EvtRender(EVT_HANDLE(0), source, flags, 0, None, &mut used, &mut properties);
        let mut buffer = vec![0u16; used as usize / 2 + 1];
        EvtRender(
            EVT_HANDLE(0),
            source,
            flags,
            (buffer.len() * 2) as u32,
            Some(buffer.as_mut_ptr() as *mut c_void),
            &mut used,
            &mut properties,
        )
        .ok()?;
        let text = String::from_utf16_lossy(&buffer[..(used as usize / 2)]);
        Some(text.trim_end_matches('\0').to_string())
    }

    unsafe extern "system" fn on_event(
        action: EVT_SUBSCRIBE_NOTIFY_ACTION,
        context: *const c_void,
        event: EVT_HANDLE,
    ) -> u32 {
        let state = &*(context as *const ChannelState);
        if action != EvtSubscribeActionDeliver {
            state.broken_with.store(event.0 as u32, Ordering::Relaxed);
            return 0;
        }
        if let Some(xml) = render(EvtRenderEventXml.0, event) {
            if let Some(record) = event_rules::parse_event(&xml, state.spec.channel) {
                let cfg = state.cfg.read().unwrap_or_else(PoisonError::into_inner).clone();
                let ctx = RuleContext {
                    vendor_roots: &cfg.os_vendor_roots,
                    known_benign_sources: &cfg.known_benign_event_sources,
                };
                if let Some(finding) = event_rules::classify(&record, &ctx) {
                    lock(&state.pending).push(finding);
                }
            }
        }
        let _ = EvtUpdateBookmark(*lock(&state.bookmark), event);
        state.bookmark_dirty.store(true, Ordering::Relaxed);
        0
    }

    fn subscription_query(spec: &ChannelSpec, first_run: bool) -> String {
        let ids = spec.event_ids.iter().map(|id| format!("EventID={id}")).collect::<Vec<_>>().join(" or ");
        if first_run {
            let lookback_ms = spec.first_run_lookback_hours * 60 * 60 * 1000;
            format!("*[System[({ids}) and TimeCreated[timediff(@SystemTime)<={lookback_ms}]]]")
        } else {
            format!("*[System[({ids})]]")
        }
    }

    fn subscribe(state: &'static ChannelState, saved_bookmark_xml: Option<&str>) -> Result<EVT_HANDLE, SubscribeFailure> {
        unsafe {
            let from_saved = |xml: Option<&str>| xml.and_then(|x| EvtCreateBookmark(&HSTRING::from(x)).ok());
            let resumed = from_saved(saved_bookmark_xml);
            let (bookmark_for_subscribe, flags, query) = match resumed {
                Some(handle) => (handle, EvtSubscribeStartAfterBookmark.0, subscription_query(state.spec, false)),
                None => (EVT_HANDLE(0), EvtSubscribeStartAtOldestRecord.0, subscription_query(state.spec, true)),
            };
            let tracking = from_saved(saved_bookmark_xml)
                .or_else(|| EvtCreateBookmark(PCWSTR::null()).ok())
                .unwrap_or(EVT_HANDLE(0));
            let previous_tracking = std::mem::replace(&mut *lock(&state.bookmark), tracking);
            if previous_tracking.0 != 0 {
                let _ = EvtClose(previous_tracking);
            }
            let subscription = EvtSubscribe(
                EVT_HANDLE(0),
                HANDLE::default(),
                &HSTRING::from(state.spec.channel),
                &HSTRING::from(query),
                bookmark_for_subscribe,
                Some(state as *const ChannelState as *const c_void),
                Some(on_event),
                flags,
            );
            if resumed.is_some() {
                let _ = EvtClose(bookmark_for_subscribe);
            }
            subscription.map_err(|e| match win32_code(&e) {
                ERROR_ACCESS_DENIED => SubscribeFailure::AccessDenied,
                ERROR_EVT_CHANNEL_NOT_FOUND => SubscribeFailure::ChannelAbsent,
                code => SubscribeFailure::Other(format!("EvtSubscribe error {code}")),
            })
        }
    }

    fn newest_record_id(channel: &str) -> Option<u64> {
        static RECORD: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        unsafe {
            let results = EvtQuery(
                EVT_HANDLE(0),
                &HSTRING::from(channel),
                &HSTRING::from("*"),
                EvtQueryChannelPath.0 | EvtQueryReverseDirection.0,
            )
            .ok()?;
            let mut handles = [0isize; 1];
            let mut returned = 0u32;
            let started = Instant::now();
            let mut newest = None;
            while started.elapsed() < Duration::from_secs(10) {
                match EvtNext(results, &mut handles, 1000, 0, &mut returned) {
                    Ok(()) if returned == 1 => {
                        let xml = render(EvtRenderEventXml.0, EVT_HANDLE(handles[0]));
                        let _ = EvtClose(EVT_HANDLE(handles[0]));
                        let pattern = RECORD.get_or_init(|| Regex::new(r"<EventRecordID>(\d+)</EventRecordID>").expect("static regex"));
                        newest = xml.and_then(|x| pattern.captures(&x).and_then(|c| c[1].parse().ok()));
                        break;
                    }
                    Err(e) if win32_code(&e) == 1460 => continue,
                    _ => break,
                }
            }
            let _ = EvtClose(results);
            newest
        }
    }

    fn bookmark_record_id(bookmark_xml: &str) -> Option<u64> {
        static RECORD: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        let pattern = RECORD.get_or_init(|| Regex::new(r#"RecordId=['"](\d+)['"]"#).expect("static regex"));
        pattern.captures(bookmark_xml).and_then(|c| c[1].parse().ok())
    }

    struct SavedBookmarks {
        path: PathBuf,
        xml_by_channel: HashMap<String, String>,
    }

    impl SavedBookmarks {
        fn load() -> Self {
            let path = dirs_home().join(".goofedup").join("events.bookmarks.json");
            let xml_by_channel = std::fs::read_to_string(&path)
                .ok()
                .and_then(|text| serde_json::from_str(&text).ok())
                .unwrap_or_default();
            Self { path, xml_by_channel }
        }

        fn save(&self) {
            let Ok(text) = serde_json::to_string_pretty(&self.xml_by_channel) else { return };
            let staging = self.path.with_extension("json.tmp");
            if std::fs::write(&staging, text).is_ok() {
                let _ = std::fs::rename(&staging, &self.path);
            }
        }
    }

    struct Visibility {
        watching: Vec<&'static str>,
        denied: Vec<&'static str>,
        absent: Vec<&'static str>,
    }

    fn report_visibility(alerts: &AlertSink, v: &Visibility) {
        let absent_note = if v.absent.is_empty() { String::new() } else { format!(" -- not present on this machine: {}", v.absent.join(", ")) };
        if v.denied.is_empty() {
            alerts.info(
                "event-visibility",
                format!("watching {} Windows event log(s): {}{absent_note}", v.watching.len(), v.watching.join(", ")),
            );
            return;
        }
        alerts.info(
            "event-visibility",
            format!(
                "limited visibility -- cannot read event log(s): {} (access denied; run elevated to include them). Watching: {}{absent_note}",
                v.denied.join(", "),
                if v.watching.is_empty() { "none".to_string() } else { v.watching.join(", ") },
            ),
        );
    }

    fn emit_batch(alerts: &AlertSink, findings: Vec<Finding>) {
        for f in event_rules::coalesce_batch(findings) {
            alerts.emit(Alert { level: f.level, category: f.category, message: f.message, evidence: Some(f.evidence) });
        }
    }

    pub fn run(cfg: SharedConfig, alerts: Arc<AlertSink>, running: Arc<AtomicBool>) {
        let mut saved = SavedBookmarks::load();
        let mut visibility = Visibility { watching: Vec::new(), denied: Vec::new(), absent: Vec::new() };
        let mut states: Vec<&'static ChannelState> = Vec::new();
        let mut subscriptions: Vec<EVT_HANDLE> = Vec::new();

        for spec in CHANNELS.iter() {
            let state: &'static ChannelState = Box::leak(Box::new(ChannelState {
                spec,
                cfg: cfg.clone(),
                bookmark: Mutex::new(EVT_HANDLE(0)),
                pending: Mutex::new(Vec::new()),
                broken_with: AtomicU32::new(0),
                bookmark_dirty: AtomicBool::new(false),
            }));
            let mut resume_from = saved.xml_by_channel.get(spec.channel).cloned();
            if let (Some(xml), Some(newest)) = (&resume_from, newest_record_id(spec.channel)) {
                if bookmark_record_id(xml).is_some_and(|last| newest < last) {
                    alerts.warn(
                        "log-cleared",
                        format!("record ids went backwards in {} -- the log was cleared or reset while goofedup was not watching", spec.channel),
                        format!("last_seen_record={} newest_record_now={newest}", bookmark_record_id(xml).unwrap_or(0)),
                    );
                    resume_from = None;
                }
            }
            match subscribe(state, resume_from.as_deref()) {
                Ok(handle) => {
                    visibility.watching.push(spec.channel);
                    subscriptions.push(handle);
                    states.push(state);
                }
                Err(SubscribeFailure::AccessDenied) => visibility.denied.push(spec.channel),
                Err(SubscribeFailure::ChannelAbsent) => visibility.absent.push(spec.channel),
                Err(SubscribeFailure::Other(reason)) => {
                    alerts.warn("event-visibility", format!("could not subscribe to {}", spec.channel), reason);
                }
            }
        }
        report_visibility(&alerts, &visibility);

        let mut last_resubscribe = Instant::now();
        while running.load(Ordering::Relaxed) {
            std::thread::sleep(LOOP_INTERVAL);
            let mut any_bookmark_dirty = false;
            for state in &states {
                let findings = std::mem::take(&mut *lock(&state.pending));
                emit_batch(&alerts, findings);
                if state.bookmark_dirty.swap(false, Ordering::Relaxed) {
                    let handle = *lock(&state.bookmark);
                    if let Some(xml) = unsafe { render(EvtRenderBookmark.0, handle) } {
                        saved.xml_by_channel.insert(state.spec.channel.to_string(), xml);
                        any_bookmark_dirty = true;
                    }
                }
            }
            if any_bookmark_dirty {
                saved.save();
            }
            resubscribe_broken(&states, &mut subscriptions, &saved, &alerts, &mut last_resubscribe);
        }
        unsafe {
            for handle in subscriptions {
                let _ = EvtClose(handle);
            }
        }
    }

    fn resubscribe_broken(
        states: &[&'static ChannelState],
        subscriptions: &mut [EVT_HANDLE],
        saved: &SavedBookmarks,
        alerts: &AlertSink,
        last_attempt: &mut Instant,
    ) {
        if last_attempt.elapsed() < RESUBSCRIBE_BACKOFF {
            return;
        }
        for (index, state) in states.iter().enumerate() {
            let code = state.broken_with.swap(0, Ordering::Relaxed);
            if code == 0 {
                continue;
            }
            *last_attempt = Instant::now();
            alerts.warn(
                "event-visibility",
                format!("event log subscription to {} broke (error {code}) -- resubscribing from its bookmark", state.spec.channel),
                "events written while the subscription was down are replayed from the bookmark",
            );
            unsafe {
                let _ = EvtClose(subscriptions[index]);
            }
            match subscribe(state, saved.xml_by_channel.get(state.spec.channel).map(String::as_str)) {
                Ok(handle) => subscriptions[index] = handle,
                Err(_) => state.broken_with.store(code, Ordering::Relaxed),
            }
        }
    }
}
