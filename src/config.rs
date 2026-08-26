// Central tunables. Every detector reads from here so the whole posture can
// be adjusted without hunting through module internals.
//
// Config itself stays a plain, always-fully-populated struct built by
// default_for_platform() -- the platform/env-var detection logic below is
// the one thing a config file must never have to reimplement. Runtime
// tuning layers OVER this via ConfigOverrides (see below): an all-Option
// struct deserialized from ~/.goofedup/goofedup.config.json and merged on
// top, so a hand-edited file only needs to name the fields it actually wants
// to change. SharedConfig is the hot-reloadable handle every consumer holds;
// see config_reload.rs for the load/merge/reload-loop machinery built on
// top of the types defined here.

use serde::Deserialize;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

pub struct Config {
    /// Known-tiny bootstrap/loader files that must never grow past a sane
    /// ceiling. Born from the real incident: Discord's own
    /// discord_desktop_core/index.js should be ~40 bytes
    /// ("module.exports = require('./core.asar')") and was overwritten with
    /// a 270KB obfuscated payload.
    pub bootstrap_watch: Vec<BootstrapEntry>,

    /// Directories to watch for a *.orig/*.bak/*.inz/*.original sibling
    /// appearing next to a real file -- the infector's own backup, since it
    /// has to preserve the original somewhere to keep the host app from
    /// visibly breaking.
    pub backup_sibling_roots: Vec<PathBuf>,

    /// Process names worth inspecting the command line of when they spawn.
    pub watched_interpreters: Vec<String>,

    /// Path fragments that are an instant flag for ANY executing process,
    /// regardless of name -- nothing legitimate runs from these. The
    /// Recycle Bin holding ~21,000 stray Go/JS files in the real incident is
    /// exactly this shape.
    pub deny_exec_path_fragments: Vec<String>,

    /// Root directories process images are allowed to execute from without
    /// triggering the "unusual path" flag. Anything outside all of these
    /// (and not caught by the deny list above) is flagged WARN, not
    /// CRITICAL -- an allowlist gap is common and noisy, not proof of
    /// compromise.
    pub allowed_exec_roots: Vec<PathBuf>,

    /// Network scan detection: a process opening connections to more than
    /// this many DISTINCT destination ports OR DISTINCT destination hosts
    /// within the rolling window is flagged as scanning behavior.
    pub scan_distinct_ports_threshold: usize,
    pub scan_distinct_hosts_threshold: usize,
    pub scan_window_secs: u64,

    /// Mass file-read (drive scanning / harvesting) detection, via
    /// sysinfo's per-process cumulative disk_usage() -- no elevation
    /// required, works identically on all three platforms. Two independent
    /// triggers, either one alerts: an ABSOLUTE burst (this many bytes read
    /// in one poll interval, regardless of history -- catches a fast
    /// scanner even on its very first observation) and a RELATIVE spike
    /// (this many times the process's own recent average read rate --
    /// catches a normally-quiet process suddenly scanning, even if the
    /// absolute rate is modest for the system as a whole).
    pub file_read_burst_absolute_bytes_per_poll: u64,
    pub file_read_burst_relative_multiplier: f64,

    /// A read this large fires CRITICAL regardless of exe path/name trust --
    /// no dev tool observed on real hardware has ever legitimately needed
    /// this much in one poll. Exists because path/name-based trust answers
    /// "is this a legitimate BINARY," never "is this the actor actually
    /// running it" (the same principle already applied to c2-shaped-process
    /// severity) -- a compromise of an otherwise-trusted process could still
    /// use it to exfiltrate at effectively unbounded volume, so trust must
    /// have a ceiling it cannot buy past. Calibrated above the highest
    /// legitimate burst live-witnessed on real dev-workstation hardware
    /// (claude.exe and powershell.exe both hit 1.2-1.7GB/poll during normal
    /// heavy operation -- a full codebase read, a large build).
    pub file_read_burst_uncorroborated_ceiling_bytes: u64,

    /// Process names (case-insensitive, matched against sysinfo's reported
    /// process name) that are KNOWN to legitimately sustain high burst reads
    /// as their normal operating shape -- sync/backup/indexer tools and
    /// browsers/Electron apps, per the README's own "Known false-positive
    /// classes" section. A name match raises this process's effective
    /// threshold on BOTH burst paths by `known_high_throughput_tool_
    /// multiplier` -- the absolute floor AND the relative-spike multiplier
    /// against its own baseline -- it does NOT exempt the process from
    /// detection entirely: a name is not the same as the actor running
    /// under it, so a genuinely extreme read still alerts.
    pub known_high_throughput_tool_names: Vec<String>,
    pub known_high_throughput_tool_multiplier: f64,

    /// Root directories that only an OS installer or an administrator/root
    /// can write to (`C:\Windows`, `C:\Program Files*` on Windows; `/usr`,
    /// `/System`, `/Applications` on macOS; `/usr`, `/opt`, `/bin`, `/sbin`
    /// on Linux) -- a fundamentally different trust basis than
    /// `known_high_throughput_tool_names` above: that list says "this NAME
    /// is known to burst," which only ever covers tools already seen and
    /// degrades into a whitelist-of-the-week; this says "a binary an
    /// attacker cannot silently drop a file into is not a plausible drive-
    /// harvester," which covers any legitimate vendor/system tool doing
    /// bulk I/O as its normal job (an archiver unpacking a large tree, an
    /// IDE indexing a workspace, a COM surrogate doing thumbnail/search
    /// work) without needing its name enumerated first. Live-witnessed
    /// false positives of exactly this shape and nothing else in common:
    /// `tar.exe` (C:\Program Files\Git\usr\bin), `Code.exe` (C:\Program
    /// Files\Microsoft VS Code), `dllhost.exe` (C:\Windows\System32) --
    /// three unrelated binaries whose only shared property is running from
    /// a location a real attacker's dropped payload never occupies (writing
    /// there requires the elevation a compromise doesn't grant for free).
    /// Applied identically to both burst paths via the same
    /// `known_high_throughput_tool_multiplier`, not a separate exemption --
    /// a genuinely extreme read from a vendor-root binary still alerts.
    pub os_vendor_roots: Vec<PathBuf>,

    /// Parent-process names (case-insensitive) known to legitimately spawn
    /// interpreters with obfuscated-looking command lines as their normal
    /// operating shape -- AI-assistant/automation harnesses that pass
    /// scripts via -EncodedCommand to sidestep shell-escaping, per the
    /// README's own "Known false-positive classes" section (the exact shape
    /// a real attacker's living-off-the-land technique uses too). A match
    /// does NOT change severity or suppress the alert -- c2-shaped-process
    /// always fires CRITICAL regardless of parent, since a genuinely
    /// malicious payload could run under a parent name that happens to
    /// match this list too (live-confirmed: a real Discord-bootstrap-hijack
    /// C2 loader fired under parent=recognized-dev-tool-ancestor on its
    /// first hit). A match is noted in the evidence text as triage context
    /// only.
    pub known_automation_parent_names: Vec<String>,

    /// How often to re-poll process list / connection table / firewall
    /// state (seconds). Real event sources are used where the platform
    /// offers them (notify for fs, WMI/ETW on Windows); this interval only
    /// governs the polling fallbacks (process/connection enumeration has no
    /// portable cross-OS push API without extra native deps per platform).
    pub poll_interval_secs: u64,

    pub log_path: PathBuf,

    // -- Promoted from inline `const`s so they become config-tunable too.
    // Defaults below are bit-for-bit identical to the constants they
    // replaced; their calibration-history doc comments moved here with
    // them rather than being duplicated or dropped.
    /// How many of the last N polls (a fixed-size sliding window, not
    /// strict back-to-back consecutiveness) must score as a spike before
    /// file-read-burst actually alerts. A real drive-scanning/harvesting
    /// process sustains elevated reads across a short window; a legitimate
    /// app's burst (a page load, a cache write, an update check) is
    /// characteristically one-shot. Live-witnessed false positives
    /// (firefox.exe, Discord.exe) were both single-poll spikes; requiring
    /// persistence within a window eliminates that shape. A STRICT
    /// back-to-back-with-no-gap requirement was tried first and
    /// live-witnessed to fail: a real process whose own read rounds are
    /// separated by even one intervening near-zero-delta poll (a genuinely
    /// common shape -- disk I/O is bursty, not perfectly uniform, even for
    /// a real scanner) never accumulates past 1 under strict
    /// consecutiveness, since a single zero-delta poll resets the count to
    /// 0 and erases all prior progress. A sliding window tolerates that gap
    /// while still requiring genuine persistence, not one sample.
    pub read_burst_window_size: usize,
    /// See `read_burst_window_size`'s doc comment for the windowed-
    /// persistence rationale -- this is the count of spikes-in-window
    /// required before it counts as sustained rather than one-shot.
    pub read_burst_required_spikes_in_window: usize,
    /// A read-burst also flagged by the existing process-path checks
    /// (denied or unlisted exec path -- reused, not reinvented) is far
    /// stronger evidence than volume alone, so it clears the absolute floor
    /// at this fraction of the normal bar. This is the volume-alone
    /// false-positive class's actual fix: 223 CRITICALs in one operating
    /// log, all from well-located, ordinarily-installed dev tools with no
    /// other red flag -- corroboration lets a genuinely suspicious
    /// combination (unusual location AND a large read) still alert well
    /// below the raised floor, while volume by itself must clear the much
    /// higher bar.
    pub read_burst_corroborated_threshold_fraction: f64,
    /// Live-witnessed: a process whose own baseline is already substantial
    /// (python.exe reading 60MB against a 13-24MB/poll established average)
    /// is not anomalous relative to ITSELF just because the raw byte count
    /// clears the absolute floor -- the absolute check exists to catch a
    /// scanner even on its very first observation (no baseline yet), not to
    /// re-flag a consistently high-throughput process on every poll near
    /// its own normal level. A read within this multiple of the process's
    /// own established baseline is excluded from the absolute-burst check
    /// even if it clears the raw threshold.
    pub read_burst_baseline_exemption_multiplier: f64,
    /// A live-witnessed false-positive source: a low EMA baseline built up
    /// during a genuinely quiet stretch (an idle browser tab) makes any
    /// ordinary burst of real activity look like a huge relative spike.
    /// This floor requires the baseline itself to already reflect a
    /// meaningful amount of steady-state activity (in bytes/poll) before
    /// the relative check even engages, not just "greater than noise."
    pub read_burst_baseline_warm_up_floor_bytes: f64,
    /// EMA smoothing factor for the read-rate baseline -- low enough that
    /// one legitimate burst (a real build, a real backup job starting)
    /// doesn't permanently poison the baseline as "normal," but the
    /// baseline still adapts over a handful of polls to genuine sustained
    /// changes in a process's normal operating level.
    pub read_burst_ema_alpha: f64,
    /// Bound on how many nested `-EncodedCommand`/`$EncodedCommand = '...'`
    /// layers the C2-shape decoder will unwrap before giving up -- exists so
    /// a pathological or adversarial input can't force unbounded recursion,
    /// not because any real legitimate or malicious sample observed so far
    /// has needed more than a couple of layers.
    pub c2_max_decode_depth: u32,
}

pub struct BootstrapEntry {
    pub search_root: PathBuf,
    pub file_name: String,
    pub path_must_contain: String,
    pub max_bytes: u64,
}

/// All-`Option<T>` mirror of `Config`, deserialized from
/// `~/.goofedup/goofedup.config.json` if present. `None` means "not
/// overridden, use the platform-computed default from
/// `Config::default_for_platform()`" -- a config file is a set of
/// deviations from the computed baseline, never a full replacement, so
/// `default_for_platform()`'s env-var/platform-detection logic never needs
/// reimplementing in JSON. A `Vec<T>` override REPLACES the default list
/// wholesale, it does not append -- simplest semantics, and matches "this
/// list is wrong, here's my list" rather than an ambiguous merge rule.
///
/// `deny_unknown_fields` is deliberately NOT set: an older binary reading a
/// newer config file (or vice versa) should ignore fields it doesn't
/// recognize, not fail to start.
#[derive(Deserialize, Default)]
#[serde(default)]
pub struct ConfigOverrides {
    pub bootstrap_watch: Option<Vec<BootstrapEntryOverride>>,
    pub backup_sibling_roots: Option<Vec<PathBuf>>,
    pub watched_interpreters: Option<Vec<String>>,
    pub deny_exec_path_fragments: Option<Vec<String>>,
    pub allowed_exec_roots: Option<Vec<PathBuf>>,
    pub scan_distinct_ports_threshold: Option<usize>,
    pub scan_distinct_hosts_threshold: Option<usize>,
    pub scan_window_secs: Option<u64>,
    pub file_read_burst_absolute_bytes_per_poll: Option<u64>,
    pub file_read_burst_relative_multiplier: Option<f64>,
    pub file_read_burst_uncorroborated_ceiling_bytes: Option<u64>,
    pub known_high_throughput_tool_names: Option<Vec<String>>,
    pub known_high_throughput_tool_multiplier: Option<f64>,
    pub os_vendor_roots: Option<Vec<PathBuf>>,
    pub known_automation_parent_names: Option<Vec<String>>,
    pub poll_interval_secs: Option<u64>,
    pub log_path: Option<PathBuf>,
    pub read_burst_window_size: Option<usize>,
    pub read_burst_required_spikes_in_window: Option<usize>,
    pub read_burst_corroborated_threshold_fraction: Option<f64>,
    pub read_burst_baseline_exemption_multiplier: Option<f64>,
    pub read_burst_baseline_warm_up_floor_bytes: Option<f64>,
    pub read_burst_ema_alpha: Option<f64>,
    pub c2_max_decode_depth: Option<u32>,
}

#[derive(Deserialize)]
pub struct BootstrapEntryOverride {
    pub search_root: PathBuf,
    pub file_name: String,
    pub path_must_contain: String,
    pub max_bytes: u64,
}

/// Merges `overrides` onto `base` field-by-field: a `Some(v)` replaces the
/// default, a `None` leaves the computed default untouched. An explicit
/// function rather than a generic/macro-based merge -- more debuggable and
/// greppable for ~23 fields than machinery that obscures which field maps
/// to which.
pub fn apply_overrides(mut base: Config, o: &ConfigOverrides) -> Config {
    if let Some(v) = &o.bootstrap_watch {
        base.bootstrap_watch = v
            .iter()
            .map(|e| BootstrapEntry {
                search_root: e.search_root.clone(),
                file_name: e.file_name.clone(),
                path_must_contain: e.path_must_contain.clone(),
                max_bytes: e.max_bytes,
            })
            .collect();
    }
    if let Some(v) = &o.backup_sibling_roots {
        base.backup_sibling_roots = v.clone();
    }
    if let Some(v) = &o.watched_interpreters {
        base.watched_interpreters = v.clone();
    }
    if let Some(v) = &o.deny_exec_path_fragments {
        base.deny_exec_path_fragments = v.clone();
    }
    if let Some(v) = &o.allowed_exec_roots {
        base.allowed_exec_roots = v.clone();
    }
    if let Some(v) = o.scan_distinct_ports_threshold {
        base.scan_distinct_ports_threshold = v;
    }
    if let Some(v) = o.scan_distinct_hosts_threshold {
        base.scan_distinct_hosts_threshold = v;
    }
    if let Some(v) = o.scan_window_secs {
        base.scan_window_secs = v;
    }
    if let Some(v) = o.file_read_burst_absolute_bytes_per_poll {
        base.file_read_burst_absolute_bytes_per_poll = v;
    }
    if let Some(v) = o.file_read_burst_relative_multiplier {
        base.file_read_burst_relative_multiplier = v;
    }
    if let Some(v) = o.file_read_burst_uncorroborated_ceiling_bytes {
        base.file_read_burst_uncorroborated_ceiling_bytes = v;
    }
    if let Some(v) = &o.known_high_throughput_tool_names {
        base.known_high_throughput_tool_names = v.clone();
    }
    if let Some(v) = o.known_high_throughput_tool_multiplier {
        base.known_high_throughput_tool_multiplier = v;
    }
    if let Some(v) = &o.os_vendor_roots {
        base.os_vendor_roots = v.clone();
    }
    if let Some(v) = &o.known_automation_parent_names {
        base.known_automation_parent_names = v.clone();
    }
    if let Some(v) = o.poll_interval_secs {
        base.poll_interval_secs = v;
    }
    if let Some(v) = &o.log_path {
        base.log_path = v.clone();
    }
    if let Some(v) = o.read_burst_window_size {
        base.read_burst_window_size = v;
    }
    if let Some(v) = o.read_burst_required_spikes_in_window {
        base.read_burst_required_spikes_in_window = v;
    }
    if let Some(v) = o.read_burst_corroborated_threshold_fraction {
        base.read_burst_corroborated_threshold_fraction = v;
    }
    if let Some(v) = o.read_burst_baseline_exemption_multiplier {
        base.read_burst_baseline_exemption_multiplier = v;
    }
    if let Some(v) = o.read_burst_baseline_warm_up_floor_bytes {
        base.read_burst_baseline_warm_up_floor_bytes = v;
    }
    if let Some(v) = o.read_burst_ema_alpha {
        base.read_burst_ema_alpha = v;
    }
    if let Some(v) = o.c2_max_decode_depth {
        base.c2_max_decode_depth = v;
    }
    base
}

/// The hot-reloadable handle every watcher thread holds. The OUTER Arc is
/// what gets cloned per-thread (cheap, same as before); the inner Arc is
/// what gets swapped on reload (a single pointer write under a brief
/// write-lock) and is also what a reader clones once per poll iteration so
/// that iteration sees a fully-consistent Config snapshot, never a mix of
/// old and new fields. See config_reload.rs for the reload loop that
/// actually calls `apply_reload`.
pub type SharedConfig = Arc<RwLock<Arc<Config>>>;

/// Swaps in a newly-loaded, already-merged Config. The write-lock is held
/// only for the duration of the pointer assignment -- readers never block
/// on anything but that instant, and this call never blocks on a slow
/// reader either, since readers only ever hold a read-lock long enough to
/// clone the inner Arc.
pub fn apply_reload(shared: &SharedConfig, new_cfg: Config) {
    *shared.write().unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(new_cfg);
}

pub struct ConfigRow {
    pub label: String,
    pub value: String,
}

pub struct ConfigSection {
    pub title: &'static str,
    pub description: &'static str,
    pub rows: Vec<ConfigRow>,
}

/// Single source of truth for "what does the current config look like,
/// human-readably" -- both the CLI's `--show-config` and the GUI's "Show
/// Config" window call this same function and format the result for their
/// own output, so there is exactly one place enumerating Config's fields
/// instead of two independently hand-maintained lists silently drifting
/// out of sync with each other and with the real struct (as they had:
/// os_vendor_roots, known_high_throughput_tool_names,
/// known_high_throughput_tool_multiplier, known_automation_parent_names,
/// and file_read_burst_uncorroborated_ceiling_bytes were missing from both
/// before this function existed).
///
/// A row whose value came from `overrides` rather than the computed
/// default gets an explicit "(from config file)" suffix folded directly
/// into its value string -- a deliberate choice over a separate
/// is_overridden flag/column, since it needs no changes to the existing
/// win32 list-view rendering in gui/alert_window.rs at all.
pub fn config_sections(cfg: &Config, overrides: &ConfigOverrides) -> Vec<ConfigSection> {
    fn marked(value: String, overridden: bool) -> String {
        if overridden {
            format!("{value} (from config file)")
        } else {
            value
        }
    }

    vec![
        ConfigSection {
            title: "General",
            description: "Basic runtime info: where logs are written and how often the background watchers poll.",
            rows: vec![
                ConfigRow { label: "Platform".to_string(), value: std::env::consts::OS.to_string() },
                ConfigRow {
                    label: "Log path".to_string(),
                    value: marked(cfg.log_path.display().to_string(), overrides.log_path.is_some()),
                },
                ConfigRow {
                    label: "Poll interval".to_string(),
                    value: marked(format!("{}s", cfg.poll_interval_secs), overrides.poll_interval_secs.is_some()),
                },
            ],
        },
        ConfigSection {
            title: "Bootstrap Watch",
            description: "Known-tiny entry-point files that must never grow past a sane size -- a real trusted app loader file suddenly ballooning is the tell-tale sign of it being overwritten with a payload.",
            rows: cfg
                .bootstrap_watch
                .iter()
                .map(|e| ConfigRow {
                    label: marked(
                        e.search_root.join(&e.file_name).display().to_string(),
                        overrides.bootstrap_watch.is_some(),
                    ),
                    value: format!("must contain '{}', > {} bytes", e.path_must_contain, e.max_bytes),
                })
                .collect(),
        },
        ConfigSection {
            title: "Backup-Sibling Roots",
            description: "Folders watched for a *.orig/*.bak-style backup file appearing next to a real one -- the copy an infector leaves behind to preserve the original while it replaces it.",
            rows: cfg
                .backup_sibling_roots
                .iter()
                .enumerate()
                .map(|(i, r)| ConfigRow {
                    label: format!("Root {}", i + 1),
                    value: marked(r.display().to_string(), overrides.backup_sibling_roots.is_some()),
                })
                .collect(),
        },
        ConfigSection {
            title: "Process Detection",
            description: "Command lines are only inspected for these interpreters (avoids false-positiving on unrelated long command lines); paths containing these fragments are an instant flag for any process, regardless of name.",
            rows: vec![
                ConfigRow {
                    label: "Watched interpreters".to_string(),
                    value: marked(cfg.watched_interpreters.join(", "), overrides.watched_interpreters.is_some()),
                },
                ConfigRow {
                    label: "Denied exec path fragments".to_string(),
                    value: marked(cfg.deny_exec_path_fragments.join(", "), overrides.deny_exec_path_fragments.is_some()),
                },
            ],
        },
        ConfigSection {
            title: "Allowed Exec Roots",
            description: "Processes launching from one of these locations are treated as trusted and do not trigger the unusual-path warning -- launching from anywhere else still gets flagged for review, even a normally-legitimate install location, since a trusted location can still be compromised.",
            rows: cfg
                .allowed_exec_roots
                .iter()
                .enumerate()
                .map(|(i, r)| ConfigRow {
                    label: format!("Root {}", i + 1),
                    value: marked(r.display().to_string(), overrides.allowed_exec_roots.is_some()),
                })
                .collect(),
        },
        ConfigSection {
            title: "OS Vendor Roots",
            description: "Root directories only an OS installer or administrator/root can write to -- a binary running from one of these gets a raised file-read-burst threshold regardless of its name, since a compromise can't silently plant a file here.",
            rows: cfg
                .os_vendor_roots
                .iter()
                .enumerate()
                .map(|(i, r)| ConfigRow {
                    label: format!("Root {}", i + 1),
                    value: marked(r.display().to_string(), overrides.os_vendor_roots.is_some()),
                })
                .collect(),
        },
        ConfigSection {
            title: "Known High-Throughput Tools",
            description: "Process names known to legitimately sustain high burst reads as their normal operating shape -- a match raises the effective file-read-burst threshold, it does not exempt the process from detection.",
            rows: vec![
                ConfigRow {
                    label: "Tool names".to_string(),
                    value: marked(cfg.known_high_throughput_tool_names.join(", "), overrides.known_high_throughput_tool_names.is_some()),
                },
                ConfigRow {
                    label: "Threshold multiplier".to_string(),
                    value: marked(format!("{}x", cfg.known_high_throughput_tool_multiplier), overrides.known_high_throughput_tool_multiplier.is_some()),
                },
            ],
        },
        ConfigSection {
            title: "Known Automation Parents",
            description: "Parent-process names known to legitimately spawn interpreters with obfuscated-looking command lines as normal operating shape. Triage context only -- never changes c2-shaped-process severity.",
            rows: vec![ConfigRow {
                label: "Parent names".to_string(),
                value: marked(cfg.known_automation_parent_names.join(", "), overrides.known_automation_parent_names.is_some()),
            }],
        },
        ConfigSection {
            title: "Network Scan Thresholds",
            description: "A process opening connections to this many distinct destination ports or hosts within the window below is flagged as scanning behavior.",
            rows: vec![
                ConfigRow {
                    label: "Distinct ports".to_string(),
                    value: marked(format!("{}+", cfg.scan_distinct_ports_threshold), overrides.scan_distinct_ports_threshold.is_some()),
                },
                ConfigRow {
                    label: "Distinct hosts".to_string(),
                    value: marked(format!("{}+", cfg.scan_distinct_hosts_threshold), overrides.scan_distinct_hosts_threshold.is_some()),
                },
                ConfigRow {
                    label: "Window".to_string(),
                    value: marked(format!("{}s", cfg.scan_window_secs), overrides.scan_window_secs.is_some()),
                },
            ],
        },
        ConfigSection {
            title: "File-Read-Burst Thresholds",
            description: "Watches every running process for an unusual amount of file reading in one interval -- either an absolute amount, or a large multiple of that process's own recent average -- the tell-tale shape of drive scanning or harvesting.",
            rows: vec![
                ConfigRow {
                    label: "Absolute burst".to_string(),
                    value: marked(format_bytes(cfg.file_read_burst_absolute_bytes_per_poll), overrides.file_read_burst_absolute_bytes_per_poll.is_some()),
                },
                ConfigRow {
                    label: "Relative spike multiplier".to_string(),
                    value: marked(format!("{}x", cfg.file_read_burst_relative_multiplier), overrides.file_read_burst_relative_multiplier.is_some()),
                },
                ConfigRow {
                    label: "Uncorroborated ceiling".to_string(),
                    value: marked(format_bytes(cfg.file_read_burst_uncorroborated_ceiling_bytes), overrides.file_read_burst_uncorroborated_ceiling_bytes.is_some()),
                },
                ConfigRow {
                    label: "Window size".to_string(),
                    value: marked(cfg.read_burst_window_size.to_string(), overrides.read_burst_window_size.is_some()),
                },
                ConfigRow {
                    label: "Required spikes in window".to_string(),
                    value: marked(cfg.read_burst_required_spikes_in_window.to_string(), overrides.read_burst_required_spikes_in_window.is_some()),
                },
                ConfigRow {
                    label: "Corroborated threshold fraction".to_string(),
                    value: marked(cfg.read_burst_corroborated_threshold_fraction.to_string(), overrides.read_burst_corroborated_threshold_fraction.is_some()),
                },
                ConfigRow {
                    label: "Baseline exemption multiplier".to_string(),
                    value: marked(format!("{}x", cfg.read_burst_baseline_exemption_multiplier), overrides.read_burst_baseline_exemption_multiplier.is_some()),
                },
                ConfigRow {
                    label: "Baseline warm-up floor".to_string(),
                    value: marked(format_bytes(cfg.read_burst_baseline_warm_up_floor_bytes as u64), overrides.read_burst_baseline_warm_up_floor_bytes.is_some()),
                },
                ConfigRow {
                    label: "EMA alpha".to_string(),
                    value: marked(cfg.read_burst_ema_alpha.to_string(), overrides.read_burst_ema_alpha.is_some()),
                },
            ],
        },
        ConfigSection {
            title: "C2-Shaped-Process Decoder",
            description: "How deep the -EncodedCommand/nested-$EncodedCommand decoder recurses before giving up and scoring whatever it has -- bounded so a pathological input can't force unbounded recursion.",
            rows: vec![ConfigRow {
                label: "Max decode depth".to_string(),
                value: marked(cfg.c2_max_decode_depth.to_string(), overrides.c2_max_decode_depth.is_some()),
            }],
        },
    ]
}

fn format_bytes(b: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    if b >= GB {
        format!("{:.1}GB", b as f64 / GB as f64)
    } else if b >= MB {
        format!("{:.1}MB", b as f64 / MB as f64)
    } else if b >= KB {
        format!("{:.1}KB", b as f64 / KB as f64)
    } else {
        format!("{b}B")
    }
}

impl Config {
    pub fn default_for_platform() -> Self {
        let home = dirs_home();
        let log_path = home.join(".goofedup").join("goofedup.log");

        let mut bootstrap_watch = Vec::new();
        let mut backup_sibling_roots = Vec::new();
        let mut allowed_exec_roots = Vec::new();
        // A STRICT subset of allowed_exec_roots below: only the roots an
        // attacker cannot write to without the elevation a compromise
        // doesn't grant for free (the OS install tree, the vendor
        // application-install tree). Deliberately excludes the
        // user-writable dev-tool homes (.cargo, .local, LOCALAPPDATA, etc.)
        // that share allowed_exec_roots for the unrelated process-PATH
        // check -- those are fine places to run FROM, but not a reason to
        // expect bulk I/O to be safe, since a compromise can write there
        // freely.
        let mut os_vendor_roots = Vec::new();

        #[cfg(target_os = "windows")]
        {
            if let Ok(local) = std::env::var("LOCALAPPDATA") {
                let local = PathBuf::from(local);
                bootstrap_watch.push(BootstrapEntry {
                    search_root: local.join("Discord"),
                    file_name: "index.js".to_string(),
                    path_must_contain: "discord_desktop_core".to_string(),
                    max_bytes: 2048,
                });
                backup_sibling_roots.push(local.join("Discord"));
                backup_sibling_roots.push(local.join("npm-cache"));
                allowed_exec_roots.push(local.clone());
                allowed_exec_roots.push(local.join("Microsoft"));
            }
            if let Ok(appdata) = std::env::var("APPDATA") {
                let appdata = PathBuf::from(appdata);
                backup_sibling_roots.push(appdata.join("npm"));
                backup_sibling_roots.push(appdata.join("npm-cache"));
                allowed_exec_roots.push(appdata);
            }
            // Portable dev-tool install homes -- the same roots macOS/Linux
            // already allow below. Live-witnessed allowlist gaps: rustc/
            // cargo/clippy run from ~/.rustup/~/.cargo toolchain dirs, pip
            // and scoop-managed tools from ~/scoop, user-local CLI tooling
            // from ~/.local/bin and per-tool homes like ~/.kimi-code and
            // ~/.gm-tools. Each is a user-writable location, so the check
            // stays WARN-tier exactly as before -- this only closes known
            // noise gaps, it does not trust anything.
            for dev_home in [
                ".cargo",
                ".rustup",
                "scoop",
                ".local",
                ".gm-tools",
                ".kimi-code",
            ] {
                allowed_exec_roots.push(home.join(dev_home));
            }
            if let Ok(pf) = std::env::var("ProgramFiles") {
                allowed_exec_roots.push(PathBuf::from(pf.clone()));
                os_vendor_roots.push(PathBuf::from(pf));
            }
            if let Ok(pf86) = std::env::var("ProgramFiles(x86)") {
                allowed_exec_roots.push(PathBuf::from(pf86.clone()));
                os_vendor_roots.push(PathBuf::from(pf86));
            }
            if let Ok(windir) = std::env::var("WINDIR") {
                allowed_exec_roots.push(PathBuf::from(windir.clone()));
                os_vendor_roots.push(PathBuf::from(windir));
            }
            // python.org's Windows installer's "Install for all users" option
            // (an admin-elevation-gated install, same trust tier as Program
            // Files/WINDIR above) writes directly to the system drive root
            // as `PythonXX`, not under Program Files -- live-witnessed as
            // this machine's single largest process-path WARN source (34
            // occurrences, C:\Python312\python.exe) despite being a
            // completely standard install location, not an unusual one.
            // Enumerated by version rather than matched by glob since
            // is_unlisted_exec_path does exact-prefix matching; covers the
            // actively-maintained CPython release line plus enough headroom
            // for this to keep working across ordinary version upgrades
            // without needing another gap-fill each time.
            if let Ok(sysdrive) = std::env::var("SystemDrive") {
                let sysdrive = PathBuf::from(sysdrive);
                for minor in 8..=14u32 {
                    let root = sysdrive.join(format!("Python3{minor}"));
                    allowed_exec_roots.push(root.clone());
                    os_vendor_roots.push(root);
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            backup_sibling_roots.push(home.join("Library/Application Support"));
            allowed_exec_roots.push(PathBuf::from("/Applications"));
            allowed_exec_roots.push(PathBuf::from("/usr"));
            allowed_exec_roots.push(PathBuf::from("/opt"));
            allowed_exec_roots.push(PathBuf::from("/System"));
            allowed_exec_roots.push(PathBuf::from("/bin"));
            allowed_exec_roots.push(PathBuf::from("/sbin"));
            allowed_exec_roots.push(home.join(".local"));
            os_vendor_roots.push(PathBuf::from("/Applications"));
            os_vendor_roots.push(PathBuf::from("/usr"));
            os_vendor_roots.push(PathBuf::from("/opt"));
            os_vendor_roots.push(PathBuf::from("/System"));
            os_vendor_roots.push(PathBuf::from("/bin"));
            os_vendor_roots.push(PathBuf::from("/sbin"));
        }

        #[cfg(target_os = "linux")]
        {
            backup_sibling_roots.push(home.join(".config"));
            allowed_exec_roots.push(PathBuf::from("/usr"));
            allowed_exec_roots.push(PathBuf::from("/opt"));
            allowed_exec_roots.push(PathBuf::from("/bin"));
            allowed_exec_roots.push(PathBuf::from("/sbin"));
            allowed_exec_roots.push(home.join(".local"));
            allowed_exec_roots.push(home.join(".cargo"));
            os_vendor_roots.push(PathBuf::from("/usr"));
            os_vendor_roots.push(PathBuf::from("/opt"));
            os_vendor_roots.push(PathBuf::from("/bin"));
            os_vendor_roots.push(PathBuf::from("/sbin"));
        }

        allowed_exec_roots.push(home.join(".goofedup"));

        let deny_exec_path_fragments = vec![
            "$Recycle.Bin".to_string(),
            "RECYCLE.BIN".to_string(),
            ".Trash".to_string(),
            ".local/share/Trash".to_string(),
        ];

        Self {
            bootstrap_watch,
            backup_sibling_roots,
            watched_interpreters: vec![
                "node".to_string(),
                "node.exe".to_string(),
                "python".to_string(),
                "python3".to_string(),
                "powershell".to_string(),
                "powershell.exe".to_string(),
                "pwsh".to_string(),
                "pwsh.exe".to_string(),
                "wscript.exe".to_string(),
                "cscript.exe".to_string(),
                "mshta.exe".to_string(),
                "bash".to_string(),
                "sh".to_string(),
                "osascript".to_string(),
            ],
            deny_exec_path_fragments,
            allowed_exec_roots,
            os_vendor_roots,
            scan_distinct_ports_threshold: 20,
            // Live-witnessed false-positive calibration: a desktop browser
            // loading a normal page fans out to 15-27 distinct CDN hosts in
            // a 10s window (recorded chrome.exe peaks), so the old value of
            // 15 fired on ordinary browsing. 40+ distinct hosts in 10s is
            // still far outside any legitimate interactive app's shape
            // while remaining well below a real scanner's rate.
            scan_distinct_hosts_threshold: 40,
            scan_window_secs: 10,
            // Originally 50MB, calibrated against real recorded evidence:
            // on an actual dev workstation (compilers, package managers,
            // repo-wide grep, AI coding tools, browsers, archivers all
            // running normally) this floor alone produced 223 CRITICALs in
            // one operating log with a true-positive rate of zero -- every
            // single one traced to ordinary tool activity, never to the
            // real incident this log also contains (caught by other
            // detectors entirely). 300MB is still well past a real
            // interactive tool's one-shot need, but clears the routine
            // 70-290MB bursts live-witnessed from grep/tar/dllhost/Code/zig
            // doing their normal job. A real bulk build/backup/indexer
            // legitimately sustains high read rates, which is exactly what
            // the relative-multiplier check below is for -- this absolute
            // floor exists to catch a fast scanner even the very first time
            // it's observed, before any baseline exists to compare against.
            file_read_burst_absolute_bytes_per_poll: 300 * 1024 * 1024,
            file_read_burst_relative_multiplier: 8.0,
            // No trust exemption applies past this -- see the field's own
            // doc comment.
            file_read_burst_uncorroborated_ceiling_bytes: 2 * 1024 * 1024 * 1024,
            known_high_throughput_tool_names: vec![
                "syncthing.exe".to_string(),
                "syncthing".to_string(),
                "onedrive.exe".to_string(),
                "dropbox.exe".to_string(),
                "backblaze.exe".to_string(),
                "rsync".to_string(),
                "robocopy.exe".to_string(),
                // Browsers and Electron apps: live-witnessed false-positive
                // sources for the RELATIVE-spike path (chrome/firefox/Discord
                // all recorded sustained multi-poll spikes against their own
                // quiet-tab baselines during ordinary page loads and media
                // playback). Listed here, not exempted -- an extreme read
                // still alerts, just against a proportionally higher bar.
                "chrome.exe".to_string(),
                "chrome".to_string(),
                "firefox.exe".to_string(),
                "firefox".to_string(),
                "msedgewebview2.exe".to_string(),
                "msedge.exe".to_string(),
                "discord.exe".to_string(),
                // gm's own dispatch daemon. Live bug found via a one-shot
                // sysinfo-name-vs-allowlist witness: this name was described
                // in this field's own doc comment above as already listed,
                // but was never actually added to this Vec -- so the
                // relaxation never applied and every dispatch burst fell
                // through to the unrelaxed 50MB floor, which its normal
                // 70-99MB reads clear easily. The relative-spike relaxation
                // alone can't fix this either: agentplug-runner.exe respawns
                // under a fresh PID often (self-update swaps, daemon
                // restarts), so its ReadTracker rarely has an established
                // baseline to be relative to -- only the absolute floor
                // matters for its real shape (idle, then a burst).
                "agentplug-runner.exe".to_string(),
                "agentplug-runner".to_string(),
                // grep.exe (Git-for-Windows' usr/bin/grep, and its Unix
                // equivalents): a codebase-search tool's whole job is
                // reading large amounts of file data quickly across many
                // files -- the exact "drive scanning/harvesting" shape this
                // detector looks for, but as its own normal, expected
                // operation. Live-witnessed: 34 CRITICALs across 5 days, all
                // 'grep.exe', both absolute-burst and relative-spike paths,
                // recurring in the same dense bursts (a large `grep -r`
                // across a big repo hits many polls in a row) rather than a
                // single one-off -- a real scanning/harvesting process would
                // look identical by design, but a search tool doing exactly
                // what it's for is not evidence of anything.
                "grep.exe".to_string(),
                "grep".to_string(),
                // claude.exe (the Claude Code CLI itself, installed at the
                // standard ~/.local/bin location): a large (~384MB)
                // self-contained binary that reads a burst of its own
                // bundled assets/model data into memory on startup.
                // Live-witnessed: 1.7GB read in ~3s against a 0B baseline
                // (session startup, no prior activity to average against)
                // -- the AI-assistant-harness startup shape this project's
                // own README already documents as expected noise for
                // -EncodedCommand PowerShell, now confirmed for this
                // process's own file-read pattern too.
                "claude.exe".to_string(),
                "claude".to_string(),
            ],
            // 6.0 -> 16.0: syncthing.exe (already listed above, since before
            // this session's tuning) kept firing file-read-burst on the
            // RELATIVE-spike path even with the 6.0 relaxation -- live-
            // witnessed real bursts of 62x-121x its own recent baseline
            // (e.g. 65.1MB against a 549KB/poll average = ~121x), a real
            // sync engine catching up after a quiet stretch, comfortably
            // clearing the old 8.0*6.0=48x effective bar. 16.0 gives
            // 8.0*16.0=128x headroom, covering the worst observed real
            // spike with margin, while the absolute floor this multiplier
            // also relaxes (50MB*16=800MB) and the network-scan host-sweep
            // floor (40*16=640 hosts) both stay far below what a genuinely
            // extreme scanner/harvester would need to clear -- this raises
            // the bar for known-legitimate tools only, it doesn't touch
            // what counts as extreme in the first place.
            known_high_throughput_tool_multiplier: 16.0,
            // agentplug-runner.exe is gm's own dispatch daemon: its exec_js
            // verb spawns powershell.exe -EncodedCommand directly for every
            // PowerShell script dispatch, live-confirmed via
            // agentplug-host's exec_js.rs and this project's own recorded
            // c2-shaped-process alerts (168 hits in one session, all firing
            // during active /gm dispatch windows) -- a real, identifiable
            // source of this exact false-positive shape, not a guess.
            //
            // bash.exe/cmd.exe/claude.exe are live-witnessed via a real
            // sysinfo::Process::parent() chain walk of a process launched
            // through this session's own AI-assistant tool-dispatch path:
            // the interpreter's immediate parent was NOT agentplug-runner.exe
            // at all but an intermediate shell (bash.exe, nested three deep)
            // itself parented by claude.exe then cmd.exe -- explaining why
            // an immediate-parent-only check against agentplug-runner.exe
            // alone almost never matched in practice. explorer.exe also
            // appears further up this same chain but is deliberately
            // excluded: it is the universal desktop-shell ancestor of nearly
            // every interactive process on the machine, so trusting it would
            // make the whole check match almost anything a user launches by
            // hand, defeating its purpose.
            known_automation_parent_names: vec![
                "agentplug-runner.exe".to_string(),
                "agentplug-runner".to_string(),
                "bash.exe".to_string(),
                "cmd.exe".to_string(),
                "claude.exe".to_string(),
            ],
            poll_interval_secs: 3,
            log_path,
            read_burst_window_size: 4,
            read_burst_required_spikes_in_window: 2,
            read_burst_corroborated_threshold_fraction: 0.25,
            read_burst_baseline_exemption_multiplier: 3.0,
            read_burst_baseline_warm_up_floor_bytes: 512.0 * 1024.0,
            read_burst_ema_alpha: 0.2,
            c2_max_decode_depth: 4,
        }
    }
}

pub fn dirs_home() -> PathBuf {
    #[cfg(windows)]
    {
        if let Ok(p) = std::env::var("USERPROFILE") {
            return PathBuf::from(p);
        }
    }
    if let Ok(p) = std::env::var("HOME") {
        return PathBuf::from(p);
    }
    PathBuf::from(".")
}

/// Where the hot-reloadable override file lives -- sibling to the existing
/// log file, under the same directory both binaries already create at
/// startup.
pub fn override_path(home: &std::path::Path) -> PathBuf {
    home.join(".goofedup").join("goofedup.config.json")
}
