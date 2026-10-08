use crate::trust::UnsignedUserWritablePolicy;
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

const KIB: u64 = 1024;
const MIB: u64 = KIB * 1024;
const GIB: u64 = MIB * 1024;

const DEFAULT_SCAN_DISTINCT_PORTS_THRESHOLD: usize = 20;
const DEFAULT_SCAN_DISTINCT_HOSTS_THRESHOLD: usize = 40;
const DEFAULT_SCAN_WINDOW_SECS: u64 = 10;
const DEFAULT_FILE_READ_BURST_ABSOLUTE_BYTES_PER_POLL: u64 = 300 * MIB;
const DEFAULT_FILE_READ_BURST_RELATIVE_MULTIPLIER: f64 = 8.0;
const DEFAULT_FILE_READ_BURST_UNCORROBORATED_CEILING_BYTES: u64 = 2 * GIB;
const DEFAULT_KNOWN_HIGH_THROUGHPUT_TOOL_MULTIPLIER: f64 = 16.0;
const DEFAULT_POLL_INTERVAL_SECS: u64 = 3;
const DEFAULT_READ_BURST_WINDOW_SIZE: usize = 4;
const DEFAULT_READ_BURST_REQUIRED_SPIKES_IN_WINDOW: usize = 2;
const DEFAULT_READ_BURST_CORROBORATED_THRESHOLD_FRACTION: f64 = 0.25;
const DEFAULT_READ_BURST_BASELINE_EXEMPTION_MULTIPLIER: f64 = 3.0;
const DEFAULT_READ_BURST_BASELINE_WARM_UP_FLOOR_BYTES: f64 = 512.0 * 1024.0;
const DEFAULT_READ_BURST_EMA_ALPHA: f64 = 0.2;
const DEFAULT_C2_MAX_DECODE_DEPTH: u32 = 4;
const DEFAULT_ELECTRON_SWEEP_INTERVAL_SECS: u64 = 60 * 60;

#[cfg(target_os = "windows")]
const DISCORD_DESKTOP_CORE_INDEX_JS_MAX_BYTES: u64 = 2048;
const NPM_LIB_CLI_JS_MAX_BYTES: u64 = 2048;
const NPM_LIB_CLI_JS_PATH_FRAGMENT: &str = "npm\\lib";
#[cfg(target_os = "windows")]
const DEV_TOOL_HOME_DIRS_UNDER_USER_HOME: [&str; 6] =
    [".cargo", ".rustup", "scoop", ".local", ".gm-tools", ".kimi-code"];
#[cfg(target_os = "windows")]
const PYTHON_ALL_USERS_INSTALL_MIN_MINOR_VERSION: u32 = 8;
#[cfg(target_os = "windows")]
const PYTHON_ALL_USERS_INSTALL_MAX_MINOR_VERSION: u32 = 14;

const TRASH_PATH_FRAGMENTS: [&str; 4] = ["$Recycle.Bin", "RECYCLE.BIN", ".Trash", ".local/share/Trash"];

const SHELL_AND_SCRIPT_INTERPRETER_NAMES: [&str; 14] = [
    "node",
    "node.exe",
    "python",
    "python3",
    "powershell",
    "powershell.exe",
    "pwsh",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "bash",
    "sh",
    "osascript",
];


fn owned_strings(names: &[&str]) -> Vec<String> {
    names.iter().map(|n| n.to_string()).collect()
}

pub struct Config {
    pub bootstrap_watch: Vec<BootstrapEntry>,

    pub backup_sibling_roots: Vec<PathBuf>,

    pub watched_interpreters: Vec<String>,

    pub deny_exec_path_fragments: Vec<String>,

    pub allowed_exec_roots: Vec<PathBuf>,

    pub scan_distinct_ports_threshold: usize,
    pub scan_distinct_hosts_threshold: usize,
    pub scan_window_secs: u64,

    pub file_read_burst_absolute_bytes_per_poll: u64,
    pub file_read_burst_relative_multiplier: f64,

    pub file_read_burst_uncorroborated_ceiling_bytes: u64,

    pub known_high_throughput_tool_names: Vec<String>,
    pub known_high_throughput_tool_multiplier: f64,

    pub os_vendor_roots: Vec<PathBuf>,

    pub known_automation_parent_names: Vec<String>,

    pub poll_interval_secs: u64,

    pub log_path: PathBuf,

    pub read_burst_window_size: usize,
    pub read_burst_required_spikes_in_window: usize,
    pub read_burst_corroborated_threshold_fraction: f64,
    pub read_burst_baseline_exemption_multiplier: f64,
    pub read_burst_baseline_warm_up_floor_bytes: f64,
    pub read_burst_ema_alpha: f64,
    pub c2_max_decode_depth: u32,

    pub electron_sweep_enabled: bool,
    pub electron_sweep_interval_secs: u64,
    pub electron_sweep_roots: Vec<PathBuf>,
    pub tamper: crate::tamper_config::TamperConfig,
    pub trusted_publishers: Vec<String>,
    pub unsigned_user_writable_policy: UnsignedUserWritablePolicy,

    pub repo_watch_roots: Vec<PathBuf>,
    pub known_benign_event_sources: Vec<String>,
}

pub struct BootstrapEntry {
    pub search_root: PathBuf,
    pub file_name: String,
    pub path_must_contain: String,
    pub max_bytes: u64,
}

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
    pub electron_sweep_enabled: Option<bool>,
    pub electron_sweep_interval_secs: Option<u64>,
    pub electron_sweep_roots: Option<Vec<PathBuf>>,
    pub tamper: crate::tamper_config::TamperOverrides,
    pub trusted_publishers: Option<Vec<String>>,
    pub unsigned_user_writable_policy: Option<UnsignedUserWritablePolicy>,
    pub repo_watch_roots: Option<Vec<PathBuf>>,
    pub known_benign_event_sources: Option<Vec<String>>,
}

#[derive(Deserialize)]
pub struct BootstrapEntryOverride {
    pub search_root: PathBuf,
    pub file_name: String,
    pub path_must_contain: String,
    pub max_bytes: u64,
}

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
    if let Some(v) = o.electron_sweep_enabled {
        base.electron_sweep_enabled = v;
    }
    if let Some(v) = o.electron_sweep_interval_secs {
        base.electron_sweep_interval_secs = v;
    }
    if let Some(v) = &o.electron_sweep_roots {
        base.electron_sweep_roots = v.clone();
    }
    base.tamper = base.tamper.with_overrides(&o.tamper);
    if let Some(v) = &o.trusted_publishers {
        base.trusted_publishers = v.clone();
    }
    if let Some(v) = &o.unsigned_user_writable_policy {
        base.unsigned_user_writable_policy = v.clone();
    }
    if let Some(v) = &o.repo_watch_roots {
        base.repo_watch_roots = v.clone();
    }
    if let Some(v) = &o.known_benign_event_sources {
        base.known_benign_event_sources = v.clone();
    }
    base
}

pub type SharedConfig = Arc<RwLock<Arc<Config>>>;

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

pub fn config_sections(cfg: &Config, overrides: &ConfigOverrides) -> Vec<ConfigSection> {
    fn marked(value: String, overridden: bool) -> String {
        if overridden {
            format!("{value} (from config file)")
        } else {
            value
        }
    }

    let mut sections = vec![
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
            description: "Where signature verification is unavailable (non-Windows) or the unsigned user-writable policy is off, processes launching from one of these locations do not trigger the unusual-path warning; the file-read-burst corroboration check always uses this list. On Windows with the policy on, user-writable roots listed here no longer imply trust -- see Signature Trust.",
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
        ConfigSection {
            title: "Electron/VSCode-Family Sweep",
            description: "Periodic proactive scan of every Electron/VSCode-family app install discovered by SHAPE (app.asar / @vscode module tree / electron binary), not a hardcoded name list -- runs the same HiddenSpawn content scan plus an existing-file backup-sibling walk over each one on this cadence.",
            rows: {
                let mut rows = vec![
                    ConfigRow {
                        label: "Enabled".to_string(),
                        value: marked(cfg.electron_sweep_enabled.to_string(), overrides.electron_sweep_enabled.is_some()),
                    },
                    ConfigRow {
                        label: "Interval".to_string(),
                        value: marked(format!("{}s", cfg.electron_sweep_interval_secs), overrides.electron_sweep_interval_secs.is_some()),
                    },
                ];
                rows.extend(cfg.electron_sweep_roots.iter().enumerate().map(|(i, r)| ConfigRow {
                    label: format!("Root {}", i + 1),
                    value: marked(r.display().to_string(), overrides.electron_sweep_roots.is_some()),
                }));
                rows
            },
        },
        ConfigSection {
            title: "Signature Trust",
            description: "A process image in a user-writable location (AppData, Downloads, Temp, dev directories, anywhere outside the OS vendor roots) is only trusted when validly signed by one of these publishers, or when its exact SHA-256 is pinned. Unsigned images there warn, and escalate to CRITICAL with outbound public network traffic, an obfuscated command line, or a masquerading system-process name. Policy mode is warn, critical, or off (off falls back to the Allowed Exec Roots allowlist).",
            rows: vec![
                ConfigRow {
                    label: "Trusted publishers".to_string(),
                    value: marked(cfg.trusted_publishers.join(", "), overrides.trusted_publishers.is_some()),
                },
                ConfigRow {
                    label: "Unsigned user-writable policy".to_string(),
                    value: marked(
                        cfg.unsigned_user_writable_policy.mode.label().to_string(),
                        overrides.unsigned_user_writable_policy.is_some(),
                    ),
                },
                ConfigRow {
                    label: "Pinned unsigned SHA-256".to_string(),
                    value: marked(
                        cfg.unsigned_user_writable_policy.trusted_sha256.join(", "),
                        overrides.unsigned_user_writable_policy.is_some(),
                    ),
                },
            ],
        },
        ConfigSection {
            title: "Repo Compromise Watch",
            description: "Dev roots watched recursively for a hidden .vscode/tasks.json auto-run task, task.allowAutomaticTasks in workspace settings, a payload-hiding .gitignore entry, a package.json lifecycle dropper, a tampered *.config.js, a risky workflow or git hook, or JavaScript disguised as a font/image -- checked within a couple of seconds of the file changing.",
            rows: cfg
                .repo_watch_roots
                .iter()
                .enumerate()
                .map(|(i, r)| ConfigRow {
                    label: format!("Root {}", i + 1),
                    value: marked(r.display().to_string(), overrides.repo_watch_roots.is_some()),
                })
                .collect(),
        },
        ConfigSection {
            title: "Known Benign Event Sources",
            description: "Executable names whose Windows event-log findings (CreateRemoteThread, process lineage, lsass access, tampering) are downgraded to Info with a note -- still recorded, never suppressed.",
            rows: vec![ConfigRow {
                label: "Source names".to_string(),
                value: marked(cfg.known_benign_event_sources.join(", "), overrides.known_benign_event_sources.is_some()),
            }],
        },
    ];
    sections.push(cfg.tamper.section(&overrides.tamper));
    sections
}

fn format_bytes(b: u64) -> String {
    if b >= GIB {
        format!("{:.1}GB", b as f64 / GIB as f64)
    } else if b >= MIB {
        format!("{:.1}MB", b as f64 / MIB as f64)
    } else if b >= KIB {
        format!("{:.1}KB", b as f64 / KIB as f64)
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
        let mut os_vendor_roots = Vec::new();
        let mut electron_sweep_roots = Vec::new();

        #[cfg(target_os = "windows")]
        {
            if let Ok(local) = std::env::var("LOCALAPPDATA") {
                let local = PathBuf::from(local);
                bootstrap_watch.push(BootstrapEntry {
                    search_root: local.join("Discord"),
                    file_name: "index.js".to_string(),
                    path_must_contain: "discord_desktop_core".to_string(),
                    max_bytes: DISCORD_DESKTOP_CORE_INDEX_JS_MAX_BYTES,
                });
                backup_sibling_roots.push(local.join("Discord"));
                backup_sibling_roots.push(local.join("npm-cache"));
                allowed_exec_roots.push(local.clone());
                allowed_exec_roots.push(local.join("Microsoft"));
                electron_sweep_roots.push(local.join("Programs"));
            }
            let mut npm_install_roots = Vec::new();
            if let Ok(pf) = std::env::var("ProgramFiles") {
                npm_install_roots.push(PathBuf::from(pf).join("nodejs").join("node_modules").join("npm"));
            }
            if let Ok(appdata) = std::env::var("APPDATA") {
                npm_install_roots.push(PathBuf::from(appdata).join("npm").join("node_modules").join("npm"));
            }
            if let Ok(program_data) = std::env::var("ProgramData") {
                npm_install_roots.push(PathBuf::from(program_data).join("nvm"));
            }
            for root in npm_install_roots {
                bootstrap_watch.push(BootstrapEntry {
                    search_root: root,
                    file_name: "cli.js".to_string(),
                    path_must_contain: NPM_LIB_CLI_JS_PATH_FRAGMENT.to_string(),
                    max_bytes: NPM_LIB_CLI_JS_MAX_BYTES,
                });
            }
            if let Ok(appdata) = std::env::var("APPDATA") {
                let appdata = PathBuf::from(appdata);
                backup_sibling_roots.push(appdata.join("npm"));
                backup_sibling_roots.push(appdata.join("npm-cache"));
                allowed_exec_roots.push(appdata);
            }
            for dev_home in DEV_TOOL_HOME_DIRS_UNDER_USER_HOME {
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
            if let Ok(program_data) = std::env::var("ProgramData") {
                allowed_exec_roots.push(PathBuf::from(program_data).join("Microsoft").join("Windows Defender"));
            }
            if let Ok(sysdrive) = std::env::var("SystemDrive") {
                let sysdrive = sysdrive.trim_end_matches('\\').to_string();
                for minor in PYTHON_ALL_USERS_INSTALL_MIN_MINOR_VERSION..=PYTHON_ALL_USERS_INSTALL_MAX_MINOR_VERSION {
                    let root = PathBuf::from(format!("{sysdrive}\\Python3{minor}"));
                    allowed_exec_roots.push(root.clone());
                    os_vendor_roots.push(root);
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            backup_sibling_roots.push(home.join("Library/Application Support"));
            electron_sweep_roots.push(PathBuf::from("/Applications"));
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
            electron_sweep_roots.push(home.join(".local/share"));
            electron_sweep_roots.push(PathBuf::from("/opt"));
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

        let deny_exec_path_fragments = owned_strings(&TRASH_PATH_FRAGMENTS);

        Self {
            bootstrap_watch,
            backup_sibling_roots,
            watched_interpreters: owned_strings(&SHELL_AND_SCRIPT_INTERPRETER_NAMES),
            deny_exec_path_fragments,
            allowed_exec_roots,
            os_vendor_roots,
            scan_distinct_ports_threshold: DEFAULT_SCAN_DISTINCT_PORTS_THRESHOLD,
            scan_distinct_hosts_threshold: DEFAULT_SCAN_DISTINCT_HOSTS_THRESHOLD,
            scan_window_secs: DEFAULT_SCAN_WINDOW_SECS,
            file_read_burst_absolute_bytes_per_poll: DEFAULT_FILE_READ_BURST_ABSOLUTE_BYTES_PER_POLL,
            file_read_burst_relative_multiplier: DEFAULT_FILE_READ_BURST_RELATIVE_MULTIPLIER,
            file_read_burst_uncorroborated_ceiling_bytes: DEFAULT_FILE_READ_BURST_UNCORROBORATED_CEILING_BYTES,
            known_high_throughput_tool_names: Vec::new(),
            known_high_throughput_tool_multiplier: DEFAULT_KNOWN_HIGH_THROUGHPUT_TOOL_MULTIPLIER,
            known_automation_parent_names: Vec::new(),
            poll_interval_secs: DEFAULT_POLL_INTERVAL_SECS,
            log_path,
            read_burst_window_size: DEFAULT_READ_BURST_WINDOW_SIZE,
            read_burst_required_spikes_in_window: DEFAULT_READ_BURST_REQUIRED_SPIKES_IN_WINDOW,
            read_burst_corroborated_threshold_fraction: DEFAULT_READ_BURST_CORROBORATED_THRESHOLD_FRACTION,
            read_burst_baseline_exemption_multiplier: DEFAULT_READ_BURST_BASELINE_EXEMPTION_MULTIPLIER,
            read_burst_baseline_warm_up_floor_bytes: DEFAULT_READ_BURST_BASELINE_WARM_UP_FLOOR_BYTES,
            read_burst_ema_alpha: DEFAULT_READ_BURST_EMA_ALPHA,
            c2_max_decode_depth: DEFAULT_C2_MAX_DECODE_DEPTH,
            electron_sweep_enabled: true,
            electron_sweep_interval_secs: DEFAULT_ELECTRON_SWEEP_INTERVAL_SECS,
            electron_sweep_roots,
            tamper: crate::tamper_config::TamperConfig::default(),
            trusted_publishers: crate::trust::default_trusted_publishers(),
            unsigned_user_writable_policy: UnsignedUserWritablePolicy::default(),
            repo_watch_roots: default_repo_watch_roots(&home),
            known_benign_event_sources: Vec::new(),
        }
    }
}

fn default_repo_watch_roots(home: &std::path::Path) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();
    #[cfg(windows)]
    roots.extend([r"C:\dev", r"D:\dev", r"C:\d"].map(PathBuf::from));
    roots.extend(["dev", "src", "projects", "Documents"].map(|dir| home.join(dir)));
    roots.push(PathBuf::from(env!("CARGO_MANIFEST_DIR")));
    roots
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

pub fn override_path(home: &std::path::Path) -> PathBuf {
    home.join(".goofedup").join("goofedup.config.json")
}
