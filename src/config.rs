// Central tunables. Every detector reads from here so the whole posture can
// be adjusted without hunting through module internals.

use std::path::PathBuf;

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

    /// Process names (case-insensitive, matched against sysinfo's reported
    /// process name) that are KNOWN to legitimately sustain high burst reads
    /// as their normal operating shape -- sync/backup/indexer tools, per the
    /// README's own "Known false-positive classes" section. A name match
    /// raises this process's effective absolute-burst threshold by
    /// `known_high_throughput_tool_multiplier`, it does NOT exempt the
    /// process from detection entirely: a name is not the same as the actor
    /// running under it, so a genuinely extreme read still alerts.
    pub known_high_throughput_tool_names: Vec<String>,
    pub known_high_throughput_tool_multiplier: f64,

    /// Parent-process names (case-insensitive) known to legitimately spawn
    /// interpreters with obfuscated-looking command lines as their normal
    /// operating shape -- AI-assistant/automation harnesses that pass
    /// scripts via -EncodedCommand to sidestep shell-escaping, per the
    /// README's own "Known false-positive classes" section (the exact shape
    /// a real attacker's living-off-the-land technique uses too). A match
    /// does NOT change severity or suppress the alert -- c2-shaped-process
    /// always fires CRITICAL regardless of parent, since a genuinely
    /// malicious payload could run under a parent name that happens to
    /// match this list too. A match is noted in the evidence text as triage
    /// context only.
    pub known_automation_parent_names: Vec<String>,

    /// How often to re-poll process list / connection table / firewall
    /// state (seconds). Real event sources are used where the platform
    /// offers them (notify for fs, WMI/ETW on Windows); this interval only
    /// governs the polling fallbacks (process/connection enumeration has no
    /// portable cross-OS push API without extra native deps per platform).
    pub poll_interval_secs: u64,

    pub log_path: PathBuf,
}

pub struct BootstrapEntry {
    pub search_root: PathBuf,
    pub file_name: &'static str,
    pub path_must_contain: &'static str,
    pub max_bytes: u64,
}

impl Config {
    pub fn default_for_platform() -> Self {
        let home = dirs_home();
        let log_path = home.join(".goofedup").join("goofedup.log");

        let mut bootstrap_watch = Vec::new();
        let mut backup_sibling_roots = Vec::new();
        let mut allowed_exec_roots = Vec::new();

        #[cfg(target_os = "windows")]
        {
            if let Ok(local) = std::env::var("LOCALAPPDATA") {
                let local = PathBuf::from(local);
                bootstrap_watch.push(BootstrapEntry {
                    search_root: local.join("Discord"),
                    file_name: "index.js",
                    path_must_contain: "discord_desktop_core",
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
            if let Ok(pf) = std::env::var("ProgramFiles") {
                allowed_exec_roots.push(PathBuf::from(pf));
            }
            if let Ok(pf86) = std::env::var("ProgramFiles(x86)") {
                allowed_exec_roots.push(PathBuf::from(pf86));
            }
            if let Ok(windir) = std::env::var("WINDIR") {
                allowed_exec_roots.push(PathBuf::from(windir));
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
            scan_distinct_ports_threshold: 20,
            scan_distinct_hosts_threshold: 15,
            scan_window_secs: 10,
            // 50MB read in a single ~3s poll interval is well past what any
            // normal interactive tool does in that window; a real bulk
            // build/backup/indexer legitimately sustains high read rates,
            // which is exactly what the relative-multiplier check below is
            // for -- this absolute floor exists to catch a fast scanner
            // even the very first time it's observed, before any baseline
            // exists to compare against.
            file_read_burst_absolute_bytes_per_poll: 50 * 1024 * 1024,
            file_read_burst_relative_multiplier: 8.0,
            known_high_throughput_tool_names: vec![
                "syncthing.exe".to_string(),
                "syncthing".to_string(),
                "onedrive.exe".to_string(),
                "dropbox.exe".to_string(),
                "backblaze.exe".to_string(),
                "rsync".to_string(),
                "robocopy.exe".to_string(),
            ],
            known_high_throughput_tool_multiplier: 6.0,
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
        }
    }
}

fn dirs_home() -> PathBuf {
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
