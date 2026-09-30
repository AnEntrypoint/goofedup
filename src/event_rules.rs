use crate::alert::Level;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

pub const CH_SECURITY: &str = "Security";
pub const CH_SYSTEM: &str = "System";
pub const CH_DEFENDER: &str = "Microsoft-Windows-Windows Defender/Operational";
pub const CH_SYSMON: &str = "Microsoft-Windows-Sysmon/Operational";
pub const CH_FIREWALL: &str = "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall";
pub const CH_TASKS: &str = "Microsoft-Windows-TaskScheduler/Operational";

const DEFENDER_SETTING_CHANGED: &str = "Defender protection setting changed";
const DEFENDER_CLOUD_FAILURE_TIMESTAMP_VALUE: &str = "\\spynet\\lastmapsfailuretimestring";

pub struct ChannelSpec {
    pub channel: &'static str,
    pub event_ids: &'static [u32],
    pub first_run_lookback_hours: u64,
}

pub static CHANNELS: [ChannelSpec; 6] = [
    ChannelSpec { channel: CH_SECURITY, event_ids: &[4697, 4698, 4702, 4720, 4728, 4732, 1102], first_run_lookback_hours: 1 },
    ChannelSpec { channel: CH_SYSTEM, event_ids: &[7045, 104], first_run_lookback_hours: 1 },
    ChannelSpec {
        channel: CH_DEFENDER,
        event_ids: &[1116, 1117, 1118, 1119, 5001, 5004, 5007, 5010, 5012],
        first_run_lookback_hours: 6,
    },
    ChannelSpec { channel: CH_SYSMON, event_ids: &[1, 8, 10, 25], first_run_lookback_hours: 1 },
    ChannelSpec { channel: CH_FIREWALL, event_ids: &[2004, 2005, 2006, 2097, 2099, 2052, 2059], first_run_lookback_hours: 1 },
    ChannelSpec { channel: CH_TASKS, event_ids: &[106, 140, 141], first_run_lookback_hours: 1 },
];

pub struct EventRecord {
    pub channel: String,
    pub event_id: u32,
    pub record_id: u64,
    pub time: String,
    pub fields: HashMap<String, String>,
}

impl EventRecord {
    fn field(&self, name: &str) -> &str {
        self.fields.get(name).map(String::as_str).unwrap_or("")
    }
}

pub struct Finding {
    pub level: Level,
    pub category: &'static str,
    pub message: String,
    pub evidence: String,
}

pub struct RuleContext<'a> {
    pub vendor_roots: &'a [PathBuf],
    pub known_benign_sources: &'a [String],
}

#[derive(PartialEq, Clone, Copy)]
enum PathTrust {
    Vendor,
    UserWritable,
    Other,
}

const USER_WRITABLE_FRAGMENTS: [&str; 8] = [
    "\\users\\",
    "\\appdata\\",
    "\\temp\\",
    "\\downloads\\",
    "$recycle.bin",
    "\\perflogs\\",
    "\\programdata\\",
    "\\windows\\tasks\\",
];

const STAGING_FRAGMENTS: [&str; 5] = [
    "\\appdata\\local\\temp\\",
    "\\users\\public\\",
    "$recycle.bin",
    "\\windows\\temp\\",
    "\\downloads\\",
];

const WORLD_WRITABLE_STAGING_FRAGMENTS: [&str; 3] = ["\\users\\public\\", "$recycle.bin", "\\windows\\temp\\"];

const LOLBINS: [&str; 14] = [
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "msbuild.exe",
    "installutil.exe",
    "wmic.exe",
    "curl.exe",
];

const EXPLOITABLE_PARENTS: [&str; 16] = [
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "onenote.exe",
    "msaccess.exe",
    "mspub.exe",
    "acrord32.exe",
    "acrobat.exe",
    "foxitreader.exe",
    "wmiprvse.exe",
    "w3wp.exe",
    "sqlservr.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
];

const BROWSER_PARENTS: [&str; 5] = ["chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "brave.exe"];

const LSASS_SYSTEM_SOURCES: [&str; 6] = [
    "\\windows\\system32\\",
    "\\windows\\syswow64\\",
    "\\program files\\windows defender\\",
    "\\programdata\\microsoft\\windows defender\\",
    "\\windows\\sysnative\\",
    "\\windows\\winsxs\\",
];

const EXPOSED_ADMIN_PORTS: [&str; 22] = [
    "22", "23", "135", "139", "445", "1433", "2375", "2376", "3306", "3389", "4444", "5005", "5432",
    "5555", "5900", "5985", "5986", "6379", "8000", "9222", "9229", "27017",
];

fn regex(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("static regex"))
}

fn unescape(text: &str) -> String {
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

pub fn parse_event(xml: &str, channel_hint: &str) -> Option<EventRecord> {
    static ID: OnceLock<Regex> = OnceLock::new();
    static RECORD: OnceLock<Regex> = OnceLock::new();
    static TIME: OnceLock<Regex> = OnceLock::new();
    static CHANNEL: OnceLock<Regex> = OnceLock::new();
    static DATA: OnceLock<Regex> = OnceLock::new();
    static USER_DATA: OnceLock<Regex> = OnceLock::new();

    let event_id = regex(&ID, r"<EventID[^>]*>(\d+)</EventID>").captures(xml)?[1].parse().ok()?;
    let record_id = regex(&RECORD, r"<EventRecordID>(\d+)</EventRecordID>").captures(xml)?[1].parse().ok()?;
    let time = regex(&TIME, r#"SystemTime=['"]([^'"]+)['"]"#)
        .captures(xml)
        .map(|c| c[1].to_string())
        .unwrap_or_default();
    let channel = regex(&CHANNEL, r"<Channel>([^<]*)</Channel>")
        .captures(xml)
        .map(|c| unescape(&c[1]))
        .unwrap_or_else(|| channel_hint.to_string());

    let mut fields = HashMap::new();
    for c in regex(&DATA, r#"(?s)<Data Name=['"]([^'"]*)['"]\s*>(.*?)</Data>"#).captures_iter(xml) {
        fields.insert(c[1].to_string(), unescape(&c[2]));
    }
    if let Some(start) = xml.find("<UserData>") {
        for c in regex(&USER_DATA, r"<(\w+)>([^<]*)</\w+>").captures_iter(&xml[start..]) {
            fields.entry(c[1].to_string()).or_insert_with(|| unescape(&c[2]));
        }
    }
    Some(EventRecord { channel, event_id, record_id, time, fields })
}

pub fn compact(text: &str, max: usize) -> String {
    let collapsed = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.chars().count() <= max {
        return collapsed;
    }
    let cut: String = collapsed.chars().take(max).collect();
    format!("{cut}...")
}

fn basename(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_lowercase()
}

fn expand_env(text: &str) -> String {
    static ENV: OnceLock<Regex> = OnceLock::new();
    let expanded = regex(&ENV, r"%(\w+)%").replace_all(text, |c: &regex::Captures| {
        std::env::var(&c[1]).unwrap_or_else(|_| c[0].to_string())
    });
    let windir = std::env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".to_string());
    let lowered = expanded.to_lowercase();
    if lowered.starts_with("\\systemroot\\") {
        return format!("{windir}{}", &expanded["\\systemroot".len()..]);
    }
    if lowered.starts_with("system32\\") {
        return format!("{windir}\\{expanded}");
    }
    expanded.into_owned()
}

fn first_executable(command_line: &str) -> String {
    let trimmed = expand_env(command_line.trim());
    if let Some(rest) = trimmed.strip_prefix('"') {
        return rest.split('"').next().unwrap_or("").to_string();
    }
    let lowered = trimmed.to_lowercase();
    for suffix in [".exe", ".sys", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js"] {
        if let Some(end) = lowered.find(suffix) {
            return trimmed[..end + suffix.len()].to_string();
        }
    }
    trimmed.split_whitespace().next().unwrap_or("").to_string()
}

fn path_trust(path: &str, ctx: &RuleContext) -> PathTrust {
    let lowered = path.to_lowercase().replace('/', "\\");
    let microsoft_programdata = lowered.contains("\\programdata\\microsoft\\");
    let user_writable = STAGING_FRAGMENTS.iter().any(|f| lowered.contains(f))
        || (!microsoft_programdata && USER_WRITABLE_FRAGMENTS.iter().any(|f| lowered.contains(f)));
    if user_writable {
        return PathTrust::UserWritable;
    }
    let under_vendor_root = ctx
        .vendor_roots
        .iter()
        .any(|root| lowered.starts_with(&root.to_string_lossy().to_lowercase().replace('/', "\\")));
    if under_vendor_root || microsoft_programdata {
        PathTrust::Vendor
    } else {
        PathTrust::Other
    }
}

fn is_staging_path(path: &str) -> bool {
    let lowered = path.to_lowercase();
    STAGING_FRAGMENTS.iter().any(|f| lowered.contains(f))
}

fn is_world_writable_staging_path(path: &str) -> bool {
    let lowered = path.to_lowercase();
    WORLD_WRITABLE_STAGING_FRAGMENTS.iter().any(|f| lowered.contains(f))
}

fn is_known_benign(path: &str, ctx: &RuleContext) -> bool {
    let name = basename(path);
    ctx.known_benign_sources.iter().any(|b| b.to_lowercase() == name)
}

fn finding(level: Level, category: &'static str, message: String, evidence: String) -> Option<Finding> {
    Some(Finding { level, category, message, evidence })
}

fn stamp(ev: &EventRecord) -> String {
    format!("channel={} event={} record={} time={}", ev.channel, ev.event_id, ev.record_id, ev.time)
}

fn downgrade_if_benign(mut f: Finding, source_paths: &[&str], ctx: &RuleContext) -> Finding {
    if source_paths.iter().any(|p| is_known_benign(p, ctx)) {
        f.level = Level::Info;
        f.message = format!("{} [known_benign_event_sources match -- recorded, not suppressed]", f.message);
    }
    f
}

pub fn classify(ev: &EventRecord, ctx: &RuleContext) -> Option<Finding> {
    match (ev.channel.as_str(), ev.event_id) {
        (CH_DEFENDER, 1116..=1119) => defender_detection(ev),
        (CH_DEFENDER, 5001) => finding(
            Level::Critical,
            "defender-tamper",
            "Defender real-time protection was disabled".to_string(),
            stamp(ev),
        ),
        (CH_DEFENDER, 5004) => finding(
            Level::Warn,
            "defender-tamper",
            "Defender real-time protection configuration changed".to_string(),
            format!("{} detail={}", stamp(ev), compact(&fields_summary(ev), 240)),
        ),
        (CH_DEFENDER, 5010 | 5012) => finding(
            Level::Warn,
            "defender-tamper",
            if ev.event_id == 5010 {
                "Defender scanning for malware and unwanted software is disabled".to_string()
            } else {
                "Defender scanning for viruses is disabled".to_string()
            },
            stamp(ev),
        ),
        (CH_DEFENDER, 5007) => defender_config_change(ev),
        (CH_SYSMON, 1) => sysmon_process_create(ev, ctx),
        (CH_SYSMON, 8) => sysmon_remote_thread(ev, ctx),
        (CH_SYSMON, 10) => sysmon_lsass_access(ev, ctx),
        (CH_SYSMON, 25) => sysmon_tampering(ev, ctx),
        (CH_SECURITY, 4698 | 4702) | (CH_TASKS, 106 | 140 | 141) => scheduled_task(ev, ctx),
        (CH_SECURITY, 4697) | (CH_SYSTEM, 7045) => service_installed(ev, ctx),
        (CH_SECURITY, 4720) => finding(
            Level::Warn,
            "account-change",
            format!("local user account created: {}", ev.field("TargetUserName")),
            format!("{} by={}\\{}", stamp(ev), ev.field("SubjectDomainName"), ev.field("SubjectUserName")),
        ),
        (CH_SECURITY, 4728 | 4732) => admin_group_member_added(ev),
        (CH_SECURITY, 1102) => finding(
            Level::Critical,
            "log-cleared",
            "Security audit log was cleared".to_string(),
            format!("{} by={}\\{}", stamp(ev), ev.field("SubjectDomainName"), ev.field("SubjectUserName")),
        ),
        (CH_SYSTEM, 104) => finding(
            Level::Critical,
            "log-cleared",
            format!("event log cleared: {}", ev.field("Channel")),
            format!("{} by={}\\{}", stamp(ev), ev.field("SubjectDomainName"), ev.field("SubjectUserName")),
        ),
        (CH_FIREWALL, 2059) => finding(
            Level::Critical,
            "firewall-rule",
            "all Windows Firewall rules were deleted (firewall reset)".to_string(),
            format!("{} modified_by={}", stamp(ev), ev.field("ModifyingApplication")),
        ),
        (CH_FIREWALL, 2004 | 2005 | 2006 | 2097 | 2099 | 2052) => firewall_rule(ev, ctx),
        _ => None,
    }
}

pub fn coalesce_batch(findings: Vec<Finding>) -> Vec<Finding> {
    let created: Vec<String> = findings
        .iter()
        .filter_map(|f| f.message.strip_prefix("scheduled task created: ").map(str::to_string))
        .collect();
    let findings: Vec<Finding> = findings
        .into_iter()
        .filter(|f| {
            f.message
                .strip_prefix("scheduled task updated: ")
                .is_none_or(|name| !created.iter().any(|c| c == name))
        })
        .collect();
    let (settings, others): (Vec<Finding>, Vec<Finding>) =
        findings.into_iter().partition(|f| f.message == DEFENDER_SETTING_CHANGED);
    let (rules, mut merged): (Vec<Finding>, Vec<Finding>) =
        others.into_iter().partition(|f| f.category == "firewall-rule" && f.level != Level::Critical);
    if let Some(one) = merge_group(settings, "defender-tamper", "Defender protection settings changed in one batch") {
        merged.push(one);
    }
    if let Some(one) = merge_group(rules, "firewall-rule", "firewall rule changes in one batch") {
        merged.push(one);
    }
    merged
}

fn merge_group(group: Vec<Finding>, category: &'static str, batch_message: &str) -> Option<Finding> {
    if group.len() <= 1 {
        return group.into_iter().next();
    }
    let level = group.iter().map(|f| f.level).max().unwrap_or(Level::Info);
    let messages_differ = group.iter().any(|f| f.message != group[0].message);
    let evidence = group
        .iter()
        .map(|f| if messages_differ { format!("{} :: {}", f.message, f.evidence) } else { f.evidence.clone() })
        .collect::<Vec<_>>()
        .join(" || ");
    Some(Finding {
        level,
        category,
        message: format!("{} {batch_message}", group.len()),
        evidence: compact(&evidence, 1800),
    })
}

fn fields_summary(ev: &EventRecord) -> String {
    let mut pairs: Vec<_> = ev.fields.iter().filter(|(_, v)| !v.is_empty()).collect();
    pairs.sort();
    pairs.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; ")
}

fn defender_detection(ev: &EventRecord) -> Option<Finding> {
    let verb = match ev.event_id {
        1116 => "detected",
        1117 => "took action against",
        1118 => "FAILED to take action against",
        _ => "CRITICALLY FAILED to take action against",
    };
    let threat = ev.field("Threat Name");
    finding(
        Level::Critical,
        "defender-detection",
        format!(
            "Defender {verb} {threat} ({}) at {}",
            ev.field("Severity Name"),
            compact(ev.field("Path"), 160)
        ),
        format!(
            "{} action={} user={} process={} category={}",
            stamp(ev),
            ev.field("Action Name"),
            ev.field("Detection User"),
            ev.field("Process Name"),
            ev.field("Category Name")
        ),
    )
}

fn defender_config_change(ev: &EventRecord) -> Option<Finding> {
    let new_value = ev.field("New Value");
    let old_value = ev.field("Old Value");
    let key = new_value.to_lowercase();
    let old_key = old_value.to_lowercase();
    let change = format!("{} old=[{}] new=[{}]", stamp(ev), compact(old_value, 200), compact(new_value, 200));
    if key.contains("\\exclusions\\") || old_key.contains("\\exclusions\\") {
        let removed = new_value.trim().is_empty();
        return finding(
            if removed { Level::Info } else { Level::Critical },
            "defender-tamper",
            if removed {
                "Defender exclusion removed".to_string()
            } else {
                "Defender exclusion added or changed -- anything under it is no longer scanned".to_string()
            },
            change,
        );
    }
    let turned_off = key.contains("= 0x1")
        && (key.contains("\\real-time protection\\disable")
            || key.contains("\\disableantispyware")
            || key.contains("\\disableantivirus"));
    if turned_off {
        return finding(Level::Critical, "defender-tamper", "Defender protection setting turned off".to_string(), change);
    }
    if key.contains(DEFENDER_CLOUD_FAILURE_TIMESTAMP_VALUE) || old_key.contains(DEFENDER_CLOUD_FAILURE_TIMESTAMP_VALUE) {
        return None;
    }
    let sensitive = [
        "\\real-time protection\\",
        "\\spynet\\",
        "\\exploit guard\\",
        "\\asr\\",
        "tamperprotection",
        "\\puaprotection",
        "\\mpengine\\",
        "\\controlled folder access",
        "\\network protection",
    ];
    if sensitive.iter().any(|s| key.contains(s)) {
        return finding(Level::Warn, "defender-tamper", DEFENDER_SETTING_CHANGED.to_string(), change);
    }
    None
}

fn sysmon_process_create(ev: &EventRecord, ctx: &RuleContext) -> Option<Finding> {
    let image = ev.field("Image");
    let parent = ev.field("ParentImage");
    let child = basename(image);
    let parent_name = basename(parent);
    let is_lolbin = LOLBINS.contains(&child.as_str());
    let evidence = format!(
        "{} image={} parent={} user={} cmd={}",
        stamp(ev),
        image,
        parent,
        ev.field("User"),
        compact(ev.field("CommandLine"), 300)
    );

    let (level, message) = if is_lolbin && EXPLOITABLE_PARENTS.contains(&parent_name.as_str()) {
        (Level::Critical, format!("{child} spawned by {parent_name} -- document/script-host/service lineage"))
    } else if is_lolbin
        && BROWSER_PARENTS.contains(&parent_name.as_str())
        && !ev.field("CommandLine").contains("chrome-extension://")
    {
        (Level::Warn, format!("{child} spawned by browser {parent_name}"))
    } else if is_lolbin && is_staging_path(parent) {
        (Level::Warn, format!("{child} spawned by {parent_name} running from a staging path"))
    } else if image.to_lowercase().contains("$recycle.bin") {
        (Level::Critical, format!("process executing from the Recycle Bin: {image}"))
    } else if is_world_writable_staging_path(image) && matches!(ev.field("Company").trim(), "" | "-") {
        (Level::Warn, format!("unsigned-looking process executing from a staging path: {image}"))
    } else {
        return None;
    };
    Some(downgrade_if_benign(
        Finding { level, category: "sysmon-lineage", message, evidence },
        &[image, parent],
        ctx,
    ))
}

fn sysmon_remote_thread(ev: &EventRecord, ctx: &RuleContext) -> Option<Finding> {
    let source = ev.field("SourceImage");
    let target = ev.field("TargetImage");
    if source.eq_ignore_ascii_case(target) {
        return None;
    }
    let level = if path_trust(source, ctx) == PathTrust::UserWritable { Level::Critical } else { Level::Warn };
    Some(downgrade_if_benign(
        Finding {
            level,
            category: "sysmon-remote-thread",
            message: format!("CreateRemoteThread from {source} into {target}"),
            evidence: format!(
                "{} source_user={} target_user={} start_address={} start_module={}",
                stamp(ev),
                ev.field("SourceUser"),
                ev.field("TargetUser"),
                ev.field("StartAddress"),
                ev.field("StartModule")
            ),
        },
        &[source],
        ctx,
    ))
}

fn sysmon_lsass_access(ev: &EventRecord, ctx: &RuleContext) -> Option<Finding> {
    let target = ev.field("TargetImage");
    if !target.to_lowercase().ends_with("\\lsass.exe") {
        return None;
    }
    let source = ev.field("SourceImage");
    let lowered = source.to_lowercase().replace('/', "\\");
    if LSASS_SYSTEM_SOURCES.iter().any(|s| lowered.contains(s)) {
        return None;
    }
    let granted = ev.field("GrantedAccess");
    let mask = u32::from_str_radix(granted.trim_start_matches("0x"), 16).unwrap_or(0);
    let can_read_memory = mask & 0x0010 != 0;
    Some(downgrade_if_benign(
        Finding {
            level: if can_read_memory { Level::Critical } else { Level::Warn },
            category: "sysmon-lsass-access",
            message: format!("{source} opened lsass.exe with access {granted}"),
            evidence: format!(
                "{} source_user={} memory_read={} call_trace={}",
                stamp(ev),
                ev.field("SourceUser"),
                can_read_memory,
                compact(ev.field("CallTrace"), 240)
            ),
        },
        &[source],
        ctx,
    ))
}

fn sysmon_tampering(ev: &EventRecord, ctx: &RuleContext) -> Option<Finding> {
    let image = ev.field("Image");
    Some(downgrade_if_benign(
        Finding {
            level: Level::Critical,
            category: "sysmon-tampering",
            message: format!("process tampering ({}): {image}", ev.field("Type")),
            evidence: format!("{} user={}", stamp(ev), ev.field("User")),
        },
        &[image],
        ctx,
    ))
}

fn task_command(content: &str) -> String {
    static COMMAND: OnceLock<Regex> = OnceLock::new();
    static ARGUMENTS: OnceLock<Regex> = OnceLock::new();
    let command = regex(&COMMAND, r"(?s)<Command>(.*?)</Command>")
        .captures(content)
        .map(|c| c[1].trim().to_string())
        .unwrap_or_default();
    let arguments = regex(&ARGUMENTS, r"(?s)<Arguments>(.*?)</Arguments>")
        .captures(content)
        .map(|c| c[1].trim().to_string())
        .unwrap_or_default();
    unescape(format!("{command} {arguments}").trim())
}

fn first_update_of_task_this_session(task_name: &str) -> bool {
    static UPDATED: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    UPDATED
        .get_or_init(|| Mutex::new(HashSet::new()))
        .lock()
        .map(|mut seen| seen.insert(task_name.to_lowercase()))
        .unwrap_or(true)
}

fn scheduled_task(ev: &EventRecord, ctx: &RuleContext) -> Option<Finding> {
    let name = ev.field("TaskName");
    let verb = match (ev.channel.as_str(), ev.event_id) {
        (_, 4698 | 106) => "created",
        (_, 4702 | 140) => "updated",
        _ => "deleted",
    };
    let content = ev.field("TaskContent");
    let command = task_command(content);
    let trust = if command.is_empty() { PathTrust::Other } else { path_trust(&first_executable(&command), ctx) };
    if name.starts_with("\\Microsoft\\") || (trust == PathTrust::Vendor && verb != "deleted") {
        return None;
    }
    let level = if trust == PathTrust::UserWritable { Level::Critical } else { Level::Warn };
    if verb == "updated" && level == Level::Warn && !first_update_of_task_this_session(name) {
        return None;
    }
    finding(
        level,
        "persistence-event",
        format!("scheduled task {verb}: {name}"),
        format!(
            "{} by={} command={}",
            stamp(ev),
            if ev.field("SubjectUserName").is_empty() { ev.field("UserContext") } else { ev.field("SubjectUserName") },
            compact(&command, 240)
        ),
    )
}

fn service_installed(ev: &EventRecord, ctx: &RuleContext) -> Option<Finding> {
    let image_path = if ev.event_id == 7045 { ev.field("ImagePath") } else { ev.field("ServiceFileName") };
    let trust = path_trust(&first_executable(image_path), ctx);
    if trust == PathTrust::Vendor {
        return None;
    }
    finding(
        if trust == PathTrust::UserWritable { Level::Critical } else { Level::Warn },
        "persistence-event",
        format!("service installed from a non-vendor path: {}", ev.field("ServiceName")),
        format!(
            "{} image_path={} account={} start_type={}",
            stamp(ev),
            compact(image_path, 240),
            ev.field("AccountName"),
            ev.field("StartType")
        ),
    )
}

fn admin_group_member_added(ev: &EventRecord) -> Option<Finding> {
    let sid = ev.field("TargetSid");
    let is_admin_group = sid == "S-1-5-32-544"
        || sid.ends_with("-512")
        || sid.ends_with("-519")
        || ev.field("TargetUserName").eq_ignore_ascii_case("Administrators");
    if !is_admin_group {
        return None;
    }
    finding(
        Level::Critical,
        "account-change",
        format!("member added to an administrators group: {}", ev.field("MemberName")),
        format!(
            "{} group={} member_sid={} by={}\\{}",
            stamp(ev),
            ev.field("TargetUserName"),
            ev.field("MemberSid"),
            ev.field("SubjectDomainName"),
            ev.field("SubjectUserName")
        ),
    )
}

fn firewall_rule(ev: &EventRecord, ctx: &RuleContext) -> Option<Finding> {
    let name = ev.field("RuleName");
    let modifier = ev.field("ModifyingApplication");
    if matches!(ev.event_id, 2006 | 2052) {
        let level = if path_trust(modifier, ctx) == PathTrust::UserWritable { Level::Warn } else { Level::Info };
        return finding(
            level,
            "firewall-rule",
            format!("firewall rule deleted: {name}"),
            format!("{} modified_by={modifier}", stamp(ev)),
        );
    }
    let inbound_allow = ev.field("Direction") == "1" && ev.field("Action") == "3";
    if !inbound_allow || ev.field("Active") == "0" {
        return None;
    }
    let ports = ev.field("LocalPorts");
    let program = ev.field("ApplicationPath");
    let exposes_admin_port = ports
        .split(',')
        .flat_map(|p| p.split('-'))
        .any(|p| EXPOSED_ADMIN_PORTS.contains(&p.trim()));
    let all_profiles = matches!(ev.field("Profiles"), "2147483647" | "7");
    let any_port_any_program = matches!(ports, "" | "*") && program.is_empty();
    let program_is_vendor = !program.is_empty() && path_trust(&first_executable(program), ctx) == PathTrust::Vendor;
    let level = if exposes_admin_port || any_port_any_program {
        Level::Critical
    } else if all_profiles && !program_is_vendor {
        Level::Warn
    } else {
        return None;
    };
    let verb = if matches!(ev.event_id, 2004 | 2097) { "added" } else { "changed" };
    finding(
        level,
        "firewall-rule",
        format!("inbound allow firewall rule {verb}: {name} ports={ports}"),
        format!(
            "{} profiles={} program={} active={} modified_by={modifier}",
            stamp(ev),
            ev.field("Profiles"),
            compact(ev.field("ApplicationPath"), 160),
            ev.field("Active")
        ),
    )
}
