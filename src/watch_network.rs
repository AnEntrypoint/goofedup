use crate::alert::AlertSink;
use crate::config::SharedConfig;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct Connection {
    pub pid: u32,
    pub process_name: String,
    pub remote_ip: String,
    pub remote_port: u16,
}

struct ProcWindow {
    first_seen: Instant,
    ports: HashSet<u16>,
    hosts: HashSet<String>,
    alerted: bool,
}

const HOST_SWEEP_MIN_PORT_VARIETY: usize = 3;
const FIREWALL_POLL_INTERVAL_MULTIPLIER: u64 = 5;

pub fn run(cfg_shared: SharedConfig, alerts: Arc<AlertSink>, running: Arc<AtomicBool>) {
    {
        let cfg = cfg_shared.read().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
        alerts.info(
            "network",
            format!(
                "watching outbound connections (poll every {}s) for scan behavior ({}+ ports or {}+ hosts within {}s from one process)",
                cfg.poll_interval_secs, cfg.scan_distinct_ports_threshold, cfg.scan_distinct_hosts_threshold, cfg.scan_window_secs
            ),
        );
    }

    let mut windows: HashMap<u32, ProcWindow> = HashMap::new();
    let mut known_connections: HashSet<(u32, String, u16)> = HashSet::new();

    while running.load(Ordering::Relaxed) {
        let cfg = cfg_shared.read().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
        std::thread::sleep(Duration::from_secs(cfg.poll_interval_secs));

        let conns = list_connections();
        crate::process_trust::on_connections(&alerts, &conns);
        let now = Instant::now();

        for c in &conns {
            let key = (c.pid, c.remote_ip.clone(), c.remote_port);
            let is_new = known_connections.insert(key);

            let w = windows.entry(c.pid).or_insert_with(|| ProcWindow {
                first_seen: now,
                ports: HashSet::new(),
                hosts: HashSet::new(),
                alerted: false,
            });
            if now.duration_since(w.first_seen) > Duration::from_secs(cfg.scan_window_secs) {
                *w = ProcWindow {
                    first_seen: now,
                    ports: HashSet::new(),
                    hosts: HashSet::new(),
                    alerted: false,
                };
            }
            w.ports.insert(c.remote_port);
            w.hosts.insert(c.remote_ip.clone());

            let is_known_high_throughput_tool = cfg
                .known_high_throughput_tool_names
                .iter()
                .any(|n| n.eq_ignore_ascii_case(&c.process_name));
            let effective_hosts_threshold = if is_known_high_throughput_tool {
                (cfg.scan_distinct_hosts_threshold as f64 * cfg.known_high_throughput_tool_multiplier) as usize
            } else {
                cfg.scan_distinct_hosts_threshold
            };

            let port_scan_shape = w.ports.len() >= cfg.scan_distinct_ports_threshold;
            let host_sweep_shape = w.hosts.len() >= effective_hosts_threshold
                && w.ports.len() >= HOST_SWEEP_MIN_PORT_VARIETY;

            if !w.alerted && (port_scan_shape || host_sweep_shape) {
                w.alerted = true;
                alerts.critical(
                    "network-scan",
                    format!(
                        "'{}' (PID {}) is opening connections to an unusual number of distinct destinations -- shaped like port/host scanning",
                        c.process_name, c.pid
                    ),
                    format!(
                        "distinct_ports={} distinct_hosts={} window={}s",
                        w.ports.len(),
                        w.hosts.len(),
                        cfg.scan_window_secs
                    ),
                );
            }

            if is_new {
                alerts.info(
                    "network-connection",
                    format!(
                        "'{}' (PID {}) -> {}:{}",
                        c.process_name, c.pid, c.remote_ip, c.remote_port
                    ),
                );
            }
        }

        windows.retain(|pid, _| conns.iter().any(|c| c.pid == *pid));
    }
}

pub fn run_firewall_drift(cfg_shared: SharedConfig, alerts: Arc<AlertSink>, running: Arc<AtomicBool>) {
    let mut last_state: HashMap<String, bool> = HashMap::new();
    for (name, enabled) in firewall_profile_state() {
        last_state.insert(name, enabled);
    }
    {
        let cfg = cfg_shared.read().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
        alerts.info(
            "firewall-drift",
            format!(
                "polling firewall state every {}s -- baseline: {}",
                cfg.poll_interval_secs * FIREWALL_POLL_INTERVAL_MULTIPLIER,
                last_state
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        );
    }

    while running.load(Ordering::Relaxed) {
        let cfg = cfg_shared.read().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
        std::thread::sleep(Duration::from_secs(cfg.poll_interval_secs * FIREWALL_POLL_INTERVAL_MULTIPLIER));
        for (name, enabled) in firewall_profile_state() {
            if let Some(prev) = last_state.get(&name) {
                if *prev && !enabled {
                    alerts.critical(
                        "firewall-drift",
                        format!("firewall profile '{name}' went from enabled to disabled"),
                        "a common malware self-defense move -- this exact gap let the real incident's C2 traffic through unblocked".to_string(),
                    );
                }
            }
            last_state.insert(name, enabled);
        }
    }
}

fn list_connections() -> Vec<Connection> {
    #[cfg(windows)]
    {
        windows_impl::list_connections()
    }
    #[cfg(target_os = "macos")]
    {
        unix_impl::list_connections_lsof()
    }
    #[cfg(target_os = "linux")]
    {
        unix_impl::list_connections_proc()
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        Vec::new()
    }
}

fn firewall_profile_state() -> Vec<(String, bool)> {
    #[cfg(windows)]
    {
        windows_impl::firewall_profile_state()
    }
    #[cfg(target_os = "macos")]
    {
        unix_impl::firewall_state_macos()
    }
    #[cfg(target_os = "linux")]
    {
        unix_impl::firewall_state_linux()
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        Vec::new()
    }
}

#[cfg(windows)]
mod windows_impl {
    use super::Connection;
    use crate::native_tcp::{self, MIB_TCP_STATE_ESTABLISHED};
    use windows::core::HSTRING;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE,
    };

    pub fn list_connections() -> Vec<Connection> {
        let pid_names = pid_name_map();
        native_tcp::tcp_rows()
            .into_iter()
            .filter(|row| row.state == MIB_TCP_STATE_ESTABLISHED && row.remote.is_ipv4())
            .filter_map(|row| {
                let remote_ip = row.remote.to_string();
                if is_local(&remote_ip) {
                    return None;
                }
                Some(Connection {
                    pid: row.pid,
                    process_name: pid_names.get(&row.pid).cloned().unwrap_or_default(),
                    remote_ip,
                    remote_port: row.remote_port,
                })
            })
            .collect()
    }

    fn pid_name_map() -> std::collections::HashMap<u32, String> {
        let mut sys = sysinfo::System::new();
        sys.refresh_processes_specifics(
            sysinfo::ProcessesToUpdate::All,
            true,
            sysinfo::ProcessRefreshKind::nothing(),
        );
        sys.processes()
            .iter()
            .map(|(pid, proc)| (pid.as_u32(), proc.name().to_string_lossy().to_string()))
            .collect()
    }

    fn is_local(ip: &str) -> bool {
        ip == "127.0.0.1" || ip == "::1" || ip.starts_with("169.254.") || ip == "0.0.0.0"
    }

    const FIREWALL_POLICY_KEY: &str = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";
    const FIREWALL_PROFILE_KEYS: [(&str, &str); 3] = [("DomainProfile", "Domain"), ("StandardProfile", "Private"), ("PublicProfile", "Public")];

    pub fn firewall_profile_state() -> Vec<(String, bool)> {
        FIREWALL_PROFILE_KEYS
            .iter()
            .filter_map(|(key, name)| firewall_profile_enabled(key).map(|enabled| (name.to_string(), enabled)))
            .collect()
    }

    fn firewall_profile_enabled(profile_key: &str) -> Option<bool> {
        let path = format!("{FIREWALL_POLICY_KEY}\\{profile_key}");
        let mut hkey = HKEY::default();
        unsafe {
            if RegOpenKeyExW(HKEY_LOCAL_MACHINE, &HSTRING::from(path), 0, KEY_QUERY_VALUE, &mut hkey).is_err() {
                return None;
            }
        }
        let mut data = [0u8; 4];
        let mut size = data.len() as u32;
        let status = unsafe {
            RegQueryValueExW(hkey, &HSTRING::from("EnableFirewall"), None, None, Some(data.as_mut_ptr()), Some(&mut size))
        };
        unsafe {
            let _ = RegCloseKey(hkey);
        }
        status.is_ok().then(|| u32::from_le_bytes(data) == 1)
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod unix_impl {
    use super::Connection;
    use std::process::Command;

    #[cfg(target_os = "macos")]
    pub fn list_connections_lsof() -> Vec<Connection> {
        let mut out = Vec::new();
        let Ok(o) = Command::new("lsof").args(["-i", "TCP", "-n", "-P", "-sTCP:ESTABLISHED"]).output() else {
            return out;
        };
        let Ok(text) = String::from_utf8(o.stdout) else {
            return out;
        };
        for line in text.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 9 {
                continue;
            }
            let process_name = parts[0].to_string();
            let Ok(pid) = parts[1].parse::<u32>() else {
                continue;
            };
            let name_field = parts[8];
            let Some(arrow) = name_field.find("->") else {
                continue;
            };
            let remote = &name_field[arrow + 2..];
            let Some((ip, port)) = split_host_port(remote) else {
                continue;
            };
            if is_local(&ip) {
                continue;
            }
            out.push(Connection {
                pid,
                process_name,
                remote_ip: ip,
                remote_port: port,
            });
        }
        out
    }

    #[cfg(target_os = "linux")]
    pub fn list_connections_proc() -> Vec<Connection> {
        let mut out = Vec::new();
        let Ok(tcp) = std::fs::read_to_string("/proc/net/tcp") else {
            return out;
        };
        let inode_to_conn = parse_proc_net_tcp(&tcp);
        let Ok(procs) = std::fs::read_dir("/proc") else {
            return out;
        };
        for entry in procs.flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            let fd_dir = entry.path().join("fd");
            let Ok(fds) = std::fs::read_dir(&fd_dir) else {
                continue;
            };
            let comm = std::fs::read_to_string(entry.path().join("comm"))
                .unwrap_or_default()
                .trim()
                .to_string();
            for fd in fds.flatten() {
                let Ok(link) = std::fs::read_link(fd.path()) else {
                    continue;
                };
                let link_str = link.to_string_lossy();
                if let Some(inode) = link_str.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']')) {
                    if let Some((ip, port)) = inode_to_conn.get(inode) {
                        if !is_local(ip) {
                            out.push(Connection {
                                pid,
                                process_name: comm.clone(),
                                remote_ip: ip.clone(),
                                remote_port: *port,
                            });
                        }
                    }
                }
            }
        }
        out
    }

    #[cfg(target_os = "linux")]
    fn parse_proc_net_tcp(text: &str) -> std::collections::HashMap<String, (String, u16)> {
        let mut map = std::collections::HashMap::new();
        const TCP_STATE_ESTABLISHED_HEX: &str = "01";
        for line in text.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 {
                continue;
            }
            let state = fields[3];
            if state != TCP_STATE_ESTABLISHED_HEX {
                continue;
            }
            let remote = fields[2];
            let inode = fields[9];
            if let Some((ip, port)) = decode_hex_addr(remote) {
                map.insert(inode.to_string(), (ip, port));
            }
        }
        map
    }

    #[cfg(target_os = "linux")]
    fn decode_hex_addr(s: &str) -> Option<(String, u16)> {
        let (addr_hex, port_hex) = s.split_once(':')?;
        let port = u16::from_str_radix(port_hex, 16).ok()?;
        let bytes = u32::from_str_radix(addr_hex, 16).ok()?;
        let ip = std::net::Ipv4Addr::from(bytes.swap_bytes());
        Some((ip.to_string(), port))
    }

    #[cfg(target_os = "macos")]
    fn split_host_port(s: &str) -> Option<(String, u16)> {
        let idx = s.rfind(':')?;
        let ip = s[..idx].to_string();
        let port = s[idx + 1..].parse().ok()?;
        Some((ip, port))
    }

    fn is_local(ip: &str) -> bool {
        ip == "127.0.0.1" || ip == "::1" || ip.starts_with("169.254.") || ip == "0.0.0.0"
    }

    #[cfg(target_os = "macos")]
    pub fn firewall_state_macos() -> Vec<(String, bool)> {
        let mut out = Vec::new();
        if let Ok(o) = Command::new("/usr/libexec/ApplicationFirewall/socketfilterfw")
            .args(["--getglobalstate"])
            .output()
        {
            if let Ok(text) = String::from_utf8(o.stdout) {
                let enabled = text.to_lowercase().contains("enabled") && !text.to_lowercase().contains("disabled");
                out.push(("application-firewall".to_string(), enabled));
            }
        }
        out
    }

    #[cfg(target_os = "linux")]
    pub fn firewall_state_linux() -> Vec<(String, bool)> {
        let mut out = Vec::new();
        if let Ok(o) = Command::new("ufw").args(["status"]).output() {
            if let Ok(text) = String::from_utf8(o.stdout) {
                if text.to_lowercase().contains("status:") {
                    let enabled = text.to_lowercase().contains("status: active");
                    out.push(("ufw".to_string(), enabled));
                    return out;
                }
            }
        }
        const IPTABLES_EMPTY_CHAIN_HEADER_LINES: usize = 8;
        if let Ok(o) = Command::new("iptables").args(["-L", "-n"]).output() {
            if let Ok(text) = String::from_utf8(o.stdout) {
                let has_rules = text.lines().count() > IPTABLES_EMPTY_CHAIN_HEADER_LINES;
                out.push(("iptables".to_string(), has_rules));
            }
        }
        out
    }
}
