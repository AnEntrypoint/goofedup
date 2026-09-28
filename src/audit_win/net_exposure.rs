use super::pathing::Context;
use super::registry::{self, OpenError};
use super::shell::command_output;
use super::Finding;
use crate::alert::Level;
use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;

const PORTPROXY_CATEGORY: &str = "tamper-portproxy";
const LISTENER_CATEGORY: &str = "tamper-listener";
const PORTPROXY_FAMILIES: [&str; 4] = ["v4tov4", "v4tov6", "v6tov4", "v6tov6"];
const ALWAYS_ON_LISTENER_PORTS: [u16; 3] = [445, 135, 139];

pub fn is_sensitive_port(ctx: &Context, port: u16) -> bool {
    ctx.cfg.critical_exposure_ports.contains(&port) || ctx.cfg.admin_exposure_ports.contains(&port)
}

fn split_endpoint(text: &str) -> (String, Option<u16>) {
    match text.rsplit_once('/') {
        Some((address, port)) => (address.trim().to_string(), port.trim().parse().ok()),
        None => (text.trim().to_string(), None),
    }
}

fn is_loopback(address: &str) -> bool {
    address.starts_with("127.") || address == "::1" || address.eq_ignore_ascii_case("localhost") || address == "[::1]"
}

pub fn portproxy(ctx: &Context) -> Vec<Finding> {
    let mut findings = Vec::new();
    for family in PORTPROXY_FAMILIES {
        let path = format!("SYSTEM\\CurrentControlSet\\Services\\PortProxy\\{family}\\tcp");
        let key = match registry::open(HKEY_LOCAL_MACHINE, &path) {
            Ok(key) => key,
            Err(OpenError::Denied) => {
                findings.push(Finding::limited_visibility(PORTPROXY_CATEGORY, format!("HKLM\\{path} is not readable")));
                continue;
            }
            Err(OpenError::Missing) => continue,
        };
        for (listen, target) in key.values() {
            let (listen_address, listen_port) = split_endpoint(&listen);
            let (connect_address, connect_port) = split_endpoint(&target.as_display());
            let exposed = !is_loopback(&listen_address);
            let sensitive = [listen_port, connect_port].into_iter().flatten().any(|p| is_sensitive_port(ctx, p));
            let level = match (exposed, sensitive) {
                (true, true) => Level::Critical,
                (true, false) => Level::Warn,
                (false, _) => Level::Info,
            };
            let shown_listen = if listen_address.is_empty() { "*" } else { listen_address.as_str() };
            let scope = if exposed { "listens beyond loopback" } else { "loopback only" };
            let title = format!(
                "portproxy {family} {shown_listen}:{} -> {connect_address}:{} ({scope}{})",
                listen_port.map(|p| p.to_string()).unwrap_or_default(),
                connect_port.map(|p| p.to_string()).unwrap_or_default(),
                if sensitive { ", debugger/admin port" } else { "" }
            );
            findings.push(
                Finding::new(
                    level,
                    PORTPROXY_CATEGORY,
                    format!("portproxy:{family}:{listen}"),
                    title,
                    format!("HKLM\\{path} value '{listen}' = '{}'", target.as_display()),
                )
                .tracked(),
            );
        }
    }
    findings
}

struct Listener {
    address: String,
    port: u16,
    pid: u32,
}

fn parse_listeners(netstat_output: &str) -> Vec<Listener> {
    let mut listeners: Vec<Listener> = Vec::new();
    for line in netstat_output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 || !parts[0].eq_ignore_ascii_case("TCP") {
            continue;
        }
        if parts[2] != "0.0.0.0:0" && parts[2] != "[::]:0" {
            continue;
        }
        let Some((address, port)) = parts[1].rsplit_once(':') else { continue };
        let (Ok(port), Ok(pid)) = (port.parse::<u16>(), parts[4].parse::<u32>()) else { continue };
        let address = address.trim_matches(|c| c == '[' || c == ']').to_string();
        if is_loopback(&address) {
            continue;
        }
        if !listeners.iter().any(|l| l.port == port && l.address == address) {
            listeners.push(Listener { address, port, pid });
        }
    }
    listeners
}

pub fn listeners(ctx: &Context) -> Vec<Finding> {
    let Some(output) = command_output("netstat", &["-ano", "-p", "TCP"]) else { return Vec::new() };
    let v6 = command_output("netstat", &["-ano", "-p", "TCPv6"]).unwrap_or_default();
    let mut all = parse_listeners(&output);
    all.extend(parse_listeners(&v6));
    let relevant: Vec<&Listener> = all
        .iter()
        .filter(|l| {
            is_sensitive_port(ctx, l.port)
                && !(ALWAYS_ON_LISTENER_PORTS.contains(&l.port) && !ctx.cfg.critical_exposure_ports.contains(&l.port))
        })
        .collect();
    if relevant.is_empty() {
        return Vec::new();
    }
    let system = sysinfo::System::new_all();
    relevant
        .into_iter()
        .map(|l| {
            let process = system.process(sysinfo::Pid::from_u32(l.pid));
            let name = process.map(|p| p.name().to_string_lossy().to_string()).unwrap_or_else(|| "?".to_string());
            let exe = process
                .and_then(|p| p.exe().map(|e| e.display().to_string()))
                .unwrap_or_else(|| "unreadable (needs elevation)".to_string());
            let critical = ctx.cfg.critical_exposure_ports.contains(&l.port);
            Finding::new(
                if critical { Level::Critical } else { Level::Warn },
                LISTENER_CATEGORY,
                format!("listener:{}:{}", l.address, l.port),
                format!(
                    "{} port {} listening on {} by {name}",
                    if critical { "debugger/admin" } else { "remote-access" },
                    l.port,
                    l.address
                ),
                format!("exe={exe}"),
            )
            .tracked()
        })
        .collect()
}
