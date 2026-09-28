use crate::config::dirs_home;
use crate::win_identity::{self, SID_ADMINISTRATORS, SID_SYSTEM, SID_USERS};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use windows::core::w;
use windows::Win32::Foundation::{GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::Console::{
    AttachConsole, GetStdHandle, SetStdHandle, ATTACH_PARENT_PROCESS, STD_ERROR_HANDLE,
    STD_OUTPUT_HANDLE,
};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
pub const DEFAULT_TASK_NAME: &str = "Goofedup";
const GUI_EXE_NAME: &str = "goofedup-gui.exe";
const CLI_EXE_NAME: &str = "goofedup.exe";
const TASK_XML_NAME: &str = "goofedup-task.xml";

pub struct Locations {
    pub task_name: String,
    pub install_dir: PathBuf,
    pub data_dir: PathBuf,
    pub isolated: bool,
}

enum Operation {
    CreateDir(PathBuf),
    CopyFile { from: PathBuf, to: PathBuf },
    WriteTaskXml { path: PathBuf, xml: String },
    Run { program: &'static str, args: Vec<String>, tolerate_failure: bool },
    RemoveRunKey,
    RemoveFile(PathBuf),
    RemoveDirIfEmpty(PathBuf),
}

fn program_files() -> PathBuf {
    PathBuf::from(std::env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".to_string()))
}

fn quote_if_needed(arg: &str) -> String {
    if arg.contains(' ') || arg.contains('(') {
        format!("\"{arg}\"")
    } else {
        arg.to_string()
    }
}

impl Operation {
    fn describe(&self) -> String {
        match self {
            Operation::CreateDir(p) => format!("create directory {}", p.display()),
            Operation::CopyFile { from, to } => format!("copy {} -> {}", from.display(), to.display()),
            Operation::WriteTaskXml { path, xml } => {
                format!("write task definition {} (UTF-16LE, {} chars):\n{xml}", path.display(), xml.chars().count())
            }
            Operation::Run { program, args, .. } => {
                format!("run {program} {}", args.iter().map(|a| quote_if_needed(a)).collect::<Vec<_>>().join(" "))
            }
            Operation::RemoveRunKey => {
                "delete registry value HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Goofedup".to_string()
            }
            Operation::RemoveFile(p) => format!("delete file {}", p.display()),
            Operation::RemoveDirIfEmpty(p) => format!("remove directory {} if empty", p.display()),
        }
    }

    fn execute(&self) -> Result<String, String> {
        match self {
            Operation::CreateDir(p) => std::fs::create_dir_all(p).map(|_| "ok".to_string()).map_err(|e| e.to_string()),
            Operation::CopyFile { from, to } => {
                std::fs::copy(from, to).map(|n| format!("{n} bytes")).map_err(|e| e.to_string())
            }
            Operation::WriteTaskXml { path, xml } => {
                let mut bytes = vec![0xFF, 0xFE];
                bytes.extend(xml.encode_utf16().flat_map(u16::to_le_bytes));
                std::fs::write(path, bytes).map(|_| "ok".to_string()).map_err(|e| e.to_string())
            }
            Operation::Run { program, args, tolerate_failure } => {
                let output = Command::new(program)
                    .args(args)
                    .creation_flags(CREATE_NO_WINDOW)
                    .output()
                    .map_err(|e| e.to_string())?;
                let text = format!(
                    "{}{}",
                    String::from_utf8_lossy(&output.stdout).trim(),
                    String::from_utf8_lossy(&output.stderr).trim()
                );
                if output.status.success() || *tolerate_failure {
                    Ok(text)
                } else {
                    Err(format!("exit {:?}: {text}", output.status.code()))
                }
            }
            Operation::RemoveRunKey => {
                super::autostart::remove_run_key();
                Ok("ok".to_string())
            }
            Operation::RemoveFile(p) => match std::fs::remove_file(p) {
                Ok(()) => Ok("ok".to_string()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok("already absent".to_string()),
                Err(e) => Err(e.to_string()),
            },
            Operation::RemoveDirIfEmpty(p) => match std::fs::remove_dir(p) {
                Ok(()) => Ok("ok".to_string()),
                Err(e) => Ok(format!("left in place ({e})")),
            },
        }
    }
}

pub fn locations(args: &[String]) -> Locations {
    let value_of = |flag: &str| args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).cloned();
    let task_name = value_of("--task-name");
    let install_dir = value_of("--install-dir");
    let data_dir = value_of("--data-dir");
    let isolated = task_name.is_some() || install_dir.is_some() || data_dir.is_some();
    Locations {
        task_name: task_name.unwrap_or_else(|| DEFAULT_TASK_NAME.to_string()),
        install_dir: install_dir.map(PathBuf::from).unwrap_or_else(|| program_files().join("goofedup")),
        data_dir: data_dir.map(PathBuf::from).unwrap_or_else(|| dirs_home().join(".goofedup")),
        isolated,
    }
}

fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

pub fn task_xml(task_name: &str, command: &Path, user_sid: &str) -> String {
    let command = xml_escape(&command.display().to_string());
    let sid = xml_escape(user_sid);
    let lines = [
        "<?xml version=\"1.0\" encoding=\"UTF-16\"?>".to_string(),
        "<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">".to_string(),
        "  <RegistrationInfo>".to_string(),
        "    <Author>goofedup</Author>".to_string(),
        "    <Description>goofedup structural-anomaly watcher, elevated at logon and restarted on failure</Description>".to_string(),
        format!("    <URI>\\{}</URI>", xml_escape(task_name)),
        "  </RegistrationInfo>".to_string(),
        "  <Triggers>".to_string(),
        "    <LogonTrigger>".to_string(),
        "      <Enabled>true</Enabled>".to_string(),
        format!("      <UserId>{sid}</UserId>"),
        "    </LogonTrigger>".to_string(),
        "  </Triggers>".to_string(),
        "  <Principals>".to_string(),
        "    <Principal id=\"Author\">".to_string(),
        format!("      <UserId>{sid}</UserId>"),
        "      <LogonType>InteractiveToken</LogonType>".to_string(),
        "      <RunLevel>HighestAvailable</RunLevel>".to_string(),
        "    </Principal>".to_string(),
        "  </Principals>".to_string(),
        "  <Settings>".to_string(),
        "    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>".to_string(),
        "    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>".to_string(),
        "    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>".to_string(),
        "    <StartWhenAvailable>true</StartWhenAvailable>".to_string(),
        "    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>".to_string(),
        "    <AllowStartOnDemand>true</AllowStartOnDemand>".to_string(),
        "    <Enabled>true</Enabled>".to_string(),
        "    <Hidden>false</Hidden>".to_string(),
        "    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>".to_string(),
        "    <Priority>7</Priority>".to_string(),
        "    <RestartOnFailure>".to_string(),
        "      <Interval>PT1M</Interval>".to_string(),
        "      <Count>999</Count>".to_string(),
        "    </RestartOnFailure>".to_string(),
        "  </Settings>".to_string(),
        "  <Actions Context=\"Author\">".to_string(),
        "    <Exec>".to_string(),
        format!("      <Command>{command}</Command>"),
        "    </Exec>".to_string(),
        "  </Actions>".to_string(),
        "</Task>".to_string(),
    ];
    lines.join("\r\n") + "\r\n"
}

fn icacls_lockdown(target: &Path, user_read_sid: &str) -> Operation {
    Operation::Run {
        program: "icacls",
        args: vec![
            target.display().to_string(),
            "/inheritance:r".to_string(),
            "/grant:r".to_string(),
            format!("*{SID_SYSTEM}:(OI)(CI)F"),
            format!("*{SID_ADMINISTRATORS}:(OI)(CI)F"),
            format!("*{user_read_sid}:(OI)(CI)RX"),
        ],
        tolerate_failure: false,
    }
}

fn schtasks(args: &[&str], tolerate_failure: bool) -> Operation {
    Operation::Run {
        program: "schtasks",
        args: args.iter().map(|a| a.to_string()).collect(),
        tolerate_failure,
    }
}

fn install_plan(loc: &Locations) -> Result<Vec<Operation>, String> {
    let running = std::env::current_exe().map_err(|e| format!("cannot locate the running exe: {e}"))?;
    let sid = win_identity::current_user_sid().ok_or("cannot read the current user SID")?;
    let installed_gui = loc.install_dir.join(GUI_EXE_NAME);
    let task_xml_path = loc.install_dir.join(TASK_XML_NAME);
    let mut plan = vec![
        Operation::CreateDir(loc.install_dir.clone()),
        icacls_lockdown(&loc.install_dir, SID_USERS),
        Operation::CopyFile { from: running.clone(), to: installed_gui.clone() },
    ];
    let sibling_cli = running.with_file_name(CLI_EXE_NAME);
    if sibling_cli.exists() {
        plan.push(Operation::CopyFile { from: sibling_cli, to: loc.install_dir.join(CLI_EXE_NAME) });
    }
    plan.push(Operation::CreateDir(loc.data_dir.clone()));
    plan.push(icacls_lockdown(&loc.data_dir, &sid));
    plan.push(Operation::WriteTaskXml {
        path: task_xml_path.clone(),
        xml: task_xml(&loc.task_name, &installed_gui, &sid),
    });
    plan.push(Operation::Run {
        program: "schtasks",
        args: vec![
            "/Create".to_string(),
            "/TN".to_string(),
            loc.task_name.clone(),
            "/XML".to_string(),
            task_xml_path.display().to_string(),
            "/F".to_string(),
        ],
        tolerate_failure: false,
    });
    if !loc.isolated {
        plan.push(Operation::RemoveRunKey);
    }
    Ok(plan)
}

fn uninstall_plan(loc: &Locations) -> Vec<Operation> {
    let mut plan = vec![
        schtasks(&["/End", "/TN", &loc.task_name], true),
        schtasks(&["/Delete", "/TN", &loc.task_name, "/F"], false),
        Operation::Run {
            program: "icacls",
            args: vec![loc.data_dir.display().to_string(), "/reset".to_string(), "/Q".to_string()],
            tolerate_failure: false,
        },
    ];
    for name in [GUI_EXE_NAME, CLI_EXE_NAME, TASK_XML_NAME] {
        plan.push(Operation::RemoveFile(loc.install_dir.join(name)));
    }
    plan.push(Operation::RemoveDirIfEmpty(loc.install_dir.clone()));
    plan
}

fn run_plan(plan: &[Operation], dry_run: bool) -> bool {
    let mut all_ok = true;
    for op in plan {
        if dry_run {
            println!("DRY-RUN would {}", op.describe());
            continue;
        }
        println!("{}", op.describe());
        match op.execute() {
            Ok(detail) if detail.is_empty() => println!("  ok"),
            Ok(detail) => println!("  ok: {detail}"),
            Err(reason) => {
                println!("  FAILED: {reason}");
                all_ok = false;
                break;
            }
        }
    }
    all_ok
}

fn attach_parent_console() {
    unsafe {
        let has_stdout = GetStdHandle(STD_OUTPUT_HANDLE)
            .map(|h| !h.is_invalid() && h != HANDLE::default())
            .unwrap_or(false);
        if has_stdout || AttachConsole(ATTACH_PARENT_PROCESS).is_err() {
            return;
        }
        if let Ok(console) = CreateFileW(
            w!("CONOUT$"),
            GENERIC_WRITE.0,
            FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE::default(),
        ) {
            if console != INVALID_HANDLE_VALUE {
                let _ = SetStdHandle(STD_OUTPUT_HANDLE, console);
                let _ = SetStdHandle(STD_ERROR_HANDLE, console);
            }
        }
    }
}

pub fn run_cli(args: &[String]) -> Option<i32> {
    let install = args.iter().any(|a| a == "--install-hardened");
    let uninstall = args.iter().any(|a| a == "--uninstall-hardened");
    if !install && !uninstall {
        return None;
    }
    attach_parent_console();
    let dry_run = args.iter().any(|a| a == "--dry-run");
    if install && uninstall {
        println!("choose one of --install-hardened or --uninstall-hardened");
        return Some(2);
    }
    if !dry_run && !win_identity::is_elevated() {
        println!(
            "goofedup: {} needs an elevated (Run as administrator) prompt because it writes to Program Files, sets ACLs and registers a HighestAvailable task. Nothing was changed. Add --dry-run to print the exact operations without elevation.",
            if install { "--install-hardened" } else { "--uninstall-hardened" }
        );
        return Some(2);
    }
    let loc = locations(args);
    let plan = if install {
        match install_plan(&loc) {
            Ok(plan) => plan,
            Err(reason) => {
                println!("goofedup: cannot build the install plan: {reason}");
                return Some(1);
            }
        }
    } else {
        uninstall_plan(&loc)
    };
    Some(if run_plan(&plan, dry_run) { 0 } else { 1 })
}

fn schtasks_output(args: &[&str]) -> Option<std::process::Output> {
    Command::new("schtasks").args(args).creation_flags(CREATE_NO_WINDOW).output().ok()
}

pub fn task_exists(task_name: &str) -> bool {
    schtasks_output(&["/Query", "/TN", task_name]).is_some_and(|o| o.status.success())
}

pub fn task_enabled(task_name: &str) -> bool {
    let Some(output) = schtasks_output(&["/Query", "/TN", task_name, "/XML"]) else { return false };
    if !output.status.success() {
        return false;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let settings = text.split("<Settings>").nth(1).unwrap_or("");
    !settings.contains("<Enabled>false</Enabled>")
}

pub fn set_task_enabled(task_name: &str, enabled: bool) -> bool {
    let flag = if enabled { "/ENABLE" } else { "/DISABLE" };
    schtasks_output(&["/Change", "/TN", task_name, flag]).is_some_and(|o| o.status.success())
}

pub fn install_default() -> bool {
    let loc = locations(&[]);
    match install_plan(&loc) {
        Ok(plan) => run_plan(&plan, false),
        Err(_) => false,
    }
}
