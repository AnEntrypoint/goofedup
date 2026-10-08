use std::io::Read;
use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const POWERSHELL_TIMEOUT: Duration = Duration::from_secs(25);

fn run_bounded(mut command: Command, limit: Duration) -> Option<String> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .ok()?;
    let mut stdout = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut captured = Vec::new();
        stdout.read_to_end(&mut captured).ok().map(|_| captured)
    });
    let deadline = Instant::now() + limit;
    let finished = loop {
        match child.try_wait() {
            Ok(Some(_)) => break true,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            _ => break false,
        }
    };
    if !finished {
        let _ = child.kill();
        let _ = child.wait();
        return None;
    }
    String::from_utf8(reader.join().ok()??).ok()
}

pub fn powershell_json(script: &str) -> Option<serde_json::Value> {
    let mut command = Command::new("powershell");
    command.args(["-NoProfile", "-NonInteractive", "-Command", script]);
    serde_json::from_str(run_bounded(command, POWERSHELL_TIMEOUT)?.trim()).ok()
}

pub fn json_items(value: &serde_json::Value) -> Vec<&serde_json::Value> {
    match value {
        serde_json::Value::Array(items) => items.iter().collect(),
        serde_json::Value::Null => Vec::new(),
        other => vec![other],
    }
}

