use regex::Regex;
use std::sync::OnceLock;

pub const NON_SOURCE_ASSET_EXTENSIONS: &[&str] = &[
    "woff", "woff2", "ttf", "eot", "otf", "png", "jpg", "jpeg", "gif", "webp", "bmp", "svg", "ico",
    "mp3", "mp4", "pdf", "txt", "json", "map", "bin", "dat",
];

const JS_CARRIER_EXTENSIONS: &[&str] = &[
    "woff", "woff2", "ttf", "eot", "otf", "png", "jpg", "jpeg", "gif", "webp", "bmp", "svg", "ico",
];

pub fn is_js_carrier(path: &std::path::Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| JS_CARRIER_EXTENSIONS.iter().any(|known| known.eq_ignore_ascii_case(ext)))
}

#[derive(Default)]
pub struct CommandShape {
    pub executed_asset: Option<String>,
    pub downloads: bool,
    pub pipes_download_to_interpreter: bool,
    pub inline_code: bool,
    pub obfuscated_execution: bool,
    pub uses_powershell: bool,
}

impl CommandShape {
    pub fn dropper_reasons(&self) -> Vec<String> {
        let mut reasons = self.payload_reasons();
        if self.uses_powershell {
            reasons.push("invokes powershell".to_string());
        }
        reasons
    }

    pub fn payload_reasons(&self) -> Vec<String> {
        let mut reasons = Vec::new();
        if let Some(asset) = &self.executed_asset {
            reasons.push(format!("executes non-source asset '{asset}' with an interpreter"));
        }
        if self.pipes_download_to_interpreter {
            reasons.push("pipes a download straight into an interpreter".to_string());
        } else if self.downloads {
            reasons.push("downloads from the network".to_string());
        }
        if self.obfuscated_execution {
            reasons.push("decodes/evaluates encoded content".to_string());
        }
        reasons
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Interpreter {
    Node,
    Python,
    PowerShell,
    Cmd,
    Shell,
    Other,
}

fn download_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\b(curl|wget|invoke-webrequest|invoke-restmethod|iwr|irm|bitsadmin|start-bitstransfer)\b|\bcertutil\b[^\n]*-(urlcache|verifyctl)",
        )
        .unwrap()
    })
}

fn pipe_to_interpreter_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\b(curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n]*?\|\s*(sudo\s+)?(bash|sh|zsh|iex|invoke-expression|node|python3?|pwsh|powershell)\b",
        )
        .unwrap()
    })
}

fn obfuscation_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)frombase64string|\bbase64\s+(-d|-di|--decode)\b|\batob\s*\(|['"]base64['"]|\biex\b|\binvoke-expression\b|\bcertutil\b[^\n]*-decode"#,
        )
        .unwrap()
    })
}

fn inline_code_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)\b((?:node|nodejs|deno|bun)(?:\.exe)?[^&|;\n]*?\s(?:-e|--eval|-p|--print)|python[0-9.]*(?:\.exe)?[^&|;\n]*?\s-c)\s+("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')"#,
        )
        .unwrap()
    })
}

pub fn pipes_download_to_interpreter(text: &str) -> bool {
    pipe_to_interpreter_re().is_match(text)
}

pub fn asset_extension(token: &str) -> Option<&'static str> {
    let trimmed = token.trim_end_matches([';', ',', ')', '\'', '"']);
    let file_name = trimmed.rsplit(['/', '\\']).next()?;
    let (_, ext) = file_name.rsplit_once('.')?;
    NON_SOURCE_ASSET_EXTENSIONS
        .iter()
        .find(|known| known.eq_ignore_ascii_case(ext))
        .copied()
}

fn interpreter_of(token: &str) -> Option<Interpreter> {
    let base = token.rsplit(['/', '\\']).next()?.to_ascii_lowercase();
    let name = base.strip_suffix(".exe").unwrap_or(&base);
    match name {
        "node" | "nodejs" | "deno" | "bun" => Some(Interpreter::Node),
        "py" | "pythonw" => Some(Interpreter::Python),
        n if n.starts_with("python") => Some(Interpreter::Python),
        "powershell" | "pwsh" => Some(Interpreter::PowerShell),
        "cmd" => Some(Interpreter::Cmd),
        "bash" | "sh" | "zsh" => Some(Interpreter::Shell),
        "cscript" | "wscript" | "mshta" | "ruby" | "perl" => Some(Interpreter::Other),
        _ => None,
    }
}

fn is_redirect(token: &str) -> bool {
    let without_fd = token.trim_start_matches(|c: char| c.is_ascii_digit());
    without_fd.starts_with('>') || without_fd.starts_with('<')
}

fn script_argument<'a>(
    kind: Interpreter,
    args: &[&'a str],
    shape: &mut CommandShape,
) -> Option<&'a str> {
    let mut iter = args.iter().copied();
    while let Some(arg) = iter.next() {
        let lower = arg.to_ascii_lowercase();
        match kind {
            Interpreter::Node => {
                if matches!(lower.as_str(), "-e" | "--eval" | "-p" | "--print") {
                    shape.inline_code = true;
                    return None;
                }
                if matches!(
                    lower.as_str(),
                    "-r" | "--require" | "--import" | "--loader" | "--experimental-loader" | "--conditions"
                ) {
                    iter.next();
                    continue;
                }
                if lower.starts_with('-') {
                    continue;
                }
                return Some(arg);
            }
            Interpreter::Python => {
                if lower == "-c" {
                    shape.inline_code = true;
                    return None;
                }
                if lower == "-m" {
                    return None;
                }
                if matches!(lower.as_str(), "-w" | "-x") {
                    iter.next();
                    continue;
                }
                if lower.starts_with('-') {
                    continue;
                }
                return Some(arg);
            }
            Interpreter::PowerShell => {
                match lower.as_str() {
                    "-file" | "-f" => return iter.next(),
                    "-command" | "-c" => return None,
                    "-encodedcommand" | "-enc" | "-e" | "-ec" => {
                        shape.obfuscated_execution = true;
                        return None;
                    }
                    "-executionpolicy" | "-ep" | "-windowstyle" | "-w" | "-workingdirectory" => {
                        iter.next();
                        continue;
                    }
                    _ => {}
                }
                if lower.starts_with('-') {
                    continue;
                }
                return Some(arg);
            }
            Interpreter::Cmd => {
                if lower.starts_with('/') && lower.len() <= 3 {
                    continue;
                }
                return Some(arg);
            }
            Interpreter::Shell => {
                if lower == "-c" {
                    return None;
                }
                if lower.starts_with('-') {
                    continue;
                }
                return Some(arg);
            }
            Interpreter::Other => {
                if lower.starts_with('-') {
                    continue;
                }
                return Some(arg);
            }
        }
    }
    None
}

fn analyze_segment(segment: &str, shape: &mut CommandShape) {
    let cleaned = segment.replace(['"', '\''], " ");
    let tokens: Vec<&str> = cleaned.split_whitespace().filter(|t| !is_redirect(t)).collect();
    if let Some(first) = tokens.first() {
        if interpreter_of(first).is_none() && asset_extension(first).is_some() {
            shape.executed_asset = Some((*first).to_string());
        }
    }
    for (index, token) in tokens.iter().enumerate() {
        let Some(kind) = interpreter_of(token) else {
            continue;
        };
        if kind == Interpreter::PowerShell {
            shape.uses_powershell = true;
        }
        let Some(script) = script_argument(kind, &tokens[index + 1..], shape) else {
            continue;
        };
        if asset_extension(script).is_some() && shape.executed_asset.is_none() {
            shape.executed_asset = Some(script.to_string());
        }
    }
}

pub fn analyze(command: &str) -> CommandShape {
    let redacted = inline_code_re().replace_all(command, "$1 INLINE").into_owned();
    let mut shape = CommandShape {
        downloads: download_re().is_match(command),
        pipes_download_to_interpreter: pipe_to_interpreter_re().is_match(command),
        obfuscated_execution: obfuscation_re().is_match(command),
        ..CommandShape::default()
    };
    for segment in redacted.split(|c| matches!(c, '&' | '|' | ';' | '(' | ')' | '\n' | '\r' | '`')) {
        analyze_segment(segment, &mut shape);
    }
    shape
}
