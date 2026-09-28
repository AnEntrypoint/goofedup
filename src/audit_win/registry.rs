use windows::core::{HSTRING, PWSTR};
use windows::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegEnumValueW, RegOpenKeyExW, RegQueryInfoKeyW, HKEY, KEY_READ,
};

const REG_SZ: u32 = 1;
const REG_EXPAND_SZ: u32 = 2;
const REG_BINARY: u32 = 3;
const REG_DWORD: u32 = 4;
const REG_MULTI_SZ: u32 = 7;
const ERROR_ACCESS_DENIED: u32 = 5;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Text(String),
    Number(u32),
    List(Vec<String>),
    Bytes(Vec<u8>),
}

impl Value {
    pub fn text(&self) -> Option<&str> {
        match self {
            Value::Text(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn number(&self) -> Option<u32> {
        match self {
            Value::Number(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_display(&self) -> String {
        match self {
            Value::Text(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            Value::List(l) => l.join(" | "),
            Value::Bytes(b) => format!("<{} bytes>", b.len()),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum OpenError {
    Missing,
    Denied,
}

pub struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        unsafe {
            let _ = RegCloseKey(self.0);
        }
    }
}

pub fn open(root: HKEY, path: &str) -> Result<Key, OpenError> {
    let mut handle = HKEY::default();
    let status = unsafe { RegOpenKeyExW(root, &HSTRING::from(path), 0, KEY_READ, &mut handle) };
    match status.0 {
        0 => Ok(Key(handle)),
        ERROR_ACCESS_DENIED => Err(OpenError::Denied),
        _ => Err(OpenError::Missing),
    }
}

fn decode_text(data: &[u8]) -> String {
    let units: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&c| c != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

fn decode(kind: u32, data: &[u8]) -> Value {
    match kind {
        REG_SZ | REG_EXPAND_SZ => Value::Text(decode_text(data)),
        REG_DWORD if data.len() >= 4 => Value::Number(u32::from_le_bytes([data[0], data[1], data[2], data[3]])),
        REG_MULTI_SZ => {
            let units: Vec<u16> = data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            Value::List(
                units
                    .split(|&u| u == 0)
                    .filter(|s| !s.is_empty())
                    .map(String::from_utf16_lossy)
                    .collect(),
            )
        }
        REG_BINARY => Value::Bytes(data.to_vec()),
        _ => Value::Bytes(data.to_vec()),
    }
}

impl Key {
    pub fn open_child(&self, name: &str) -> Result<Key, OpenError> {
        open(self.0, name)
    }

    pub fn subkeys(&self) -> Vec<String> {
        let mut count = 0u32;
        let mut longest = 0u32;
        unsafe {
            let _ = RegQueryInfoKeyW(
                self.0,
                PWSTR::null(),
                None,
                None,
                Some(&mut count),
                Some(&mut longest),
                None,
                None,
                None,
                None,
                None,
                None,
            );
        }
        let mut names = Vec::new();
        for index in 0..count {
            let mut buffer = vec![0u16; longest as usize + 2];
            let mut length = buffer.len() as u32;
            let status = unsafe {
                RegEnumKeyExW(self.0, index, PWSTR(buffer.as_mut_ptr()), &mut length, None, PWSTR::null(), None, None)
            };
            if status.0 == 0 {
                names.push(String::from_utf16_lossy(&buffer[..length as usize]));
            }
        }
        names
    }

    pub fn values(&self) -> Vec<(String, Value)> {
        let mut count = 0u32;
        let mut longest_name = 0u32;
        let mut longest_data = 0u32;
        unsafe {
            let _ = RegQueryInfoKeyW(
                self.0,
                PWSTR::null(),
                None,
                None,
                None,
                None,
                None,
                Some(&mut count),
                Some(&mut longest_name),
                Some(&mut longest_data),
                None,
                None,
            );
        }
        let mut values = Vec::new();
        for index in 0..count {
            let mut name = vec![0u16; longest_name as usize + 2];
            let mut name_length = name.len() as u32;
            let mut data = vec![0u8; longest_data as usize + 2];
            let mut data_length = data.len() as u32;
            let mut kind = 0u32;
            let status = unsafe {
                RegEnumValueW(
                    self.0,
                    index,
                    PWSTR(name.as_mut_ptr()),
                    &mut name_length,
                    None,
                    Some(&mut kind),
                    Some(data.as_mut_ptr()),
                    Some(&mut data_length),
                )
            };
            if status.0 == 0 {
                values.push((
                    String::from_utf16_lossy(&name[..name_length as usize]),
                    decode(kind, &data[..data_length as usize]),
                ));
            }
        }
        values
    }

    pub fn value(&self, name: &str) -> Option<Value> {
        self.values().into_iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v)
    }
}

pub fn read_value(root: HKEY, path: &str, name: &str) -> Option<Value> {
    open(root, path).ok()?.value(name)
}
