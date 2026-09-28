use super::hardened;
use crate::win_identity;
use std::path::PathBuf;
use windows::core::HSTRING;
use windows::Win32::System::Registry::{
    RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY,
    HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_WRITE, REG_SZ,
};

const RUN_KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
const VALUE_NAME: &str = "Goofedup";

fn exe_path() -> Option<PathBuf> {
    std::env::current_exe().ok()
}

fn nul_terminated_utf16(text: &str) -> Vec<u16> {
    let mut wide: Vec<u16> = HSTRING::from(text).as_wide().to_vec();
    wide.push(0);
    wide
}

fn run_key_present() -> bool {
    unsafe {
        let mut hkey = HKEY::default();
        if RegOpenKeyExW(HKEY_CURRENT_USER, &HSTRING::from(RUN_KEY), 0, KEY_QUERY_VALUE, &mut hkey).is_err() {
            return false;
        }
        let found = RegQueryValueExW(hkey, &HSTRING::from(VALUE_NAME), None, None, None, None).is_ok();
        let _ = RegCloseKey(hkey);
        found
    }
}

fn set_run_key() -> bool {
    let Some(exe) = exe_path() else { return false };
    let exe_str = exe.display().to_string();
    unsafe {
        let mut hkey = HKEY::default();
        if RegOpenKeyExW(HKEY_CURRENT_USER, &HSTRING::from(RUN_KEY), 0, KEY_WRITE, &mut hkey).is_err() {
            return false;
        }
        let wide = nul_terminated_utf16(&exe_str);
        let byte_slice = std::slice::from_raw_parts(wide.as_ptr() as *const u8, wide.len() * 2);
        let ok = RegSetValueExW(hkey, &HSTRING::from(VALUE_NAME), 0, REG_SZ, Some(byte_slice)).is_ok();
        let _ = RegCloseKey(hkey);
        ok
    }
}

pub fn remove_run_key() -> bool {
    unsafe {
        let mut hkey = HKEY::default();
        if RegOpenKeyExW(HKEY_CURRENT_USER, &HSTRING::from(RUN_KEY), 0, KEY_WRITE, &mut hkey).is_err() {
            return false;
        }
        let ok = RegDeleteValueW(hkey, &HSTRING::from(VALUE_NAME)).is_ok();
        let _ = RegCloseKey(hkey);
        ok
    }
}

pub fn is_enabled() -> bool {
    run_key_present() || (hardened::task_exists(hardened::DEFAULT_TASK_NAME) && hardened::task_enabled(hardened::DEFAULT_TASK_NAME))
}

pub fn enable() -> bool {
    if hardened::task_exists(hardened::DEFAULT_TASK_NAME) {
        return hardened::set_task_enabled(hardened::DEFAULT_TASK_NAME, true);
    }
    if win_identity::is_elevated() {
        return hardened::install_default();
    }
    set_run_key()
}

pub fn disable() -> bool {
    let task_disabled = !hardened::task_exists(hardened::DEFAULT_TASK_NAME)
        || hardened::set_task_enabled(hardened::DEFAULT_TASK_NAME, false);
    let run_key_cleared = !run_key_present() || remove_run_key();
    task_disabled && run_key_cleared
}
