// Optional launch-at-login via the per-user Run registry key -- no admin
// rights required, matches how most tray utilities offer autostart.

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

pub fn is_enabled() -> bool {
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

pub fn enable() -> bool {
    let Some(exe) = exe_path() else { return false };
    let exe_str = exe.display().to_string();
    unsafe {
        let mut hkey = HKEY::default();
        if RegOpenKeyExW(HKEY_CURRENT_USER, &HSTRING::from(RUN_KEY), 0, KEY_WRITE, &mut hkey).is_err() {
            return false;
        }
        // REG_SZ requires the buffer to include a trailing UTF-16 NUL;
        // HSTRING::as_wide() does not include one in its reported length,
        // so build an explicitly NUL-terminated Vec rather than reading
        // past the end of its slice (undefined behavior even when the
        // extra byte happens to be zero).
        let mut wide: Vec<u16> = HSTRING::from(exe_str).as_wide().to_vec();
        wide.push(0);
        let byte_slice = std::slice::from_raw_parts(wide.as_ptr() as *const u8, wide.len() * 2);
        let ok = RegSetValueExW(hkey, &HSTRING::from(VALUE_NAME), 0, REG_SZ, Some(byte_slice)).is_ok();
        let _ = RegCloseKey(hkey);
        ok
    }
}

pub fn disable() -> bool {
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
