// One goofedup-gui at a time: a named mutex held for the process lifetime.
// A second launch sees the mutex already owned and exits immediately rather
// than spawning a duplicate set of watcher threads.

use windows::core::HSTRING;
use windows::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS};
use windows::Win32::System::Threading::CreateMutexW;

const MUTEX_NAME: &str = "Global\\AnEntrypoint.Goofedup.SingleInstance";

/// Returns Some(guard) if this is the only instance; the guard must be kept
/// alive for the process lifetime (drop releases the mutex). None means
/// another instance already holds it.
pub struct InstanceGuard {
    _handle: windows::Win32::Foundation::HANDLE,
}

pub fn acquire() -> Option<InstanceGuard> {
    unsafe {
        let handle = CreateMutexW(None, true, &HSTRING::from(MUTEX_NAME)).ok()?;
        if GetLastError() == ERROR_ALREADY_EXISTS {
            return None;
        }
        Some(InstanceGuard { _handle: handle })
    }
}
