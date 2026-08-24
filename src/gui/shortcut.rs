// Start Menu shortcut carrying goofedup's AppUserModelID -- unpackaged win32
// apps need this alongside SetCurrentProcessExplicitAppUserModelID
// (toast::init) for Windows to actually render a toast at all: without a
// registered AUMID source (an MSIX identity, or a Start Menu shortcut whose
// System.AppUserModel.ID property matches the process's own), Windows
// silently drops every notifier.Show() call -- no error, Setting still
// reports Enabled, the toast just never appears. Live-confirmed: this
// project had toast::init() calling SetCurrentProcessExplicitAppUserModelID
// since early on, but never created this shortcut, so toasts never worked
// at all (only the tray icon's red-on-critical color change was ever
// visible) despite the toast call path itself being exercised on every
// Warn/Critical alert with no error surfaced anywhere.

use windows::core::{Interface, HSTRING, PCWSTR};
use windows::Win32::Storage::EnhancedStorage::PKEY_AppUserModel_ID;
use windows::Win32::System::Com::StructuredStorage::{InitPropVariantFromStringVector, PropVariantClear};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, IPersistFile, CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED,
};
use windows::Win32::UI::Shell::PropertiesSystem::IPropertyStore;
use windows::Win32::UI::Shell::{IShellLinkW, ShellLink};

use crate::gui::toast::AUMID;

const SHORTCUT_NAME: &str = "goofedup.lnk";

fn shortcut_path() -> Option<std::path::PathBuf> {
    let appdata = std::env::var("APPDATA").ok()?;
    Some(
        std::path::PathBuf::from(appdata)
            .join("Microsoft\\Windows\\Start Menu\\Programs")
            .join(SHORTCUT_NAME),
    )
}

/// Creates (or repairs) the Start Menu shortcut carrying goofedup's AUMID,
/// if it doesn't already exist -- idempotent, cheap to call unconditionally
/// on every startup. Best-effort: any failure just means toasts stay silent
/// (same as before this existed), never a crash or a blocking error.
pub fn ensure_registered() {
    let Some(path) = shortcut_path() else { return };
    if path.exists() {
        return;
    }
    let Some(exe) = std::env::current_exe().ok() else { return };

    unsafe {
        // COINIT_APARTMENTTHREADED matches tray-icon/toast's own COM usage
        // on this thread; CoInitializeEx returning RPC_E_CHANGED_MODE or
        // S_FALSE (already initialized) is fine, only a hard error aborts.
        let init = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        if init.is_err() && init != windows::Win32::Foundation::RPC_E_CHANGED_MODE {
            return;
        }

        let Ok(link): windows::core::Result<IShellLinkW> = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER) else {
            return;
        };
        let exe_wide = HSTRING::from(exe.display().to_string());
        if link.SetPath(&exe_wide).is_err() {
            return;
        }
        let _ = link.SetDescription(&HSTRING::from("goofedup -- structural-anomaly watcher"));

        let Ok(store): windows::core::Result<IPropertyStore> = link.cast() else {
            return;
        };
        let Ok(aumid_variant) = InitPropVariantFromStringVector(Some(&[PCWSTR(HSTRING::from(AUMID).as_ptr())])) else {
            return;
        };
        let set_ok = store.SetValue(&PKEY_AppUserModel_ID, &aumid_variant).is_ok();
        let mut variant = aumid_variant;
        let _ = PropVariantClear(&mut variant);
        if !set_ok || store.Commit().is_err() {
            return;
        }

        let Ok(persist): windows::core::Result<IPersistFile> = link.cast() else {
            return;
        };
        let path_wide = HSTRING::from(path.display().to_string());
        let _ = persist.Save(&path_wide, true);
    }
}
