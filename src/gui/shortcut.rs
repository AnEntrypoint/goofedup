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

pub fn ensure_registered() {
    let Some(path) = shortcut_path() else { return };
    if path.exists() {
        return;
    }
    let Some(exe) = std::env::current_exe().ok() else { return };

    unsafe {
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
