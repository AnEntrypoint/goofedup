// "Show recent alerts" opens the rendered history in Notepad rather than a
// custom-drawn window -- a bounded win32 rich-text renderer is a lot of
// surface for what is fundamentally a scrollable text view, and Notepad
// already gives search/copy/select for free.

use std::io::Write;
use windows::core::HSTRING;
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

/// Returns `Ok(())` once Notepad has genuinely been launched on the
/// rendered text, or `Err(reason)` naming exactly which step failed (temp
/// file create/write, or the ShellExecuteW launch itself) so the caller can
/// surface it to the user instead of a silent no-op click.
pub fn show(text: &str) -> Result<(), String> {
    let path = std::env::temp_dir().join("goofedup-alerts.log");
    let mut f = std::fs::File::create(&path)
        .map_err(|e| format!("could not create temp file {}: {e}", path.display()))?;
    f.write_all(text.as_bytes())
        .map_err(|e| format!("could not write temp file {}: {e}", path.display()))?;
    drop(f);

    let result = unsafe {
        ShellExecuteW(
            None,
            &HSTRING::from("open"),
            &HSTRING::from("notepad.exe"),
            &HSTRING::from(path.display().to_string()),
            None,
            SW_SHOWNORMAL,
        )
    };
    // ShellExecuteW returns an HINSTANCE that is actually an error code
    // when <= 32 -- a real, documented Win32 API quirk (SHELLEXECUTEINFO
    // docs), not a made-up threshold.
    if result.0 as isize <= 32 {
        return Err(format!("ShellExecuteW(notepad.exe) failed, code {}", result.0 as isize));
    }
    Ok(())
}
