// "Show recent alerts" opens the rendered history in Notepad rather than a
// custom-drawn window -- a bounded win32 rich-text renderer is a lot of
// surface for what is fundamentally a scrollable text view, and Notepad
// already gives search/copy/select for free.

use std::io::Write;
use windows::core::HSTRING;
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

pub fn show(text: &str) {
    let path = std::env::temp_dir().join("goofedup-alerts.log");
    let Ok(mut f) = std::fs::File::create(&path) else {
        return;
    };
    let _ = f.write_all(text.as_bytes());
    drop(f);

    unsafe {
        ShellExecuteW(
            None,
            &HSTRING::from("open"),
            &HSTRING::from("notepad.exe"),
            &HSTRING::from(path.display().to_string()),
            None,
            SW_SHOWNORMAL,
        );
    }
}
