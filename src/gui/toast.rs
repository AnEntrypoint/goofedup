// Native Windows toast notifications via WinRT ToastNotificationManager.
// Unpackaged win32 apps need an explicit AppUserModelID registered before
// any toast is shown, or the OS silently drops it -- init() must run once
// before any call to show().

use windows::core::HSTRING;
use windows::Data::Xml::Dom::XmlDocument;
use windows::UI::Notifications::{ToastNotification, ToastNotificationManager};
use windows::Win32::UI::Shell::SetCurrentProcessExplicitAppUserModelID;

pub const AUMID: &str = "AnEntrypoint.Goofedup";

pub fn init() {
    unsafe {
        let _ = SetCurrentProcessExplicitAppUserModelID(&HSTRING::from(AUMID));
    }
}

pub fn show(title: &str, body: &str) {
    let xml = format!(
        "<toast><visual><binding template=\"ToastGeneric\"><text>{}</text><text>{}</text></binding></visual></toast>",
        xml_escape(title),
        xml_escape(body)
    );

    let Ok(doc) = XmlDocument::new() else {
        return;
    };
    if doc.LoadXml(&HSTRING::from(xml.as_str())).is_err() {
        return;
    }
    let Ok(notification) = ToastNotification::CreateToastNotification(&doc) else {
        return;
    };
    if let Ok(notifier) = ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(AUMID)) {
        let _ = notifier.Show(&notification);
    }
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
