// "Show recent alerts"/"Show Config" open a real native Win32 window
// (title bar, close button, read-only scrollable multiline text) instead of
// shelling out to notepad.exe on a temp file -- the user explicitly asked
// for this over the prior notepad-based approach for a more polished,
// self-contained experience. The window's own message pump runs on a
// dedicated thread so it never blocks the tray icon's own event loop.

use std::sync::Once;
use windows::core::{w, HSTRING, PCWSTR};
use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::Graphics::Gdi::{CreateFontW, GetDeviceCaps, GetDC, GetStockObject, ReleaseDC, LOGPIXELSY, WHITE_BRUSH};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Controls::WC_EDITW;
use windows::Win32::UI::Input::KeyboardAndMouse::VK_ESCAPE;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetClientRect, GetMessageW,
    LoadCursorW, PostQuitMessage, RegisterClassW, SendMessageW, SetWindowTextW, ShowWindow,
    TranslateMessage, CW_USEDEFAULT, ES_AUTOVSCROLL, ES_MULTILINE, ES_READONLY, IDC_ARROW, MSG,
    SW_SHOW, WM_CLOSE, WM_DESTROY, WM_KEYDOWN, WM_SETFONT, WM_SIZE, WNDCLASSW, WS_BORDER,
    WS_CHILD, WS_EX_CLIENTEDGE, WS_HSCROLL, WS_OVERLAPPEDWINDOW, WS_VISIBLE, WS_VSCROLL,
};

const CLASS_NAME: PCWSTR = w!("GoofedupAlertWindow");

static REGISTER_CLASS: Once = Once::new();

unsafe extern "system" fn wnd_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_SIZE => {
            // Resize the child edit control to fill the client area on
            // every resize, including the initial WM_SIZE fired at creation.
            let mut rect = Default::default();
            let _ = GetClientRect(hwnd, &mut rect);
            let edit_hwnd = windows::Win32::UI::WindowsAndMessaging::GetWindow(
                hwnd,
                windows::Win32::UI::WindowsAndMessaging::GW_CHILD,
            );
            if let Ok(edit_hwnd) = edit_hwnd {
                if !edit_hwnd.is_invalid() {
                    let _ = windows::Win32::UI::WindowsAndMessaging::SetWindowPos(
                        edit_hwnd,
                        None,
                        0,
                        0,
                        rect.right - rect.left,
                        rect.bottom - rect.top,
                        windows::Win32::UI::WindowsAndMessaging::SWP_NOZORDER,
                    );
                }
            }
            LRESULT(0)
        }
        WM_CLOSE => {
            let _ = DestroyWindow(hwnd);
            LRESULT(0)
        }
        WM_DESTROY => {
            PostQuitMessage(0);
            LRESULT(0)
        }
        WM_KEYDOWN => {
            if wparam.0 as u32 == VK_ESCAPE.0 as u32 {
                let _ = DestroyWindow(hwnd);
                LRESULT(0)
            } else {
                DefWindowProcW(hwnd, msg, wparam, lparam)
            }
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

fn register_class_once(hinstance: windows::Win32::Foundation::HMODULE) {
    REGISTER_CLASS.call_once(|| unsafe {
        let wc = WNDCLASSW {
            lpfnWndProc: Some(wnd_proc),
            hInstance: hinstance.into(),
            lpszClassName: CLASS_NAME,
            hCursor: LoadCursorW(None, IDC_ARROW).unwrap_or_default(),
            hbrBackground: windows::Win32::Graphics::Gdi::HBRUSH(GetStockObject(WHITE_BRUSH).0),
            ..Default::default()
        };
        RegisterClassW(&wc);
    });
}

/// Opens a real native window titled `title` showing `text` in a read-only,
/// scrollable multiline edit control. Runs the window's message pump on a
/// dedicated detached thread so the caller (the tray event loop) never
/// blocks -- returns as soon as the window is created and visible, or
/// `Err(reason)` if window/control creation itself failed.
pub fn show(title: &str, text: &str) -> Result<(), String> {
    let title = title.to_string();
    let text = text.to_string();
    let (tx, rx) = std::sync::mpsc::channel::<Result<(), String>>();

    std::thread::spawn(move || unsafe {
        let hinstance = match GetModuleHandleW(None) {
            Ok(h) => h,
            Err(e) => {
                let _ = tx.send(Err(format!("GetModuleHandleW failed: {e}")));
                return;
            }
        };
        register_class_once(hinstance);

        let hwnd = CreateWindowExW(
            Default::default(),
            CLASS_NAME,
            &HSTRING::from(title.as_str()),
            WS_OVERLAPPEDWINDOW | WS_VISIBLE,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            760,
            560,
            None,
            None,
            hinstance,
            None,
        );
        let Ok(hwnd) = hwnd else {
            let _ = tx.send(Err("CreateWindowExW failed for the alert window".to_string()));
            return;
        };
        if hwnd.is_invalid() {
            let _ = tx.send(Err("CreateWindowExW returned an invalid window handle".to_string()));
            return;
        }

        let mut rect = Default::default();
        let _ = GetClientRect(hwnd, &mut rect);
        let edit_hwnd = CreateWindowExW(
            WS_EX_CLIENTEDGE,
            WC_EDITW,
            &HSTRING::from(text.as_str()),
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | WS_HSCROLL
                | windows::Win32::UI::WindowsAndMessaging::WINDOW_STYLE(ES_MULTILINE as u32)
                | windows::Win32::UI::WindowsAndMessaging::WINDOW_STYLE(ES_READONLY as u32)
                | windows::Win32::UI::WindowsAndMessaging::WINDOW_STYLE(ES_AUTOVSCROLL as u32),
            0,
            0,
            rect.right - rect.left,
            rect.bottom - rect.top,
            hwnd,
            None,
            hinstance,
            None,
        );
        let Ok(edit_hwnd) = edit_hwnd else {
            let _ = tx.send(Err("CreateWindowExW failed for the text control".to_string()));
            let _ = DestroyWindow(hwnd);
            return;
        };

        // Segoe UI at a readable size instead of the tiny default system
        // font -- the user's "super user friendly" bar means legible text,
        // not the smallest thing that technically renders.
        let dc = GetDC(hwnd);
        let dpi_y = GetDeviceCaps(dc, LOGPIXELSY);
        ReleaseDC(hwnd, dc);
        let point_size = 11i32;
        let height = -(point_size * dpi_y / 72);
        let font = CreateFontW(
            height,
            0,
            0,
            0,
            windows::Win32::Graphics::Gdi::FW_NORMAL.0 as i32,
            0,
            0,
            0,
            windows::Win32::Graphics::Gdi::DEFAULT_CHARSET.0 as u32,
            windows::Win32::Graphics::Gdi::OUT_DEFAULT_PRECIS.0 as u32,
            windows::Win32::Graphics::Gdi::CLIP_DEFAULT_PRECIS.0 as u32,
            windows::Win32::Graphics::Gdi::ANTIALIASED_QUALITY.0 as u32,
            (windows::Win32::Graphics::Gdi::DEFAULT_PITCH.0 | windows::Win32::Graphics::Gdi::FF_DONTCARE.0) as u32,
            w!("Segoe UI"),
        );
        let _ = SendMessageW(edit_hwnd, WM_SETFONT, WPARAM(font.0 as usize), LPARAM(1));

        let _ = ShowWindow(hwnd, SW_SHOW);
        let _ = SetWindowTextW(hwnd, &HSTRING::from(title.as_str()));

        let _ = tx.send(Ok(()));

        let mut msg = MSG::default();
        while GetMessageW(&mut msg, None, 0, 0).into() {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    });

    rx.recv().unwrap_or_else(|_| Err("alert window thread exited before signaling readiness".to_string()))
}
