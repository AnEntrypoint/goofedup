use std::sync::Once;
use windows::core::{w, HSTRING, PCWSTR};
use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::Graphics::Gdi::{
    CreateFontW, DeleteObject, GetDC, GetDeviceCaps, GetStockObject, ReleaseDC, ANTIALIASED_QUALITY,
    DEFAULT_CHARSET, DEFAULT_PITCH, FF_DONTCARE, FW_NORMAL, HBRUSH, LOGPIXELSY, OUT_DEFAULT_PRECIS,
    CLIP_DEFAULT_PRECIS, WHITE_BRUSH,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Controls::WC_EDITW;
use windows::Win32::UI::Input::KeyboardAndMouse::VK_ESCAPE;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetClientRect, GetMessageW,
    GetWindow, LoadCursorW, PostQuitMessage, RegisterClassW, SendMessageW, SetWindowPos,
    SetWindowTextW, ShowWindow, TranslateMessage, CW_USEDEFAULT, ES_AUTOVSCROLL, ES_MULTILINE,
    ES_READONLY, GW_CHILD, IDC_ARROW, MSG, SW_SHOW, SWP_NOZORDER, WINDOW_STYLE, WM_CLOSE,
    WM_DESTROY, WM_KEYDOWN, WM_SETFONT, WM_SIZE, WNDCLASSW, WS_BORDER, WS_CHILD, WS_EX_CLIENTEDGE,
    WS_HSCROLL, WS_OVERLAPPEDWINDOW, WS_VISIBLE, WS_VSCROLL,
};

const CLASS_NAME: PCWSTR = w!("GoofedupAlertWindow");
const WINDOW_WIDTH: i32 = 760;
const WINDOW_HEIGHT: i32 = 560;
const EDIT_FONT_POINT_SIZE: i32 = 11;

static REGISTER_CLASS: Once = Once::new();

fn resize_child_edit_to_client_area(hwnd: HWND) {
    let mut rect = Default::default();
    unsafe {
        let _ = GetClientRect(hwnd, &mut rect);
        if let Ok(edit_hwnd) = GetWindow(hwnd, GW_CHILD) {
            if !edit_hwnd.is_invalid() {
                let _ = SetWindowPos(
                    edit_hwnd,
                    None,
                    0,
                    0,
                    rect.right - rect.left,
                    rect.bottom - rect.top,
                    SWP_NOZORDER,
                );
            }
        }
    }
}

unsafe extern "system" fn wnd_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_SIZE => {
            resize_child_edit_to_client_area(hwnd);
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
        WM_KEYDOWN if wparam.0 as u32 == VK_ESCAPE.0 as u32 => {
            let _ = DestroyWindow(hwnd);
            LRESULT(0)
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
            hbrBackground: HBRUSH(GetStockObject(WHITE_BRUSH).0),
            ..Default::default()
        };
        RegisterClassW(&wc);
    });
}

fn create_readable_edit_font(hwnd: HWND) -> windows::Win32::Graphics::Gdi::HFONT {
    unsafe {
        let dc = GetDC(hwnd);
        let dpi_y = GetDeviceCaps(dc, LOGPIXELSY);
        ReleaseDC(hwnd, dc);
        let height = -(EDIT_FONT_POINT_SIZE * dpi_y / 72);
        CreateFontW(
            height,
            0,
            0,
            0,
            FW_NORMAL.0 as i32,
            0,
            0,
            0,
            DEFAULT_CHARSET.0 as u32,
            OUT_DEFAULT_PRECIS.0 as u32,
            CLIP_DEFAULT_PRECIS.0 as u32,
            ANTIALIASED_QUALITY.0 as u32,
            (DEFAULT_PITCH.0 | FF_DONTCARE.0) as u32,
            w!("Segoe UI"),
        )
    }
}

fn create_alert_window_and_pump(title: &str, text: &str, result_tx: std::sync::mpsc::Sender<Result<(), String>>) {
    unsafe {
        let hinstance = match GetModuleHandleW(None) {
            Ok(h) => h,
            Err(e) => {
                let _ = result_tx.send(Err(format!("GetModuleHandleW failed: {e}")));
                return;
            }
        };
        register_class_once(hinstance);

        let hwnd = CreateWindowExW(
            Default::default(),
            CLASS_NAME,
            &HSTRING::from(title),
            WS_OVERLAPPEDWINDOW | WS_VISIBLE,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            WINDOW_WIDTH,
            WINDOW_HEIGHT,
            None,
            None,
            hinstance,
            None,
        );
        let Ok(hwnd) = hwnd else {
            let _ = result_tx.send(Err("CreateWindowExW failed for the alert window".to_string()));
            return;
        };
        if hwnd.is_invalid() {
            let _ = result_tx.send(Err("CreateWindowExW returned an invalid window handle".to_string()));
            return;
        }

        let mut rect = Default::default();
        let _ = GetClientRect(hwnd, &mut rect);
        let edit_style = WS_CHILD
            | WS_VISIBLE
            | WS_BORDER
            | WS_VSCROLL
            | WS_HSCROLL
            | WINDOW_STYLE(ES_MULTILINE as u32)
            | WINDOW_STYLE(ES_READONLY as u32)
            | WINDOW_STYLE(ES_AUTOVSCROLL as u32);
        let edit_hwnd = CreateWindowExW(
            WS_EX_CLIENTEDGE,
            WC_EDITW,
            &HSTRING::from(""),
            edit_style,
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
            let _ = result_tx.send(Err("CreateWindowExW failed for the text control".to_string()));
            let _ = DestroyWindow(hwnd);
            return;
        };
        if SetWindowTextW(edit_hwnd, &HSTRING::from(text)).is_err() {
            let _ = result_tx.send(Err("SetWindowTextW failed to set the alert text into the edit control".to_string()));
            let _ = DestroyWindow(hwnd);
            return;
        }

        let font = create_readable_edit_font(hwnd);
        let _ = SendMessageW(edit_hwnd, WM_SETFONT, WPARAM(font.0 as usize), LPARAM(1));

        let _ = ShowWindow(hwnd, SW_SHOW);
        let _ = SetWindowTextW(hwnd, &HSTRING::from(title));

        let _ = result_tx.send(Ok(()));

        let mut msg = MSG::default();
        while GetMessageW(&mut msg, None, 0, 0).into() {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        if !font.is_invalid() {
            let _ = DeleteObject(font);
        }
    }
}

pub fn show(title: &str, text: &str) -> Result<(), String> {
    let title = title.to_string();
    let text = text.to_string();
    let (tx, rx) = std::sync::mpsc::channel::<Result<(), String>>();

    std::thread::spawn(move || create_alert_window_and_pump(&title, &text, tx));

    rx.recv().unwrap_or_else(|_| Err("alert window thread exited before signaling readiness".to_string()))
}
