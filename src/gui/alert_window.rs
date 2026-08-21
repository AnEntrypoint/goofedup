use crate::gui::history::EntrySnapshot;
use crate::gui::icon::{shield_hicon, IconState};
use std::sync::Once;
use windows::core::{w, HSTRING, PCWSTR};
use windows::Win32::Foundation::{COLORREF, HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::{
    CreateFontW, CreateSolidBrush, DeleteObject, DrawTextW, Ellipse, FillRect, GetDC,
    GetDeviceCaps, ReleaseDC, SelectObject, SetBkMode, SetTextColor, ANTIALIASED_QUALITY,
    DEFAULT_CHARSET, DEFAULT_PITCH, DT_LEFT, DT_SINGLELINE, DT_VCENTER, FF_DONTCARE, FW_BOLD,
    FW_NORMAL, LOGPIXELSY, OUT_DEFAULT_PRECIS, TRANSPARENT, CLIP_DEFAULT_PRECIS,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Controls::{
    ImageList_Create, InitCommonControlsEx, DRAWITEMSTRUCT, ICC_LISTVIEW_CLASSES, ILC_COLOR32,
    INITCOMMONCONTROLSEX, LVCFMT_LEFT, LVCOLUMNW, LVITEMW, LVCF_FMT, LVCF_SUBITEM, LVCF_TEXT,
    LVCF_WIDTH, LVIF_TEXT, LVM_INSERTCOLUMNW, LVM_INSERTITEMW, LVM_SETIMAGELIST, LVM_SETITEMW,
    LVS_EX_FULLROWSELECT, LVS_EX_GRIDLINES, LVS_OWNERDRAWFIXED, LVS_REPORT, LVS_SINGLESEL,
    LVSIL_SMALL, NMHDR, NMLISTVIEW, ODT_LISTVIEW, WC_LISTVIEWW, WC_STATICW, LVN_ITEMCHANGED,
};
use windows::Win32::UI::Input::KeyboardAndMouse::VK_ESCAPE;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyIcon, DestroyWindow, DispatchMessageW, GetClientRect,
    GetMessageW, GetWindowLongPtrW, HICON, LoadCursorW, PostQuitMessage, RegisterClassW,
    SendMessageW, SetWindowLongPtrW, SetWindowPos, SetWindowTextW, ShowWindow, TranslateMessage,
    CW_USEDEFAULT, GWLP_USERDATA, HMENU, ICON_BIG, ICON_SMALL, MSG, SW_SHOW, SWP_NOZORDER,
    WINDOW_STYLE, WM_CLOSE, WM_CTLCOLORSTATIC, WM_DESTROY, WM_DRAWITEM, WM_GETMINMAXINFO,
    WM_KEYDOWN, WM_NOTIFY, WM_SETFONT, WM_SETICON, WM_SIZE, WNDCLASSW, WS_BORDER, WS_CHILD,
    WS_EX_CLIENTEDGE, WS_OVERLAPPEDWINDOW, WS_VISIBLE, WS_VSCROLL,
};

const SS_CENTER: WINDOW_STYLE = WINDOW_STYLE(1);
const SS_CENTERIMAGE: WINDOW_STYLE = WINDOW_STYLE(512);

const CLASS_NAME: PCWSTR = w!("GoofedupAlertWindow");
const WINDOW_WIDTH: i32 = 820;
const WINDOW_HEIGHT: i32 = 600;
const MIN_WINDOW_WIDTH: i32 = 520;
const MIN_WINDOW_HEIGHT: i32 = 360;
const BASE_FONT_POINT_SIZE: i32 = 11;

const LIST_ID: i32 = 1001;
const DETAILS_ID: i32 = 1002;
const EMPTY_LABEL_ID: i32 = 1003;

const CRITICAL_BG: (u8, u8, u8) = (254, 226, 226);
const CRITICAL_FG: (u8, u8, u8) = (153, 27, 27);
const WARN_BG: (u8, u8, u8) = (255, 251, 235);
const WARN_FG: (u8, u8, u8) = (146, 64, 14);
const HEADER_BG: (u8, u8, u8) = (238, 242, 247);
const HEADER_FG: (u8, u8, u8) = (30, 41, 59);
const DESCRIPTION_FG: (u8, u8, u8) = (100, 116, 139);

// Solid (non-pastel) fill for the severity badge dot -- distinct from the
// pastel CRITICAL_BG/WARN_BG row tint so the badge reads as a deliberate
// indicator against the row, not just more of the same wash of color.
const CRITICAL_BADGE: (u8, u8, u8) = (220, 38, 38);
const WARN_BADGE: (u8, u8, u8) = (217, 119, 6);
const INFO_BADGE: (u8, u8, u8) = (100, 116, 139);
const BADGE_DIAMETER: i32 = 10;
const CELL_LEFT_PADDING: i32 = 10;
const CELL_RIGHT_PADDING: i32 = 10;
const ROW_HEIGHT_PX: i32 = 26;

static REGISTER_CLASS: Once = Once::new();

#[derive(Clone, Copy)]
enum RowKind {
    Alert(crate::alert::Level),
    SectionHeader,
    Description,
    Plain,
}

struct WindowState {
    row_kinds: Vec<RowKind>,
    details: Vec<String>,
    base_font: windows::Win32::Graphics::Gdi::HFONT,
    bold_font: windows::Win32::Graphics::Gdi::HFONT,
    owner_draw_column_widths: Vec<i32>,
    caller_owned_destroy_icon: HICON,
}

fn rgb(c: (u8, u8, u8)) -> COLORREF {
    COLORREF((c.0 as u32) | ((c.1 as u32) << 8) | ((c.2 as u32) << 16))
}

unsafe fn window_state(hwnd: HWND) -> Option<&'static mut WindowState> {
    let ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut WindowState;
    if ptr.is_null() {
        None
    } else {
        Some(&mut *ptr)
    }
}

fn resize_children_to_client_area(hwnd: HWND) {
    unsafe {
        let mut rect = RECT::default();
        let _ = GetClientRect(hwnd, &mut rect);
        let width = rect.right - rect.left;
        let height = rect.bottom - rect.top;

        if let Ok(list_hwnd) = windows::Win32::UI::WindowsAndMessaging::GetDlgItem(hwnd, LIST_ID) {
            if !list_hwnd.is_invalid() {
                let details_exists =
                    !windows::Win32::UI::WindowsAndMessaging::GetDlgItem(hwnd, DETAILS_ID)
                        .map(|h| h.is_invalid())
                        .unwrap_or(true);
                let list_height = if details_exists { (height * 2) / 3 } else { height };
                let _ = SetWindowPos(list_hwnd, None, 0, 0, width, list_height, SWP_NOZORDER);
                if details_exists {
                    if let Ok(details_hwnd) =
                        windows::Win32::UI::WindowsAndMessaging::GetDlgItem(hwnd, DETAILS_ID)
                    {
                        let _ = SetWindowPos(
                            details_hwnd,
                            None,
                            0,
                            list_height,
                            width,
                            height - list_height,
                            SWP_NOZORDER,
                        );
                    }
                }
            }
        }
        if let Ok(empty_hwnd) = windows::Win32::UI::WindowsAndMessaging::GetDlgItem(hwnd, EMPTY_LABEL_ID) {
            if !empty_hwnd.is_invalid() {
                let _ = SetWindowPos(empty_hwnd, None, 0, 0, width, height, SWP_NOZORDER);
            }
        }
    }
}

unsafe extern "system" fn wnd_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_SIZE => {
            resize_children_to_client_area(hwnd);
            LRESULT(0)
        }
        WM_GETMINMAXINFO => {
            let mmi = lparam.0 as *mut windows::Win32::UI::WindowsAndMessaging::MINMAXINFO;
            if !mmi.is_null() {
                (*mmi).ptMinTrackSize.x = MIN_WINDOW_WIDTH;
                (*mmi).ptMinTrackSize.y = MIN_WINDOW_HEIGHT;
            }
            LRESULT(0)
        }
        WM_CTLCOLORSTATIC => {
            let hdc = windows::Win32::Graphics::Gdi::HDC(wparam.0 as *mut core::ffi::c_void);
            SetTextColor(hdc, rgb((120, 120, 120)));
            let _ = SetBkMode(hdc, TRANSPARENT);
            LRESULT(windows::Win32::Graphics::Gdi::GetStockObject(windows::Win32::Graphics::Gdi::WHITE_BRUSH).0 as isize)
        }
        WM_DRAWITEM => {
            let dis = lparam.0 as *const DRAWITEMSTRUCT;
            if dis.is_null() || (*dis).CtlType != ODT_LISTVIEW {
                return DefWindowProcW(hwnd, msg, wparam, lparam);
            }
            if let Some(state) = window_state(hwnd) {
                let idx = (*dis).itemID as usize;
                let kind = state.row_kinds.get(idx).copied().unwrap_or(RowKind::Plain);
                let (bg, fg) = match kind {
                    RowKind::Alert(crate::alert::Level::Critical) => (CRITICAL_BG, CRITICAL_FG),
                    RowKind::Alert(crate::alert::Level::Warn) => (WARN_BG, WARN_FG),
                    RowKind::Alert(_) => ((255, 255, 255), (0, 0, 0)),
                    RowKind::SectionHeader => (HEADER_BG, HEADER_FG),
                    RowKind::Description => ((255, 255, 255), DESCRIPTION_FG),
                    RowKind::Plain => ((255, 255, 255), (0, 0, 0)),
                };
                let font = if matches!(kind, RowKind::SectionHeader) && !state.bold_font.is_invalid() {
                    state.bold_font
                } else {
                    state.base_font
                };
                let old_font = windows::Win32::Graphics::Gdi::SelectObject((*dis).hDC, font);
                let brush = CreateSolidBrush(rgb(bg));
                let _ = FillRect((*dis).hDC, &(*dis).rcItem, brush);
                let _ = DeleteObject(brush);
                SetTextColor((*dis).hDC, rgb(fg));
                let _ = SetBkMode((*dis).hDC, TRANSPARENT);

                let list_hwnd = (*dis).hwndItem;
                let column_count = state.owner_draw_column_widths.len();
                let mut col_x = (*dis).rcItem.left + CELL_LEFT_PADDING;
                let is_severity_column_badge_eligible =
                    matches!(kind, RowKind::Alert(_)) && column_count > 0;
                for col in 0..column_count {
                    let mut buf = [0u16; 512];
                    let mut item = LVITEMW {
                        mask: LVIF_TEXT,
                        iItem: idx as i32,
                        iSubItem: col as i32,
                        pszText: windows::core::PWSTR(buf.as_mut_ptr()),
                        cchTextMax: buf.len() as i32,
                        ..Default::default()
                    };
                    SendMessageW(
                        list_hwnd,
                        windows::Win32::UI::Controls::LVM_GETITEMW,
                        WPARAM(0),
                        LPARAM(&mut item as *mut _ as isize),
                    );
                    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
                    let text = String::from_utf16_lossy(&buf[..len]);
                    let text = text.as_str();
                    let is_last = col + 1 == column_count;
                    let col_width = if is_last {
                        ((*dis).rcItem.right - col_x - CELL_RIGHT_PADDING).max(0)
                    } else {
                        state.owner_draw_column_widths[col]
                    };

                    // Severity badge: a small solid-color dot drawn before the
                    // text in column 0, so severity reads as a shape/color at
                    // a glance instead of requiring the eye to parse the word
                    // CRITICAL/WARN/INFO. Row background tint alone (the prior
                    // behavior) is far more subtle than a dedicated indicator.
                    let mut text_left = col_x;
                    if col == 0 && is_severity_column_badge_eligible {
                        if let RowKind::Alert(level) = kind {
                            let badge_color = match level {
                                crate::alert::Level::Critical => CRITICAL_BADGE,
                                crate::alert::Level::Warn => WARN_BADGE,
                                crate::alert::Level::Info => INFO_BADGE,
                            };
                            let cy = ((*dis).rcItem.top + (*dis).rcItem.bottom) / 2;
                            let badge_rect = RECT {
                                left: col_x,
                                top: cy - BADGE_DIAMETER / 2,
                                right: col_x + BADGE_DIAMETER,
                                bottom: cy + BADGE_DIAMETER / 2,
                            };
                            let badge_brush = CreateSolidBrush(rgb(badge_color));
                            let old_brush = SelectObject((*dis).hDC, badge_brush);
                            let _ = Ellipse(
                                (*dis).hDC,
                                badge_rect.left,
                                badge_rect.top,
                                badge_rect.right,
                                badge_rect.bottom,
                            );
                            SelectObject((*dis).hDC, old_brush);
                            let _ = DeleteObject(badge_brush);
                            text_left = col_x + BADGE_DIAMETER + 6;
                        }
                    }

                    let would_crash_drawtextw_with_zero_length_buffer = text.is_empty();
                    if !would_crash_drawtextw_with_zero_length_buffer {
                        let mut cell_rect = RECT {
                            left: text_left,
                            top: (*dis).rcItem.top,
                            right: col_x + col_width,
                            bottom: (*dis).rcItem.bottom,
                        };
                        let mut wide: Vec<u16> = text.encode_utf16().collect();
                        DrawTextW(
                            (*dis).hDC,
                            &mut wide,
                            &mut cell_rect,
                            DT_LEFT | DT_VCENTER | DT_SINGLELINE,
                        );
                    }
                    col_x += col_width;
                }
                windows::Win32::Graphics::Gdi::SelectObject((*dis).hDC, old_font);
            }
            LRESULT(1)
        }
        WM_NOTIFY => {
            let nmhdr = lparam.0 as *const NMHDR;
            if !nmhdr.is_null() && (*nmhdr).code == LVN_ITEMCHANGED {
                let nmlv = lparam.0 as *const NMLISTVIEW;
                if !nmlv.is_null() && (*nmlv).iItem >= 0 {
                    if let Some(state) = window_state(hwnd) {
                        if let Ok(details_hwnd) =
                            windows::Win32::UI::WindowsAndMessaging::GetDlgItem(hwnd, DETAILS_ID)
                        {
                            if !details_hwnd.is_invalid() {
                                let idx = (*nmlv).iItem as usize;
                                let text = state.details.get(idx).cloned().unwrap_or_default();
                                let _ = SetWindowTextW(details_hwnd, &HSTRING::from(text.as_str()));
                            }
                        }
                    }
                }
            }
            LRESULT(0)
        }
        WM_CLOSE => {
            let _ = DestroyWindow(hwnd);
            LRESULT(0)
        }
        WM_DESTROY => {
            if let Some(state) = window_state(hwnd) {
                if !state.base_font.is_invalid() {
                    let _ = DeleteObject(state.base_font);
                }
                if !state.bold_font.is_invalid() {
                    let _ = DeleteObject(state.bold_font);
                }
                if !state.caller_owned_destroy_icon.is_invalid() {
                    let _ = DestroyIcon(state.caller_owned_destroy_icon);
                }
                let _ = Box::from_raw(state as *mut WindowState);
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            }
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
        let init_comctl32_v6_listview_classes_to_prevent_gdi_leak = INITCOMMONCONTROLSEX {
            dwSize: std::mem::size_of::<INITCOMMONCONTROLSEX>() as u32,
            dwICC: ICC_LISTVIEW_CLASSES,
        };
        let _ = InitCommonControlsEx(&init_comctl32_v6_listview_classes_to_prevent_gdi_leak);

        let wc = WNDCLASSW {
            lpfnWndProc: Some(wnd_proc),
            hInstance: hinstance.into(),
            lpszClassName: CLASS_NAME,
            hCursor: LoadCursorW(None, windows::Win32::UI::WindowsAndMessaging::IDC_ARROW).unwrap_or_default(),
            hbrBackground: windows::Win32::Graphics::Gdi::HBRUSH(
                windows::Win32::Graphics::Gdi::GetStockObject(windows::Win32::Graphics::Gdi::WHITE_BRUSH).0,
            ),
            ..Default::default()
        };
        RegisterClassW(&wc);
    });
}

fn readable_font(hwnd: HWND, point_size: i32, bold: bool) -> windows::Win32::Graphics::Gdi::HFONT {
    unsafe {
        let dc = GetDC(hwnd);
        let dpi_y = GetDeviceCaps(dc, LOGPIXELSY);
        ReleaseDC(hwnd, dc);
        let height = -(point_size * dpi_y / 72);
        CreateFontW(
            height,
            0,
            0,
            0,
            if bold { FW_BOLD.0 as i32 } else { FW_NORMAL.0 as i32 },
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

fn open_window(title: &str, hinstance: windows::Win32::Foundation::HMODULE) -> Result<(HWND, HICON), String> {
    register_class_once(hinstance);
    let hwnd = unsafe {
        CreateWindowExW(
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
        )
    };
    let hwnd = hwnd.map_err(|_| "CreateWindowExW failed for the window".to_string())?;
    if hwnd.is_invalid() {
        return Err("CreateWindowExW returned an invalid window handle".to_string());
    }

    let hicon = shield_hicon(IconState::Idle).unwrap_or_default();
    if !hicon.is_invalid() {
        unsafe {
            SendMessageW(hwnd, WM_SETICON, WPARAM(ICON_SMALL as usize), LPARAM(hicon.0 as isize));
            SendMessageW(hwnd, WM_SETICON, WPARAM(ICON_BIG as usize), LPARAM(hicon.0 as isize));
        }
    }

    Ok((hwnd, hicon))
}

/// SysListView32 in LVS_REPORT has no direct "set row height" message --
/// the documented trick (used by every real-world app that needs taller
/// report-mode rows) is assigning a small-icon imagelist whose item size IS
/// the desired row height; report mode measures rows against that
/// imagelist's cy even when no per-row icon is ever actually drawn (this
/// window's rows are owner-drawn, so the icon slot itself stays visually
/// empty). Zero initial images (cinitial=0) keeps this a pure sizing hack
/// with no icon content. The imagelist is intentionally leaked to the OS
/// image-list cache for the process lifetime rather than tracked/destroyed
/// -- it holds no GDI bitmap resources of consequence (0 images, comctl32
/// manages it internally) and this window is opened at most a handful of
/// times per process run, not in a hot loop.
fn set_report_row_height(list_hwnd: HWND, desired_row_height_px: i32) {
    unsafe {
        let himl = ImageList_Create(1, desired_row_height_px, ILC_COLOR32, 0, 1);
        if !himl.is_invalid() {
            SendMessageW(
                list_hwnd,
                LVM_SETIMAGELIST,
                WPARAM(LVSIL_SMALL as usize),
                LPARAM(himl.0),
            );
        }
    }
}

fn insert_column(list_hwnd: HWND, index: i32, text: &str, width: i32) {
    let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    let mut col = LVCOLUMNW {
        mask: LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM,
        fmt: LVCFMT_LEFT,
        cx: width,
        pszText: windows::core::PWSTR(wide.as_ptr() as *mut u16),
        iSubItem: index,
        ..Default::default()
    };
    unsafe {
        SendMessageW(
            list_hwnd,
            LVM_INSERTCOLUMNW,
            WPARAM(index as usize),
            LPARAM(&mut col as *mut _ as isize),
        );
    }
}

fn strip_embedded_nuls_to_avoid_lvm_insertitemw_crash(text: &str) -> std::borrow::Cow<'_, str> {
    if text.contains('\0') {
        std::borrow::Cow::Owned(text.replace('\0', ""))
    } else {
        std::borrow::Cow::Borrowed(text)
    }
}

fn insert_row(list_hwnd: HWND, row: i32, columns: &[&str]) {
    for (col_idx, text) in columns.iter().enumerate() {
        let text = strip_embedded_nuls_to_avoid_lvm_insertitemw_crash(text);
        let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
        let mut item = LVITEMW {
            mask: LVIF_TEXT,
            iItem: row,
            iSubItem: col_idx as i32,
            pszText: windows::core::PWSTR(wide.as_ptr() as *mut u16),
            ..Default::default()
        };
        unsafe {
            if col_idx == 0 {
                SendMessageW(list_hwnd, LVM_INSERTITEMW, WPARAM(0), LPARAM(&mut item as *mut _ as isize));
            } else {
                SendMessageW(list_hwnd, LVM_SETITEMW, WPARAM(0), LPARAM(&mut item as *mut _ as isize));
            }
        }
    }
}

fn attach_state(hwnd: HWND, state: WindowState) {
    let boxed = Box::new(state);
    unsafe {
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, Box::into_raw(boxed) as isize);
    }
}

fn free_pre_attach_resources_since_wm_destroy_has_no_state_yet(
    hwnd: HWND,
    base_font: windows::Win32::Graphics::Gdi::HFONT,
    icon: HICON,
) {
    unsafe {
        if !base_font.is_invalid() {
            let _ = DeleteObject(base_font);
        }
        if !icon.is_invalid() {
            let _ = DestroyIcon(icon);
        }
        let _ = DestroyWindow(hwnd);
    }
}

/// Builds the details-pane text for one alert as labeled fields on their own
/// lines instead of one run-on sentence -- a plain WC_EDITW control can't
/// mix font weights, so real bold labels aren't possible here without a
/// second control; a colon-labeled field-per-line layout is the readable
/// middle ground that still reads as a structured record at a glance.
fn format_detail_record(e: &EntrySnapshot) -> String {
    let mut out = String::new();
    out.push_str("Severity:  ");
    out.push_str(&e.level.to_string());
    out.push_str("\r\n");
    out.push_str("Time:      ");
    out.push_str(&e.ts);
    out.push_str("\r\n");
    out.push_str("Category:  ");
    out.push_str(e.category);
    out.push_str("\r\n\r\n");
    out.push_str("Message:\r\n");
    out.push_str(&e.message);
    out.push_str("\r\n\r\n");
    out.push_str("Evidence:\r\n");
    match &e.evidence {
        Some(ev) => out.push_str(ev),
        None => out.push_str("No further evidence recorded."),
    }
    out
}

fn create_empty_state_label(hwnd: HWND, hinstance: windows::Win32::Foundation::HMODULE, message: &str) {
    unsafe {
        let mut rect = RECT::default();
        let _ = GetClientRect(hwnd, &mut rect);
        let _ = CreateWindowExW(
            Default::default(),
            WC_STATICW,
            &HSTRING::from(message),
            WS_CHILD | WS_VISIBLE | SS_CENTER | SS_CENTERIMAGE,
            0,
            0,
            rect.right - rect.left,
            rect.bottom - rect.top,
            hwnd,
            HMENU(EMPTY_LABEL_ID as *mut core::ffi::c_void),
            hinstance,
            None,
        );
    }
}

fn create_alert_window_and_pump(
    title: &str,
    entries: Vec<EntrySnapshot>,
    result_tx: std::sync::mpsc::Sender<Result<(), String>>,
) {
    let hinstance = match unsafe { GetModuleHandleW(None) } {
        Ok(h) => h,
        Err(e) => {
            let _ = result_tx.send(Err(format!("GetModuleHandleW failed: {e}")));
            return;
        }
    };

    let (hwnd, icon) = match open_window(title, hinstance) {
        Ok(h) => h,
        Err(e) => {
            let _ = result_tx.send(Err(e));
            return;
        }
    };

    let base_font = readable_font(hwnd, BASE_FONT_POINT_SIZE, false);

    if entries.is_empty() {
        create_empty_state_label(hwnd, hinstance, "No alerts yet -- everything looks normal.");
        let empty_state_label_font_stored_in_bold_font_slot_for_wm_destroy_cleanup =
            readable_font(hwnd, BASE_FONT_POINT_SIZE + 2, false);
        if let Ok(label_hwnd) = unsafe { windows::Win32::UI::WindowsAndMessaging::GetDlgItem(hwnd, EMPTY_LABEL_ID) } {
            unsafe {
                SendMessageW(
                    label_hwnd,
                    WM_SETFONT,
                    WPARAM(empty_state_label_font_stored_in_bold_font_slot_for_wm_destroy_cleanup.0 as usize),
                    LPARAM(1),
                );
            }
        }
        attach_state(hwnd, WindowState {
            row_kinds: Vec::new(),
            details: Vec::new(),
            base_font,
            bold_font: empty_state_label_font_stored_in_bold_font_slot_for_wm_destroy_cleanup,
            owner_draw_column_widths: Vec::new(),
            caller_owned_destroy_icon: icon,
        });
    } else {
        let mut rect = RECT::default();
        unsafe {
            let _ = GetClientRect(hwnd, &mut rect);
        }
        let list_height = (rect.bottom - rect.top) * 2 / 3;

        let list_hwnd = unsafe {
            CreateWindowExW(
                WS_EX_CLIENTEDGE,
                WC_LISTVIEWW,
                &HSTRING::from(""),
                WS_CHILD
                    | WS_VISIBLE
                    | WS_BORDER
                    | WS_VSCROLL
                    | WINDOW_STYLE(LVS_REPORT)
                    | WINDOW_STYLE(LVS_SINGLESEL)
                    | WINDOW_STYLE(LVS_OWNERDRAWFIXED),
                0,
                0,
                rect.right - rect.left,
                list_height,
                hwnd,
                HMENU(LIST_ID as *mut core::ffi::c_void),
                hinstance,
                None,
            )
        };
        let Ok(list_hwnd) = list_hwnd else {
            let _ = result_tx.send(Err("CreateWindowExW failed for the alert list".to_string()));
            free_pre_attach_resources_since_wm_destroy_has_no_state_yet(hwnd, base_font, icon);
            return;
        };

        unsafe {
            SendMessageW(
                list_hwnd,
                windows::Win32::UI::Controls::LVM_SETEXTENDEDLISTVIEWSTYLE,
                WPARAM(0),
                LPARAM((LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES) as isize),
            );
            SendMessageW(list_hwnd, WM_SETFONT, WPARAM(base_font.0 as usize), LPARAM(1));
            set_report_row_height(list_hwnd, ROW_HEIGHT_PX);
        }

        insert_column(list_hwnd, 0, "Severity", 90);
        insert_column(list_hwnd, 1, "Time", 150);
        insert_column(list_hwnd, 2, "Category", 130);
        insert_column(list_hwnd, 3, "Message", 420);

        let mut row_kinds = Vec::with_capacity(entries.len());
        let mut details = Vec::with_capacity(entries.len());
        for (i, e) in entries.iter().enumerate() {
            insert_row(
                list_hwnd,
                i as i32,
                &[&e.level.to_string(), &e.ts, e.category, &e.message],
            );
            row_kinds.push(RowKind::Alert(e.level));
            details.push(format_detail_record(e));
        }

        let details_hwnd = unsafe {
            CreateWindowExW(
                WS_EX_CLIENTEDGE,
                windows::Win32::UI::Controls::WC_EDITW,
                &HSTRING::from(""),
                WS_CHILD
                    | WS_VISIBLE
                    | WS_BORDER
                    | WS_VSCROLL
                    | WINDOW_STYLE(windows::Win32::UI::WindowsAndMessaging::ES_MULTILINE as u32)
                    | WINDOW_STYLE(windows::Win32::UI::WindowsAndMessaging::ES_READONLY as u32)
                    | WINDOW_STYLE(windows::Win32::UI::WindowsAndMessaging::ES_AUTOVSCROLL as u32),
                0,
                list_height,
                rect.right - rect.left,
                (rect.bottom - rect.top) - list_height,
                hwnd,
                HMENU(DETAILS_ID as *mut core::ffi::c_void),
                hinstance,
                None,
            )
        };
        if let Ok(details_hwnd) = details_hwnd {
            unsafe {
                SendMessageW(details_hwnd, WM_SETFONT, WPARAM(base_font.0 as usize), LPARAM(1));
                let _ = SetWindowTextW(details_hwnd, &HSTRING::from(details.first().cloned().unwrap_or_default().as_str()));
            }
        }

        attach_state(hwnd, WindowState {
            row_kinds,
            details,
            base_font,
            bold_font: windows::Win32::Graphics::Gdi::HFONT::default(),
            owner_draw_column_widths: vec![90, 150, 130, 420],
            caller_owned_destroy_icon: icon,
        });
    }

    unsafe {
        let _ = ShowWindow(hwnd, SW_SHOW);
        let _ = SetWindowTextW(hwnd, &HSTRING::from(title));
    }

    let _ = result_tx.send(Ok(()));

    let mut msg = MSG::default();
    unsafe {
        while GetMessageW(&mut msg, None, 0, 0).into() {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}

fn create_config_window_and_pump(
    title: &str,
    sections: Vec<(String, String, Vec<(String, String)>)>,
    result_tx: std::sync::mpsc::Sender<Result<(), String>>,
) {
    let hinstance = match unsafe { GetModuleHandleW(None) } {
        Ok(h) => h,
        Err(e) => {
            let _ = result_tx.send(Err(format!("GetModuleHandleW failed: {e}")));
            return;
        }
    };

    let (hwnd, icon) = match open_window(title, hinstance) {
        Ok(h) => h,
        Err(e) => {
            let _ = result_tx.send(Err(e));
            return;
        }
    };

    let base_font = readable_font(hwnd, BASE_FONT_POINT_SIZE, false);
    let bold_font = readable_font(hwnd, BASE_FONT_POINT_SIZE, true);

    let mut rect = RECT::default();
    unsafe {
        let _ = GetClientRect(hwnd, &mut rect);
    }

    let list_hwnd = unsafe {
        CreateWindowExW(
            WS_EX_CLIENTEDGE,
            WC_LISTVIEWW,
            &HSTRING::from(""),
            WS_CHILD
                | WS_VISIBLE
                | WS_BORDER
                | WS_VSCROLL
                | WINDOW_STYLE(LVS_REPORT)
                | WINDOW_STYLE(LVS_OWNERDRAWFIXED),
            0,
            0,
            rect.right - rect.left,
            rect.bottom - rect.top,
            hwnd,
            HMENU(LIST_ID as *mut core::ffi::c_void),
            hinstance,
            None,
        )
    };
    let Ok(list_hwnd) = list_hwnd else {
        let _ = result_tx.send(Err("CreateWindowExW failed for the config list".to_string()));
        free_pre_attach_resources_since_wm_destroy_has_no_state_yet(hwnd, base_font, icon);
        unsafe {
            if !bold_font.is_invalid() {
                let _ = DeleteObject(bold_font);
            }
        }
        return;
    };

    unsafe {
        SendMessageW(
            list_hwnd,
            windows::Win32::UI::Controls::LVM_SETEXTENDEDLISTVIEWSTYLE,
            WPARAM(0),
            LPARAM((LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES) as isize),
        );
        SendMessageW(list_hwnd, WM_SETFONT, WPARAM(base_font.0 as usize), LPARAM(1));
        set_report_row_height(list_hwnd, ROW_HEIGHT_PX);
    }

    insert_column(list_hwnd, 0, "Setting", 300);
    insert_column(list_hwnd, 1, "Value", (rect.right - rect.left - 300).max(200));

    let mut row_kinds = Vec::new();
    let mut row = 0i32;
    for (section, description, rows) in &sections {
        insert_row(list_hwnd, row, &[section.as_str(), ""]);
        row_kinds.push(RowKind::SectionHeader);
        row += 1;
        if !description.is_empty() {
            insert_row(list_hwnd, row, &[description.as_str(), ""]);
            row_kinds.push(RowKind::Description);
            row += 1;
        }
        for (k, v) in rows {
            insert_row(list_hwnd, row, &[k, v]);
            row_kinds.push(RowKind::Plain);
            row += 1;
        }
    }

    unsafe {
        let _ = ShowWindow(hwnd, SW_SHOW);
        let _ = SetWindowTextW(hwnd, &HSTRING::from(title));
    }

    attach_state(hwnd, WindowState {
        row_kinds,
        details: Vec::new(),
        base_font,
        bold_font,
        owner_draw_column_widths: vec![300],
        caller_owned_destroy_icon: icon,
    });

    let _ = result_tx.send(Ok(()));

    let mut msg = MSG::default();
    unsafe {
        while GetMessageW(&mut msg, None, 0, 0).into() {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}

pub fn show_alerts(title: &str, entries: &[EntrySnapshot]) -> Result<(), String> {
    let title = title.to_string();
    let entries = entries.to_vec();
    let (tx, rx) = std::sync::mpsc::channel::<Result<(), String>>();
    std::thread::spawn(move || create_alert_window_and_pump(&title, entries, tx));
    rx.recv().unwrap_or_else(|_| Err("alert window thread exited before signaling readiness".to_string()))
}

pub fn show_config(title: &str, sections: &[(&str, &str, Vec<(String, String)>)]) -> Result<(), String> {
    let title = title.to_string();
    let sections: Vec<(String, String, Vec<(String, String)>)> = sections
        .iter()
        .map(|(name, description, rows)| (name.to_string(), description.to_string(), rows.clone()))
        .collect();
    let (tx, rx) = std::sync::mpsc::channel::<Result<(), String>>();
    std::thread::spawn(move || create_config_window_and_pump(&title, sections, tx));
    rx.recv().unwrap_or_else(|_| Err("config window thread exited before signaling readiness".to_string()))
}
