use crate::gui::history::{GroupedEntry, History};
use crate::gui::icon::{shield_hicon, IconState};
use std::sync::{Arc, Mutex, Once};
use windows::core::{w, HSTRING, PCWSTR};
use windows::Win32::Foundation::{COLORREF, HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::{
    BeginPaint, CreateFontW, CreatePen, CreateSolidBrush, DeleteObject, DrawTextW, Ellipse,
    EndPaint, FillRect, GetDC, GetDeviceCaps, InvalidateRect, PAINTSTRUCT, ReleaseDC, RoundRect,
    SelectObject, SetBkMode, SetTextColor, ANTIALIASED_QUALITY, DEFAULT_CHARSET, DEFAULT_PITCH,
    DT_CALCRECT, DT_LEFT, DT_NOPREFIX, DT_SINGLELINE, DT_VCENTER, DT_WORDBREAK, FF_DONTCARE,
    FW_BOLD, FW_NORMAL, LOGPIXELSY, OUT_DEFAULT_PRECIS, PS_SOLID, TRANSPARENT, CLIP_DEFAULT_PRECIS,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Controls::{
    ImageList_Create, InitCommonControlsEx, DRAWITEMSTRUCT, ICC_LISTVIEW_CLASSES, ILC_COLOR32,
    INITCOMMONCONTROLSEX, LVCFMT_LEFT, LVCOLUMNW, LVITEMW, LVCF_FMT, LVCF_SUBITEM, LVCF_TEXT,
    LVCF_WIDTH, LVIF_TEXT, LVM_INSERTCOLUMNW, LVM_INSERTITEMW, LVM_SETIMAGELIST, LVM_SETITEMW,
    LVS_EX_FULLROWSELECT, LVS_EX_GRIDLINES, LVS_OWNERDRAWFIXED, LVS_REPORT,
    LVSIL_SMALL, ODT_LISTVIEW, WC_LISTVIEWW, WC_STATICW,
};
use windows::Win32::UI::Input::KeyboardAndMouse::VK_ESCAPE;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyIcon, DestroyWindow, DispatchMessageW, GetClientRect,
    GetMessageW, GetWindowLongPtrW, HICON, LoadCursorW, PostMessageW, PostQuitMessage,
    RegisterClassW, SendMessageW, SetWindowLongPtrW, SetWindowPos, SetWindowTextW, ShowWindow,
    TranslateMessage,
    CW_USEDEFAULT, GWLP_USERDATA, HMENU, ICON_BIG, ICON_SMALL, MSG, SB_BOTTOM, SB_VERT,
    SB_LINEDOWN, SB_LINEUP, SB_PAGEDOWN, SB_PAGEUP, SB_THUMBPOSITION, SB_THUMBTRACK, SB_TOP,
    SCROLLINFO, SIF_PAGE, SIF_POS, SIF_RANGE, SW_SHOW, SWP_NOZORDER, WINDOW_STYLE, WM_CLOSE,
    WM_CTLCOLORSTATIC, WM_DESTROY, WM_DRAWITEM, WM_GETMINMAXINFO, WM_KEYDOWN, WM_LBUTTONDOWN,
    WM_MOUSEWHEEL, WM_PAINT, WM_SETFONT, WM_SETICON, WM_SIZE, WM_VSCROLL, WNDCLASSW,
    WS_BORDER, WS_CHILD, WS_EX_CLIENTEDGE, WS_OVERLAPPEDWINDOW, WS_VISIBLE, WS_VSCROLL,
};
use windows::Win32::UI::Controls::SetScrollInfo;

const SS_CENTER: WINDOW_STYLE = WINDOW_STYLE(1);
const SS_CENTERIMAGE: WINDOW_STYLE = WINDOW_STYLE(512);

const CLASS_NAME: PCWSTR = w!("GoofedupAlertWindow");
const WINDOW_WIDTH: i32 = 820;
const WINDOW_HEIGHT: i32 = 600;
const MIN_WINDOW_WIDTH: i32 = 520;
const MIN_WINDOW_HEIGHT: i32 = 360;
const BASE_FONT_POINT_SIZE: i32 = 11;

const LIST_ID: i32 = 1001;
const EMPTY_LABEL_ID: i32 = 1003;
const FEED_ID: i32 = 1004;

const FEED_CLASS_NAME: PCWSTR = w!("GoofedupAlertFeed");

// A private-range custom message telling the feed window new data may be
// available in the History it already holds -- posted from whatever
// watcher thread AlertSink::emit runs on, handled on the feed window's own
// message-pump thread. WM_APP (0x8000) is the documented start of the
// range reserved for private application messages.
const WM_APP: u32 = 0x8000;
const WM_GOOFEDUP_NEW_ALERT: u32 = WM_APP + 1;

// The currently-open feed window's HWND, if any -- set right after the
// feed child window is created and shown, cleared on its own WM_DESTROY.
// A watcher thread calling notify_new_alert() reads this to know where to
// PostMessageW; None (no window open) is the common case and is a cheap
// no-op, not an error.
//
// A single slot, deliberately: if a user somehow opens two feed windows at
// once (no per-window single-instance guard exists), the second one to
// open overwrites this slot and the first silently reverts to pre-refresh
// (close-and-reopen-to-see-new-alerts) behavior for the rest of its
// lifetime -- accepted as a rare, non-corrupting, self-correcting-on-close
// edge case rather than building multi-window fan-out (a set of HWNDs) for
// it.
static OPEN_FEED_HWND: Mutex<Option<isize>> = Mutex::new(None);

/// Called from AlertSink's on_alert callback (a watcher thread) whenever a
/// new alert lands, regardless of whether the alert window is currently
/// open. A no-op if it isn't -- PostMessageW to a HWND that no longer
/// exists (or was never opened) returns FALSE/ERROR_INVALID_WINDOW_HANDLE,
/// never a crash or a delivery to an unrelated recycled handle, per the
/// documented Win32 contract, so no extra liveness check is needed beyond
/// holding the lock briefly to read the slot.
pub fn notify_new_alert() {
    let hwnd = OPEN_FEED_HWND.lock().ok().and_then(|g| *g);
    if let Some(raw) = hwnd {
        unsafe {
            let _ = PostMessageW(HWND(raw as *mut core::ffi::c_void), WM_GOOFEDUP_NEW_ALERT, WPARAM(0), LPARAM(0));
        }
    }
}
const CARD_MARGIN_X: i32 = 12;
const CARD_MARGIN_TOP: i32 = 10;
const CARD_GAP: i32 = 8;
const CARD_PADDING: i32 = 12;
const CARD_BADGE_DIAMETER: i32 = 12;
const CARD_BORDER: (u8, u8, u8) = (226, 232, 240);
const CARD_BG: (u8, u8, u8) = (255, 255, 255);
const CARD_HOVER_HINT_FG: (u8, u8, u8) = (148, 163, 184);

const CARD_ACKNOWLEDGED_BORDER: (u8, u8, u8) = (226, 232, 240);
const CARD_ACKNOWLEDGED_BG: (u8, u8, u8) = (248, 250, 252);
const CARD_ACKNOWLEDGED_BADGE: (u8, u8, u8) = (148, 163, 184);
const CARD_ACKNOWLEDGED_FG: (u8, u8, u8) = (100, 116, 139);
const MARK_SAFE_BG: (u8, u8, u8) = (241, 245, 249);
const MARK_SAFE_FG: (u8, u8, u8) = (51, 65, 85);
const MARK_SAFE_ACKED_FG: (u8, u8, u8) = (148, 163, 184);
const MARK_SAFE_BUTTON_WIDTH: i32 = 84;
const MARK_SAFE_BUTTON_HEIGHT: i32 = 20;

const CRITICAL_FG: (u8, u8, u8) = (153, 27, 27);
const WARN_FG: (u8, u8, u8) = (146, 64, 14);
const HEADER_BG: (u8, u8, u8) = (238, 242, 247);
const HEADER_FG: (u8, u8, u8) = (30, 41, 59);
const DESCRIPTION_FG: (u8, u8, u8) = (100, 116, 139);

// Solid badge dot fill -- used both for a card's severity indicator and
// its accent subline text color.
const CRITICAL_BADGE: (u8, u8, u8) = (220, 38, 38);
const WARN_BADGE: (u8, u8, u8) = (217, 119, 6);
const INFO_BADGE: (u8, u8, u8) = (100, 116, 139);
const CELL_LEFT_PADDING: i32 = 10;
const CELL_RIGHT_PADDING: i32 = 10;
const ROW_HEIGHT_PX: i32 = 26;

static REGISTER_CLASS: Once = Once::new();

#[derive(Clone, Copy)]
enum RowKind {
    SectionHeader,
    Description,
    Plain,
}

struct WindowState {
    row_kinds: Vec<RowKind>,
    base_font: windows::Win32::Graphics::Gdi::HFONT,
    bold_font: windows::Win32::Graphics::Gdi::HFONT,
    owner_draw_column_widths: Vec<i32>,
    caller_owned_destroy_icon: HICON,
}

struct CardFeedState {
    entries: Vec<GroupedEntry>,
    expanded: Vec<bool>,
    scroll_offset_y: i32,
    base_font: windows::Win32::Graphics::Gdi::HFONT,
    bold_font: windows::Win32::Graphics::Gdi::HFONT,
    history: Arc<History>,
}

struct CardLayout {
    card_top_in_unscrolled_content_space: Vec<i32>,
    card_height: Vec<i32>,
    total_height: i32,
    mark_safe_button_y_in_unscrolled_content_space: Vec<Option<(i32, i32)>>,
}

fn measure_wrapped_text_height(hdc: windows::Win32::Graphics::Gdi::HDC, text: &str, width: i32) -> i32 {
    if text.is_empty() || width <= 0 {
        return 0;
    }
    let mut wide: Vec<u16> = text.encode_utf16().collect();
    let mut rect = RECT { left: 0, top: 0, right: width, bottom: 0 };
    unsafe {
        DrawTextW(hdc, &mut wide, &mut rect, DT_CALCRECT | DT_WORDBREAK | DT_NOPREFIX);
    }
    (rect.bottom - rect.top).max(0)
}

/// Recomputes every card's position/height from scratch against the given
/// device context (needed for accurate DT_CALCRECT text measurement) and
/// viewport width. Deliberately stateless/idempotent -- called on every
/// paint and every hit-test, never memoized, so it can never go stale
/// relative to `expanded` (mut-card-hit-test-post-reflow).
fn compute_card_layout(
    hdc: windows::Win32::Graphics::Gdi::HDC,
    feed: &CardFeedState,
    viewport_width: i32,
) -> CardLayout {
    let mut card_top_in_unscrolled_content_space = Vec::with_capacity(feed.entries.len());
    let mut card_height = Vec::with_capacity(feed.entries.len());
    let mut mark_safe_button_y_in_unscrolled_content_space = Vec::with_capacity(feed.entries.len());
    let mut y = CARD_MARGIN_TOP;
    let text_width = (viewport_width - CARD_MARGIN_X * 2 - CARD_PADDING * 2).max(40);
    let headline_width_reserved_for_mark_safe_button = MARK_SAFE_BUTTON_WIDTH + 8;

    for (i, e) in feed.entries.iter().enumerate() {
        card_top_in_unscrolled_content_space.push(y);
        let show_mark_safe = e.is_group() && !e.is_acknowledged_group();
        let headline_text_width = if show_mark_safe {
            (text_width - headline_width_reserved_for_mark_safe_button).max(20)
        } else {
            text_width
        };
        let headline_h = measure_wrapped_text_height(hdc, &e.headline(), headline_text_width).max(18);
        let subline_h = 18;
        let mut h = CARD_PADDING * 2 + headline_h.max(MARK_SAFE_BUTTON_HEIGHT) + 4 + subline_h;
        if feed.expanded.get(i).copied().unwrap_or(false) {
            let detail_h = measure_wrapped_text_height(hdc, &e.detail_text(), text_width).max(18);
            h += 8 + detail_h;
        }
        card_height.push(h);

        mark_safe_button_y_in_unscrolled_content_space.push(if show_mark_safe {
            let btn_top = y + CARD_PADDING;
            Some((btn_top, btn_top + MARK_SAFE_BUTTON_HEIGHT))
        } else {
            None
        });

        y += h + CARD_GAP;
    }
    let total_height = if feed.entries.is_empty() { 0 } else { (y - CARD_GAP + CARD_MARGIN_TOP).max(0) };
    CardLayout {
        card_top_in_unscrolled_content_space,
        card_height,
        total_height,
        mark_safe_button_y_in_unscrolled_content_space,
    }
}

fn mark_safe_button_rect(layout: &CardLayout, i: usize, viewport_width: i32) -> Option<RECT> {
    let (top, bottom) = layout.mark_safe_button_y_in_unscrolled_content_space.get(i).copied().flatten()?;
    let right = viewport_width - CARD_MARGIN_X - CARD_PADDING;
    let left = right - MARK_SAFE_BUTTON_WIDTH;
    Some(RECT { left, top, right, bottom })
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

        // The config window's ListView (LIST_ID) is the only remaining
        // consumer of this branch -- the alert history no longer creates a
        // ListView or a details pane, it uses FEED_ID below.
        if let Ok(list_hwnd) = windows::Win32::UI::WindowsAndMessaging::GetDlgItem(hwnd, LIST_ID) {
            if !list_hwnd.is_invalid() {
                let _ = SetWindowPos(list_hwnd, None, 0, 0, width, height, SWP_NOZORDER);
            }
        }
        if let Ok(empty_hwnd) = windows::Win32::UI::WindowsAndMessaging::GetDlgItem(hwnd, EMPTY_LABEL_ID) {
            if !empty_hwnd.is_invalid() {
                let _ = SetWindowPos(empty_hwnd, None, 0, 0, width, height, SWP_NOZORDER);
            }
        }
        if let Ok(feed_hwnd) = windows::Win32::UI::WindowsAndMessaging::GetDlgItem(hwnd, FEED_ID) {
            if !feed_hwnd.is_invalid() {
                let _ = SetWindowPos(feed_hwnd, None, 0, 0, width, height, SWP_NOZORDER);
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

                    let text_left = col_x;
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

unsafe fn feed_state(hwnd: HWND) -> Option<&'static mut CardFeedState> {
    let ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut CardFeedState;
    if ptr.is_null() {
        None
    } else {
        Some(&mut *ptr)
    }
}

/// A cheap content fingerprint for deciding whether a fresh grouped_snapshot()
/// differs from what's currently rendered -- count, plus per-entry category
/// and either the group's member count or the single entry's message, joined
/// into one string. Not a full structural comparison, but sufficient to tell
/// "nothing changed" (skip repaint) from "something changed" (repaint), which
/// is all a refresh decision needs.
fn entries_fingerprint(entries: &[GroupedEntry]) -> String {
    let mut out = String::with_capacity(entries.len() * 24);
    for e in entries {
        out.push_str(e.category());
        out.push('|');
        match e {
            GroupedEntry::Single(s) => {
                out.push_str(&s.message);
            }
            GroupedEntry::Group { count, acknowledged, .. } => {
                out.push_str(&count.to_string());
                out.push(if *acknowledged { 'A' } else { 'a' });
            }
        }
        out.push(';');
    }
    out
}

/// Re-derives the feed's entries from its live History and repaints ONLY if
/// the content actually changed (mut-realtime-refresh-no-repaint-when-
/// unchanged). Preserves scroll_offset_y as-is (a byte position, unaffected
/// by which entries exist) and re-applies expanded=true to whichever new
/// entries share a GROUP's (category, key) identity with a currently-
/// expanded entry (mut-realtime-refresh-preserves-scroll-and-expand-state)
/// -- a Single entry has no identity that survives a refresh, so an
/// expanded Single may legitimately re-collapse; only grouped cards have a
/// stable identity to carry forward.
unsafe fn refresh_feed_from_history(hwnd: HWND) {
    let Some(state) = feed_state(hwnd) else { return };

    let previously_expanded_group_identities: std::collections::HashSet<(&'static str, String)> = state
        .entries
        .iter()
        .enumerate()
        .filter(|(i, _)| state.expanded.get(*i).copied().unwrap_or(false))
        .filter_map(|(_, e)| e.acknowledgeable_group_identity())
        .map(|(cat, key)| (cat, key.to_string()))
        .collect();

    let fresh = state.history.grouped_snapshot();
    if entries_fingerprint(&fresh) == entries_fingerprint(&state.entries) {
        return;
    }

    let fresh_expanded: Vec<bool> = fresh
        .iter()
        .map(|e| {
            e.acknowledgeable_group_identity()
                .map(|(cat, key)| previously_expanded_group_identities.contains(&(cat, key.to_string())))
                .unwrap_or(false)
        })
        .collect();

    state.entries = fresh;
    state.expanded = fresh_expanded;
    let _ = InvalidateRect(hwnd, None, true);
}

/// Clamps scroll_offset_y to [0, max(0, total_height - viewport_height)] --
/// the sole place this clamp is applied, called after every event that can
/// change either operand (mut-card-scroll-bounds).
fn clamp_scroll_offset(offset: i32, total_height: i32, viewport_height: i32) -> i32 {
    let max_offset = (total_height - viewport_height).max(0);
    offset.clamp(0, max_offset)
}

fn feed_update_scrollbar(hwnd: HWND, total_height: i32, viewport_height: i32, offset: i32) {
    unsafe {
        let mut si = SCROLLINFO {
            cbSize: std::mem::size_of::<SCROLLINFO>() as u32,
            fMask: SIF_RANGE | SIF_PAGE | SIF_POS,
            nMin: 0,
            nMax: total_height.max(0),
            nPage: viewport_height.max(0) as u32,
            nPos: offset,
            nTrackPos: 0,
        };
        SetScrollInfo(hwnd, SB_VERT, &mut si, true);
    }
}

unsafe extern "system" fn feed_wnd_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_PAINT => {
            let mut ps = PAINTSTRUCT::default();
            let hdc = BeginPaint(hwnd, &mut ps);
            let mut client = RECT::default();
            let _ = GetClientRect(hwnd, &mut client);
            let width = client.right - client.left;
            let height = client.bottom - client.top;

            if let Some(state) = feed_state(hwnd) {
                let layout = compute_card_layout(hdc, state, width);
                state.scroll_offset_y = clamp_scroll_offset(state.scroll_offset_y, layout.total_height, height);
                let offset = state.scroll_offset_y;

                let bg_brush = CreateSolidBrush(rgb((248, 250, 252)));
                let _ = FillRect(hdc, &client, bg_brush);
                let _ = DeleteObject(bg_brush);

                for (i, e) in state.entries.iter().enumerate() {
                    let top = layout.card_top_in_unscrolled_content_space[i] - offset;
                    let h = layout.card_height[i];
                    let bottom = top + h;
                    // mut-card-paint-viewport-clip: skip any card whose rect
                    // does not intersect the visible client area at all.
                    if bottom < 0 || top > height {
                        continue;
                    }

                    let card_rect = RECT {
                        left: CARD_MARGIN_X,
                        top,
                        right: width - CARD_MARGIN_X,
                        bottom,
                    };

                    let acked = e.is_acknowledged_group();
                    let (badge_color, accent_fg) = if acked {
                        (CARD_ACKNOWLEDGED_BADGE, CARD_ACKNOWLEDGED_FG)
                    } else {
                        match e.level() {
                            crate::alert::Level::Critical => (CRITICAL_BADGE, CRITICAL_FG),
                            crate::alert::Level::Warn => (WARN_BADGE, WARN_FG),
                            crate::alert::Level::Info => (INFO_BADGE, DESCRIPTION_FG),
                        }
                    };
                    let (card_bg, card_border) = if acked {
                        (CARD_ACKNOWLEDGED_BG, CARD_ACKNOWLEDGED_BORDER)
                    } else {
                        (CARD_BG, CARD_BORDER)
                    };

                    let card_brush = CreateSolidBrush(rgb(card_bg));
                    let border_pen = CreatePen(PS_SOLID, 1, rgb(card_border));
                    let old_brush = SelectObject(hdc, card_brush);
                    let old_pen = SelectObject(hdc, border_pen);
                    let _ = RoundRect(hdc, card_rect.left, card_rect.top, card_rect.right, card_rect.bottom, 8, 8);
                    SelectObject(hdc, old_brush);
                    SelectObject(hdc, old_pen);
                    let _ = DeleteObject(card_brush);
                    let _ = DeleteObject(border_pen);

                    let badge_cy = card_rect.top + CARD_PADDING + 8;
                    let badge_brush = CreateSolidBrush(rgb(badge_color));
                    let old_brush2 = SelectObject(hdc, badge_brush);
                    let _ = Ellipse(
                        hdc,
                        card_rect.left + CARD_PADDING,
                        badge_cy - CARD_BADGE_DIAMETER / 2,
                        card_rect.left + CARD_PADDING + CARD_BADGE_DIAMETER,
                        badge_cy + CARD_BADGE_DIAMETER / 2,
                    );
                    SelectObject(hdc, old_brush2);
                    let _ = DeleteObject(badge_brush);

                    let text_left = card_rect.left + CARD_PADDING + CARD_BADGE_DIAMETER + 8;
                    let show_mark_safe = e.is_group() && !acked;
                    let text_right = if show_mark_safe {
                        card_rect.right - CARD_PADDING - MARK_SAFE_BUTTON_WIDTH - 8
                    } else {
                        card_rect.right - CARD_PADDING
                    };

                    let headline = e.headline();
                    let old_font = SelectObject(hdc, state.bold_font);
                    SetTextColor(hdc, rgb(if acked { CARD_ACKNOWLEDGED_FG } else { (15, 23, 42) }));
                    let _ = SetBkMode(hdc, TRANSPARENT);
                    let text_width = (text_right - text_left).max(10);
                    let headline_h = measure_wrapped_text_height(hdc, &headline, text_width).max(18);
                    let mut headline_rect = RECT {
                        left: text_left,
                        top: card_rect.top + CARD_PADDING,
                        right: text_right,
                        bottom: card_rect.top + CARD_PADDING + headline_h,
                    };
                    let mut headline_wide: Vec<u16> = headline.encode_utf16().collect();
                    DrawTextW(hdc, &mut headline_wide, &mut headline_rect, DT_LEFT | DT_WORDBREAK | DT_NOPREFIX);

                    if show_mark_safe {
                        if let Some(btn) = mark_safe_button_rect(&layout, i, width) {
                            let btn_top = btn.top - offset;
                            let btn_bottom = btn.bottom - offset;
                            let btn_brush = CreateSolidBrush(rgb(MARK_SAFE_BG));
                            let btn_pen = CreatePen(PS_SOLID, 1, rgb(CARD_BORDER));
                            let old_btn_brush = SelectObject(hdc, btn_brush);
                            let old_btn_pen = SelectObject(hdc, btn_pen);
                            let _ = RoundRect(hdc, btn.left, btn_top, btn.right, btn_bottom, 4, 4);
                            SelectObject(hdc, old_btn_brush);
                            SelectObject(hdc, old_btn_pen);
                            let _ = DeleteObject(btn_brush);
                            let _ = DeleteObject(btn_pen);

                            SelectObject(hdc, state.base_font);
                            SetTextColor(hdc, rgb(MARK_SAFE_FG));
                            let mut btn_text_rect = RECT { left: btn.left, top: btn_top, right: btn.right, bottom: btn_bottom };
                            let mut btn_wide: Vec<u16> = "Mark safe".encode_utf16().collect();
                            DrawTextW(hdc, &mut btn_wide, &mut btn_text_rect, DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX);
                        }
                    } else if acked && e.is_group() {
                        SelectObject(hdc, state.base_font);
                        SetTextColor(hdc, rgb(MARK_SAFE_ACKED_FG));
                        let mut label_rect = RECT {
                            left: card_rect.right - CARD_PADDING - MARK_SAFE_BUTTON_WIDTH,
                            top: card_rect.top + CARD_PADDING,
                            right: card_rect.right - CARD_PADDING,
                            bottom: card_rect.top + CARD_PADDING + MARK_SAFE_BUTTON_HEIGHT,
                        };
                        let mut label_wide: Vec<u16> = "Marked safe".encode_utf16().collect();
                        DrawTextW(hdc, &mut label_wide, &mut label_rect, DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX);
                    }

                    SelectObject(hdc, state.base_font);
                    SetTextColor(hdc, rgb(accent_fg));
                    let subline = format!("{}   \u{2022}   {}", e.newest_member_ts(), e.category());
                    let mut subline_rect = RECT {
                        left: text_left,
                        top: headline_rect.bottom + 4,
                        right: card_rect.right - CARD_PADDING,
                        bottom: headline_rect.bottom + 4 + 18,
                    };
                    let mut subline_wide: Vec<u16> = subline.encode_utf16().collect();
                    DrawTextW(hdc, &mut subline_wide, &mut subline_rect, DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX);

                    let is_expanded = state.expanded.get(i).copied().unwrap_or(false);
                    let full_text_right = card_rect.right - CARD_PADDING;
                    let full_text_width = (full_text_right - text_left).max(10);
                    if is_expanded {
                        let detail_text = e.detail_text();
                        SetTextColor(hdc, rgb((51, 65, 85)));
                        let detail_h = measure_wrapped_text_height(hdc, &detail_text, full_text_width).max(18);
                        let mut detail_rect = RECT {
                            left: text_left,
                            top: subline_rect.bottom + 8,
                            right: full_text_right,
                            bottom: subline_rect.bottom + 8 + detail_h,
                        };
                        let mut detail_wide: Vec<u16> = detail_text.encode_utf16().collect();
                        DrawTextW(hdc, &mut detail_wide, &mut detail_rect, DT_LEFT | DT_WORDBREAK | DT_NOPREFIX);
                    } else {
                        SetTextColor(hdc, rgb(CARD_HOVER_HINT_FG));
                        let hint = "click to expand";
                        let mut hint_rect = RECT {
                            left: full_text_right - 110,
                            top: subline_rect.top,
                            right: full_text_right,
                            bottom: subline_rect.bottom,
                        };
                        let mut hint_wide: Vec<u16> = hint.encode_utf16().collect();
                        DrawTextW(hdc, &mut hint_wide, &mut hint_rect, DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX);
                    }

                    SelectObject(hdc, old_font);
                }

                feed_update_scrollbar(hwnd, layout.total_height, height, offset);
            }

            let _ = EndPaint(hwnd, &ps);
            LRESULT(0)
        }
        WM_LBUTTONDOWN => {
            let x = (lparam.0 & 0xFFFF) as i16 as i32;
            let y = ((lparam.0 >> 16) & 0xFFFF) as i16 as i32;
            let mut client = RECT::default();
            let _ = GetClientRect(hwnd, &mut client);
            let width = client.right - client.left;

            if let Some(state) = feed_state(hwnd) {
                let hdc = GetDC(hwnd);
                let layout = compute_card_layout(hdc, state, width);
                ReleaseDC(hwnd, hdc);
                let offset = state.scroll_offset_y;

                let clicked_mark_safe_index = (0..state.entries.len()).find(|&i| {
                    mark_safe_button_rect(&layout, i, width).is_some_and(|btn| {
                        let btn_top = btn.top - offset;
                        let btn_bottom = btn.bottom - offset;
                        y >= btn_top && y < btn_bottom && x >= btn.left && x < btn.right
                    })
                });

                if let Some(i) = clicked_mark_safe_index {
                    if let Some((category, key)) = state.entries[i].acknowledgeable_group_identity() {
                        state.history.acknowledge_group(category, key);
                    }
                    let fresh = state.history.grouped_snapshot();
                    state.expanded = vec![false; fresh.len()];
                    state.entries = fresh;
                    let _ = InvalidateRect(hwnd, None, true);
                } else {
                    for i in 0..state.entries.len() {
                        let top = layout.card_top_in_unscrolled_content_space[i] - offset;
                        let bottom = top + layout.card_height[i];
                        if y >= top && y < bottom && x >= 0 && x < width {
                            if let Some(v) = state.expanded.get_mut(i) {
                                *v = !*v;
                            }
                            let _ = InvalidateRect(hwnd, None, true);
                            break;
                        }
                    }
                }
            }
            LRESULT(0)
        }
        WM_MOUSEWHEEL => {
            let delta = ((wparam.0 >> 16) & 0xFFFF) as i16 as i32;
            let mut client = RECT::default();
            let _ = GetClientRect(hwnd, &mut client);
            let height = client.bottom - client.top;
            let width = client.right - client.left;
            if let Some(state) = feed_state(hwnd) {
                let hdc = GetDC(hwnd);
                let layout = compute_card_layout(hdc, state, width);
                ReleaseDC(hwnd, hdc);
                let step = (delta / 120) * 48;
                let new_offset = state.scroll_offset_y - step;
                state.scroll_offset_y = clamp_scroll_offset(new_offset, layout.total_height, height);
                let _ = InvalidateRect(hwnd, None, true);
            }
            LRESULT(0)
        }
        WM_VSCROLL => {
            let code = (wparam.0 & 0xFFFF) as i32;
            let mut client = RECT::default();
            let _ = GetClientRect(hwnd, &mut client);
            let height = client.bottom - client.top;
            let width = client.right - client.left;
            if let Some(state) = feed_state(hwnd) {
                let hdc = GetDC(hwnd);
                let layout = compute_card_layout(hdc, state, width);
                ReleaseDC(hwnd, hdc);
                let page = height.max(1);
                let new_offset = match code {
                    c if c == SB_LINEUP.0 => state.scroll_offset_y - 24,
                    c if c == SB_LINEDOWN.0 => state.scroll_offset_y + 24,
                    c if c == SB_PAGEUP.0 => state.scroll_offset_y - page,
                    c if c == SB_PAGEDOWN.0 => state.scroll_offset_y + page,
                    c if c == SB_TOP.0 => 0,
                    c if c == SB_BOTTOM.0 => layout.total_height,
                    c if c == SB_THUMBTRACK.0 || c == SB_THUMBPOSITION.0 => {
                        ((wparam.0 >> 16) & 0xFFFF) as i32
                    }
                    _ => state.scroll_offset_y,
                };
                state.scroll_offset_y = clamp_scroll_offset(new_offset, layout.total_height, height);
                let _ = InvalidateRect(hwnd, None, true);
            }
            LRESULT(0)
        }
        WM_SIZE => {
            let _ = InvalidateRect(hwnd, None, true);
            LRESULT(0)
        }
        WM_DESTROY => {
            // Clear the shared HWND slot BEFORE freeing state: once cleared,
            // notify_new_alert() can no longer target this window at all
            // (its only way to reach it is that slot), so there is no
            // window where a post could still land after the state below
            // is freed and the handle potentially recycled.
            if let Ok(mut slot) = OPEN_FEED_HWND.lock() {
                if *slot == Some(hwnd.0 as isize) {
                    *slot = None;
                }
            }
            if let Some(state) = feed_state(hwnd) {
                let _ = Box::from_raw(state as *mut CardFeedState);
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            }
            LRESULT(0)
        }
        WM_GOOFEDUP_NEW_ALERT => {
            refresh_feed_from_history(hwnd);
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

static REGISTER_FEED_CLASS: Once = Once::new();

fn register_feed_class_once(hinstance: windows::Win32::Foundation::HMODULE) {
    REGISTER_FEED_CLASS.call_once(|| unsafe {
        let wc = WNDCLASSW {
            lpfnWndProc: Some(feed_wnd_proc),
            hInstance: hinstance.into(),
            lpszClassName: FEED_CLASS_NAME,
            hCursor: LoadCursorW(None, windows::Win32::UI::WindowsAndMessaging::IDC_ARROW).unwrap_or_default(),
            hbrBackground: windows::Win32::Graphics::Gdi::HBRUSH(
                windows::Win32::Graphics::Gdi::GetStockObject(windows::Win32::Graphics::Gdi::WHITE_BRUSH).0,
            ),
            ..Default::default()
        };
        RegisterClassW(&wc);
    });
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
    history: Arc<History>,
    result_tx: std::sync::mpsc::Sender<Result<(), String>>,
) {
    let entries = history.grouped_snapshot();
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

        register_feed_class_once(hinstance);
        // Deliberately created WITHOUT WS_VISIBLE: a visible child window
        // can receive WM_PAINT synchronously from inside CreateWindowExW
        // itself, before this function returns -- if that happens before
        // GWLP_USERDATA is attached below, feed_state() reads null and that
        // first paint silently renders an empty background with no cards
        // and no scrollbar range, and nothing later forces a second paint
        // to correct it. Live-witnessed: this was the actual cause of
        // scrollbar_range_nonzero_for_60_entries and every scroll-dependent
        // check failing in the one-shot witness even after forcing repaints
        // from the witness side -- the state was never attached in time for
        // ANY paint the witness could trigger. Creating hidden, attaching
        // state, THEN showing (which itself queues a fresh WM_PAINT with
        // state already present) closes this ordering hole entirely.
        let feed_hwnd = unsafe {
            CreateWindowExW(
                Default::default(),
                FEED_CLASS_NAME,
                &HSTRING::from(""),
                WS_CHILD | WS_VSCROLL,
                0,
                0,
                rect.right - rect.left,
                rect.bottom - rect.top,
                hwnd,
                HMENU(FEED_ID as *mut core::ffi::c_void),
                hinstance,
                None,
            )
        };
        let Ok(feed_hwnd) = feed_hwnd else {
            let _ = result_tx.send(Err("CreateWindowExW failed for the alert feed".to_string()));
            free_pre_attach_resources_since_wm_destroy_has_no_state_yet(hwnd, base_font, icon);
            return;
        };

        // The card feed's own base/bold fonts are owned and freed by the
        // FEED child window's WM_DESTROY (feed_wnd_proc), NOT by the outer
        // window's WM_DESTROY -- the outer WindowState below intentionally
        // holds DEFAULT (invalid) font handles for this branch so the outer
        // cleanup's DeleteObject calls no-op instead of double-freeing the
        // same HFONTs the feed window already owns.
        let feed_bold_font = readable_font(hwnd, BASE_FONT_POINT_SIZE, true);
        let expanded_len = entries.len();
        let feed = CardFeedState {
            entries,
            expanded: vec![false; expanded_len],
            scroll_offset_y: 0,
            base_font,
            bold_font: feed_bold_font,
            history,
        };
        let boxed_feed = Box::new(feed);
        unsafe {
            SetWindowLongPtrW(feed_hwnd, GWLP_USERDATA, Box::into_raw(boxed_feed) as isize);
            let _ = ShowWindow(feed_hwnd, SW_SHOW);
            let _ = InvalidateRect(feed_hwnd, None, true);
        }
        if let Ok(mut slot) = OPEN_FEED_HWND.lock() {
            *slot = Some(feed_hwnd.0 as isize);
        }

        attach_state(hwnd, WindowState {
            row_kinds: Vec::new(),
            base_font: windows::Win32::Graphics::Gdi::HFONT::default(),
            bold_font: windows::Win32::Graphics::Gdi::HFONT::default(),
            owner_draw_column_widths: Vec::new(),
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

pub fn show_alerts(title: &str, history: Arc<History>) -> Result<(), String> {
    let title = title.to_string();
    let (tx, rx) = std::sync::mpsc::channel::<Result<(), String>>();
    std::thread::spawn(move || create_alert_window_and_pump(&title, history, tx));
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
