use tray_icon::Icon;

const SIZE: u32 = 32;

const CRITICAL_RGB: (u8, u8, u8) = (220, 38, 38);
const PAUSED_RGB: (u8, u8, u8) = (120, 120, 120);
const IDLE_RGB: (u8, u8, u8) = (14, 165, 233);

const SUBPIXEL_SAMPLE_OFFSETS: [(f32, f32); 4] = [(-0.17, -0.17), (0.17, -0.17), (-0.17, 0.17), (0.17, 0.17)];

const SHIELD_TOP_Y: f32 = 0.12;
const SHIELD_BOTTOM_Y: f32 = 0.88;
const SHIELD_TOP_HALF_WIDTH: f32 = 0.62;
const SHIELD_BOTTOM_HALF_WIDTH: f32 = 0.05;
const SHIELD_ROUNDED_TOP_HEIGHT: f32 = 0.13;
const SHIELD_CORNER_START_RATIO: f32 = 0.86;
const SHIELD_CORNER_RADIUS_SLACK: f32 = 0.02;

pub enum IconState {
    Idle,
    Paused,
    Critical,
}

fn shield_rgba(state: &IconState) -> Vec<u8> {
    let (r, g, b) = match state {
        IconState::Critical => CRITICAL_RGB,
        IconState::Paused => PAUSED_RGB,
        IconState::Idle => IDLE_RGB,
    };

    let mut rgba = vec![0u8; (SIZE * SIZE * 4) as usize];
    let s = SIZE as f32;

    for y in 0..SIZE {
        for x in 0..SIZE {
            let px = x as f32 + 0.5;
            let py = y as f32 + 0.5;
            let coverage = shield_coverage(px / s, py / s);
            if coverage <= 0.0 {
                continue;
            }
            let idx = ((y * SIZE + x) * 4) as usize;
            rgba[idx] = r;
            rgba[idx + 1] = g;
            rgba[idx + 2] = b;
            rgba[idx + 3] = (coverage.min(1.0) * 255.0) as u8;
        }
    }

    rgba
}

pub fn render(state: IconState) -> Option<Icon> {
    let rgba = shield_rgba(&state);
    Icon::from_rgba(rgba, SIZE, SIZE).ok()
}

#[cfg(windows)]
pub fn shield_hicon(state: IconState) -> Option<windows::Win32::UI::WindowsAndMessaging::HICON> {
    use windows::Win32::Graphics::Gdi::{
        CreateBitmap, CreateDIBSection, DeleteObject, BITMAPINFO, BITMAPINFOHEADER, BI_RGB,
        DIB_RGB_COLORS, HDC,
    };
    use windows::Win32::UI::WindowsAndMessaging::{CreateIconIndirect, ICONINFO};

    let rgba = shield_rgba(&state);
    let mut bgra = vec![0u8; rgba.len()];
    for px in 0..(SIZE * SIZE) as usize {
        let i = px * 4;
        bgra[i] = rgba[i + 2];
        bgra[i + 1] = rgba[i + 1];
        bgra[i + 2] = rgba[i];
        bgra[i + 3] = rgba[i + 3];
    }

    unsafe {
        let bmi = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: SIZE as i32,
                biHeight: -(SIZE as i32),
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB.0 as u32,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut bits_ptr: *mut core::ffi::c_void = std::ptr::null_mut();
        let Ok(color_bitmap) =
            CreateDIBSection(HDC::default(), &bmi, DIB_RGB_COLORS, &mut bits_ptr, None, 0)
        else {
            return None;
        };
        if color_bitmap.is_invalid() || bits_ptr.is_null() {
            return None;
        }
        std::ptr::copy_nonoverlapping(bgra.as_ptr(), bits_ptr as *mut u8, bgra.len());

        let mask_bits = vec![0u8; ((SIZE + 7) / 8 * SIZE) as usize];
        let mask_bitmap = CreateBitmap(SIZE as i32, SIZE as i32, 1, 1, Some(mask_bits.as_ptr() as *const core::ffi::c_void));
        if mask_bitmap.is_invalid() {
            let _ = DeleteObject(color_bitmap);
            return None;
        }

        let icon_info = ICONINFO {
            fIcon: true.into(),
            xHotspot: 0,
            yHotspot: 0,
            hbmMask: mask_bitmap,
            hbmColor: color_bitmap,
        };
        let hicon = CreateIconIndirect(&icon_info);
        let _ = DeleteObject(color_bitmap);
        let _ = DeleteObject(mask_bitmap);
        hicon.ok()
    }
}

fn shield_coverage(u: f32, v: f32) -> f32 {
    let step = 1.0 / SIZE as f32;
    let mut hits = 0;
    for (dx, dy) in SUBPIXEL_SAMPLE_OFFSETS {
        if inside_shield(u + dx * step, v + dy * step) {
            hits += 1;
        }
    }
    hits as f32 / SUBPIXEL_SAMPLE_OFFSETS.len() as f32
}

fn inside_shield(u: f32, v: f32) -> bool {
    let x = (u - 0.5) * 2.0;
    let y = v;
    if y < SHIELD_TOP_Y || y > SHIELD_BOTTOM_Y {
        return false;
    }
    let taper = ((y - SHIELD_TOP_Y) / (SHIELD_BOTTOM_Y - SHIELD_TOP_Y)).clamp(0.0, 1.0);
    let half_width = SHIELD_TOP_HALF_WIDTH * (1.0 - taper) + SHIELD_BOTTOM_HALF_WIDTH * taper;
    if x.abs() > half_width {
        return false;
    }
    if y < SHIELD_TOP_Y + SHIELD_ROUNDED_TOP_HEIGHT {
        let corner_y = SHIELD_TOP_Y + SHIELD_ROUNDED_TOP_HEIGHT;
        let corner_x = half_width * SHIELD_CORNER_START_RATIO;
        if x.abs() > corner_x {
            let dx = x.abs() - corner_x;
            let dy = corner_y - y;
            let radius = half_width - corner_x + SHIELD_CORNER_RADIUS_SLACK;
            if dx * dx + dy * dy > radius * radius {
                return false;
            }
        }
    }
    true
}
