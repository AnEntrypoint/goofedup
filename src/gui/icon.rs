// Tray icon rendered at runtime instead of shipping a static .ico -- a
// shield silhouette (the conventional "protection" glyph) with a coverage
// arc suggesting an eye, anti-aliased at the edge. Color communicates
// state: cyan idle/watching, gray paused, red an unacknowledged Critical
// alert is pending. Keeps the binary self-contained with no asset pipeline.

use tray_icon::Icon;

const SIZE: u32 = 32;

pub enum IconState {
    Idle,
    Paused,
    Critical,
}

fn shield_rgba(state: &IconState) -> Vec<u8> {
    let (r, g, b) = match state {
        IconState::Critical => (220u8, 38, 38),
        IconState::Paused => (120u8, 120, 120),
        IconState::Idle => (14u8, 165, 233),
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

/// Antialiased coverage (0.0..=1.0) of a shield silhouette at normalized
/// point (u, v) in [0,1]x[0,1] -- a rounded-top rectangle tapering to a
/// point at the bottom, the standard "protection" glyph shape. Computed as
/// a signed-distance-ish approximation sampled at sub-pixel offsets rather
/// than a true SDF, cheap enough to run per-pixel at tray resolution
/// without a rasterization library dependency.
fn shield_coverage(u: f32, v: f32) -> f32 {
    const SAMPLES: [(f32, f32); 4] = [(-0.17, -0.17), (0.17, -0.17), (-0.17, 0.17), (0.17, 0.17)];
    let step = 1.0 / SIZE as f32;
    let mut hits = 0;
    for (dx, dy) in SAMPLES {
        if inside_shield(u + dx * step, v + dy * step) {
            hits += 1;
        }
    }
    hits as f32 / SAMPLES.len() as f32
}

fn inside_shield(u: f32, v: f32) -> bool {
    // Shield spans roughly x in [0.2,0.8], y in [0.12,0.88] of the icon,
    // rounded top, tapering to a point at the bottom.
    let x = (u - 0.5) * 2.0; // -1..1
    let y = v;
    if y < 0.12 || y > 0.88 {
        return false;
    }
    let top_half_width = 0.62;
    let bottom_half_width = 0.05;
    let taper = ((y - 0.12) / (0.88 - 0.12)).clamp(0.0, 1.0);
    let half_width = top_half_width * (1.0 - taper) + bottom_half_width * taper;
    if x.abs() > half_width {
        return false;
    }
    // Round the top corners: within the top 15% of height, additionally
    // require distance from the nearest top corner to stay within radius.
    if y < 0.12 + 0.13 {
        let corner_y = 0.12 + 0.13;
        let corner_x = half_width * 0.86;
        if x.abs() > corner_x {
            let dx = x.abs() - corner_x;
            let dy = corner_y - y;
            let radius = half_width - corner_x + 0.02;
            if dx * dx + dy * dy > radius * radius {
                return false;
            }
        }
    }
    true
}
