// Tray icon rendered at runtime instead of shipping a static .ico -- a
// filled circle, cyan when idle/informational, red when an unacknowledged
// Critical alert is pending. Keeps the binary self-contained with no asset
// pipeline.

use tray_icon::Icon;

const SIZE: u32 = 32;

pub fn render(critical_pending: bool) -> Option<Icon> {
    let (r, g, b) = if critical_pending {
        (220u8, 38, 38)
    } else {
        (14u8, 165, 233)
    };

    let mut rgba = vec![0u8; (SIZE * SIZE * 4) as usize];
    let center = SIZE as f32 / 2.0;
    let radius = center - 2.0;
    for y in 0..SIZE {
        for x in 0..SIZE {
            let dx = x as f32 + 0.5 - center;
            let dy = y as f32 + 0.5 - center;
            let inside = (dx * dx + dy * dy).sqrt() <= radius;
            let idx = ((y * SIZE + x) * 4) as usize;
            if inside {
                rgba[idx] = r;
                rgba[idx + 1] = g;
                rgba[idx + 2] = b;
                rgba[idx + 3] = 255;
            }
        }
    }

    Icon::from_rgba(rgba, SIZE, SIZE).ok()
}
