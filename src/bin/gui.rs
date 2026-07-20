//! Native desktop GUI entry point (feature-gated behind `gui`).
//!
//! `--probe` runs a headless smoke path (construct the app state, print a
//! one-line summary, exit) so CI on displayless machines can verify the GUI
//! binary at least starts up and its startup logic doesn't panic, without
//! needing a real window/display.
//!
//! ## Overlay translucency (Windows)
//!
//! Per-pixel GPU alpha (`clear_color` → zero alpha) never composites against
//! the desktop on Windows in either eframe backend (glow or wgpu) — the
//! window renders over an opaque white/black backdrop instead
//! (<https://github.com/emilk/egui/issues/4451>). So the see-through look is
//! done at the OS level: the window is marked `WS_EX_LAYERED` and given a
//! whole-window alpha via `SetLayeredWindowAttributes`, which DWM composites
//! against whatever is behind the window regardless of how the frame was
//! rendered.

use renpyex::gui::RenpyExApp;

/// Whole-window alpha for the layered overlay (0 = invisible, 255 = opaque).
#[cfg(windows)]
const OVERLAY_ALPHA: u8 = 210;

/// Mark the native window as layered and apply [`OVERLAY_ALPHA`].
///
/// Isolated `unsafe`: raw Win32 calls on a valid HWND obtained from winit via
/// `raw-window-handle`; both calls are documented safe for any window owned
/// by the calling thread's process. No-op if the handle is unavailable.
#[cfg(windows)]
#[allow(unsafe_code)]
fn make_window_translucent(frame: &eframe::Frame) {
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        GetWindowLongPtrW, SetLayeredWindowAttributes, SetWindowLongPtrW, GWL_EXSTYLE, LWA_ALPHA,
        WS_EX_LAYERED,
    };

    let Ok(handle) = frame.window_handle() else {
        return;
    };
    let RawWindowHandle::Win32(win32) = handle.as_raw() else {
        return;
    };
    let hwnd = win32.hwnd.get() as windows_sys::Win32::Foundation::HWND;
    // SAFETY: `hwnd` comes from winit's live window; adding WS_EX_LAYERED and
    // setting whole-window alpha are benign style tweaks with no memory
    // safety concerns.
    unsafe {
        let ex_style = GetWindowLongPtrW(hwnd, GWL_EXSTYLE);
        SetWindowLongPtrW(hwnd, GWL_EXSTYLE, ex_style | WS_EX_LAYERED as isize);
        SetLayeredWindowAttributes(hwnd, 0, OVERLAY_ALPHA, LWA_ALPHA);
    }
}

#[cfg(not(windows))]
fn make_window_translucent(_frame: &eframe::Frame) {}

/// Wrapper that applies the layered-window style once on the first frame —
/// the HWND doesn't exist yet in the creation closure, so it can't be done
/// there.
struct TranslucentApp {
    inner: RenpyExApp,
    styled: bool,
}

impl eframe::App for TranslucentApp {
    fn clear_color(&self, visuals: &egui::Visuals) -> [f32; 4] {
        self.inner.clear_color(visuals)
    }

    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        if !self.styled {
            make_window_translucent(frame);
            self.styled = true;
        }
        self.inner.update(ctx, frame);
    }
}

fn main() {
    let probe = std::env::args().any(|a| a == "--probe");
    if probe {
        let app = RenpyExApp::new();
        println!(
            "renpyex-gui probe ok (source={:?}, python_available={})",
            app.source, app.python_available
        );
        return;
    }

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1100.0, 700.0])
            .with_min_inner_size([720.0, 480.0])
            .with_title("RenpyEx")
            // Borderless: the native frame would be excluded from the layered
            // alpha unevenly and looks out of place on an overlay. The toolbar
            // acts as the title bar (drag to move, ❌/🗕 buttons) — see
            // `RenpyExApp::update`.
            .with_decorations(false),
        ..Default::default()
    };

    let result = eframe::run_native(
        "RenpyEx",
        native_options,
        Box::new(|cc| {
            renpyex::gui::theme::apply(&cc.egui_ctx);
            Ok(Box::new(TranslucentApp {
                inner: RenpyExApp::new(),
                styled: false,
            }))
        }),
    );

    if let Err(e) = result {
        eprintln!("renpyex-gui: fatal error: {e}");
        std::process::exit(1);
    }
}
