//! Native desktop GUI entry point (feature-gated behind `gui`).
//!
//! `--probe` runs a headless smoke path (construct the app state, print a
//! one-line summary, exit) so CI on displayless machines can verify the GUI
//! binary at least starts up and its startup logic doesn't panic, without
//! needing a real window/display.

use renpyex::gui::RenpyExApp;

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
            .with_transparent(true),
        ..Default::default()
    };

    let result = eframe::run_native(
        "RenpyEx",
        native_options,
        Box::new(|cc| {
            renpyex::gui::theme::apply(&cc.egui_ctx);
            Ok(Box::new(RenpyExApp::new()))
        }),
    );

    if let Err(e) = result {
        eprintln!("renpyex-gui: fatal error: {e}");
        std::process::exit(1);
    }
}
