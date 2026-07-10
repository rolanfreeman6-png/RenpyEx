//! Visual theme: a retro 16-bit console-RPG palette (deep royal-blue panels,
//! gold headings, light-periwinkle borders) made **fully transparent** so the
//! desktop shows through behind the window, plus a hand-painted steel,
//! semi-glossy, slightly convex button style.
//!
//! egui's `Visuals` system has no gradient or bevel primitives, so the
//! convex/glossy button look ([`steel_button`]) is painted manually rather
//! than expressed as a style tweak.

/// Deepest background tone (log pane, central panel base) — semi-transparent
/// navy so the desktop is visible behind it.
///
/// `Color32` stores premultiplied alpha, so these are the straight color
/// `(8, 11, 28)` at alpha `150/255` pre-multiplied by hand (`channel *
/// alpha / 255`), not the straight values themselves.
pub const BG: egui::Color32 = egui::Color32::from_rgba_premultiplied(5, 6, 16, 150);
/// Panel fill (side panel, top/bottom bars) — slightly lighter than [`BG`].
/// Premultiplied form of straight color `(15, 20, 48)` at alpha `150/255`.
pub const PANEL: egui::Color32 = egui::Color32::from_rgba_premultiplied(9, 12, 28, 150);
/// Highlight fill for framed inner elements (e.g. the portrait slot).
/// Premultiplied form of straight color `(24, 31, 64)` at alpha `165/255`.
pub const PANEL_HI: egui::Color32 = egui::Color32::from_rgba_premultiplied(16, 20, 41, 165);
/// Border stroke color (light periwinkle), kept opaque so frames stay crisp.
pub const BORDER: egui::Color32 = egui::Color32::from_rgb(184, 180, 235);
/// Accent color for headings and the title (retro gold).
pub const ACCENT: egui::Color32 = egui::Color32::from_rgb(255, 209, 102);
/// Default foreground text color.
pub const FG: egui::Color32 = egui::Color32::from_rgb(228, 228, 242);
/// Log line color: success markers.
pub const LOG_OK: egui::Color32 = egui::Color32::from_rgb(120, 220, 150);
/// Log line color: failure markers.
pub const LOG_ERR: egui::Color32 = egui::Color32::from_rgb(235, 120, 120);
/// Log line color: informational headers.
pub const LOG_INFO: egui::Color32 = egui::Color32::from_rgb(160, 190, 255);
/// Log line color: skipped/muted entries.
pub const LOG_MUTED: egui::Color32 = egui::Color32::from_rgb(140, 140, 162);

/// Apply the theme to the given egui context. Call once from the app's
/// creation closure.
pub fn apply(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = PANEL;
    visuals.window_fill = PANEL;
    visuals.extreme_bg_color = BG;
    visuals.faint_bg_color = PANEL_HI;
    visuals.override_text_color = Some(FG);
    visuals.window_rounding = egui::Rounding::same(6.0);
    visuals.window_stroke = egui::Stroke::new(1.0, BORDER);

    for widgets in [
        &mut visuals.widgets.noninteractive,
        &mut visuals.widgets.inactive,
        &mut visuals.widgets.hovered,
        &mut visuals.widgets.active,
        &mut visuals.widgets.open,
    ] {
        widgets.rounding = egui::Rounding::same(4.0);
    }
    visuals.widgets.noninteractive.bg_fill = PANEL;
    visuals.widgets.inactive.bg_fill = PANEL_HI;
    visuals.widgets.inactive.weak_bg_fill = PANEL_HI;
    visuals.widgets.hovered.bg_fill = PANEL_HI;
    visuals.widgets.active.bg_fill = PANEL_HI;
    visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, BORDER);

    ctx.set_visuals(visuals);

    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::vec2(8.0, 6.0);
    style.spacing.button_padding = egui::vec2(10.0, 4.0);
    ctx.set_style(style);
}

/// Frame for the central log pane: transparent-tinted background with a
/// crisp border, matching the retro double-frame look.
#[must_use]
pub fn screen_frame() -> egui::Frame {
    egui::Frame::none()
        .fill(BG)
        .stroke(egui::Stroke::new(1.0, BORDER))
        .rounding(egui::Rounding::same(4.0))
        .inner_margin(egui::Margin::same(6.0))
}

/// A steel-gray, semi-glossy button with a slightly convex (embossed) look.
///
/// Manually painted: base fill, a banded specular highlight across the
/// upper portion (fakes a gradient), and light/dark edge strokes (fakes a
/// bevel). While pressed, the banding flattens and the edge strokes invert
/// so the button reads as pushed in rather than raised.
pub fn steel_button(ui: &mut egui::Ui, label: &str) -> egui::Response {
    let text_color = egui::Color32::from_rgb(28, 30, 36);
    let font = egui::FontId::proportional(14.0);
    let galley = ui.painter().layout_no_wrap(label.to_string(), font, text_color);

    let padding = egui::vec2(14.0, 6.0);
    let size = galley.size() + padding * 2.0;
    let (rect, response) = ui.allocate_exact_size(size, egui::Sense::click());

    if !ui.is_rect_visible(rect) {
        return response;
    }

    let pressed = response.is_pointer_button_down_on();
    let hovered = response.hovered();
    let rounding = egui::Rounding::same(5.0);
    let painter = ui.painter();

    let base = if pressed {
        egui::Color32::from_rgb(118, 126, 136)
    } else if hovered {
        egui::Color32::from_rgb(170, 178, 188)
    } else {
        egui::Color32::from_rgb(150, 158, 170)
    };
    painter.rect_filled(rect, rounding, base);

    // Banded highlight standing in for a real gradient: several stacked
    // semi-transparent white bands, each covering less of the button height,
    // so opacity increases toward the top edge.
    let bands: &[(f32, u8)] = if pressed {
        &[(0.5, 16)]
    } else {
        &[(0.18, 75), (0.32, 55), (0.46, 34), (0.60, 16)]
    };
    for (frac, alpha) in bands {
        let band_rect = egui::Rect::from_min_max(
            rect.min,
            egui::pos2(rect.max.x, rect.min.y + rect.height() * frac),
        );
        painter.rect_filled(band_rect, rounding, egui::Color32::from_white_alpha(*alpha));
    }

    let (top_edge, bottom_edge) = if pressed {
        (
            egui::Color32::from_black_alpha(90),
            egui::Color32::from_white_alpha(40),
        )
    } else {
        (
            egui::Color32::from_white_alpha(130),
            egui::Color32::from_black_alpha(90),
        )
    };
    painter.line_segment(
        [
            rect.left_top() + egui::vec2(2.0, 1.0),
            rect.right_top() + egui::vec2(-2.0, 1.0),
        ],
        egui::Stroke::new(1.0, top_edge),
    );
    painter.line_segment(
        [
            rect.left_bottom() + egui::vec2(2.0, -1.0),
            rect.right_bottom() + egui::vec2(-2.0, -1.0),
        ],
        egui::Stroke::new(1.0, bottom_edge),
    );
    painter.rect_stroke(
        rect,
        rounding,
        egui::Stroke::new(1.0, egui::Color32::from_rgb(92, 98, 108)),
    );

    let text_offset = if pressed { egui::vec2(0.0, 1.0) } else { egui::Vec2::ZERO };
    let text_pos = rect.center() - galley.size() / 2.0 + text_offset;
    painter.galley(text_pos, galley, text_color);

    response
}
