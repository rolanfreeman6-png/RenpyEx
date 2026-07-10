//! egui immediate-mode application.
//!
//! Architecture (no async, no rayon — per project constraints):
//! - Each operation runs on a plain `std::thread`, streaming its result back
//!   over an `mpsc` channel. While a job is in flight the action buttons are
//!   disabled and the status bar reflects progress.
//! - The UI thread drains the channel every frame and repaints on demand.
//!
//! Visual styling (colors, spacing, fonts) is intentionally minimal here; the
//! concrete theme is applied by the binary in `src/bin/gui.rs` via
//! [`crate::gui::theme`] once finalized. This module owns *layout and behavior*,
//! not aesthetics.

use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender};

use crate::convert::ConvertTarget;
use crate::gui::config::Config;
use crate::gui::ops::{self, OpSettings};
use crate::gui::theme;

/// Which operation a background job was running (for status messages).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Job {
    /// `scan` — inventory only.
    Scan,
    /// `extract` — byte-perfect copy.
    Extract,
    /// `verify` — SHA256SUMS check.
    Verify,
    /// `convert` — image re-emit.
    Convert,
}

impl Job {
    /// Present-tense label for the status bar while running.
    pub fn running_label(self) -> &'static str {
        match self {
            Job::Scan => "scanning…",
            Job::Extract => "extracting…",
            Job::Verify => "verifying…",
            Job::Convert => "converting…",
        }
    }
}

/// Message sent from a worker thread back to the UI thread.
pub struct JobResult {
    /// Which job produced this result.
    pub job: Job,
    /// `Ok(log)` on success, `Err(message)` on failure.
    pub outcome: Result<String, String>,
}

/// The eframe application state.
pub struct RenpyExApp {
    /// Source (game) directory as typed / picked.
    pub source: String,
    /// Output directory as typed / picked.
    pub output: String,
    /// Operation settings mirrored into the left panel controls.
    pub settings: OpSettings,
    /// Accumulated log text shown in the right pane.
    pub log: String,
    /// Short status line for the bottom bar.
    pub status: String,
    /// The currently running job, if any (disables the toolbar).
    pub running: Option<Job>,
    /// Whether an external Python `unrpyc` was detected at startup.
    pub python_available: bool,

    /// Receiver for background job results (present only while a job runs).
    rx: Option<Receiver<JobResult>>,

    /// Memoized colorized render of `log`, keyed on its byte length. Rebuilt
    /// only when `log` changes, so the continuous repaints during a job don't
    /// re-classify the whole log every frame.
    log_cache: Option<(usize, egui::text::LayoutJob)>,

    /// Portrait art texture, uploaded lazily on the first paint from the
    /// embedded PNG. `None` until loaded (and if decoding ever fails).
    portrait: Option<egui::TextureHandle>,
}

/// Portrait art embedded into the binary (downscaled to 384×640 to stay lean).
const PORTRAIT_PNG: &[u8] = include_bytes!("assets/portrait.png");

impl Default for RenpyExApp {
    fn default() -> Self {
        let cfg = Config::load();
        let python_available =
            crate::archive::find_unrpyc(&crate::archive::RpycDecompileOptions::default()).is_some();
        Self {
            source: cfg.last_source,
            output: cfg.last_output,
            settings: OpSettings::default(),
            log: String::new(),
            status: "ready".to_string(),
            running: None,
            python_available,
            rx: None,
            log_cache: None,
            portrait: None,
        }
    }
}

impl RenpyExApp {
    /// Construct a fresh app state. Used both by the event loop and the
    /// headless `--probe` smoke path.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Persist the current source/output paths, ignoring errors.
    pub fn persist(&self) {
        let cfg = Config {
            last_source: self.source.clone(),
            last_output: self.output.clone(),
        };
        let _ = cfg.save();
    }

    /// Append a line to the log pane.
    fn push_log(&mut self, text: &str) {
        if !self.log.is_empty() {
            self.log.push('\n');
        }
        self.log.push_str(text);
    }

    /// Spawn a background worker for `job`. No-op if one is already running or
    /// required paths are empty.
    fn start(&mut self, job: Job) {
        if self.running.is_some() {
            return;
        }
        // Enforce the required-paths contract before spawning a doomed worker.
        let source_str = self.source.trim();
        if source_str.is_empty() {
            self.status = "set a Source directory first".to_string();
            return;
        }
        let needs_output = matches!(job, Job::Extract | Job::Convert);
        if needs_output && self.output.trim().is_empty() {
            self.status = "set an Output directory first".to_string();
            return;
        }
        let source = PathBuf::from(source_str);
        let output = PathBuf::from(self.output.trim());
        let settings = self.settings.clone();

        let (tx, rx): (Sender<JobResult>, Receiver<JobResult>) = std::sync::mpsc::channel();
        self.rx = Some(rx);
        self.running = Some(job);
        self.status = job.running_label().to_string();

        std::thread::spawn(move || {
            let outcome = run_job(job, &source, &output, &settings).map_err(|e| e.to_string());
            let _ = tx.send(JobResult { job, outcome });
        });
    }

    /// Drain any finished job result and update state.
    ///
    /// Distinguishes an empty channel (job still running) from a *disconnected*
    /// one: if the worker thread panics it drops its sender without sending, so
    /// `try_recv` yields `Disconnected`. We must clear `running` in that case —
    /// otherwise the toolbar stays disabled and the spinner spins forever.
    fn poll(&mut self) {
        use std::sync::mpsc::TryRecvError;
        let msg = self.rx.as_ref().map(|rx| rx.try_recv());
        match msg {
            Some(Ok(result)) => {
                self.rx = None;
                self.running = None;
                match result.outcome {
                    Ok(log) => {
                        self.push_log(log.trim_end());
                        self.status = "done".to_string();
                    }
                    Err(e) => {
                        self.push_log(&format!("ERROR: {e}"));
                        self.status = format!("error: {e}");
                    }
                }
            }
            Some(Err(TryRecvError::Disconnected)) => {
                self.rx = None;
                self.running = None;
                self.push_log("ERROR: worker terminated unexpectedly (panic)");
                self.status = "error: worker terminated".to_string();
            }
            // Empty → job still running; None → no job in flight.
            Some(Err(TryRecvError::Empty)) | None => {}
        }
    }

    /// Return the colorized log render, rebuilding it only when `log` changed
    /// since the last call (cheap clone of the cached job otherwise).
    fn log_job(&mut self) -> egui::text::LayoutJob {
        let len = self.log.len();
        if let Some((cached_len, job)) = &self.log_cache
            && *cached_len == len
        {
            return job.clone();
        }
        let job = colorize_log(&self.log);
        self.log_cache = Some((len, job.clone()));
        job
    }
}

/// Execute the concrete op for `job`. Kept free-standing so it runs cleanly on
/// a worker thread without borrowing the app.
fn run_job(
    job: Job,
    source: &std::path::Path,
    output: &std::path::Path,
    settings: &OpSettings,
) -> crate::Result<String> {
    match job {
        Job::Scan => ops::scan(source),
        Job::Extract => ops::extract(source, output, settings),
        Job::Verify => ops::verify(source, None),
        Job::Convert => ops::convert(source, output, settings),
    }
}

impl eframe::App for RenpyExApp {
    /// Clear the frame buffer with zero alpha instead of `Visuals::window_fill`
    /// so the glow backend actually renders a transparent window (paired with
    /// `ViewportBuilder::with_transparent(true)` in `src/bin/gui.rs`) — panels
    /// still draw their own semi-transparent fills on top via `theme::apply`.
    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        egui::Rgba::TRANSPARENT.to_array()
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll();

        let busy = self.running.is_some();

        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            ui.add_space(3.0);
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("✦ RENPYEX ✦")
                        .heading()
                        .strong()
                        .color(theme::ACCENT),
                );
                ui.separator();
                ui.add_enabled_ui(!busy, |ui| {
                    if theme::steel_button(ui, "Scan").clicked() {
                        self.start(Job::Scan);
                    }
                    if theme::steel_button(ui, "Extract").clicked() {
                        self.persist();
                        self.start(Job::Extract);
                    }
                    if theme::steel_button(ui, "Verify").clicked() {
                        self.start(Job::Verify);
                    }
                    if theme::steel_button(ui, "Convert").clicked() {
                        self.persist();
                        self.start(Job::Convert);
                    }
                });
                if busy {
                    ui.spinner();
                }
            });
            ui.add_space(3.0);
        });

        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(&self.status).color(theme::FG));
                ui.separator();
                let (label, color) = if self.python_available {
                    ("Python/unrpyc: available", theme::LOG_OK)
                } else {
                    ("Python/unrpyc: not found", theme::LOG_MUTED)
                };
                ui.label(egui::RichText::new(label).color(color));
            });
        });

        egui::SidePanel::left("controls")
            .resizable(true)
            .default_width(340.0)
            .min_width(300.0)
            .show(ctx, |ui| {
                // Portrait art. Kept outside the disabled scope so it stays at
                // full contrast while a job runs.
                self.portrait_slot(ui);
                ui.add_space(8.0);
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.add_enabled_ui(!busy, |ui| self.left_panel(ui));
                    });
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            section_heading(ui, "Log");
            theme::screen_frame().show(ui, |ui| {
                // `both` so long, unwrapped monospace lines (e.g. absolute paths
                // in failure messages) stay reachable via horizontal scroll.
                egui::ScrollArea::both()
                    .auto_shrink([false, false])
                    .stick_to_bottom(true)
                    .show(ui, |ui| {
                        if self.log.is_empty() {
                            ui.label(
                                egui::RichText::new("Logs will appear here…")
                                    .italics()
                                    .color(theme::LOG_MUTED),
                            );
                        } else {
                            let job = self.log_job();
                            ui.add(egui::Label::new(job).selectable(true));
                        }
                    });
            });
        });

        if busy {
            // Keep repainting so the channel is drained promptly.
            ctx.request_repaint();
        }
    }
}

impl RenpyExApp {
    /// Render the left settings panel (path pickers + operation flags).
    fn left_panel(&mut self, ui: &mut egui::Ui) {
        section_heading(ui, "Paths");
        ui.horizontal(|ui| {
            ui.label("Source");
            ui.text_edit_singleline(&mut self.source);
            if theme::steel_button(ui, "Browse…").clicked()
                && let Some(dir) = rfd::FileDialog::new().pick_folder()
            {
                self.source = dir.display().to_string();
            }
        });
        ui.horizontal(|ui| {
            ui.label("Output");
            ui.text_edit_singleline(&mut self.output);
            if theme::steel_button(ui, "Browse…").clicked()
                && let Some(dir) = rfd::FileDialog::new().pick_folder()
            {
                self.output = dir.display().to_string();
            }
        });

        ui.separator();
        section_heading(ui, "Settings");
        ui.checkbox(&mut self.settings.overwrite, "Overwrite non-empty output");
        ui.checkbox(&mut self.settings.include_rpa, "Unpack .rpa archives");
        ui.checkbox(&mut self.settings.decompile_rpyc, "Decompile .rpyc (needs Python)");

        ui.horizontal(|ui| {
            ui.label("XOR key (hex)");
            let mut key = self.settings.key.clone().unwrap_or_default();
            if ui.text_edit_singleline(&mut key).changed() {
                self.settings.key = if key.trim().is_empty() { None } else { Some(key) };
            }
        });

        ui.separator();
        section_heading(ui, "Convert");
        egui::ComboBox::from_label("Target format")
            .selected_text(match self.settings.convert_to {
                ConvertTarget::Png => "PNG",
                ConvertTarget::Jpeg => "JPEG",
            })
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut self.settings.convert_to, ConvertTarget::Png, "PNG");
                ui.selectable_value(&mut self.settings.convert_to, ConvertTarget::Jpeg, "JPEG");
            });
        if self.settings.convert_to == ConvertTarget::Jpeg {
            ui.add(egui::Slider::new(&mut self.settings.jpeg_quality, 1..=100).text("JPEG quality"));
        }
    }
}

/// A gold, retro-styled section heading.
fn section_heading(ui: &mut egui::Ui, title: &str) {
    ui.add_space(2.0);
    ui.label(
        egui::RichText::new(title)
            .heading()
            .strong()
            .color(theme::ACCENT),
    );
}

impl RenpyExApp {
    /// Draw the portrait at the top of the left panel: the embedded character
    /// art fit (letterboxed, aspect-preserved) inside the classic RPG
    /// double-bordered frame. Falls back to a faint hint if decoding failed.
    fn portrait_slot(&mut self, ui: &mut egui::Ui) {
        // Upload the embedded PNG as a texture once, on first paint.
        if self.portrait.is_none() {
            self.portrait = load_portrait(ui.ctx());
        }

        let w = ui.available_width();
        let h = (w * 1.4).min(360.0);
        let (rect, _resp) = ui.allocate_exact_size(egui::vec2(w, h), egui::Sense::hover());
        let painter = ui.painter();
        let outer_r = egui::Rounding::same(6.0);
        painter.rect_filled(rect, outer_r, theme::PANEL_HI);

        if let Some(tex) = &self.portrait {
            // Contain: scale to fit inside the frame without cropping, centered.
            let img = tex.size_vec2();
            let inner = rect.shrink(5.0);
            let scale = (inner.width() / img.x).min(inner.height() / img.y);
            let draw = egui::vec2(img.x * scale, img.y * scale);
            let img_rect = egui::Rect::from_center_size(rect.center(), draw);
            painter.image(
                tex.id(),
                img_rect,
                egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)),
                egui::Color32::WHITE,
            );
        } else {
            painter.text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                "portrait",
                egui::FontId::proportional(14.0),
                theme::LOG_MUTED,
            );
        }

        // Double border painted on top so it frames the art crisply.
        painter.rect_stroke(rect, outer_r, egui::Stroke::new(2.0_f32, theme::BORDER));
        let inner = rect.shrink(4.0);
        painter.rect_stroke(inner, egui::Rounding::same(4.0), egui::Stroke::new(1.0_f32, theme::ACCENT));
    }
}

/// Decode the embedded portrait PNG and upload it as an egui texture. Returns
/// `None` if the bytes fail to decode (never panics — the slot degrades to its
/// placeholder hint).
fn load_portrait(ctx: &egui::Context) -> Option<egui::TextureHandle> {
    let img = image::load_from_memory(PORTRAIT_PNG).ok()?;
    let rgba = img.to_rgba8();
    let (w, h) = rgba.dimensions();
    let color = egui::ColorImage::from_rgba_unmultiplied([w as usize, h as usize], &rgba);
    Some(ctx.load_texture("portrait", color, egui::TextureOptions::LINEAR))
}

/// Build a colorized [`egui::text::LayoutJob`] from the raw log, tinting only
/// the key markers (success / failure / info) and leaving the bulk in the
/// default foreground so the coloring stays subtle.
fn colorize_log(log: &str) -> egui::text::LayoutJob {
    use egui::text::{LayoutJob, TextFormat};

    let mut job = LayoutJob::default();
    let font = egui::FontId::monospace(13.0);
    for line in log.lines() {
        let color = log_line_color(line);
        let fmt = TextFormat {
            font_id: font.clone(),
            color,
            ..Default::default()
        };
        job.append(line, 0.0, fmt.clone());
        job.append("\n", 0.0, fmt);
    }
    job
}

/// Pick the accent color for a single log line based on its leading marker.
///
/// Best-effort cosmetic only: tinting keys off textual markers and never
/// affects the outcome of an operation. Ambiguous lines fall back to `FG`.
fn log_line_color(line: &str) -> egui::Color32 {
    let l = line.trim_start();
    // Convert summary "Converted: C, skipped: S, failed: N" — success only when
    // N == 0, otherwise flag it (it starts with "Converted:" but may report
    // failures). Checked before the success branch so it isn't mislabeled green.
    if l.starts_with("Converted:") {
        return if l.contains("failed: 0") {
            theme::LOG_OK
        } else {
            theme::LOG_ERR
        };
    }
    if l.starts_with("ERROR")
        || l.contains("MISMATCH")
        || l.contains("MISSING")
        || l.contains("fail ")
        || l.starts_with("Done with")
    {
        theme::LOG_ERR
    } else if l.starts_with("Extracted")
        || l.starts_with("Decompiled")
        || l.starts_with("Copied")
        || l.starts_with("Verified")
        || l.starts_with("Done")
    {
        theme::LOG_OK
    } else if l.starts_with("Skipped") {
        theme::LOG_MUTED
    } else if l.starts_with("Archive detected")
        || l.starts_with("Game directory")
        || l.starts_with("Walking")
        || l.starts_with("Files:")
        || l.starts_with("Total bytes")
        || l.starts_with("By classified")
        || l.ends_with(':')
    {
        theme::LOG_INFO
    } else {
        theme::FG
    }
}
