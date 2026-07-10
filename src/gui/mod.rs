//! Native desktop GUI (feature-gated behind `gui`).
//!
//! Thin egui/eframe layer over the same library API the CLI uses in
//! [`crate::cli`] — the extraction/verification/conversion logic itself
//! lives only in the library, this module wraps it for interactive use.

pub mod app;
pub mod config;
pub mod ops;
pub mod theme;

pub use app::RenpyExApp;
