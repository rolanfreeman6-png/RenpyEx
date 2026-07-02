//! Selected conversion targets.

use std::path::PathBuf;

/// User-facing conversion choice for `convert` subcommand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConvertTarget {
    /// Re-emit all decode-able images as PNG (lossless).
    Png,
    /// Re-emit all decode-able images as JPEG (lossy).
    Jpeg,
}

impl ConvertTarget {
    /// Parse from a user-facing string.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "png" | "PNG" => Some(Self::Png),
            "jpg" | "jpeg" | "JPG" | "JPEG" => Some(Self::Jpeg),
            _ => None,
        }
    }
}

/// Concrete plan describing which files to convert, and their output paths.
#[derive(Debug, Clone)]
pub struct ConversionPlan {
    /// Output base directory (created with `prepare_output`).
    pub out_root: PathBuf,
}

impl ConversionPlan {
    /// Construct a fresh plan.
    #[must_use]
    pub fn new(out_root: PathBuf) -> Self {
        Self { out_root }
    }
}
