//! Conversion of extracted assets into different output formats.
//!
//! Conversion is explicitly **lossless-only by default**. JPEG is offered
//! as a lossy option with explicit `--jpeg-quality` knob (default 90).
//!
//! Supported conversions:
//! - Any decode-able image → PNG (lossless)
//! - Any decode-able image → JPEG (lossy, configurable quality)
//!
//! Audio and video conversions are intentionally out of scope for this
//! iteration: pass-through extraction already produces the original
//! byte-perfect output, and re-encoding audio/video through ffmpeg would
//! either be lossy or require an external dependency.

pub mod image;
pub mod targets;

pub use image::{
    convert_to_jpeg, convert_to_png, ensure_decode, FormatQuality, ImageFormat,
};
pub use targets::{ConvertTarget, ConversionPlan};
