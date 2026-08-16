//! Image conversion: read a decoded image and re-encode into a target
//! format.
//!
//! PNG output preserves decoded pixel values and dimensions; JPEG is
//! intrinsically lossy and discards alpha. Source metadata is not preserved.

use std::path::Path;

use image::ImageReader;

use crate::Result;
use crate::error::RenpyExError;

/// Output format for image conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageFormat {
    /// PNG output, lossless.
    Png,
    /// JPEG output, lossy (controlled by `quality`).
    Jpeg,
}

/// JPEG quality, expressed as a percentage in `1..=100`.
///
/// The tuple field remains public for source compatibility; conversion still
/// validates it at the API boundary. New callers should use [`TryFrom<u8>`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormatQuality(pub u8);

impl Default for FormatQuality {
    fn default() -> Self {
        Self(90)
    }
}

impl TryFrom<u8> for FormatQuality {
    type Error = RenpyExError;

    fn try_from(value: u8) -> Result<Self> {
        if (1..=100).contains(&value) {
            Ok(Self(value))
        } else {
            Err(RenpyExError::invalid(format!(
                "JPEG quality must be in 1..=100, got {value}"
            )))
        }
    }
}

impl FormatQuality {
    /// Return the raw quality value after construction through [`TryFrom`].
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// RenpyEx decode policy: the maximum sum of decoder allocations for a
/// single image. Set explicitly so behaviour does not silently change with
/// the `image` crate's defaults; matches the historical default of 512 MiB.
pub const MAX_DECODE_ALLOC_BYTES: u64 = 512 * 1024 * 1024;

/// Build the decoder limits applied to every decode performed by RenpyEx.
#[must_use]
pub fn decode_limits() -> image::Limits {
    let mut limits = image::Limits::default();
    limits.max_alloc = Some(MAX_DECODE_ALLOC_BYTES);
    limits
}

/// Read an input image and return a decoded `DynamicImage`. If decoding
/// fails, report a [`RenpyExError::Image`] with the input path attached.
pub fn ensure_decode(path: &Path) -> Result<image::DynamicImage> {
    let mut reader = ImageReader::open(path)
        .map_err(|e| RenpyExError::io(path, e))?
        .with_guessed_format()
        .map_err(|e| RenpyExError::io(path, e))?;
    reader.limits(decode_limits());
    reader.decode().map_err(|e| RenpyExError::Image {
        path: path.to_path_buf(),
        message: format!("decode failed: {e}"),
    })
}

/// Re-encode the supplied image bytes (PNG/JPEG/etc) to PNG.
///
/// Returns encoded PNG bytes with the decoded pixel values and dimensions.
/// Source-container metadata is not retained.
pub fn convert_to_png(input: &Path) -> Result<Vec<u8>> {
    let img = ensure_decode(input)?;
    let mut out = Vec::with_capacity(64 * 1024);
    let encoder = image::codecs::png::PngEncoder::new(&mut out);
    use image::ImageEncoder;
    encoder
        .write_image(
            img.as_bytes(),
            img.width(),
            img.height(),
            img.color().into(),
        )
        .map_err(|e| RenpyExError::Image {
            path: input.to_path_buf(),
            message: format!("PNG encode failed: {e}"),
        })?;
    Ok(out)
}

/// Re-encode the supplied image bytes to JPEG with the given quality.
pub fn convert_to_jpeg(input: &Path, quality: FormatQuality) -> Result<Vec<u8>> {
    let quality = FormatQuality::try_from(quality.0)?;
    let img = ensure_decode(input)?;
    let rgb = img.to_rgb8();
    let mut out = Vec::with_capacity(64 * 1024);
    let encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, quality.get());
    use image::ImageEncoder;
    encoder
        .write_image(
            rgb.as_raw(),
            rgb.width(),
            rgb.height(),
            image::ExtendedColorType::Rgb8,
        )
        .map_err(|e| RenpyExError::Image {
            path: input.to_path_buf(),
            message: format!("JPEG encode failed: {e}"),
        })?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageBuffer, Rgba};
    use std::io::Cursor;
    use tempfile::tempdir;

    fn make_png_bytes() -> Vec<u8> {
        let img = ImageBuffer::<Rgba<u8>, _>::from_fn(8, 8, |x, y| {
            Rgba([(x * 16) as u8, (y * 16) as u8, 128, 255])
        });
        let mut out = Vec::new();
        let dynimg = image::DynamicImage::ImageRgba8(img);
        let encoder = image::codecs::png::PngEncoder::new(&mut out);
        use image::ImageEncoder;
        encoder
            .write_image(
                dynimg.as_bytes(),
                dynimg.width(),
                dynimg.height(),
                dynimg.color().into(),
            )
            .unwrap();
        out
    }

    #[test]
    fn png_round_trip() {
        let td = tempdir().unwrap();
        let src = td.path().join("in.png");
        std::fs::write(&src, make_png_bytes()).unwrap();
        let bufs = convert_to_png(&src).unwrap();
        // Decode the re-encoded PNG to ensure validity.
        let dec = ImageReader::new(Cursor::new(bufs))
            .with_guessed_format()
            .unwrap()
            .decode()
            .unwrap();
        assert_eq!(dec.width(), 8);
        assert_eq!(dec.height(), 8);
    }

    #[test]
    fn jpeg_round_trip() {
        let rgba_buf = make_png_bytes();
        let td = tempdir().unwrap();
        let src = td.path().join("in.png");
        std::fs::write(&src, rgba_buf).unwrap();
        let bufs = convert_to_jpeg(&src, FormatQuality(90)).unwrap();
        let dec = ImageReader::new(Cursor::new(bufs))
            .with_guessed_format()
            .unwrap()
            .decode()
            .unwrap();
        assert_eq!(dec.width(), 8);
        assert_eq!(dec.height(), 8);
        assert_eq!(dec.color(), image::ColorType::Rgb8);
    }

    #[test]
    fn jpeg_drops_alpha_channel() {
        let img = ImageBuffer::<Rgba<u8>, _>::from_pixel(2, 2, Rgba([12, 34, 56, 0]));
        let mut input = Vec::new();
        let dynimg = image::DynamicImage::ImageRgba8(img);
        let encoder = image::codecs::png::PngEncoder::new(&mut input);
        use image::ImageEncoder;
        encoder
            .write_image(
                dynimg.as_bytes(),
                dynimg.width(),
                dynimg.height(),
                dynimg.color().into(),
            )
            .unwrap();

        let td = tempdir().unwrap();
        let src = td.path().join("in.png");
        std::fs::write(&src, input).unwrap();
        let bufs = convert_to_jpeg(&src, FormatQuality(90)).unwrap();
        let dec = ImageReader::new(Cursor::new(bufs))
            .with_guessed_format()
            .unwrap()
            .decode()
            .unwrap();
        assert_eq!(dec.width(), 2);
        assert_eq!(dec.height(), 2);
        assert_eq!(dec.color(), image::ColorType::Rgb8);
    }

    #[test]
    fn jpeg_quality_rejects_values_outside_documented_range() {
        let td = tempdir().unwrap();
        let src = td.path().join("in.png");
        std::fs::write(&src, make_png_bytes()).unwrap();
        assert!(convert_to_jpeg(&src, FormatQuality(0)).is_err());
        assert!(convert_to_jpeg(&src, FormatQuality(255)).is_err());
        assert!(convert_to_jpeg(&src, FormatQuality(1)).is_ok());
        assert!(convert_to_jpeg(&src, FormatQuality(100)).is_ok());
        assert!(FormatQuality::try_from(0).is_err());
        assert_eq!(FormatQuality::try_from(1).unwrap().get(), 1);
        assert_eq!(FormatQuality::try_from(100).unwrap().get(), 100);
        assert!(FormatQuality::try_from(101).is_err());
        assert!(FormatQuality::try_from(255).is_err());
    }
}
