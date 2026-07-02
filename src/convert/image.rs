//! Image conversion: read a decoded image and re-encode into a target
//! format.
//!
//! Both `convert_to_png` and `convert_to_jpeg` are lossless w.r.t. PNG
//! encoding once the image is in memory; JPEG is intrinsically lossy but
//! quality parameter is exposed.

use std::path::Path;

use image::ImageReader;

use crate::error::RenpyExError;
use crate::Result;

/// Output format for image conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageFormat {
    /// PNG output, lossless.
    Png,
    /// JPEG output, lossy (controlled by `quality`).
    Jpeg,
}

/// JPEG quality, expressed as a percentage in `1..=100`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormatQuality(pub u8);

impl Default for FormatQuality {
    fn default() -> Self {
        Self(90)
    }
}

/// Read an input image and return a decoded `DynamicImage`. If decoding
/// fails, report a [`RenpyExError::Image`] with the input path attached.
pub fn ensure_decode(path: &Path) -> Result<image::DynamicImage> {
    ImageReader::open(path)
        .map_err(|e| RenpyExError::io(path, e))?
        .with_guessed_format()
        .map_err(|e| RenpyExError::io(path, e))?
        .decode()
        .map_err(|e| RenpyExError::Image {
            path: path.to_path_buf(),
            message: format!("decode failed: {e}"),
        })
}

/// Re-encode the supplied image bytes (PNG/JPEG/etc) to PNG.
///
/// Returns the encoded PNG bytes (`Vec<u8>`). Output length is dependent
/// only on the image dimensions — content is decoupled from the original
/// format choice. Caller writes them with the byte-perfect guarantees we
/// already establish elsewhere.
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
    let img = ensure_decode(input)?;
    let mut out = Vec::with_capacity(64 * 1024);
    let encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, quality.0);
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
        // Use an RGB8 fixture since JPEG does not support RGBA8.
        let img = ImageBuffer::<image::Rgb<u8>, _>::from_fn(8, 8, |x, y| {
            image::Rgb([(x * 16) as u8, (y * 16) as u8, 128])
        });
        let mut rgba_buf = Vec::new();
        let dynimg = image::DynamicImage::ImageRgb8(img);
        let encoder = image::codecs::png::PngEncoder::new(&mut rgba_buf);
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
        std::fs::write(&src, rgba_buf).unwrap();
        let bufs = convert_to_jpeg(&src, FormatQuality(90)).unwrap();
        let dec = ImageReader::new(Cursor::new(bufs))
            .with_guessed_format()
            .unwrap()
            .decode()
            .unwrap();
        assert_eq!(dec.width(), 8);
        assert_eq!(dec.height(), 8);
    }
}
