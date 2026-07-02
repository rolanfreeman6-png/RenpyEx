//! Magic byte detection for verifying extracted files.
//!
//! Identification is based on the first bytes of a file, not its extension.
//! This catches truncation, corruption, and mis-named files that would
//! otherwise pass through extraction silently.

use std::fmt;

use crate::Result;

/// All file formats we recognise by magic bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Magic {
    /// PNG image.
    Png,
    /// JPEG image.
    Jpeg,
    /// GIF87a or GIF89a image.
    Gif,
    /// WebP image (RIFF/WEBP container).
    WebP,
    /// BMP image.
    Bmp,
    /// OGG container audio.
    Ogg,
    /// WAV/RIFF audio.
    Wav,
    /// ISO base media (MP4 / M4A family).
    IsoBmff,
    /// Matroska container (MKV / WebM).
    Matroska,
    /// FLAC audio.
    Flac,
    /// MP3 with ID3v2 tag.
    Mp3Id3,
    /// MP3 (sync-byte frame header).
    Mp3Frame,
    /// Ren'Py compiled `.rpyc` file.
    Rpyc,
    /// Ren'Py archive (RPA-3.0).
    Rpa3,
    /// Plain text (UTF-8 / ASCII hint detected).
    Text,
    /// Empty file.
    Empty,
    /// Unrecognised magic — either unknown format or truncated.
    Unknown,
}

impl Magic {
    /// Human-readable label for the kind of file.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Magic::Png => "PNG image",
            Magic::Jpeg => "JPEG image",
            Magic::Gif => "GIF image",
            Magic::WebP => "WebP image",
            Magic::Bmp => "BMP image",
            Magic::Ogg => "OGG container audio",
            Magic::Wav => "RIFF/WAV audio",
            Magic::IsoBmff => "ISO base media (MP4/M4A)",
            Magic::Matroska => "Matroska (MKV/WebM)",
            Magic::Flac => "FLAC audio",
            Magic::Mp3Id3 => "MP3 with ID3v2 tag",
            Magic::Mp3Frame => "MP3 frame",
            Magic::Rpyc => "Ren'Py compiled script (.rpyc)",
            Magic::Rpa3 => "Ren'Py archive (RPA-3.0)",
            Magic::Text => "Text (UTF-8/ASCII)",
            Magic::Empty => "empty file",
            Magic::Unknown => "unknown / truncated",
        }
    }
}

impl fmt::Display for Magic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Detect file magic from the first bytes of `data`.
///
/// Detection is exact for the formats listed in [`Magic`]. Unknown bytes
/// fall back to [`Magic::Unknown`]; common text-detection is conservative
/// and only triggers for short samples without NUL bytes.
#[must_use]
pub fn detect(data: &[u8]) -> Magic {
    if data.is_empty() {
        return Magic::Empty;
    }

    // PNG: 89 50 4E 47 0D 0A 1A 0A
    if data.len() >= 8 && &data[..8] == &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] {
        return Magic::Png;
    }

    // JPEG: FF D8 FF
    if data.len() >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF {
        return Magic::Jpeg;
    }

    // GIF: "GIF87a" or "GIF89a"
    if data.len() >= 6 && (&data[..6] == b"GIF87a" || &data[..6] == b"GIF89a") {
        return Magic::Gif;
    }

    // WebP: "RIFF????WEBP"
    if data.len() >= 12
        && &data[..4] == b"RIFF"
        && &data[8..12] == b"WEBP"
    {
        return Magic::WebP;
    }

    // BMP: "BM"
    if data.len() >= 2 && &data[..2] == b"BM" {
        return Magic::Bmp;
    }

    // OGG: "OggS"
    if data.len() >= 4 && &data[..4] == b"OggS" {
        return Magic::Ogg;
    }

    // WAV: "RIFF????WAVE"
    if data.len() >= 12 && &data[..4] == b"RIFF" && &data[8..12] == b"WAVE" {
        return Magic::Wav;
    }

    // FLAC: "fLaC"
    if data.len() >= 4 && &data[..4] == b"fLaC" {
        return Magic::Flac;
    }

    // ISO base media (MP4/M4A): four-byte size + "ftyp"
    if data.len() >= 12 && &data[4..8] == b"ftyp" {
        return Magic::IsoBmff;
    }

    // Matroska / WebM: 0x1A 0x45 0xDF 0xA3
    if data.len() >= 4 && data[..4] == [0x1A, 0x45, 0xDF, 0xA3] {
        return Magic::Matroska;
    }

    // ID3v2: "ID3" + version bytes
    if data.len() >= 3 && &data[..3] == b"ID3" {
        return Magic::Mp3Id3;
    }

    // MP3 frame: 0xFF 0xFB / 0xFF 0xFA / etc.
    if data.len() >= 2 && data[0] == 0xFF && (data[1] & 0xE0) == 0xE0 {
        return Magic::Mp3Frame;
    }

    // Ren'Py .rpyc: uncompressed marshal — starts with typecode byte
    // (typically 0xE9 / METHOD, but Python marshal stream is more complex).
    // We use extension hint by fallback in [`detect_with_ext`].
    // For magic detection alone, we accept a marker: presence of the
    // 4-byte string " Ren'" is not enough, so we skip pure-magic detection
    // and rely on extension. Pure-magic detection is unreliable across
    // Python marshal versions, so we conservatively report Unknown.

    // Ren'Py archive: "RPA-3.0"
    if data.len() >= 7 && &data[..7] == b"RPA-3.0" {
        return Magic::Rpa3;
    }

    // Conservative plain-text hint: short sample, all printable ASCII,
    // no NUL bytes.
    if data.len() <= 64 && data.iter().all(|b| is_text_byte(*b)) {
        return Magic::Text;
    }

    Magic::Unknown
}

/// Combine magic-byte detection with a hinted extension. Extension is a
/// fall-back for formats whose magic detection is unreliable (e.g. `.rpyc`).
#[must_use]
pub fn detect_with_ext(data: &[u8], ext_hint: Option<&str>) -> Magic {
    let m = detect(data);
    if m != Magic::Unknown {
        return m;
    }
    match ext_hint {
        Some("rpyc") => Magic::Rpyc,
        Some("rpy") => Magic::Text,
        Some("py") => Magic::Text,
        Some("txt") => Magic::Text,
        Some("json") => return detect(data), // small JSON may still be classified as text
        _ => Magic::Unknown,
    }
}

const fn is_text_byte(b: u8) -> bool {
    b == b'\n' || b == b'\r' || b == b'\t' || (b >= 0x20 && b < 0x7F)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_empty() {
        assert_eq!(detect(&[]), Magic::Empty);
    }

    #[test]
    fn detects_png() {
        assert_eq!(
            detect(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
            Magic::Png
        );
    }

    #[test]
    fn detects_jpeg() {
        assert_eq!(detect(&[0xFF, 0xD8, 0xFF, 0xE0]), Magic::Jpeg);
    }

    #[test]
    fn detects_gif89a() {
        assert_eq!(detect(b"GIF89a"), Magic::Gif);
    }

    #[test]
    fn detects_webp_full() {
        let mut buf = [0u8; 12];
        buf[..4].copy_from_slice(b"RIFF");
        buf[8..12].copy_from_slice(b"WEBP");
        assert_eq!(detect(&buf), Magic::WebP);
    }

    #[test]
    fn detects_wav_full() {
        let mut buf = [0u8; 12];
        buf[..4].copy_from_slice(b"RIFF");
        buf[8..12].copy_from_slice(b"WAVE");
        assert_eq!(detect(&buf), Magic::Wav);
    }

    #[test]
    fn detects_rpa3() {
        assert_eq!(detect(b"RPA-3.0"), Magic::Rpa3);
    }

    #[test]
    fn detects_text() {
        assert_eq!(detect(b"label start:\n    pass\n"), Magic::Text);
    }

    #[test]
    fn rejects_nul_text() {
        assert_eq!(
            detect(&[0x48, 0x00, 0x65, 0x6C]),
            Magic::Unknown
        );
    }

    #[test]
    fn detects_iso_bmff() {
        let mut buf = [0u8; 12];
        buf[4..8].copy_from_slice(b"ftyp");
        assert_eq!(detect(&buf), Magic::IsoBmff);
    }

    #[test]
    fn detects_matroska() {
        assert_eq!(detect(&[0x1A, 0x45, 0xDF, 0xA3]), Magic::Matroska);
    }

    #[test]
    fn extension_hint_classifies_rpyc() {
        assert_eq!(detect_with_ext(&[0, 1, 2, 3, 4], Some("rpyc")), Magic::Rpyc);
    }
}
