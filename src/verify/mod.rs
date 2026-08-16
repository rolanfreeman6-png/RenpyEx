//! Verification subcommand: read a portable UTF-8 SHA-256 manifest and re-hash every
//! referenced file to confirm integrity.
//!
//! The accepted subset uses the two coreutils separators but deliberately
//! rejects coreutils's escaped and non-UTF filename forms with a diagnostic.
//! Format of `SHA256SUMS.txt` (one record per line):
//!
//! ```text
//! <64-char-hex> *<relative-path>
//! ```

pub mod magic;
pub mod sha;

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::Result;
use crate::error::RenpyExError;
use crate::output;

pub use magic::{Magic, detect_with_ext};
pub use sha::{from_hex, sha256, sha256_file, to_hex};

/// Outcome of verifying a single file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// Hash matched and any recognized extension passed format validation.
    Ok {
        /// Path that was verified.
        path: PathBuf,
        /// Hex digest.
        sha256: String,
    },
    /// Hashes did not match.
    HashMismatch {
        /// Path that was verified.
        path: PathBuf,
        /// Expected hex digest.
        expected: String,
        /// Actual hex digest.
        actual: String,
    },
    /// Hash matched, but a recognized extension did not pass format
    /// validation.
    FormatMismatch {
        /// Path that failed format validation.
        path: PathBuf,
        /// Expected format label derived from the extension.
        expected: String,
        /// Magic-byte classification observed in the file.
        detected: Magic,
        /// Specific validation failure.
        message: String,
    },
    /// File referred to in sums file was missing on disk.
    Missing {
        /// Path that was expected but absent.
        path: PathBuf,
    },
}

/// Parse the documented portable UTF-8 manifest subset into
/// `(path, expected_hash)` pairs.
pub fn parse_sums(content: &str) -> Result<Vec<(PathBuf, [u8; 32])>> {
    let mut out = Vec::new();
    let mut first_line_by_path = std::collections::BTreeMap::new();
    for (lineno, raw_line) in content.split('\n').enumerate() {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('\\') {
            return Err(RenpyExError::Parse {
                path: "<SHA256SUMS>".into(),
                offset: lineno as u64,
                message: format!(
                    "line {}: escaped coreutils filenames are outside the portable UTF-8 manifest subset",
                    lineno + 1
                ),
            });
        }
        let bytes = line.as_bytes();
        if bytes.len() < 66 || bytes[64] != b' ' || !matches!(bytes[65], b' ' | b'*') {
            return Err(RenpyExError::Parse {
                path: "<SHA256SUMS>".into(),
                offset: lineno as u64,
                message: format!(
                    "line {}: expected 64 hex digits followed by two spaces or ` *`",
                    lineno + 1
                ),
            });
        }
        let hex_part = std::str::from_utf8(&bytes[..64]).map_err(|_| RenpyExError::Parse {
            path: "<SHA256SUMS>".into(),
            offset: lineno as u64,
            message: format!("line {}: digest is not ASCII", lineno + 1),
        })?;
        let path_str = std::str::from_utf8(&bytes[66..]).map_err(|_| RenpyExError::Parse {
            path: "<SHA256SUMS>".into(),
            offset: lineno as u64,
            message: format!("line {}: filename is not UTF-8", lineno + 1),
        })?;
        validate_relative_path(path_str)?;
        if let Some(first_line) = first_line_by_path.insert(path_str.to_string(), lineno + 1) {
            return Err(RenpyExError::Parse {
                path: "<SHA256SUMS>".into(),
                offset: lineno as u64,
                message: format!(
                    "line {}: duplicate manifest path {path_str:?}; first declared on line {first_line}",
                    lineno + 1
                ),
            });
        }
        let digest = sha::from_hex(hex_part).ok_or_else(|| RenpyExError::Parse {
            path: "<SHA256SUMS>".into(),
            offset: lineno as u64,
            message: format!("line {}: invalid hex digest {hex_part:?}", lineno + 1),
        })?;
        out.push((PathBuf::from(path_str), digest));
    }
    Ok(out)
}

fn validate_relative_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.starts_with('/')
        || path.as_bytes().get(1) == Some(&b':')
        || path.contains(['\\', '\n', '\r'])
        || path
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(RenpyExError::Invalid(format!(
            "manifest path must be normalized portable UTF-8, relative, and without traversal: {path:?}"
        )));
    }
    Ok(())
}

/// Read a sums file from disk.
pub fn read_sums(path: &Path) -> Result<Vec<(PathBuf, [u8; 32])>> {
    let content = fs::read_to_string(path).map_err(|e| RenpyExError::io(path, e))?;
    parse_sums(&content)
}

/// Verify a single file against its expected hash and validate recognized
/// file extensions against bounded header parsing.
pub fn verify_one(root: &Path, rel: &Path, expected: &[u8; 32]) -> Result<VerifyOutcome> {
    let relative_text = rel.to_str().ok_or_else(|| {
        RenpyExError::invalid(format!(
            "manifest verification supports only UTF-8 paths: {}",
            rel.display()
        ))
    })?;
    validate_relative_path(relative_text)?;
    let full = root.join(rel);
    let canonical_root = root.canonicalize().map_err(|e| RenpyExError::io(root, e))?;
    let canonical_full = match full.canonicalize() {
        Ok(path) => path,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(VerifyOutcome::Missing {
                path: rel.to_path_buf(),
            });
        }
        Err(e) => return Err(RenpyExError::io(&full, e)),
    };
    if !canonical_full.starts_with(&canonical_root) {
        return Err(RenpyExError::PathTraversal {
            archive: root.to_path_buf(),
            entry: rel.to_string_lossy().into_owned(),
        });
    }
    let actual = sha256_file(&canonical_full).map_err(|e| RenpyExError::io(&canonical_full, e))?;
    if &actual != expected {
        return Ok(VerifyOutcome::HashMismatch {
            path: rel.to_path_buf(),
            expected: to_hex(expected),
            actual: to_hex(&actual),
        });
    }
    let mut prefix = [0u8; 4096];
    let mut file =
        fs::File::open(&canonical_full).map_err(|e| RenpyExError::io(&canonical_full, e))?;
    let prefix_len = file
        .read(&mut prefix)
        .map_err(|e| RenpyExError::io(&canonical_full, e))?;
    let extension = rel
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase);
    let detected = detect_with_ext(&prefix[..prefix_len], extension.as_deref());
    if let Some((expected_label, is_image)) = format_expectation(extension.as_deref()) {
        if !magic_matches_extension(extension.as_deref().unwrap_or_default(), detected) {
            return Ok(VerifyOutcome::FormatMismatch {
                path: rel.to_path_buf(),
                expected: expected_label.into(),
                detected,
                message: format!(
                    "extension expects {expected_label}, but header classification is {detected}"
                ),
            });
        }
        if is_image && let Err(message) = validate_image_dimensions(&canonical_full) {
            return Ok(VerifyOutcome::FormatMismatch {
                path: rel.to_path_buf(),
                expected: expected_label.into(),
                detected,
                message,
            });
        }
    }
    Ok(VerifyOutcome::Ok {
        path: rel.to_path_buf(),
        sha256: to_hex(&actual),
    })
}

fn format_expectation(extension: Option<&str>) -> Option<(&'static str, bool)> {
    match extension? {
        "png" => Some(("PNG image", true)),
        "jpg" | "jpeg" => Some(("JPEG image", true)),
        "gif" => Some(("GIF image", true)),
        "webp" => Some(("WebP image", true)),
        "bmp" => Some(("BMP image", true)),
        "ogg" => Some(("OGG container", false)),
        "wav" => Some(("RIFF/WAV audio", false)),
        "flac" => Some(("FLAC audio", false)),
        "mp3" => Some(("MP3 audio", false)),
        "mp4" | "m4a" | "m4v" | "mov" => Some(("ISO base media", false)),
        "mkv" | "webm" => Some(("Matroska container", false)),
        _ => None,
    }
}

fn magic_matches_extension(extension: &str, detected: Magic) -> bool {
    match extension {
        "png" => detected == Magic::Png,
        "jpg" | "jpeg" => detected == Magic::Jpeg,
        "gif" => detected == Magic::Gif,
        "webp" => detected == Magic::WebP,
        "bmp" => detected == Magic::Bmp,
        "ogg" => detected == Magic::Ogg,
        "wav" => detected == Magic::Wav,
        "flac" => detected == Magic::Flac,
        "mp3" => matches!(detected, Magic::Mp3Id3 | Magic::Mp3Frame),
        "mp4" | "m4a" | "m4v" | "mov" => detected == Magic::IsoBmff,
        "mkv" | "webm" => detected == Magic::Matroska,
        _ => true,
    }
}

fn validate_image_dimensions(path: &Path) -> std::result::Result<(), String> {
    let mut reader = image::ImageReader::open(path)
        .map_err(|error| format!("cannot open image header: {error}"))?
        .with_guessed_format()
        .map_err(|error| format!("cannot identify image header: {error}"))?;
    reader.limits(crate::convert::image::decode_limits());
    reader
        .into_dimensions()
        .map(|_| ())
        .map_err(|error| format!("image header is incomplete or invalid: {error}"))
}

/// Recursively hash and enumerate every regular file under `root`, writing
/// the result as a SHA-256SUMS-format file at `out`.
pub fn emit_sums(root: &Path, out: &Path) -> Result<u64> {
    let mut entries: Vec<(PathBuf, [u8; 32])> = Vec::new();
    walk(root, root, out, &mut entries)?;
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut total: u64 = 0;
    output::write_atomic_with(out, |file| {
        let mut writer = std::io::BufWriter::new(file);
        for (rel, digest) in &entries {
            let manifest_path = portable_manifest_path(rel)?;
            let line = format!("{}  {manifest_path}\n", to_hex(digest));
            total = total
                .checked_add(line.len() as u64)
                .ok_or_else(|| RenpyExError::invalid("manifest size overflow"))?;
            writer
                .write_all(line.as_bytes())
                .map_err(|error| RenpyExError::io(out, error))?;
        }
        writer
            .flush()
            .map_err(|error| RenpyExError::io(out, error))?;
        Ok(())
    })?;
    Ok(total)
}

pub(crate) fn portable_manifest_path(path: &Path) -> Result<String> {
    let mut components = Vec::new();
    for component in path.components() {
        let std::path::Component::Normal(component) = component else {
            return Err(RenpyExError::invalid(format!(
                "manifest path is not normalized and relative: {}",
                path.display()
            )));
        };
        let component = component.to_str().ok_or_else(|| {
            RenpyExError::invalid(format!(
                "manifest supports only UTF-8 file names: {}",
                path.display()
            ))
        })?;
        if component.contains(['\\', '\n', '\r']) {
            return Err(RenpyExError::invalid(format!(
                "manifest filename uses an unsupported escape character: {component:?}"
            )));
        }
        components.push(component);
    }
    let manifest_path = components.join("/");
    validate_relative_path(&manifest_path)?;
    Ok(manifest_path)
}

fn walk(
    root: &Path,
    dir: &Path,
    sums_path: &Path,
    out: &mut Vec<(PathBuf, [u8; 32])>,
) -> Result<()> {
    for entry in fs::read_dir(dir).map_err(|e| RenpyExError::io(dir, e))? {
        let entry = entry.map_err(|e| RenpyExError::io(dir, e))?;
        let path = entry.path();
        let ft = entry.file_type().map_err(|e| RenpyExError::io(&path, e))?;
        if ft.is_dir() {
            walk(root, &path, sums_path, out)?;
        } else if ft.is_file() {
            if path == sums_path {
                continue;
            }
            let rel = path.strip_prefix(root).map_err(|_| {
                RenpyExError::invalid(format!(
                    "walk produced path not under root: {}",
                    path.display()
                ))
            })?;
            let digest = sha256_file(&path).map_err(|e| RenpyExError::io(&path, e))?;
            out.push((rel.to_path_buf(), digest));
        }
    }
    Ok(())
}

/// Re-verify every entry in a sums file against `root`.
///
/// Returns a tuple `(ok_count, mismatches)`.
pub fn verify_all(root: &Path, sums_path: &Path) -> Result<(u64, Vec<VerifyOutcome>)> {
    let entries = read_sums(sums_path)?;
    let mut destinations = output::DestinationRegistry::new(root);
    for (rel, _) in &entries {
        destinations.claim(format!("manifest entry {}", rel.display()), &root.join(rel))?;
    }
    let mut ok: u64 = 0;
    let mut bad: Vec<VerifyOutcome> = Vec::new();
    for (rel, expected) in &entries {
        match verify_one(root, rel, expected)? {
            VerifyOutcome::Ok { .. } => ok += 1,
            other => bad.push(other),
        }
    }
    Ok((ok, bad))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn parse_sums_happy() {
        let s = "0000000000000000000000000000000000000000000000000000000000000000  a\n";
        let v = parse_sums(s).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].0, PathBuf::from("a"));
    }

    #[test]
    fn parse_sums_skips_blank_and_comment() {
        let s =
            "# comment\n\n0000000000000000000000000000000000000000000000000000000000000000  x\n";
        let v = parse_sums(s).unwrap();
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn parse_sums_rejects_short_hex() {
        let s = "00  a\n";
        assert!(parse_sums(s).is_err());
    }

    #[test]
    fn emit_and_verify_round_trip() {
        let td = tempdir().unwrap();
        let root = td.path();
        std::fs::write(root.join("a.txt"), b"hello").unwrap();
        std::fs::write(root.join("b.bin"), [0xDE, 0xAD, 0xBE, 0xEF]).unwrap();

        let sums = root.join("SHA256SUMS.txt");
        emit_sums(root, &sums).unwrap();

        let entries = read_sums(&sums).unwrap();
        assert_eq!(entries.len(), 2);

        let (ok, bad) = verify_all(root, &sums).unwrap();
        assert_eq!(ok, 2);
        assert!(bad.is_empty());
    }

    #[test]
    fn emit_sums_orders_by_path_alphabetically() {
        let td = tempdir().unwrap();
        let root = td.path();
        std::fs::write(root.join("z.txt"), b"z").unwrap();
        std::fs::write(root.join("a.txt"), b"a").unwrap();
        std::fs::write(root.join("m.txt"), b"m").unwrap();
        let sums = root.join("SHA256SUMS.txt");
        emit_sums(root, &sums).unwrap();
        let text = std::fs::read_to_string(&sums).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3);
        // First line should reference 'a', last should reference 'z'.
        assert!(lines[0].ends_with("a.txt"));
        assert!(lines[2].ends_with("z.txt"));
    }

    #[test]
    fn emit_sums_handles_empty_directory() {
        let td = tempdir().unwrap();
        let sums = td.path().join("SHA256SUMS.txt");
        emit_sums(td.path(), &sums).unwrap();
        let entries = read_sums(&sums).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn emit_sums_excludes_previous_manifest_on_rerun() {
        let td = tempdir().unwrap();
        let root = td.path();
        std::fs::write(root.join("a.txt"), b"a").unwrap();
        let sums = root.join("SHA256SUMS.txt");
        emit_sums(root, &sums).unwrap();
        emit_sums(root, &sums).unwrap();
        let entries = read_sums(&sums).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, PathBuf::from("a.txt"));
    }

    #[test]
    fn detect_mutation() {
        let td = tempdir().unwrap();
        let root = td.path();
        std::fs::write(root.join("a.txt"), b"hello").unwrap();
        let sums = root.join("SHA256SUMS.txt");
        emit_sums(root, &sums).unwrap();
        std::fs::write(root.join("a.txt"), b"world").unwrap();
        let (ok, bad) = verify_all(root, &sums).unwrap();
        assert_eq!(ok, 0);
        assert_eq!(bad.len(), 1);
        assert!(matches!(bad[0], VerifyOutcome::HashMismatch { .. }));
    }

    #[test]
    fn verify_one_returns_missing_for_empty_path() {
        let td = tempdir().unwrap();
        let outcome = verify_one(td.path(), Path::new("ghost.txt"), &[0u8; 32]).unwrap();
        assert!(matches!(outcome, VerifyOutcome::Missing { .. }));
    }

    #[test]
    fn parse_sums_recognises_star_separator() {
        // gnu coreutils emits "<hex> *<path>" — `*` is an asterisk marker.
        let text = "0000000000000000000000000000000000000000000000000000000000000000 *sample.txt\n";
        let entries = parse_sums(text).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, PathBuf::from("sample.txt"));
    }

    #[test]
    fn parse_sums_rejects_absolute_and_traversal_paths() {
        let hash = "0000000000000000000000000000000000000000000000000000000000000000";
        assert!(parse_sums(&format!("{hash}  ../outside\n")).is_err());
        assert!(parse_sums(&format!("{hash}  C:/outside\n")).is_err());
    }

    #[test]
    fn parse_sums_rejects_non_normalized_paths() {
        let hash = "0000000000000000000000000000000000000000000000000000000000000000";
        for path in ["./a", "a/./b", "a//b", "a/"] {
            let error = parse_sums(&format!("{hash}  {path}\n"))
                .expect_err("non-normalized manifest path must fail");
            assert!(error.to_string().contains("normalized"), "{error}");
        }
    }

    #[test]
    fn parse_sums_rejects_duplicate_paths() {
        let hash = "0000000000000000000000000000000000000000000000000000000000000000";
        let error = parse_sums(&format!("{hash}  file.txt\n{hash}  file.txt\n"))
            .expect_err("duplicate manifest entry must fail");
        let message = error.to_string();
        assert!(message.contains("duplicate manifest path"), "{message}");
        assert!(message.contains("first declared on line 1"), "{message}");
    }

    #[test]
    fn verify_all_rejects_file_directory_aliases_before_hashing() {
        let td = tempdir().unwrap();
        let hash = "0000000000000000000000000000000000000000000000000000000000000000";
        let sums = td.path().join("SHA256SUMS.txt");
        std::fs::write(&sums, format!("{hash}  node\n{hash}  node/child.txt\n")).unwrap();

        let error = verify_all(td.path(), &sums)
            .expect_err("file/directory manifest alias must fail during preflight");
        assert!(error.to_string().contains("collision"), "{error}");
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[test]
    fn verify_all_rejects_case_equivalent_paths_before_hashing() {
        let td = tempdir().unwrap();
        let hash = "0000000000000000000000000000000000000000000000000000000000000000";
        let sums = td.path().join("SHA256SUMS.txt");
        std::fs::write(&sums, format!("{hash}  Case.txt\n{hash}  case.txt\n")).unwrap();

        let error = verify_all(td.path(), &sums)
            .expect_err("filesystem-equivalent manifest paths must fail during preflight");
        assert!(error.to_string().contains("collision"), "{error}");
    }

    #[test]
    fn parse_sums_empty_input_is_zero_entries() {
        let entries = parse_sums("").unwrap();
        assert!(entries.is_empty());
        let entries = parse_sums("# only comments\n# ...\n").unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_sums_preserves_leading_and_trailing_filename_spaces() {
        let hash = "0000000000000000000000000000000000000000000000000000000000000000";
        let entries = parse_sums(&format!("{hash}   leading and trailing  \n")).unwrap();
        assert_eq!(entries[0].0, PathBuf::from(" leading and trailing  "));
    }

    #[test]
    fn matching_hash_does_not_accept_truncated_png() {
        let td = tempdir().unwrap();
        let root = td.path();
        std::fs::write(
            root.join("truncated.png"),
            [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
        )
        .unwrap();
        let sums = root.join("SHA256SUMS.txt");
        emit_sums(root, &sums).unwrap();

        let (ok, bad) = verify_all(root, &sums).unwrap();
        assert_eq!(ok, 0);
        assert_eq!(bad.len(), 1);
        assert!(matches!(bad[0], VerifyOutcome::FormatMismatch { .. }));
    }

    #[test]
    fn valid_png_passes_hash_and_header_validation() {
        let td = tempdir().unwrap();
        let root = td.path();
        let image = image::RgbImage::from_pixel(1, 1, image::Rgb([1, 2, 3]));
        image
            .save_with_format(root.join("valid.png"), image::ImageFormat::Png)
            .unwrap();
        let sums = root.join("SHA256SUMS.txt");
        emit_sums(root, &sums).unwrap();

        let (ok, bad) = verify_all(root, &sums).unwrap();
        assert_eq!(ok, 1);
        assert!(bad.is_empty());
    }

    #[test]
    fn parse_sums_rejects_escaped_coreutils_filename_with_clear_error() {
        let hash = "0000000000000000000000000000000000000000000000000000000000000000";
        let error = parse_sums(&format!("\\{hash}  line\\nbreak\n"))
            .expect_err("escaped filename subset must fail");
        assert!(error.to_string().contains("escaped coreutils"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn emit_sums_rejects_non_utf8_name_instead_of_lossy_output() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let td = tempdir().unwrap();
        let name = OsString::from_vec(vec![b'f', 0x80]);
        std::fs::write(td.path().join(name), b"payload").unwrap();
        let sums = td.path().join("SHA256SUMS.txt");
        let error = emit_sums(td.path(), &sums).expect_err("non-UTF name must be diagnosed");
        assert!(error.to_string().contains("only UTF-8"), "{error}");
        assert!(!sums.exists());
    }
}
