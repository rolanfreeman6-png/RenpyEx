//! GUI-facing operations: thin wrappers around the same library calls
//! [`crate::cli`] uses, but accumulating a log `String` instead of printing
//! to stdout/stderr, so the GUI can render (and colorize) it in-app.
//!
//! Partial per-file failures are returned as [`RenpyExError::Integrity`],
//! matching the CLI's non-zero outcome instead of reporting a completed job.

use std::fmt::Write as _;
use std::path::Path;

use crate::Result;
use crate::archive::{
    self, GameWalker, RpycDecompileOptions, decompile_rpyc_to, ensure_python_available,
    extract_rpa, list_rpa,
};
use crate::convert::{ConvertTarget, FormatQuality, convert_to_jpeg, convert_to_png};
use crate::error::RenpyExError;
use crate::output;
use crate::verify::{self, magic::Magic};

/// User-editable operation settings mirrored by the left panel controls.
#[derive(Debug, Clone)]
pub struct OpSettings {
    /// Allow writing into an existing non-empty output directory.
    pub overwrite: bool,
    /// Also extract contents of every `.rpa` archive into a subdirectory.
    pub include_rpa: bool,
    /// Try to decompile `.rpyc` files via Python `unrpyc`.
    pub decompile_rpyc: bool,
    /// Override the header XOR key for a nonstandard `.rpa` archive.
    pub key: Option<String>,
    /// Target format for `convert`.
    pub convert_to: ConvertTarget,
    /// JPEG quality, 1..=100 (only used when `convert_to` is `Jpeg`).
    pub jpeg_quality: u8,
}

impl Default for OpSettings {
    fn default() -> Self {
        Self {
            overwrite: false,
            include_rpa: true,
            decompile_rpyc: false,
            key: None,
            convert_to: ConvertTarget::Png,
            jpeg_quality: 90,
        }
    }
}

/// Enumerate files in `source` and summarize by classified magic bytes.
pub fn scan(source: &Path) -> Result<String> {
    scan_with_progress(source, &mut |_| {})
}

pub(crate) fn scan_with_progress(source: &Path, progress: &mut dyn FnMut(&str)) -> Result<String> {
    let mut log = String::new();
    archive::walker::require_directory(source)?;
    let game_dir = archive::walker::resolve_game_dir(source);
    progress("walking source files");
    let inv = GameWalker::new(game_dir.clone()).walk()?;
    progress(&format!("classified {} files", inv.files.len()));
    let _ = writeln!(log, "Game directory: {}", game_dir.display());
    let _ = writeln!(log, "Files: {}", inv.files.len());
    let _ = writeln!(log, "Total bytes: {}", inv.total_bytes);

    let mut by_magic: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    for f in &inv.files {
        *by_magic.entry(f.magic.label().to_string()).or_insert(0) += 1;
    }
    let _ = writeln!(log, "By classified magic:");
    for (label, count) in by_magic {
        let _ = writeln!(log, "  {label:<30} {count}");
    }

    if game_dir.is_dir() {
        let mut rpa_found = 0usize;
        for file in &inv.files {
            if file
                .rel
                .extension()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.eq_ignore_ascii_case("rpa"))
            {
                rpa_found += 1;
                let _ = writeln!(log, "Archive detected: {}", file.rel.display());
                match list_rpa(&file.abs, None) {
                    Ok(listed) => {
                        let _ = writeln!(
                            log,
                            "  {} version, {} entries, {} bytes uncompressed",
                            listed.version,
                            listed.entries.len(),
                            listed.total_uncompressed
                        );
                    }
                    Err(error) => {
                        let _ = writeln!(
                            log,
                            "  warning: could not inspect {}: {error}",
                            file.rel.display()
                        );
                    }
                }
            }
        }
        if rpa_found > 0 {
            let _ = writeln!(
                log,
                "Pass \"Unpack .rpa archives\" with Extract to write archive contents."
            );
        }
    }
    Ok(log)
}

/// Walk `source` and copy files byte-perfect to `output`, honoring `settings`.
pub fn extract(source: &Path, output: &Path, settings: &OpSettings) -> Result<String> {
    extract_with_progress(source, output, settings, &mut |_| {})
}

pub(crate) fn extract_with_progress(
    source: &Path,
    output: &Path,
    settings: &OpSettings,
    progress: &mut dyn FnMut(&str),
) -> Result<String> {
    let mut log = String::new();
    archive::walker::require_directory(source)?;
    let game_dir = archive::walker::resolve_game_dir(source);
    output::reject_output_within_source(&game_dir, output)?;
    progress("walking source files");
    let inv = GameWalker::new(game_dir.clone()).walk()?;
    output::preflight_extraction_destinations(
        output,
        inv.files.iter().map(|file| file.rel.as_path()),
        settings.include_rpa,
        settings.decompile_rpyc,
    )?;
    let has_rpa = inv.files.iter().any(|file| {
        file.rel
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("rpa"))
    });
    let parsed_key = if settings.include_rpa {
        let key = parse_user_key(settings.key.as_deref())?;
        if has_rpa {
            ensure_python_available()?;
        }
        key
    } else {
        None
    };
    if settings.include_rpa && settings.decompile_rpyc && has_rpa {
        let archives: Vec<(std::path::PathBuf, std::path::PathBuf)> = inv
            .files
            .iter()
            .filter(|file| {
                file.rel
                    .extension()
                    .and_then(|extension| extension.to_str())
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("rpa"))
            })
            .map(|file| (file.abs.clone(), file.rel.clone()))
            .collect();
        crate::archive::rpyc::preflight_archive_decompilation(output, &archives, parsed_key)?;
    }
    output::prepare_output(output, settings.overwrite)?;
    progress(&format!("copying {} files", inv.files.len()));
    let _ = writeln!(
        log,
        "Walking {} ({} files)…",
        game_dir.display(),
        inv.files.len()
    );

    let mut failures: Vec<String> = Vec::new();
    let total = inv.files.len();
    for file in &inv.files {
        let dest = match output::safe_join_path(output, &file.rel) {
            Ok(p) => p,
            Err(e) => {
                failures.push(format!("{}: {e}", file.rel.display()));
                continue;
            }
        };
        if let Some(parent) = dest.parent()
            && let Err(err) = std::fs::create_dir_all(parent)
        {
            failures.push(format!("{}: {err}", file.rel.display()));
            continue;
        }
        if let Err(e) = output::copy_atomic(&file.abs, &dest) {
            failures.push(format!("{}: {e}", file.rel.display()));
        }
    }
    let _ = writeln!(log, "Copied {total} files.");
    progress(&format!("processed {total} copy operations"));

    if settings.include_rpa {
        for file in &inv.files {
            if file
                .rel
                .extension()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.eq_ignore_ascii_case("rpa"))
            {
                progress(&format!("unpacking {}", file.rel.display()));
                let dest = output.join("rpa").join(&file.rel);
                if let Some(parent) = dest.parent()
                    && let Err(err) = std::fs::create_dir_all(parent)
                {
                    failures.push(format!("rpa {}: {err}", file.rel.display()));
                    continue;
                }
                match extract_rpa(&file.abs, &dest, parsed_key) {
                    Ok(listed) => {
                        let _ = writeln!(
                            log,
                            "Extracted {:?} ({} entries, {} bytes uncompressed) \u{2192} {}",
                            file.rel,
                            listed.entries.len(),
                            listed.total_uncompressed,
                            dest.display()
                        );
                    }
                    Err(e) => failures.push(format!("rpa {}: {e}", file.rel.display())),
                }
            }
        }
    }

    if settings.decompile_rpyc {
        let opts = RpycDecompileOptions::default();
        for file in &inv.files {
            if file.rel.extension().and_then(|s| s.to_str()) != Some("rpyc") {
                continue;
            }
            progress(&format!("decompiling {}", file.rel.display()));
            let dest = output::safe_join_path(output, &file.rel)?;
            match decompile_rpyc_to(&file.abs, &dest, &opts) {
                Ok(Some(rpy)) => {
                    let _ = writeln!(
                        log,
                        "Decompiled: {} \u{2192} {}",
                        file.rel.display(),
                        rpy.display()
                    );
                }
                Ok(None) => {
                    let _ = writeln!(log, "Skipped (no unrpyc): {}", file.rel.display());
                }
                Err(e) => failures.push(format!("{}: {e}", file.rel.display())),
            }
        }
        if settings.include_rpa {
            // Decompile scripts unpacked from archives, in place on the
            // unpacked copies (the source game is never touched).
            let mut unpacked_rpyc = Vec::new();
            crate::archive::rpyc::collect_rpyc_files(&output.join("rpa"), &mut unpacked_rpyc);
            unpacked_rpyc.sort();
            for rpyc_path in unpacked_rpyc {
                progress(&format!(
                    "decompiling {}",
                    rpyc_path
                        .strip_prefix(output)
                        .unwrap_or(&rpyc_path)
                        .display()
                ));
                match decompile_rpyc_to(&rpyc_path, &rpyc_path, &opts) {
                    Ok(Some(rpy)) => {
                        let _ = writeln!(log, "Decompiled: {}", rpy.display());
                    }
                    Ok(None) => {
                        let _ = writeln!(
                            log,
                            "Skipped (no unrpyc): {}",
                            rpyc_path
                                .strip_prefix(output)
                                .unwrap_or(&rpyc_path)
                                .display()
                        );
                    }
                    Err(e) => failures.push(format!("{}: {e}", rpyc_path.display())),
                }
            }
        }
    }

    if failures.is_empty() {
        progress("writing SHA256SUMS.txt");
        let manifest = output.join("SHA256SUMS.txt");
        verify::emit_sums(output, &manifest)?;
        let _ = writeln!(log, "Manifest: {}", manifest.display());
        let _ = writeln!(log, "Done. Wrote {total} files.");
    } else {
        progress(&format!("{} extraction failures", failures.len()));
        let _ = writeln!(log, "Done with {} failures.", failures.len());
        for f in &failures {
            let _ = writeln!(log, "  {f}");
        }
        return Err(RenpyExError::Integrity { message: log });
    }
    Ok(log)
}

/// Re-hash every file in `sums` (defaults to `<source>/SHA256SUMS.txt`)
/// against the actual contents of `source`.
pub fn verify(source: &Path, sums: Option<&Path>) -> Result<String> {
    verify_with_progress(source, sums, &mut |_| {})
}

pub(crate) fn verify_with_progress(
    source: &Path,
    sums: Option<&Path>,
    progress: &mut dyn FnMut(&str),
) -> Result<String> {
    let mut log = String::new();
    let sums_path = sums
        .map(Path::to_path_buf)
        .unwrap_or_else(|| source.join("SHA256SUMS.txt"));
    progress(&format!("verifying {}", sums_path.display()));
    let (ok, bad) = verify::verify_all(source, &sums_path)?;
    let total = ok + bad.len() as u64;
    progress(&format!("verified {ok} of {total} files"));
    let _ = writeln!(
        log,
        "Verified {} / {} files in {}",
        ok,
        total,
        source.display()
    );
    for issue in &bad {
        match issue {
            verify::VerifyOutcome::Ok { .. } => {}
            verify::VerifyOutcome::HashMismatch {
                path,
                expected,
                actual,
            } => {
                let _ = writeln!(
                    log,
                    "  MISMATCH {}\n    expected: {}\n    actual:   {}",
                    path.display(),
                    expected,
                    actual
                );
            }
            verify::VerifyOutcome::FormatMismatch {
                path,
                expected,
                detected,
                message,
            } => {
                let _ = writeln!(
                    log,
                    "  INVALID FORMAT {}\n    expected: {}\n    detected: {}\n    detail:   {}",
                    path.display(),
                    expected,
                    detected,
                    message
                );
            }
            verify::VerifyOutcome::Missing { path } => {
                let _ = writeln!(log, "  MISSING {}", path.display());
            }
        }
    }
    if !bad.is_empty() {
        return Err(RenpyExError::Integrity { message: log });
    }
    Ok(log)
}

/// Re-emit decode-able images from `source` as PNG or JPEG into `output`.
pub fn convert(source: &Path, output: &Path, settings: &OpSettings) -> Result<String> {
    convert_with_progress(source, output, settings, &mut |_| {})
}

pub(crate) fn convert_with_progress(
    source: &Path,
    output: &Path,
    settings: &OpSettings,
    progress: &mut dyn FnMut(&str),
) -> Result<String> {
    let mut log = String::new();
    crate::archive::walker::require_directory(source)?;
    let game_dir = archive::walker::resolve_game_dir(source);
    output::reject_output_within_source(&game_dir, output)?;
    progress("walking source files");
    let inv = GameWalker::new(game_dir).walk()?;
    let target_extension = match settings.convert_to {
        ConvertTarget::Png => "png",
        ConvertTarget::Jpeg => "jpg",
    };
    let jpeg_quality = match settings.convert_to {
        ConvertTarget::Png => FormatQuality::default(),
        ConvertTarget::Jpeg => FormatQuality::try_from(settings.jpeg_quality)?,
    };
    let mut destinations = output::DestinationRegistry::new(output);
    for file in &inv.files {
        if matches!(
            file.magic,
            Magic::Png | Magic::Jpeg | Magic::Gif | Magic::WebP | Magic::Bmp
        ) {
            let dest_rel = file.rel.with_extension(target_extension);
            let dest = output::safe_join_path(output, &dest_rel)?;
            destinations.claim(file.rel.display().to_string(), &dest)?;
        }
    }
    output::prepare_output(output, settings.overwrite)?;
    progress("conversion preflight complete");

    let mut converted = 0usize;
    let mut skipped = 0usize;
    let mut failed = 0usize;

    for file in &inv.files {
        let is_image_payload = matches!(
            file.magic,
            Magic::Png | Magic::Jpeg | Magic::Gif | Magic::WebP | Magic::Bmp
        );
        if !is_image_payload {
            skipped += 1;
            continue;
        }
        let dest_rel = file.rel.with_extension(target_extension);
        let dest = match output::safe_join_path(output, &dest_rel) {
            Ok(p) => p,
            Err(e) => {
                let _ = writeln!(log, "  convert fail {}: {e}", file.rel.display());
                failed += 1;
                progress(&format!("failed to convert {}", file.rel.display()));
                continue;
            }
        };
        let res = match settings.convert_to {
            ConvertTarget::Png => convert_to_png(&file.abs),
            ConvertTarget::Jpeg => convert_to_jpeg(&file.abs, jpeg_quality),
        };
        let bytes = match res {
            Ok(b) => b,
            Err(e) => {
                let _ = writeln!(log, "  convert fail {}: {e}", file.rel.display());
                failed += 1;
                continue;
            }
        };
        if let Err(e) = output::write_atomic(&dest, &bytes) {
            let _ = writeln!(log, "  write fail {}: {e}", dest.display());
            failed += 1;
            progress(&format!("failed to write {}", dest.display()));
            continue;
        }
        converted += 1;
        if converted.is_multiple_of(50) {
            progress(&format!("converted {converted} images"));
        }
    }
    progress(&format!("converted {converted} images; {failed} failures"));
    let _ = writeln!(
        log,
        "Converted: {converted}, skipped (non-image): {skipped}, failed: {failed}"
    );
    if failed > 0 {
        return Err(RenpyExError::Integrity { message: log });
    }
    Ok(log)
}

/// Parse a user-supplied hex XOR key, tolerating an optional `0x` prefix and
/// blank input (meaning "no key").
fn parse_user_key(s: Option<&str>) -> Result<Option<u32>> {
    let raw = match s {
        Some(s) => s,
        None => return Ok(None),
    };
    let raw = raw.trim().trim_start_matches("0x").trim_start_matches("0X");
    if raw.is_empty() {
        return Ok(None);
    }
    let v = u64::from_str_radix(raw, 16)
        .map_err(|e| RenpyExError::Invalid(format!("key must be hex: {e}")))?;
    u32::try_from(v)
        .map(Some)
        .map_err(|_| RenpyExError::Invalid("key must fit in u32".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_settings_unpack_rpa_by_default() {
        let s = OpSettings::default();
        assert!(s.include_rpa);
        assert!(!s.overwrite);
        assert!(!s.decompile_rpyc);
        assert_eq!(s.key, None);
        assert_eq!(s.convert_to, ConvertTarget::Png);
        assert_eq!(s.jpeg_quality, 90);
    }

    #[test]
    fn safe_join_rejects_traversal() {
        let root = Path::new("/out");
        assert!(output::safe_join(root, "../etc/passwd").is_err());
        assert!(output::safe_join(root, "a/../../b").is_err());
    }

    #[test]
    fn safe_join_accepts_normal_relative_path() {
        let root = Path::new("/out");
        let joined = output::safe_join(root, "images/bg.png").unwrap();
        assert_eq!(joined, Path::new("/out/images/bg.png"));
    }

    #[test]
    fn parse_user_key_accepts_0x_prefix_and_blank() {
        assert_eq!(parse_user_key(None).unwrap(), None);
        assert_eq!(parse_user_key(Some("")).unwrap(), None);
        assert_eq!(
            parse_user_key(Some("0xdeadbeef")).unwrap(),
            Some(0xdead_beef)
        );
        assert_eq!(parse_user_key(Some("deadbeef")).unwrap(), Some(0xdead_beef));
    }

    #[test]
    fn parse_user_key_rejects_non_hex() {
        assert!(parse_user_key(Some("nothex")).is_err());
    }

    #[test]
    fn convert_rejects_destination_collision_before_writing() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let output = temp.path().join("output");
        std::fs::create_dir(&source).unwrap();
        let image = image::RgbImage::from_pixel(1, 1, image::Rgb([12, 34, 56]));
        image
            .save_with_format(source.join("same.png"), image::ImageFormat::Png)
            .unwrap();
        image
            .save_with_format(source.join("same.jpg"), image::ImageFormat::Jpeg)
            .unwrap();

        let error = convert(&source, &output, &OpSettings::default())
            .expect_err("destination collision must fail");
        assert!(error.to_string().contains("collision"), "{error}");
        assert!(
            !output.exists() || std::fs::read_dir(output).unwrap().next().is_none(),
            "collision preflight left converted output"
        );
    }

    #[test]
    fn extract_without_unpacking_rpa_copies_archive_and_reports_exact_count() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let output = temp.path().join("output");
        std::fs::create_dir(&source).unwrap();
        let archive_bytes = b"RPA-3.0 opaque archive bytes";
        std::fs::write(source.join("archive.rpa"), archive_bytes).unwrap();
        let settings = OpSettings {
            include_rpa: false,
            ..OpSettings::default()
        };

        let log = extract(&source, &output, &settings).unwrap();

        assert_eq!(
            std::fs::read(output.join("archive.rpa")).unwrap(),
            archive_bytes
        );
        let manifest = output.join("SHA256SUMS.txt");
        let (verified, failures) = verify::verify_all(&output, &manifest).unwrap();
        assert_eq!(verified, 1);
        assert!(failures.is_empty());
        assert!(log.contains("Done. Wrote 1 files."), "{log}");
    }

    #[test]
    fn extract_rejects_source_manifest_collision_before_writing() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let output = temp.path().join("output");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("payload.txt"), b"payload").unwrap();
        std::fs::write(source.join("SHA256SUMS.txt"), b"source manifest").unwrap();
        let settings = OpSettings {
            include_rpa: false,
            ..OpSettings::default()
        };

        let error = extract(&source, &output, &settings)
            .expect_err("source manifest collision must fail before output");

        assert!(error.to_string().contains("collision"), "{error}");
        assert!(
            !output.exists() || std::fs::read_dir(output).unwrap().next().is_none(),
            "manifest collision preflight left output"
        );
    }

    #[test]
    fn convert_rejects_invalid_persisted_jpeg_quality_before_output() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let output = temp.path().join("output");
        std::fs::create_dir(&source).unwrap();
        let image = image::RgbImage::from_pixel(1, 1, image::Rgb([1, 2, 3]));
        image
            .save_with_format(source.join("image.png"), image::ImageFormat::Png)
            .unwrap();
        let settings = OpSettings {
            convert_to: ConvertTarget::Jpeg,
            jpeg_quality: 0,
            ..OpSettings::default()
        };

        let error = convert(&source, &output, &settings).expect_err("quality 0 must fail");
        assert!(error.to_string().contains("1..=100"), "{error}");
        assert!(!output.exists(), "invalid settings created output");
    }

    #[test]
    fn extract_returns_error_when_an_archive_cannot_be_unpacked() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let output = temp.path().join("output");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("broken.rpa"), b"RPA-3.0 broken").unwrap();

        let error = extract(&source, &output, &OpSettings::default())
            .expect_err("partial extraction must fail the GUI operation");

        let message = error.to_string();
        assert!(message.contains("Done with 1 failures."), "{message}");
        assert!(message.contains("broken.rpa"), "{message}");
    }

    #[test]
    fn verify_returns_error_when_hash_does_not_match() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path();
        std::fs::write(source.join("file.txt"), b"actual").unwrap();
        std::fs::write(
            source.join("SHA256SUMS.txt"),
            format!("{}  file.txt\n", "0".repeat(64)),
        )
        .unwrap();

        let error = verify(source, None).expect_err("hash mismatch must fail the GUI operation");

        let message = error.to_string();
        assert!(message.contains("Verified 0 / 1"), "{message}");
        assert!(message.contains("MISMATCH"), "{message}");
    }

    #[test]
    fn convert_returns_error_when_a_detected_image_cannot_be_decoded() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let output = temp.path().join("output");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(
            source.join("truncated.png"),
            [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a],
        )
        .unwrap();

        let error = convert(&source, &output, &OpSettings::default())
            .expect_err("decode failure must fail the GUI operation");

        let message = error.to_string();
        assert!(message.contains("convert fail truncated.png"), "{message}");
        assert!(message.contains("failed: 1"), "{message}");
    }
}
