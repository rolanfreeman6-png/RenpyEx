//! GUI-facing operations: thin wrappers around the same library calls
//! [`crate::cli`] uses, but accumulating a log `String` instead of printing
//! to stdout/stderr, so the GUI can render (and colorize) it in-app.
//!
//! Unlike the CLI (which signals partial per-file failures via a non-zero
//! exit code), these functions return `Ok(log)` even when individual files
//! failed — the failure count is embedded in the log text and surfaced to
//! the user via [`crate::gui::app`]'s log colorizer. Only a hard, whole-job
//! failure (bad output directory, unreadable game directory, ...) is
//! propagated as `Err`.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use crate::archive::{
    self, decompile_rpyc, extract_rpa, list_rpa, GameWalker, RpycDecompileOptions,
};
use crate::convert::{convert_to_jpeg, convert_to_png, ConvertTarget, FormatQuality};
use crate::error::RenpyExError;
use crate::output;
use crate::verify::{self, magic::Magic};
use crate::Result;

/// User-editable operation settings mirrored by the left panel controls.
#[derive(Debug, Clone)]
pub struct OpSettings {
    /// Allow writing into an existing non-empty output directory.
    pub overwrite: bool,
    /// Also extract contents of every `.rpa` archive into a subdirectory.
    pub include_rpa: bool,
    /// Try to decompile `.rpyc` files via Python `unrpyc`.
    pub decompile_rpyc: bool,
    /// Optional XOR key (hex) for `.rpa` archives.
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
    let mut log = String::new();
    let game_dir = archive::walker::resolve_game_dir(source);
    let inv = GameWalker::new(game_dir.clone()).walk()?;
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

    if source.is_dir() {
        let mut rpa_found = 0usize;
        for entry in std::fs::read_dir(source).map_err(|e| RenpyExError::io(source, e))? {
            let entry = entry.map_err(|e| RenpyExError::io(source, e))?;
            let name = entry.file_name().into_string().unwrap_or_default();
            if name.ends_with(".rpa") {
                rpa_found += 1;
                let _ = writeln!(log, "Archive detected: {name}");
                if let Ok(listed) = list_rpa(&entry.path(), None) {
                    let _ = writeln!(
                        log,
                        "  {} version, {} entries, {} bytes uncompressed",
                        listed.version,
                        listed.entries.len(),
                        listed.total_uncompressed
                    );
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
    let mut log = String::new();
    output::prepare_output(output, settings.overwrite)?;
    let game_dir = archive::walker::resolve_game_dir(source);
    let inv = GameWalker::new(game_dir.clone()).walk()?;
    let _ = writeln!(
        log,
        "Walking {} ({} files)…",
        game_dir.display(),
        inv.files.len()
    );

    let mut failures: Vec<String> = Vec::new();
    let total = inv.files.len();
    for file in &inv.files {
        let is_archive =
            matches!(file.magic, Magic::Rpa3) || file.rel.to_string_lossy().ends_with(".rpa");
        if is_archive && !settings.include_rpa {
            continue;
        }
        let dest = match safe_join(output, &file.rel.to_string_lossy()) {
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
        if let Err(e) = std::fs::copy(&file.abs, &dest) {
            failures.push(format!("{}: {e}", file.rel.display()));
        }
    }
    let _ = writeln!(log, "Copied {total} files.");

    if settings.include_rpa {
        for entry in std::fs::read_dir(source).map_err(|e| RenpyExError::io(source, e))? {
            let entry = entry.map_err(|e| RenpyExError::io(source, e))?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("rpa") {
                let parsed_key = parse_user_key(settings.key.as_deref())?;
                let dest = output
                    .join("rpa")
                    .join(path.file_name().unwrap_or_default());
                if let Some(parent) = dest.parent()
                    && let Err(err) = std::fs::create_dir_all(parent)
                {
                    failures.push(format!("rpa {}: {err}", path.display()));
                    continue;
                }
                match extract_rpa(&path, &dest, parsed_key) {
                    Ok(listed) => {
                        let _ = writeln!(
                            log,
                            "Extracted {:?} ({} entries, {} bytes uncompressed) \u{2192} {}",
                            path.file_name().unwrap_or_default(),
                            listed.entries.len(),
                            listed.total_uncompressed,
                            dest.display()
                        );
                    }
                    Err(e) => failures.push(format!("rpa {}: {e}", path.display())),
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
            match decompile_rpyc(&file.abs, &opts) {
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
    }

    if failures.is_empty() {
        let _ = writeln!(log, "Done. Wrote {total} files.");
    } else {
        let _ = writeln!(log, "Done with {} failures.", failures.len());
        for f in &failures {
            let _ = writeln!(log, "  {f}");
        }
    }
    Ok(log)
}

/// Re-hash every file in `sums` (defaults to `<source>/SHA256SUMS.txt`)
/// against the actual contents of `source`.
pub fn verify(source: &Path, sums: Option<&Path>) -> Result<String> {
    let mut log = String::new();
    let sums_path = sums
        .map(Path::to_path_buf)
        .unwrap_or_else(|| source.join("SHA256SUMS.txt"));
    let (ok, bad) = verify::verify_all(source, &sums_path)?;
    let total = ok + bad.len() as u64;
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
            verify::VerifyOutcome::Missing { path } => {
                let _ = writeln!(log, "  MISSING {}", path.display());
            }
        }
    }
    Ok(log)
}

/// Re-emit decode-able images from `source` as PNG or JPEG into `output`.
pub fn convert(source: &Path, output: &Path, settings: &OpSettings) -> Result<String> {
    let mut log = String::new();
    output::prepare_output(output, settings.overwrite)?;

    let inv = GameWalker::new(source.to_path_buf()).walk()?;
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
        let dest_rel = file.rel.with_extension(match settings.convert_to {
            ConvertTarget::Png => "png",
            ConvertTarget::Jpeg => "jpg",
        });
        let dest = match safe_join(output, &dest_rel.to_string_lossy()) {
            Ok(p) => p,
            Err(e) => {
                let _ = writeln!(log, "  convert fail {}: {e}", file.rel.display());
                failed += 1;
                continue;
            }
        };
        let res = match settings.convert_to {
            ConvertTarget::Png => convert_to_png(&file.abs),
            ConvertTarget::Jpeg => convert_to_jpeg(&file.abs, FormatQuality(settings.jpeg_quality)),
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
            continue;
        }
        converted += 1;
    }
    let _ = writeln!(
        log,
        "Converted: {converted}, skipped (non-image): {skipped}, failed: {failed}"
    );
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

/// Sanitize and join `out_root` + `rel`, rejecting `..` traversal.
///
/// Duplicated (small) from `cli.rs`'s private helper of the same shape,
/// since that one isn't `pub`: both preserve the same no-traversal
/// invariant, just for the two independent front ends.
fn safe_join(out_root: &Path, rel: &str) -> Result<PathBuf> {
    let mut joined = out_root.to_path_buf();
    let normalised = rel.replace('\\', "/");
    for piece in normalised.split('/').filter(|s| !s.is_empty()) {
        match piece {
            "." => continue,
            ".." => {
                return Err(RenpyExError::PathTraversal {
                    archive: out_root.to_path_buf(),
                    entry: rel.to_string(),
                });
            }
            piece => joined.push(piece),
        }
    }
    Ok(joined)
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
        assert!(safe_join(root, "../etc/passwd").is_err());
        assert!(safe_join(root, "a/../../b").is_err());
    }

    #[test]
    fn safe_join_accepts_normal_relative_path() {
        let root = Path::new("/out");
        let joined = safe_join(root, "images/bg.png").unwrap();
        assert_eq!(joined, Path::new("/out/images/bg.png"));
    }

    #[test]
    fn parse_user_key_accepts_0x_prefix_and_blank() {
        assert_eq!(parse_user_key(None).unwrap(), None);
        assert_eq!(parse_user_key(Some("")).unwrap(), None);
        assert_eq!(parse_user_key(Some("0xdeadbeef")).unwrap(), Some(0xdead_beef));
        assert_eq!(parse_user_key(Some("deadbeef")).unwrap(), Some(0xdead_beef));
    }

    #[test]
    fn parse_user_key_rejects_non_hex() {
        assert!(parse_user_key(Some("nothex")).is_err());
    }
}
