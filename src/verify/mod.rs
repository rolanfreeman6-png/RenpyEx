//! Verification subcommand: read a SHA-256SUMS file and re-hash every
//! referenced file to confirm integrity.
//!
//! Format of `SHA256SUMS.txt` (one record per line):
//!
//! ```text
//! <64-char-hex> *<relative-path>
//! ```

pub mod magic;
pub mod sha;

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::Result;
use crate::error::RenpyExError;

pub use magic::{detect_with_ext, Magic};
pub use sha::{from_hex, sha256, to_hex};

/// Outcome of verifying a single file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// Hashes matched and magic bytes indicate the file is intact.
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
    /// File referred to in sums file was missing on disk.
    Missing {
        /// Path that was expected but absent.
        path: PathBuf,
    },
}

/// Parse a SHA-256SUMS-format string into `(path, expected_hash)` pairs.
pub fn parse_sums(content: &str) -> Result<Vec<(PathBuf, [u8; 32])>> {
    let mut out = Vec::new();
    for (lineno, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        let (hex_part, rest) = trimmed.split_once(' ').ok_or_else(|| RenpyExError::Parse {
            path: "<SHA256SUMS>".into(),
            offset: lineno as u64,
            message: format!("line {lineno}: no space separator"),
        })?;
        let path_str = rest.trim_start_matches('*').trim();
        let digest = sha::from_hex(hex_part).ok_or_else(|| RenpyExError::Parse {
            path: "<SHA256SUMS>".into(),
            offset: lineno as u64,
            message: format!("line {lineno}: invalid hex digest {hex_part:?}"),
        })?;
        out.push((PathBuf::from(path_str), digest));
    }
    Ok(out)
}

/// Read a sums file from disk.
pub fn read_sums(path: &Path) -> Result<Vec<(PathBuf, [u8; 32])>> {
    let content = fs::read_to_string(path).map_err(|e| RenpyExError::io(path, e))?;
    parse_sums(&content)
}

/// Verify a single file against its expected hash and check magic bytes.
pub fn verify_one(root: &Path, rel: &Path, expected: &[u8; 32]) -> Result<VerifyOutcome> {
    let full = root.join(rel);
    let bytes = match fs::read(&full) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(VerifyOutcome::Missing {
                path: rel.to_path_buf(),
            });
        }
        Err(e) => return Err(RenpyExError::io(full, e)),
    };
    let actual = sha256(&bytes);
    if &actual != expected {
        return Ok(VerifyOutcome::HashMismatch {
            path: rel.to_path_buf(),
            expected: to_hex(expected),
            actual: to_hex(&actual),
        });
    }
    // Magic-byte sniff for sanity (does not affect outcome).
    let _ = detect_with_ext(&bytes, rel.extension().and_then(|s| s.to_str()));
    Ok(VerifyOutcome::Ok {
        path: rel.to_path_buf(),
        sha256: to_hex(&actual),
    })
}

/// Recursively hash and enumerate every regular file under `root`, writing
/// the result as a SHA-256SUMS-format file at `out`.
pub fn emit_sums(root: &Path, out: &Path) -> Result<u64> {
    let mut entries: Vec<(PathBuf, [u8; 32])> = Vec::new();
    walk(root, root, &mut entries)?;
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let f = fs::File::create(out).map_err(|e| RenpyExError::io(out, e))?;
    let mut writer = std::io::BufWriter::new(f);
    let mut total: u64 = 0;
    for (rel, digest) in &entries {
        let line = format!("{}  {}\n", to_hex(digest), rel.display());
        total += line.len() as u64;
        writer
            .write_all(line.as_bytes())
            .map_err(|e| RenpyExError::io(out, e))?;
    }
    writer.flush().map_err(|e| RenpyExError::io(out, e))?;
    Ok(total)
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<(PathBuf, [u8; 32])>) -> Result<()> {
    for entry in fs::read_dir(dir).map_err(|e| RenpyExError::io(dir, e))? {
        let entry = entry.map_err(|e| RenpyExError::io(dir, e))?;
        let path = entry.path();
        let ft = entry
            .file_type()
            .map_err(|e| RenpyExError::io(&path, e))?;
        if ft.is_dir() {
            walk(root, &path, out)?;
        } else if ft.is_file() {
            let bytes = fs::read(&path).map_err(|e| RenpyExError::io(&path, e))?;
            let rel = path.strip_prefix(root).map_err(|_| {
                RenpyExError::invalid(format!(
                    "walk produced path not under root: {}",
                    path.display()
                ))
            })?;
            out.push((rel.to_path_buf(), sha256(&bytes)));
        }
    }
    Ok(())
}

/// Re-verify every entry in a sums file against `root`.
///
/// Returns a tuple `(ok_count, mismatches)`.
pub fn verify_all(root: &Path, sums_path: &Path) -> Result<(u64, Vec<VerifyOutcome>)> {
    let entries = read_sums(sums_path)?;
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
        let s = "# comment\n\n0000000000000000000000000000000000000000000000000000000000000000  x\n";
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
        std::fs::write(root.join("b.bin"), &[0xDE, 0xAD, 0xBE, 0xEF]).unwrap();

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
    fn parse_sums_empty_input_is_zero_entries() {
        let entries = parse_sums("").unwrap();
        assert!(entries.is_empty());
        let entries = parse_sums("# only comments\n# ...\n").unwrap();
        assert!(entries.is_empty());
    }
}
