//! Output management: prepare an output folder, write files, summarise
//! progress safely.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::Result;
use crate::error::RenpyExError;

/// Prepare an output directory for use.
///
/// If `path` does not exist, create it. If it exists and is empty, reuse.
/// If it exists and is non-empty, return an error unless `overwrite` is set.
pub fn prepare_output(path: &Path, overwrite: bool) -> Result<()> {
    match fs::metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(path).map_err(|e| RenpyExError::io(path, e))?;
            Ok(())
        }
        Err(e) => Err(RenpyExError::io(path, e)),
        Ok(md) if md.is_dir() => {
            if overwrite {
                wipe(path)?;
                Ok(())
            } else {
                let read = fs::read_dir(path).map_err(|e| RenpyExError::io(path, e))?;
                if read.count() > 0 {
                    Err(RenpyExError::Invalid(format!(
                        "output directory {} is non-empty; pass --overwrite to delete its contents",
                        path.display()
                    )))
                } else {
                    Ok(())
                }
            }
        }
        Ok(_) => Err(RenpyExError::Invalid(format!(
            "output path {} exists but is not a directory",
            path.display()
        ))),
    }
}

/// Wipe the contents of an output directory under `--overwrite`.
pub fn wipe(path: &Path) -> Result<()> {
    for entry in fs::read_dir(path).map_err(|e| RenpyExError::io(path, e))? {
        let entry = entry.map_err(|e| RenpyExError::io(path, e))?;
        let entry_path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|e| RenpyExError::io(&entry_path, e))?;
        let result = if file_type.is_dir() {
            fs::remove_dir_all(&entry_path)
        } else {
            fs::remove_file(&entry_path)
        };
        result.map_err(|e| RenpyExError::io(&entry_path, e))?;
    }
    Ok(())
}

/// Ensure that `dest` has its parent directory created.
pub fn ensure_parent(dest: &Path) -> Result<()> {
    if let Some(parent) = dest.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        fs::create_dir_all(parent).map_err(|e| RenpyExError::io(parent, e))?;
    }
    Ok(())
}

/// Write `bytes` to `dest`. Atomic via temp-file-and-rename where possible.
pub fn write_atomic(dest: &Path, bytes: &[u8]) -> Result<()> {
    ensure_parent(dest)?;
    let tmp = temporary_path(dest);
    if let Err(error) = fs::write(&tmp, bytes) {
        let _ = fs::remove_file(&tmp);
        return Err(RenpyExError::io(&tmp, error));
    }
    commit_temporary(&tmp, dest)
}

/// Reject output paths equal to or nested under a source tree.
///
/// This must run before [`prepare_output`] so `--overwrite` cannot remove
/// source data or an active walk cannot observe output files as input.
pub fn reject_output_within_source(source: &Path, output: &Path) -> Result<()> {
    let lexical_source = absolute_lexical(source)?;
    let lexical_output = absolute_lexical(output)?;
    if is_same_or_child(&lexical_output, &lexical_source)
        || is_same_or_child(&lexical_source, &lexical_output)
    {
        return Err(RenpyExError::Invalid(format!(
            "output directory {} overlaps source directory {}",
            lexical_output.display(),
            lexical_source.display()
        )));
    }
    let canonical_source = source
        .canonicalize()
        .map_err(|e| RenpyExError::io(source, e))?;
    let resolved_output = canonicalize_with_existing_ancestor(&lexical_output)?;
    if is_same_or_child(&resolved_output, &canonical_source)
        || is_same_or_child(&canonical_source, &resolved_output)
    {
        return Err(RenpyExError::Invalid(format!(
            "output directory {} resolves overlapping source directory {}",
            resolved_output.display(),
            source.display()
        )));
    }
    Ok(())
}

fn canonicalize_with_existing_ancestor(path: &Path) -> Result<PathBuf> {
    let mut ancestor = path.to_path_buf();
    let mut suffix = Vec::new();
    while !ancestor.exists() {
        let name = ancestor.file_name().ok_or_else(|| {
            RenpyExError::Invalid(format!(
                "cannot resolve output path ancestor: {}",
                path.display()
            ))
        })?;
        suffix.push(name.to_os_string());
        if !ancestor.pop() {
            return Err(RenpyExError::Invalid(format!(
                "cannot resolve output path ancestor: {}",
                path.display()
            )));
        }
    }
    let mut resolved = ancestor
        .canonicalize()
        .map_err(|e| RenpyExError::io(&ancestor, e))?;
    for component in suffix.iter().rev() {
        resolved.push(component);
    }
    Ok(resolved)
}

#[cfg(windows)]
fn is_same_or_child(output: &Path, source: &Path) -> bool {
    let output = output
        .to_string_lossy()
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase();
    let source = source
        .to_string_lossy()
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase();
    output == source || output.starts_with(&(source + "\\"))
}

#[cfg(not(windows))]
fn is_same_or_child(output: &Path, source: &Path) -> bool {
    output.starts_with(source)
}

fn absolute_lexical(path: &Path) -> Result<PathBuf> {
    let input = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| RenpyExError::io("<current-dir>", e))?
            .join(path)
    };
    let mut normalized = PathBuf::new();
    for component in input.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    Ok(normalized)
}

/// Copy `source` into `dest` atomically without buffering its whole contents.
pub fn copy_atomic(source: &Path, dest: &Path) -> Result<()> {
    ensure_parent(dest)?;
    let tmp = temporary_path(dest);
    if let Err(error) = fs::copy(source, &tmp) {
        let _ = fs::remove_file(&tmp);
        return Err(RenpyExError::io(source, error));
    }
    commit_temporary(&tmp, dest)
}

fn temporary_path(dest: &Path) -> PathBuf {
    dest.with_extension(format!(
        "{}.tmp",
        dest.extension().and_then(|s| s.to_str()).unwrap_or("part")
    ))
}

fn commit_temporary(tmp: &Path, dest: &Path) -> Result<()> {
    if let Err(error) = fs::rename(tmp, dest) {
        let _ = fs::remove_file(tmp);
        return Err(RenpyExError::io(dest, error));
    }
    Ok(())
}

/// Convert any relative path to absolute path anchored at `base`.
pub fn relative_to(base: &Path, p: &Path) -> PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        base.join(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn prepare_creates_new() {
        let td = tempdir().unwrap();
        let out = td.path().join("fresh");
        prepare_output(&out, false).unwrap();
        assert!(out.is_dir());
    }

    #[test]
    fn prepare_rejects_non_empty() {
        let td = tempdir().unwrap();
        let out = td.path().join("used");
        fs::create_dir(&out).unwrap();
        fs::write(out.join("x"), b"hi").unwrap();
        assert!(prepare_output(&out, false).is_err());
        prepare_output(&out, true).unwrap();
        assert!(fs::read_dir(&out).unwrap().next().is_none());
    }

    #[test]
    fn copy_atomic_preserves_exact_source_bytes() {
        let td = tempdir().unwrap();
        let source = td.path().join("source.bin");
        let destination = td.path().join("nested/destination.bin");
        fs::write(&source, [0, 1, 2, 255]).unwrap();
        copy_atomic(&source, &destination).unwrap();
        assert_eq!(fs::read(&destination).unwrap(), [0, 1, 2, 255]);
        assert!(!destination.with_extension("bin.tmp").exists());
    }

    #[test]
    fn reject_output_within_source_blocks_overwrite_risk() {
        let td = tempdir().unwrap();
        let source = td.path().join("game");
        fs::create_dir(&source).unwrap();
        assert!(reject_output_within_source(&source, &source).is_err());
        assert!(reject_output_within_source(&source, &source.join("out")).is_err());
        assert!(reject_output_within_source(&source, td.path()).is_err());
    }

    #[test]
    fn absolute_lexical_normalizes_parent_segments() {
        let td = tempdir().unwrap();
        let normalized = absolute_lexical(&td.path().join("a/../b")).unwrap();
        assert!(normalized.ends_with("b"));
        assert!(!normalized.ends_with("a/../b"));
    }
}
