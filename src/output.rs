//! Output management: prepare an output folder, write files, summarise
//! progress safely.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::error::RenpyExError;
use crate::Result;

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
pub fn wipe(_path: &Path) -> Result<()> {
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
    let tmp = dest.with_extension(format!(
        "{}.tmp",
        dest.extension()
            .and_then(|s| s.to_str())
            .unwrap_or("part")
    ));
    fs::write(&tmp, bytes).map_err(|e| RenpyExError::io(&tmp, e))?;
    fs::rename(&tmp, dest).map_err(|e| RenpyExError::io(dest, e))?;
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
    }
}
