//! Decompile `.rpyc` (Ren'Py compiled bytecode) into `.rpy` source.
//!
//! Approach: shell out to Python's `unrpyc` tool if available.
//!
//! If Python or unrpyc is not present, we fall back to detecting the file
//! as a `.rpyc` (via extension hint) and reporting the user should install
//! `unrpyc` if they want source extraction. The extraction workflow copies
//! the original `.rpyc` before optional decompilation.

use std::fs;
use std::path::{Path, PathBuf};

use crate::Result;
use crate::error::RenpyExError;

/// Options for `.rpyc` decompilation.
#[derive(Debug, Clone, Default)]
pub struct RpycDecompileOptions {
    /// Python interpreter to use (`python` on Windows, `python3` elsewhere).
    pub python: Option<String>,
    /// Optional path to `unrpyc` script; if absent we attempt `unrpyc` from PATH.
    pub unrpyc: Option<String>,
    /// Decompile to `.rpy` next to the `.rpyc` file when `true`.
    pub overwrite_rpyc: bool,
}

/// Locate an `unrpyc` invocation we can use. Returns the Python executable
/// name and the resolved script/executable path.
#[must_use]
pub fn find_unrpyc(opts: &RpycDecompileOptions) -> Option<(String, String)> {
    let py = opts.python.clone().unwrap_or_else(|| {
        if cfg!(windows) {
            "python".to_string()
        } else {
            "python3".to_string()
        }
    });
    let script = opts.unrpyc.clone().unwrap_or_else(|| "unrpyc".to_string());
    if opts.unrpyc.is_some() {
        return Some((py, script));
    }
    let probe = if cfg!(windows) { "where" } else { "which" };
    let output = std::process::Command::new(probe)
        .arg(&script)
        .output()
        .ok()
        .filter(|output| output.status.success())?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let resolved = stdout
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())?
        .to_owned();
    let resolved_path = PathBuf::from(resolved);
    resolved_path
        .is_file()
        .then(|| (py, resolved_path.to_string_lossy().into_owned()))
}

/// Reject unsafe in-place decompilation.
///
/// Use [`decompile_rpyc_to`] with a destination under the caller-controlled
/// output tree. This prevents APIs from creating `.rpy` files beside the
/// user's source game.
pub fn decompile_rpyc(
    source: &Path,
    _opts: &RpycDecompileOptions,
) -> Result<Option<std::path::PathBuf>> {
    if source.extension().and_then(|s| s.to_str()) != Some("rpyc") {
        return Err(RenpyExError::Invalid(format!(
            "decompile_rpyc called on non-rpyc path: {}",
            source.display()
        )));
    }

    Err(RenpyExError::Invalid(format!(
        "in-place .rpyc decompilation is disabled for {}; use decompile_rpyc_to",
        source.display()
    )))
}

/// Decompile a copied `.rpyc` into an output tree without modifying the source.
pub fn decompile_rpyc_to(
    source: &Path,
    destination_rpyc: &Path,
    opts: &RpycDecompileOptions,
) -> Result<Option<PathBuf>> {
    if source.extension().and_then(|s| s.to_str()) != Some("rpyc")
        || destination_rpyc.extension().and_then(|s| s.to_str()) != Some("rpyc")
    {
        return Err(RenpyExError::Invalid(format!(
            "decompile_rpyc_to requires .rpyc paths: {} -> {}",
            source.display(),
            destination_rpyc.display()
        )));
    }
    crate::output::copy_atomic(source, destination_rpyc)?;
    let sidecar = destination_rpyc.with_extension("rpy");
    let (python, unrpyc) = match find_unrpyc(opts) {
        Some(value) => value,
        None => return Ok(None),
    };
    let unrpyc_path = Path::new(&unrpyc);
    let is_python_script = unrpyc_path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("py"));
    let mut command = if is_python_script {
        let mut command = std::process::Command::new(&python);
        command.arg(unrpyc_path);
        command
    } else {
        std::process::Command::new(unrpyc_path)
    };
    command.arg(destination_rpyc);
    if opts.overwrite_rpyc {
        let _ = fs::remove_file(&sidecar);
        command.arg("--clobber");
    }
    let output = command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|error| RenpyExError::External {
            tool: unrpyc.clone(),
            message: error.to_string(),
        })?;
    if !output.status.success() {
        return Err(RenpyExError::External {
            tool: unrpyc,
            message: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    Ok(sidecar.exists().then_some(sidecar))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_rpyc() {
        let opts = RpycDecompileOptions::default();
        assert!(decompile_rpyc(Path::new("/tmp/no.txt"), &opts).is_err());
    }

    #[test]
    fn rejects_in_place_rpyc_without_writing_sidecar() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("script.rpyc");
        fs::write(&source, b"rpyc").unwrap();
        assert!(decompile_rpyc(&source, &RpycDecompileOptions::default()).is_err());
        assert!(!source.with_extension("rpy").exists());
    }
}
