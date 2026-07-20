//! Decompile `.rpyc` (Ren'Py compiled bytecode) into `.rpy` source.
//!
//! Approach: shell out to Python's `unrpyc` tool if available.
//!
//! If Python or unrpyc is not present, we fall back to detecting the file
//! as a `.rpyc` (via extension hint) and reporting the user should install
//! `unrpyc` if they want source extraction. The `.rpyc` itself is still
//! extracted byte-perfect under all conditions.

use std::path::Path;

use crate::error::RenpyExError;
use crate::Result;

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

/// Locate an `unrpyc` invocation we can use. Returns the python executable
/// name and the candidate script command.
#[must_use]
pub fn find_unrpyc(opts: &RpycDecompileOptions) -> Option<(String, String)> {
    let py = opts
        .python
        .clone()
        .unwrap_or_else(|| if cfg!(windows) { "python".to_string() } else { "python3".to_string() });
    Some((
        py,
        opts.unrpyc.clone().unwrap_or_else(|| "unrpyc".to_string()),
    ))
}

/// Decompile a single `.rpyc` file. Returns the path of the produced `.rpy`
/// if decompilation succeeded and Python/unrpyc is available.
///
/// If Python or unrpyc is missing, returns `Ok(None)` and the caller should
/// leave the `.rpyc` file in place.
pub fn decompile_rpyc(source: &Path, opts: &RpycDecompileOptions) -> Result<Option<std::path::PathBuf>> {
    if source.extension().and_then(|s| s.to_str()) != Some("rpyc") {
        return Err(RenpyExError::Invalid(format!(
            "decompile_rpyc called on non-rpyc path: {}",
            source.display()
        )));
    }

    let (python, unrpyc) = match find_unrpyc(opts) {
        Some(v) => v,
        None => return Ok(None),
    };
    let sidecar = source.with_extension("rpy");

    let mut cmd = std::process::Command::new(&python);
    cmd.arg(&unrpyc).arg(source);
    if !opts.overwrite_rpyc {
        // Some unrpyc versions auto-write; we ensure sidecar is deleted first
        // only if the user opted in. Leave file untouched if rerun.
    } else {
        // Best-effort cleanup of stale .rpy.
        let _ = std::fs::remove_file(&sidecar);
        cmd.arg("--clobber");
    }
    let output = cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output();
    match output {
        Ok(out) if out.status.success() => {
            if sidecar.exists() {
                Ok(Some(sidecar))
            } else {
                // Python succeeded but unrpyc may not have produced a sidecar
                // (rare). Return Ok(None) so caller knows.
                Ok(None)
            }
        }
        Ok(out) => Err(RenpyExError::External {
            tool: format!("{python}/{unrpyc}"),
            message: format!(
                "decompile failed: status={}\nstderr={}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            ),
        }),
        Err(e) => {
            // Treat "binary not found" as "unavailable" so user can decide.
            if e.kind() == std::io::ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(RenpyExError::External {
                    tool: format!("{python}/{unrpyc}"),
                    message: format!("spawn error: {e}"),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_rpyc() {
        let opts = RpycDecompileOptions::default();
        assert!(decompile_rpyc(Path::new("/tmp/no.txt"), &opts).is_err());
    }
}
