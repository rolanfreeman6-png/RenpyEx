//! Decompile `.rpyc` (Ren'Py compiled bytecode) into `.rpy` source.
//!
//! Approach: shell out to Python's `unrpyc` tool if available.
//!
//! If Python or unrpyc is not present, we fall back to detecting the file
//! as a `.rpyc` (via extension hint) and reporting the user should install
//! `unrpyc` if they want source extraction. The extraction workflow copies
//! the original `.rpyc` before optional decompilation.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::Result;
use crate::error::RenpyExError;

// RenpyEx resource policy for the delegated decompiler. Supported execution
// targets: Windows, Linux, and macOS.
const UNRPYC_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_UNRPYC_STREAM_BYTES: u64 = 16 * 1024 * 1024;
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(25);
const TIMED_OUT_PIPE_DRAIN: Duration = Duration::from_millis(500);
const COMPLETED_PIPE_DRAIN: Duration = Duration::from_secs(5);

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
    resolve_on_path(&script).map(|resolved| (py, resolved.to_string_lossy().into_owned()))
}

fn resolve_on_path(command: &str) -> Option<PathBuf> {
    let search_path = std::env::var_os("PATH")?;
    for directory in std::env::split_paths(&search_path) {
        let base = directory.join(command);
        #[cfg(windows)]
        {
            if base.extension().is_some() && base.is_file() {
                return Some(base);
            }
            let path_extensions =
                std::env::var_os("PATHEXT").unwrap_or_else(|| ".COM;.EXE;.PY".into());
            for extension in path_extensions.to_string_lossy().split(';') {
                if extension.is_empty()
                    || !matches!(
                        extension.to_ascii_uppercase().as_str(),
                        ".COM" | ".EXE" | ".PY"
                    )
                {
                    continue;
                }
                let mut candidate = base.as_os_str().to_os_string();
                candidate.push(extension);
                let candidate = PathBuf::from(candidate);
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
        #[cfg(not(windows))]
        if is_executable_file(&base) {
            return Some(base);
        }
    }
    None
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    path.metadata()
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

#[cfg(not(any(unix, windows)))]
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

/// Recursively collect `.rpyc` files under `dir` into `out`.
///
/// A missing `dir` is not an error (nothing has been unpacked there yet).
/// Callers sort the result for deterministic reporting.
pub fn collect_rpyc_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            collect_rpyc_files(&path, out);
        } else if file_type.is_file()
            && path.extension().and_then(|extension| extension.to_str()) == Some("rpyc")
        {
            out.push(path);
        }
    }
}

/// Preflight decompilation destinations for `.rpyc` entries inside archives
/// that will be unpacked under `out_root/rpa/<archive rel>`.
///
/// Rejects, before any output is written, the case where a decompiled
/// sidecar (`x.rpyc` → `x.rpy`) would collide with a file unpacked from the
/// same archive, including case-insensitive and normalized aliases on
/// Windows/macOS. Archives that cannot be listed are skipped here; the
/// unpack step reports their failure.
pub fn preflight_archive_decompilation(
    out_root: &Path,
    archives: &[(PathBuf, PathBuf)],
    key: Option<u32>,
) -> crate::Result<()> {
    for (archive_abs, archive_rel) in archives {
        let Ok(listed) = crate::archive::rpa::list_rpa(archive_abs, key) else {
            continue;
        };
        let unpack_root = out_root.join("rpa").join(archive_rel);
        let mut destinations = crate::output::DestinationRegistry::new(&unpack_root);
        // Fragmented entries repeat a path; claim each unique path once.
        let mut unique_paths = std::collections::BTreeSet::new();
        for entry in &listed.entries {
            unique_paths.insert(entry.path.clone());
        }
        for path in &unique_paths {
            if path.ends_with(".rpyc") {
                let sidecar = PathBuf::from(path).with_extension("rpy");
                let sidecar_str = sidecar.to_string_lossy().into_owned();
                let sidecar_path = crate::output::safe_join(&unpack_root, &sidecar_str)?;
                destinations.claim(
                    format!(
                        "decompiled archive script {}/{}",
                        archive_rel.display(),
                        path
                    ),
                    &sidecar_path,
                )?;
            }
        }
        for path in &unique_paths {
            let entry_path = crate::output::safe_join(&unpack_root, path)?;
            destinations.claim(
                format!("unpacked entry {}/{}", archive_rel.display(), path),
                &entry_path,
            )?;
        }
    }
    Ok(())
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
///
/// When `source` and `destination_rpyc` are the same path (decompiling an
/// already-extracted copy in place), the copy step is skipped.
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
    if source != destination_rpyc {
        crate::output::copy_atomic(source, destination_rpyc)?;
    }
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
    let output = run_bounded_command(
        &mut command,
        &unrpyc,
        UNRPYC_TIMEOUT,
        MAX_UNRPYC_STREAM_BYTES,
    )?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(RenpyExError::External {
            tool: unrpyc,
            message: format!("stderr: {stderr}\nstdout: {stdout}"),
        });
    }
    Ok(sidecar.exists().then_some(sidecar))
}

#[derive(Debug)]
struct BoundedOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn run_bounded_command(
    command: &mut Command,
    tool: &str,
    timeout: Duration,
    stream_limit: u64,
) -> Result<BoundedOutput> {
    configure_process_group(command);
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|error| RenpyExError::External {
        tool: tool.into(),
        message: error.to_string(),
    })?;
    let stdout = child.stdout.take().ok_or_else(|| RenpyExError::External {
        tool: tool.into(),
        message: "stdout pipe unavailable".into(),
    })?;
    let stderr = child.stderr.take().ok_or_else(|| RenpyExError::External {
        tool: tool.into(),
        message: "stderr pipe unavailable".into(),
    })?;
    let stdout_receiver = spawn_reader(stdout, "stdout", stream_limit);
    let stderr_receiver = spawn_reader(stderr, "stderr", stream_limit);
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| RenpyExError::invalid("unrpyc timeout is too large"))?;

    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                let now = Instant::now();
                if now >= deadline {
                    let termination_error = terminate_process_tree(&mut child).err();
                    let _ = child.wait();
                    drain_timed_out_readers(stdout_receiver, stderr_receiver);
                    let detail = termination_error
                        .map(|error| format!("; process-tree termination reported: {error}"))
                        .unwrap_or_default();
                    return Err(RenpyExError::External {
                        tool: tool.into(),
                        message: format!("timeout after {timeout:?}{detail}"),
                    });
                }
                thread::sleep(PROCESS_POLL_INTERVAL.min(deadline.saturating_duration_since(now)));
            }
            Err(error) => {
                let termination_error = terminate_process_tree(&mut child).err();
                let _ = child.wait();
                drain_timed_out_readers(stdout_receiver, stderr_receiver);
                return Err(RenpyExError::External {
                    tool: tool.into(),
                    message: format!(
                        "failed while waiting for unrpyc: {error}; termination={termination_error:?}"
                    ),
                });
            }
        }
    };

    let stdout = receive_reader(stdout_receiver, tool, "stdout")?;
    let stderr = receive_reader(stderr_receiver, tool, "stderr")?;
    Ok(BoundedOutput {
        status,
        stdout,
        stderr,
    })
}

fn spawn_reader(
    reader: impl Read + Send + 'static,
    stream_name: &'static str,
    stream_limit: u64,
) -> mpsc::Receiver<std::io::Result<Vec<u8>>> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = reader
            .take(stream_limit + 1)
            .read_to_end(&mut bytes)
            .and_then(|_| {
                if bytes.len() as u64 > stream_limit {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("unrpyc {stream_name} exceeded the {stream_limit}-byte limit"),
                    ))
                } else {
                    Ok(())
                }
            })
            .map(|()| bytes);
        let _ = sender.send(result);
    });
    receiver
}

fn receive_reader(
    receiver: mpsc::Receiver<std::io::Result<Vec<u8>>>,
    tool: &str,
    stream_name: &str,
) -> Result<Vec<u8>> {
    receiver
        .recv_timeout(COMPLETED_PIPE_DRAIN)
        .map_err(|error| RenpyExError::External {
            tool: tool.into(),
            message: format!(
                "{stream_name} pipe did not close within {COMPLETED_PIPE_DRAIN:?}: {error}"
            ),
        })?
        .map_err(|error| RenpyExError::External {
            tool: tool.into(),
            message: error.to_string(),
        })
}

fn drain_timed_out_readers(
    stdout: mpsc::Receiver<std::io::Result<Vec<u8>>>,
    stderr: mpsc::Receiver<std::io::Result<Vec<u8>>>,
) {
    let deadline = Instant::now() + TIMED_OUT_PIPE_DRAIN;
    let _ = stdout.recv_timeout(deadline.saturating_duration_since(Instant::now()));
    let _ = stderr.recv_timeout(deadline.saturating_duration_since(Instant::now()));
}

#[cfg(windows)]
fn configure_process_group(command: &mut Command) {
    use std::os::windows::process::CommandExt;

    // CREATE_NEW_PROCESS_GROUP from Microsoft Process Creation Flags:
    // https://learn.microsoft.com/windows/win32/procthread/process-creation-flags
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    command.creation_flags(CREATE_NEW_PROCESS_GROUP);
}

#[cfg(unix)]
fn configure_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt;

    command.process_group(0);
}

#[cfg(not(any(windows, unix)))]
fn configure_process_group(_command: &mut Command) {}

#[cfg(windows)]
fn terminate_process_tree(child: &mut Child) -> std::result::Result<(), String> {
    let process_id = child.id().to_string();
    let output = Command::new("taskkill.exe")
        .args(["/PID", &process_id, "/T", "/F"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| format!("could not launch taskkill.exe: {error}"))?;
    if output.status.success() {
        return Ok(());
    }
    let direct_error = child.kill().err();
    Err(format!(
        "taskkill.exe exited with {}; stderr={}; direct-kill={direct_error:?}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    ))
}

#[cfg(unix)]
fn terminate_process_tree(child: &mut Child) -> std::result::Result<(), String> {
    let process_group = format!("-{}", child.id());
    let output = Command::new("/bin/kill")
        .args(["-KILL", "--", &process_group])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| format!("could not launch /bin/kill: {error}"))?;
    if output.status.success() {
        return Ok(());
    }
    let direct_error = child.kill().err();
    Err(format!(
        "/bin/kill exited with {}; stderr={}; direct-kill={direct_error:?}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    ))
}

#[cfg(not(any(windows, unix)))]
fn terminate_process_tree(child: &mut Child) -> std::result::Result<(), String> {
    child
        .kill()
        .map_err(|error| format!("direct process kill failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn python_command(script: &str) -> Command {
        let mut command = Command::new(if cfg!(windows) { "python" } else { "python3" });
        command.arg("-c").arg(script);
        command
    }

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

    #[test]
    fn delegated_process_output_is_bounded() {
        let mut command = python_command("import sys; sys.stdout.write('x' * 4096)");
        let error = run_bounded_command(&mut command, "fake-unrpyc", Duration::from_secs(5), 64)
            .expect_err("oversized output must fail");
        assert!(error.to_string().contains("64-byte limit"), "{error}");
    }

    #[test]
    fn delegated_process_timeout_terminates_descendants() {
        let temp = tempfile::tempdir().unwrap();
        let started_marker = temp.path().join("descendant-started");
        let survivor_marker = temp.path().join("descendant-survived");
        let script = r#"
import pathlib, subprocess, sys, time
started = pathlib.Path(sys.argv[1])
survived = pathlib.Path(sys.argv[2])
child = "import pathlib,sys,time; pathlib.Path(sys.argv[1]).write_text('started'); time.sleep(2); pathlib.Path(sys.argv[2]).write_text('survived')"
subprocess.Popen([sys.executable, "-c", child, str(started), str(survived)])
for _ in range(200):
    if started.exists():
        break
    time.sleep(0.005)
time.sleep(30)
"#;
        let mut command = python_command(script);
        command.arg(&started_marker).arg(&survivor_marker);
        let started = Instant::now();

        let error = run_bounded_command(
            &mut command,
            "fake-unrpyc",
            Duration::from_millis(500),
            1024,
        )
        .expect_err("sleeping process must time out");

        assert!(error.to_string().contains("timeout"), "{error}");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "timeout waited for descendant-owned pipes: {:?}",
            started.elapsed()
        );
        assert!(
            started_marker.is_file(),
            "descendant did not start, so tree termination was not exercised"
        );
        let observation_deadline = started + Duration::from_secs(3);
        while Instant::now() < observation_deadline && !survivor_marker.exists() {
            thread::sleep(Duration::from_millis(25));
        }
        assert!(
            !survivor_marker.exists(),
            "timed-out unrpyc descendant remained alive"
        );
    }
}
