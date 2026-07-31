//! Explicit, shell-free adapter for the official Ren'Py SDK CLI.
#![allow(missing_docs)]
#![allow(clippy::possible_missing_else)]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::Result;
use crate::error::RenpyExError;

/// Actions supported by Ren'Py's official command line interface.
#[derive(Debug, Clone)]
pub enum Action {
    /// Lint scripts.
    Lint { all_problems: bool },
    /// Compile scripts.
    Compile { keep_orphan_rpyc: bool },
    /// Run testcases.
    Test {
        suite: Option<String>,
        enable_all: bool,
        report_detailed: bool,
    },
    /// Generate or count translations.
    Translate {
        language: String,
        count: bool,
        strings_only: bool,
    },
    /// Export dialogue.
    Dialogue {
        language: String,
        strings: bool,
        text: bool,
    },
    /// Build distribution packages.
    Distribute {
        destination: PathBuf,
        package: Option<String>,
        no_archive: bool,
        no_update: bool,
    },
}

/// Explicit SDK location and timeout.
#[derive(Debug, Clone)]
pub struct Spec {
    /// SDK root containing `renpy.py`.
    pub sdk_dir: PathBuf,
    /// Maximum process duration.
    pub timeout: Duration,
}

/// Captured SDK process result.
#[derive(Debug, Clone)]
pub struct ResultInfo {
    /// Exit code.
    pub exit_code: Option<i32>,
    /// Standard output.
    pub stdout: String,
    /// Standard error.
    pub stderr: String,
    /// Exact arguments.
    pub arguments: Vec<String>,
}

/// Execute an explicit SDK action without shell interpolation.
pub fn execute(spec: &Spec, project: &Path, action: &Action) -> Result<ResultInfo> {
    if !project.is_dir() {
        return Err(RenpyExError::Invalid(format!(
            "project is not a directory: {}",
            project.display()
        )));
    }
    let script = spec.sdk_dir.join("renpy.py");
    if !script.is_file() {
        return Err(RenpyExError::Invalid(format!(
            "Ren'Py SDK script not found: {}",
            script.display()
        )));
    }
    let launcher = if cfg!(windows) {
        spec.sdk_dir.join("lib/py3-windows-x86_64/python.exe")
    } else {
        spec.sdk_dir.join("renpy.sh")
    };
    if !launcher.is_file() {
        return Err(RenpyExError::Invalid(format!(
            "Ren'Py SDK launcher not found: {}",
            launcher.display()
        )));
    }
    let mut command_args = action_arguments(project, action);
    let args = if cfg!(windows) {
        let mut args = vec![script.to_string_lossy().into_owned()];
        args.append(&mut command_args);
        args
    } else {
        command_args
    };
    let mut command = Command::new(&launcher);
    command
        .current_dir(&spec.sdk_dir)
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|e| RenpyExError::External {
        tool: launcher.display().to_string(),
        message: e.to_string(),
    })?;
    let stdout = child.stdout.take().ok_or_else(|| RenpyExError::External {
        tool: "renpy-sdk".into(),
        message: "stdout pipe unavailable".into(),
    })?;
    let stderr = child.stderr.take().ok_or_else(|| RenpyExError::External {
        tool: "renpy-sdk".into(),
        message: "stderr pipe unavailable".into(),
    })?;
    let out_thread = thread::spawn(move || {
        let mut r = stdout;
        let mut b = Vec::new();
        r.read_to_end(&mut b).map(|_| b)
    });
    let err_thread = thread::spawn(move || {
        let mut r = stderr;
        let mut b = Vec::new();
        r.read_to_end(&mut b).map(|_| b)
    });
    let (status, timed_out) = wait_timeout(&mut child, spec.timeout)?;
    let out = out_thread
        .join()
        .map_err(|_| RenpyExError::External {
            tool: "renpy-sdk".into(),
            message: "stdout reader panicked".into(),
        })?
        .map_err(|e| RenpyExError::External {
            tool: "renpy-sdk".into(),
            message: e.to_string(),
        })?;
    let err = err_thread
        .join()
        .map_err(|_| RenpyExError::External {
            tool: "renpy-sdk".into(),
            message: "stderr reader panicked".into(),
        })?
        .map_err(|e| RenpyExError::External {
            tool: "renpy-sdk".into(),
            message: e.to_string(),
        })?;
    let result = ResultInfo {
        exit_code: status.code(),
        stdout: String::from_utf8_lossy(&out).into_owned(),
        stderr: String::from_utf8_lossy(&err).into_owned(),
        arguments: args,
    };
    if timed_out {
        return Err(RenpyExError::External {
            tool: "renpy-sdk".into(),
            message: format!("timeout after {} seconds", spec.timeout.as_secs()),
        });
    }
    if !status.success() {
        return Err(RenpyExError::External {
            tool: "renpy-sdk".into(),
            message: format!("exit={:?}\n{}", result.exit_code, result.stderr),
        });
    }
    Ok(result)
}

fn wait_timeout(child: &mut Child, timeout: Duration) -> Result<(std::process::ExitStatus, bool)> {
    let start = Instant::now();
    loop {
        if let Some(s) = child.try_wait().map_err(|e| RenpyExError::External {
            tool: "renpy-sdk".into(),
            message: e.to_string(),
        })? {
            return Ok((s, false));
        }
        if start.elapsed() >= timeout {
            child.kill().map_err(|error| RenpyExError::External {
                tool: "renpy-sdk".into(),
                message: format!("failed to stop timed-out process: {error}"),
            })?;
            let status = child.wait().map_err(|error| RenpyExError::External {
                tool: "renpy-sdk".into(),
                message: format!("failed to reap timed-out process: {error}"),
            })?;
            return Ok((status, true));
        }
        thread::sleep(Duration::from_millis(25))
    }
}
fn action_arguments(project: &Path, action: &Action) -> Vec<String> {
    let mut args = match action {
        Action::Distribute { .. } => vec![
            "launcher".into(),
            "distribute".into(),
            project.to_string_lossy().into_owned(),
        ],
        _ => vec![project.to_string_lossy().into_owned()],
    };
    append_args(&mut args, action);
    args
}

fn append_args(args: &mut Vec<String>, action: &Action) {
    match action {
        Action::Lint { all_problems } => {
            args.push("lint".into());
            args.push("--error-code".into());
            if *all_problems {
                args.push("--all-problems".into())
            }
        }
        Action::Compile { keep_orphan_rpyc } => {
            args.push("compile".into());
            if *keep_orphan_rpyc {
                args.push("--keep-orphan-rpyc".into())
            }
        }
        Action::Test {
            suite,
            enable_all,
            report_detailed,
        } => {
            args.push("test".into());
            if let Some(v) = suite {
                args.push(v.clone())
            }
            if *enable_all {
                args.push("--enable_all".into())
            }
            if *report_detailed {
                args.push("--report-detailed".into())
            }
        }
        Action::Translate {
            language,
            count,
            strings_only,
        } => {
            args.extend(["translate".into(), language.clone()]);
            if *count {
                args.push("--count".into())
            }
            if *strings_only {
                args.push("--strings-only".into())
            }
        }
        Action::Dialogue {
            language,
            strings,
            text,
        } => {
            args.extend(["dialogue".into(), language.clone()]);
            if *strings {
                args.push("--strings".into())
            }
            if *text {
                args.push("--text".into())
            }
        }
        Action::Distribute {
            destination,
            package,
            no_archive,
            no_update,
        } => {
            args.extend([
                "--destination".into(),
                destination.to_string_lossy().into_owned(),
            ]);
            if let Some(v) = package {
                args.extend(["--package".into(), v.clone()])
            }
            if *no_archive {
                args.push("--no-archive".into())
            }
            if *no_update {
                args.push("--no-update".into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lint_args_are_deterministic() {
        let a = action_arguments(Path::new("project"), &Action::Lint { all_problems: true });
        assert_eq!(a, ["project", "lint", "--error-code", "--all-problems"])
    }

    #[test]
    fn distribute_places_project_after_launcher_command() {
        let a = action_arguments(
            Path::new("project"),
            &Action::Distribute {
                destination: PathBuf::from("dist"),
                package: Some("pc".into()),
                no_archive: false,
                no_update: false,
            },
        );
        assert_eq!(
            a,
            [
                "launcher",
                "distribute",
                "project",
                "--destination",
                "dist",
                "--package",
                "pc"
            ]
        );
    }
}
