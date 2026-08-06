//! Explicit, shell-free adapter for the official Ren'Py SDK CLI.
#![allow(missing_docs)]
#![allow(clippy::possible_missing_else)]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::Result;
use crate::error::RenpyExError;

// Supported SDK execution targets: Windows, Linux, and macOS.
const MAX_SDK_STREAM_BYTES: u64 = 16 * 1024 * 1024;
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(25);
// One shared cleanup budget for both pipes; enforced by
// `timeout_terminates_descendants_without_waiting_for_inherited_pipes`.
const TIMED_OUT_PIPE_DRAIN: Duration = Duration::from_millis(500);
const COMPLETED_PIPE_DRAIN: Duration = Duration::from_secs(5);

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
    configure_process_group(&mut command);
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
    let out_receiver = spawn_reader(stdout, "stdout");
    let err_receiver = spawn_reader(stderr, "stderr");
    let (status, timed_out, termination_error) = wait_timeout(&mut child, spec.timeout)?;
    if timed_out {
        drain_timed_out_readers(out_receiver, err_receiver);
        let detail = termination_error
            .map(|error| format!("; process-tree termination reported: {error}"))
            .unwrap_or_default();
        return Err(RenpyExError::External {
            tool: "renpy-sdk".into(),
            message: format!(
                "timeout after {} seconds{detail}",
                spec.timeout.as_secs_f64()
            ),
        });
    }
    let out = receive_reader(out_receiver, "stdout", COMPLETED_PIPE_DRAIN)?;
    let err = receive_reader(err_receiver, "stderr", COMPLETED_PIPE_DRAIN)?;
    let result = ResultInfo {
        exit_code: status.code(),
        stdout: String::from_utf8_lossy(&out).into_owned(),
        stderr: String::from_utf8_lossy(&err).into_owned(),
        arguments: args,
    };
    if !status.success() {
        return Err(RenpyExError::External {
            tool: "renpy-sdk".into(),
            message: format!("exit={:?}\n{}", result.exit_code, result.stderr),
        });
    }
    Ok(result)
}

fn drain_timed_out_readers(
    stdout: mpsc::Receiver<std::io::Result<Vec<u8>>>,
    stderr: mpsc::Receiver<std::io::Result<Vec<u8>>>,
) {
    let deadline = Instant::now() + TIMED_OUT_PIPE_DRAIN;
    let _ = stdout.recv_timeout(deadline.saturating_duration_since(Instant::now()));
    let _ = stderr.recv_timeout(deadline.saturating_duration_since(Instant::now()));
}

fn spawn_reader(
    reader: impl Read + Send + 'static,
    stream_name: &'static str,
) -> mpsc::Receiver<std::io::Result<Vec<u8>>> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = reader
            .take(MAX_SDK_STREAM_BYTES + 1)
            .read_to_end(&mut bytes)
            .and_then(|_| {
                if bytes.len() as u64 > MAX_SDK_STREAM_BYTES {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "Ren'Py SDK {stream_name} exceeded the {MAX_SDK_STREAM_BYTES}-byte limit"
                        ),
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
    stream_name: &str,
    timeout: Duration,
) -> Result<Vec<u8>> {
    receiver
        .recv_timeout(timeout)
        .map_err(|error| RenpyExError::External {
            tool: "renpy-sdk".into(),
            message: format!("{stream_name} pipe did not close within {timeout:?}: {error}"),
        })?
        .map_err(|error| RenpyExError::External {
            tool: "renpy-sdk".into(),
            message: error.to_string(),
        })
}

fn wait_timeout(
    child: &mut Child,
    timeout: Duration,
) -> Result<(std::process::ExitStatus, bool, Option<String>)> {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok((status, false, None)),
            Ok(None) => {}
            Err(error) => {
                let termination = terminate_process_tree(child).err();
                let _ = child.wait();
                return Err(RenpyExError::External {
                    tool: "renpy-sdk".into(),
                    message: format!(
                        "failed while waiting for SDK process: {error}; termination={termination:?}"
                    ),
                });
            }
        }
        if start.elapsed() >= timeout {
            let termination_error = terminate_process_tree(child).err();
            let status = child.wait().map_err(|error| RenpyExError::External {
                tool: "renpy-sdk".into(),
                message: format!("failed to reap timed-out process: {error}"),
            })?;
            return Ok((status, true, termination_error));
        }
        thread::sleep(PROCESS_POLL_INTERVAL)
    }
}

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
    // `/bin/kill` is the POSIX kill utility on the supported Linux/macOS
    // targets. A negative id addresses the process group created above.
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
                // Ren'Py testexecution.py lines 983-989 at commit
                // da4d86679ceca69124dc2204098e1245968c9aa0.
                args.push("--enable-all".into())
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

    fn create_fake_sdk(sdk_dir: &Path, script: &str) {
        std::fs::create_dir_all(sdk_dir).unwrap();
        std::fs::write(sdk_dir.join("renpy.py"), script).unwrap();
        #[cfg(windows)]
        {
            let output = std::process::Command::new("python")
                .args(["-c", "import sys; print(sys.executable)"])
                .output()
                .unwrap();
            assert!(output.status.success());
            let interpreter = String::from_utf8(output.stdout).unwrap();
            let interpreter = Path::new(interpreter.trim());
            let target = sdk_dir.join("lib/py3-windows-x86_64/python.exe");
            std::fs::create_dir_all(target.parent().unwrap()).unwrap();
            match std::fs::hard_link(interpreter, &target) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::CrossesDevices => {
                    std::fs::copy(interpreter, target).unwrap();
                }
                Err(error) => panic!("failed to create fake SDK Python launcher: {error}"),
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let launcher = sdk_dir.join("renpy.sh");
            std::fs::write(
                &launcher,
                "#!/bin/sh\nexec python3 \"$(dirname \"$0\")/renpy.py\" \"$@\"\n",
            )
            .unwrap();
            let mut permissions = std::fs::metadata(&launcher).unwrap().permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(launcher, permissions).unwrap();
        }
    }
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

    #[test]
    fn test_action_uses_official_hyphenated_flags() {
        let arguments = action_arguments(
            Path::new("project"),
            &Action::Test {
                suite: Some("smoke".into()),
                enable_all: true,
                report_detailed: true,
            },
        );
        assert_eq!(
            arguments,
            [
                "project",
                "test",
                "smoke",
                "--enable-all",
                "--report-detailed"
            ]
        );
    }

    #[test]
    fn every_action_reaches_the_sdk_process_with_exact_arguments() {
        let temp = tempfile::tempdir().unwrap();
        let sdk_dir = temp.path().join("sdk");
        let project = temp.path().join("project with spaces");
        let destination = temp.path().join("distribution output");
        std::fs::create_dir(&project).unwrap();
        create_fake_sdk(
            &sdk_dir,
            "import json, sys\nprint(json.dumps(sys.argv[1:], ensure_ascii=False))\n",
        );
        let project_arg = project.to_string_lossy().into_owned();
        let destination_arg = destination.to_string_lossy().into_owned();
        let cases = vec![
            (
                Action::Lint {
                    all_problems: false,
                },
                vec![project_arg.clone(), "lint".into(), "--error-code".into()],
            ),
            (
                Action::Lint { all_problems: true },
                vec![
                    project_arg.clone(),
                    "lint".into(),
                    "--error-code".into(),
                    "--all-problems".into(),
                ],
            ),
            (
                Action::Compile {
                    keep_orphan_rpyc: false,
                },
                vec![project_arg.clone(), "compile".into()],
            ),
            (
                Action::Compile {
                    keep_orphan_rpyc: true,
                },
                vec![
                    project_arg.clone(),
                    "compile".into(),
                    "--keep-orphan-rpyc".into(),
                ],
            ),
            (
                Action::Test {
                    suite: None,
                    enable_all: false,
                    report_detailed: false,
                },
                vec![project_arg.clone(), "test".into()],
            ),
            (
                Action::Test {
                    suite: Some("smoke suite".into()),
                    enable_all: true,
                    report_detailed: true,
                },
                vec![
                    project_arg.clone(),
                    "test".into(),
                    "smoke suite".into(),
                    "--enable-all".into(),
                    "--report-detailed".into(),
                ],
            ),
            (
                Action::Translate {
                    language: "ru".into(),
                    count: false,
                    strings_only: false,
                },
                vec![project_arg.clone(), "translate".into(), "ru".into()],
            ),
            (
                Action::Translate {
                    language: "ru".into(),
                    count: true,
                    strings_only: true,
                },
                vec![
                    project_arg.clone(),
                    "translate".into(),
                    "ru".into(),
                    "--count".into(),
                    "--strings-only".into(),
                ],
            ),
            (
                Action::Dialogue {
                    language: "ru".into(),
                    strings: false,
                    text: false,
                },
                vec![project_arg.clone(), "dialogue".into(), "ru".into()],
            ),
            (
                Action::Dialogue {
                    language: "ru".into(),
                    strings: true,
                    text: true,
                },
                vec![
                    project_arg.clone(),
                    "dialogue".into(),
                    "ru".into(),
                    "--strings".into(),
                    "--text".into(),
                ],
            ),
            (
                Action::Distribute {
                    destination: destination.clone(),
                    package: None,
                    no_archive: false,
                    no_update: false,
                },
                vec![
                    "launcher".into(),
                    "distribute".into(),
                    project_arg.clone(),
                    "--destination".into(),
                    destination_arg.clone(),
                ],
            ),
            (
                Action::Distribute {
                    destination: destination.clone(),
                    package: Some("pc".into()),
                    no_archive: true,
                    no_update: true,
                },
                vec![
                    "launcher".into(),
                    "distribute".into(),
                    project_arg.clone(),
                    "--destination".into(),
                    destination_arg.clone(),
                    "--package".into(),
                    "pc".into(),
                    "--no-archive".into(),
                    "--no-update".into(),
                ],
            ),
        ];
        let spec = Spec {
            sdk_dir: sdk_dir.clone(),
            timeout: Duration::from_secs(5),
        };

        for (action, expected) in cases {
            let result = execute(&spec, &project, &action).unwrap();
            let received: Vec<String> = serde_json::from_str(result.stdout.trim()).unwrap();
            assert_eq!(received, expected, "SDK argv mismatch for {action:?}");
            let mut launcher_expected = expected;
            if cfg!(windows) {
                launcher_expected
                    .insert(0, sdk_dir.join("renpy.py").to_string_lossy().into_owned());
            }
            assert_eq!(
                result.arguments, launcher_expected,
                "reported argv mismatch for {action:?}"
            );
        }
    }

    #[test]
    fn timeout_terminates_descendants_without_waiting_for_inherited_pipes() {
        let temp = tempfile::tempdir().unwrap();
        let sdk_dir = temp.path().join("sdk");
        let project = temp.path().join("project");
        std::fs::create_dir(&project).unwrap();
        create_fake_sdk(
            &sdk_dir,
            r#"import pathlib, subprocess, sys, time
started = pathlib.Path(__file__).with_name("descendant-started")
survived = pathlib.Path(__file__).with_name("descendant-survived")
child_code = "import pathlib,time; pathlib.Path({!r}).write_text('started'); time.sleep(4); pathlib.Path({!r}).write_text('survived')".format(str(started), str(survived))
subprocess.Popen([sys.executable, "-c", child_code])
for _ in range(200):
    if started.exists():
        break
    time.sleep(0.005)
print("descendant-started", flush=True)
time.sleep(30)
"#,
        );
        let started = Instant::now();
        let error = execute(
            &Spec {
                sdk_dir,
                timeout: Duration::from_secs(1),
            },
            &project,
            &Action::Lint {
                all_problems: false,
            },
        )
        .expect_err("SDK process must time out");
        assert!(error.to_string().contains("timeout"), "{error}");
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "timeout waited for a descendant-owned pipe: {:?}",
            started.elapsed()
        );
        assert!(
            temp.path().join("sdk/descendant-started").is_file(),
            "descendant did not start, so the process-tree assertion was not exercised"
        );
        let survivor_marker = temp.path().join("sdk/descendant-survived");
        let observation_deadline = started + Duration::from_secs(6);
        while Instant::now() < observation_deadline && !survivor_marker.exists() {
            thread::sleep(Duration::from_millis(25));
        }
        assert!(
            !survivor_marker.exists(),
            "timed-out SDK descendant remained alive"
        );
    }
}
