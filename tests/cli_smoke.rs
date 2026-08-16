//! CLI smoke tests: invoke the compiled `renpyex` binary as a subprocess
//! and assert that extraction via the binary produces byte-perfect output,
//! matching in-process extraction.
//!
//! These tests rely on the binary having been built; if missing, they skip.

use std::path::PathBuf;
use std::process::Command;

use renpyex::archive::{extract_rpa, list_rpa};

fn binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_renpyex"))
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sample.rpa")
}

#[test]
fn cli_extract_byte_matches_in_process_extraction() {
    let bin = binary_path();
    if !fixture_path().exists() {
        return;
    }

    // Set up a clean output directory under temp.
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = tmp.path().join("cli-out");
    let fixture = fixture_path();

    // Copy fixture into a directory so the `extract --rpa` invocation
    // can find it.
    let staged_dir = tmp.path().join("game");
    std::fs::create_dir_all(&staged_dir).expect("mkdir game");
    std::fs::copy(&fixture, staged_dir.join("archive.rpa")).expect("copy fixture");

    let output = Command::new(&bin)
        .arg("extract")
        .arg(&staged_dir)
        .arg("--rpa")
        .arg("--out")
        .arg(&out)
        .output()
        .expect("spawn renpyex");
    assert!(
        output.status.success(),
        "CLI extract failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Compare in-process extraction with the files that the binary produced.
    let listed = list_rpa(&fixture, None).expect("list in-proc");
    let expected = tmp.path().join("expected");
    extract_rpa(&fixture, &expected, None).expect("in-process extract");
    for entry in &listed.entries {
        let in_proc_bytes = std::fs::read(expected.join(&entry.path)).expect("in-proc read");
        let bin_path = out.join("rpa").join("archive.rpa").join(&entry.path);
        let bin_bytes = std::fs::read(&bin_path).expect("bin read");
        assert_eq!(in_proc_bytes, bin_bytes, "byte mismatch for {}", entry.path);
    }
}

#[test]
fn cli_extract_from_project_root_unpacks_archive() {
    let bin = binary_path();
    if !fixture_path().exists() {
        return;
    }

    let tmp = tempfile::tempdir().expect("tempdir");
    let project = tmp.path().join("project");
    let game = project.join("game");
    let out = tmp.path().join("root-out");
    std::fs::create_dir_all(&game).expect("mkdir game");
    std::fs::copy(fixture_path(), game.join("archive.rpa")).expect("copy fixture");

    let output = Command::new(&bin)
        .arg("extract")
        .arg(&project)
        .arg("--rpa")
        .arg("--out")
        .arg(&out)
        .output()
        .expect("spawn renpyex");
    assert!(
        output.status.success(),
        "CLI extract failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(out.join("rpa").join("archive.rpa").is_dir());
}

#[test]
fn cli_overwrite_removes_previous_output() {
    let bin = binary_path();
    if !fixture_path().exists() {
        return;
    }

    let tmp = tempfile::tempdir().expect("tempdir");
    let staged_dir = tmp.path().join("game");
    let out = tmp.path().join("overwrite-out");
    std::fs::create_dir_all(&staged_dir).expect("mkdir game");
    std::fs::copy(fixture_path(), staged_dir.join("archive.rpa")).expect("copy fixture");
    std::fs::create_dir_all(out.join("old")).expect("mkdir old");
    std::fs::write(out.join("old").join("sentinel.txt"), b"old").expect("write sentinel");

    let output = Command::new(&bin)
        .arg("extract")
        .arg(&staged_dir)
        .arg("--overwrite")
        .arg("--out")
        .arg(&out)
        .output()
        .expect("spawn renpyex");
    assert!(
        output.status.success(),
        "CLI extract failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!out.join("old").exists());
}

#[test]
fn cli_extract_without_rpa_option_copies_archive_and_reports_exact_count() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let source = tmp.path().join("source");
    let out = tmp.path().join("out");
    std::fs::create_dir(&source).expect("mkdir source");
    let archive_bytes = b"RPA-3.0 opaque archive bytes";
    std::fs::write(source.join("archive.rpa"), archive_bytes).expect("write archive");

    let output = Command::new(binary_path())
        .arg("extract")
        .arg(&source)
        .arg("--out")
        .arg(&out)
        .output()
        .expect("spawn renpyex");

    assert!(output.status.success(), "extract failed: {output:?}");
    assert_eq!(
        std::fs::read(out.join("archive.rpa")).unwrap(),
        archive_bytes
    );
    let manifest = out.join("SHA256SUMS.txt");
    let (verified, failures) = renpyex::verify::verify_all(&out, &manifest).unwrap();
    assert_eq!(verified, 1);
    assert!(failures.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("Done. Wrote 1 files."),
        "stdout={}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn cli_convert_rejects_destination_collision_before_writing() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let source = tmp.path().join("source");
    let out = tmp.path().join("out");
    std::fs::create_dir(&source).expect("mkdir source");
    let image = image::RgbImage::from_pixel(1, 1, image::Rgb([12, 34, 56]));
    image
        .save_with_format(source.join("same.png"), image::ImageFormat::Png)
        .expect("write png");
    image
        .save_with_format(source.join("same.jpg"), image::ImageFormat::Jpeg)
        .expect("write jpeg");

    let output = Command::new(binary_path())
        .arg("convert")
        .arg(&source)
        .arg("--out")
        .arg(&out)
        .arg("--to")
        .arg("png")
        .output()
        .expect("spawn renpyex");

    assert!(
        !output.status.success(),
        "destination collision was accepted"
    );
    assert!(
        !out.exists() || std::fs::read_dir(&out).unwrap().next().is_none(),
        "collision preflight left converted output"
    );
}

#[test]
fn cli_rpyc_uses_resolved_unrpyc_path_when_cwd_differs() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let source = tmp.path().join("source");
    let output_dir = tmp.path().join("output");
    let tools_dir = tmp.path().join("tools");
    let unrelated_cwd = tmp.path().join("cwd");
    std::fs::create_dir(&source).unwrap();
    std::fs::create_dir(&tools_dir).unwrap();
    std::fs::create_dir(&unrelated_cwd).unwrap();
    std::fs::write(source.join("script.rpyc"), b"compiled").unwrap();

    #[cfg(windows)]
    let tool_path = tools_dir.join("unrpyc.py");
    #[cfg(not(windows))]
    let tool_path = tools_dir.join("unrpyc");
    let script = r#"#!/usr/bin/env python3
from pathlib import Path
import sys
Path(sys.argv[1]).with_suffix(".rpy").write_bytes(b"label fake:\n    pass\n")
"#;
    std::fs::write(&tool_path, script).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(&tool_path).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&tool_path, permissions).unwrap();
    }

    let existing_path = std::env::var_os("PATH").unwrap_or_default();
    let mut search_paths = vec![tools_dir.clone()];
    search_paths.extend(std::env::split_paths(&existing_path));
    let joined_path = std::env::join_paths(search_paths).unwrap();
    let mut command = Command::new(binary_path());
    command
        .current_dir(&unrelated_cwd)
        .env("PATH", joined_path)
        .arg("extract")
        .arg(&source)
        .arg("--out")
        .arg(&output_dir)
        .arg("--rpyc");
    #[cfg(windows)]
    command.env("PATHEXT", ".PY;.EXE;.COM;.BAT;.CMD");
    let output = command.output().expect("spawn renpyex");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(output_dir.join("script.rpy")).unwrap(),
        "label fake:\n    pass\n"
    );
}

#[test]
fn cli_extract_rejects_source_manifest_collision_before_writing() {
    let temp = tempfile::tempdir().expect("tempdir");
    let source = temp.path().join("source");
    let output_dir = temp.path().join("output");
    std::fs::create_dir(&source).expect("mkdir source");
    std::fs::write(source.join("payload.txt"), b"payload").expect("write payload");
    std::fs::write(source.join("SHA256SUMS.txt"), b"source manifest")
        .expect("write source manifest");

    let output = Command::new(binary_path())
        .arg("extract")
        .arg(&source)
        .arg("--out")
        .arg(&output_dir)
        .output()
        .expect("spawn renpyex");

    assert!(!output.status.success(), "manifest collision was accepted");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("collision"),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !output_dir.exists() || std::fs::read_dir(output_dir).unwrap().next().is_none(),
        "manifest collision preflight left output"
    );
}

/// Build an RPA-3.0 archive containing the requested entries under `path`.
fn write_archive_with_entries(path: &std::path::Path, entries: &[(&str, &[u8])]) {
    use std::io::Write;
    let script = r#"
import pickle, sys, zlib
entries = eval(sys.argv[2])
key = 0x42424242
offset = 34
body = b""
index = {}
for name, payload in entries:
    index[name] = [(offset ^ key, len(payload) ^ key)]
    body += payload
    offset += len(payload)
header = f"RPA-3.0 {offset:016x} {key:08x}\n".encode("ascii")
assert len(header) == 34
open(sys.argv[1], "wb").write(header + body + zlib.compress(pickle.dumps(index, protocol=4)))
"#;
    // Render entries as Python source: ("name", bytes.fromhex("...")).
    let mut payload = String::from("[");
    for (name, bytes) in entries {
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        payload.push_str(&format!("({name:?}, bytes.fromhex(\"{hex}\")),"));
    }
    payload.push(']');
    let status = Command::new(if cfg!(windows) { "python" } else { "python3" })
        .arg("-c")
        .arg(script)
        .arg(path)
        .arg(payload)
        .status()
        .expect("launch Python archive builder");
    assert!(status.success(), "Python archive builder failed");
    let _ = std::io::stdout().flush();
}

/// Put a fake `unrpyc` on a PATH that is prepended to the child environment.
fn fake_unrpyc_on_path(tmp: &std::path::Path) -> PathBuf {
    let tools_dir = tmp.join("tools");
    std::fs::create_dir(&tools_dir).unwrap();
    #[cfg(windows)]
    let tool_path = tools_dir.join("unrpyc.py");
    #[cfg(not(windows))]
    let tool_path = tools_dir.join("unrpyc");
    let script = r#"#!/usr/bin/env python3
from pathlib import Path
import sys
Path(sys.argv[-1]).with_suffix(".rpy").write_bytes(b"label fake_archive_script:\n    pass\n")
"#;
    std::fs::write(&tool_path, script).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(&tool_path).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&tool_path, permissions).unwrap();
    }
    tools_dir
}

fn command_with_tool_path(tools_dir: &std::path::Path, args: &[&str]) -> Command {
    let mut command = Command::new(binary_path());
    let existing_path = std::env::var_os("PATH").unwrap_or_default();
    let mut search_paths = vec![tools_dir.to_path_buf()];
    search_paths.extend(std::env::split_paths(&existing_path));
    command.env("PATH", std::env::join_paths(search_paths).unwrap());
    #[cfg(windows)]
    command.env("PATHEXT", ".PY;.EXE;.COM;.BAT;.CMD");
    for arg in args {
        command.arg(arg);
    }
    command
}

#[test]
fn cli_extract_decompiles_rpyc_inside_unpacks_archives() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let source = tmp.path().join("game");
    let output_dir = tmp.path().join("out");
    std::fs::create_dir(&source).unwrap();
    write_archive_with_entries(
        &source.join("scripts.rpa"),
        &[("script.rpyc", b"compiled-bytes")],
    );

    let tools_dir = fake_unrpyc_on_path(tmp.path());
    let output = command_with_tool_path(
        &tools_dir,
        &[
            "extract",
            source.to_str().unwrap(),
            "--out",
            output_dir.to_str().unwrap(),
            "--rpa",
            "--rpyc",
        ],
    )
    .output()
    .expect("spawn renpyex");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(
            output_dir
                .join("rpa")
                .join("scripts.rpa")
                .join("script.rpy")
        )
        .unwrap(),
        "label fake_archive_script:\n    pass\n",
        "archive-internal .rpyc must be decompiled next to its unpacked copy"
    );
    // The unpacked .rpyc itself must still be present and untouched.
    assert_eq!(
        std::fs::read(
            output_dir
                .join("rpa")
                .join("scripts.rpa")
                .join("script.rpyc")
        )
        .unwrap(),
        b"compiled-bytes"
    );
}

#[test]
fn cli_extract_rejects_archive_sidecar_collision_before_writing() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let source = tmp.path().join("game");
    let output_dir = tmp.path().join("out");
    std::fs::create_dir(&source).unwrap();
    write_archive_with_entries(
        &source.join("scripts.rpa"),
        &[
            ("shared.rpy", b"original script\n"),
            ("shared.rpyc", b"compiled bytes"),
        ],
    );

    let tools_dir = fake_unrpyc_on_path(tmp.path());
    let output = command_with_tool_path(
        &tools_dir,
        &[
            "extract",
            source.to_str().unwrap(),
            "--out",
            output_dir.to_str().unwrap(),
            "--rpa",
            "--rpyc",
        ],
    )
    .output()
    .expect("spawn renpyex");

    assert!(
        !output.status.success(),
        "sidecar collision was accepted: stdout={}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("collision"),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !output_dir.exists() || std::fs::read_dir(&output_dir).unwrap().next().is_none(),
        "sidecar collision preflight left output"
    );
}

#[test]
fn cli_info_reports_uninspectable_archive_on_stderr() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let source = tmp.path().join("game");
    std::fs::create_dir(&source).unwrap();
    std::fs::write(source.join("broken.rpa"), b"RPA-3.0 broken bytes").unwrap();

    let output = Command::new(binary_path())
        .arg("info")
        .arg(&source)
        .output()
        .expect("spawn renpyex");

    assert!(output.status.success(), "info stays read-only");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("could not inspect") && stderr.contains("broken.rpa"),
        "stderr={stderr}"
    );
}

#[test]
fn cli_extract_rejects_file_input_with_actionable_error() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let file_input = tmp.path().join("game.rpa");
    std::fs::write(&file_input, b"RPA-3.0 not a directory").unwrap();

    let output = Command::new(binary_path())
        .arg("extract")
        .arg(&file_input)
        .arg("--out")
        .arg(tmp.path().join("out"))
        .output()
        .expect("spawn renpyex");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("not a directory"), "stderr={stderr}");
}
