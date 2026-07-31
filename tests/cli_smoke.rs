//! CLI smoke tests: invoke the compiled `renpyex` binary as a subprocess
//! and assert that extraction via the binary produces byte-perfect output,
//! matching in-process extraction.
//!
//! These tests rely on the binary having been built; if missing, they skip.

use std::path::PathBuf;
use std::process::Command;

use renpyex::archive::{list_rpa, read_entry};

fn binary_path() -> PathBuf {
    let exe = if cfg!(windows) {
        "renpyex.exe"
    } else {
        "renpyex"
    };
    let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    here.join("target").join("release").join(exe)
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sample.rpa")
}

#[test]
fn cli_extract_byte_matches_in_process_extraction() {
    let bin = binary_path();
    if !bin.exists() || !fixture_path().exists() {
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
    for entry in &listed.entries {
        let in_proc_bytes = read_entry(&fixture, entry).expect("in-proc read");
        let bin_path = out.join("rpa").join("archive.rpa").join(&entry.path);
        let bin_bytes = std::fs::read(&bin_path).expect("bin read");
        assert_eq!(in_proc_bytes, bin_bytes, "byte mismatch for {}", entry.path);
    }
}

#[test]
fn cli_extract_from_project_root_unpacks_archive() {
    let bin = binary_path();
    if !bin.exists() || !fixture_path().exists() {
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
    if !bin.exists() || !fixture_path().exists() {
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
