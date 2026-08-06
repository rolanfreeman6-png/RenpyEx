//! Mutation tests: deliberately corrupt real Ren'Py-formatted bytes and
//! verify the parser either fails cleanly with a structured error or —
//! in pathological cases where the corrupt input still self-consistently
//! parses — does so without any panic or undefined behaviour.
//!
//! These tests are explicit and one-off (no fuzzing framework). The invariant
//! we want is that mutating inputs in any single-byte way NEVER causes the
//! parser to silently produce wrong data.

use std::fs;
use std::path::PathBuf;

use renpyex::RenpyExError;
use renpyex::archive::{Length, Offset, RpaEntry, extract_rpa, list_rpa, read_entry};

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sample.rpa")
}

/// Owns a tempdir alive while we return the contained path.
fn tmp_copy(suffix: &str) -> (PathBuf, tempfile::TempDir) {
    let src = fixture();
    assert!(
        src.exists(),
        "fixture missing: {}. Run `python tests/build_fixtures.py` first.",
        src.display()
    );
    let data = fs::read(&src).expect("read fixture");
    let dir = tempfile::tempdir().expect("tempdir");
    let dst = dir.path().join(format!("sample{suffix}.rpa"));
    fs::write(&dst, &data).expect("write copy");
    (dst, dir)
}

fn write_archive_with_path(path: &std::path::Path, archived_path: &str) {
    let script = r#"
import pickle, sys, zlib
name = sys.argv[2]
payload = b"payload"
key = 0x42424242
data_offset = 34
index_offset = data_offset + len(payload)
index = {name: [(data_offset ^ key, len(payload) ^ key)]}
header = f"RPA-3.0 {index_offset:016x} {key:08x}\n".encode("ascii")
assert len(header) == 34
open(sys.argv[1], "wb").write(header + payload + zlib.compress(pickle.dumps(index, protocol=2)))
"#;
    // Supported test targets: Windows, Linux, macOS. RPA parsing itself has
    // the same Python 3 runtime requirement, so the fixture uses that runtime.
    let status = std::process::Command::new(if cfg!(windows) { "python" } else { "python3" })
        .arg("-c")
        .arg(script)
        .arg(path)
        .arg(archived_path)
        .status()
        .expect("launch Python fixture builder");
    assert!(status.success(), "Python fixture builder failed");
}

#[test]
fn mutation_truncated_rpa_fails_cleanly() {
    let (truncated, _guard) = tmp_copy("_truncated");
    let data = fs::read(&truncated).expect("read");
    fs::write(&truncated, &data[..data.len() / 2]).expect("write truncated");
    let error = list_rpa(&truncated, None).expect_err("truncated index must fail");
    assert!(matches!(error, RenpyExError::SizeMismatch { .. }));
}

#[test]
fn mutation_flip_header_byte_returns_bad_magic() {
    let mut data = fs::read(fixture()).expect("read fixture");
    data[0] ^= 0xFF;
    let (dst, _guard) = tmp_copy("_flipped");
    fs::write(&dst, &data).expect("write");
    let error = list_rpa(&dst, None).expect_err("corrupt magic must fail");
    assert!(matches!(error, RenpyExError::BadMagic { .. }));
}

#[test]
fn zero_length_entry_reads_as_exact_empty_payload() {
    let temp = tempfile::tempdir().expect("tempdir");
    let archive = temp.path().join("empty.rpa");
    fs::write(&archive, []).expect("write empty archive body");
    let entry = RpaEntry {
        path: "empty.bin".into(),
        offset: Offset::new(0),
        length: Length::new(0),
        prefix: None,
    };
    assert_eq!(read_entry(&archive, &entry).unwrap(), Vec::<u8>::new());
}

#[test]
fn mutation_completely_garbage_input_returns_bad_magic() {
    let (dst, _guard) = tmp_copy("_garbage");
    let garbage: Vec<u8> = (0..2048).map(|i| (i * 31) as u8).collect();
    fs::write(&dst, &garbage).expect("write");
    let error = list_rpa(&dst, None).expect_err("garbage must fail");
    assert!(matches!(error, RenpyExError::BadMagic { .. }));
}

#[test]
fn malicious_archive_path_is_rejected_before_any_write() {
    let temp = tempfile::tempdir().expect("tempdir");
    let archive = temp.path().join("traversal.rpa");
    let output = temp.path().join("output");
    let escaped = temp.path().join("escape.txt");
    write_archive_with_path(&archive, "../escape.txt");

    let error = extract_rpa(&archive, &output, None).expect_err("traversal must fail");
    assert!(matches!(
        error,
        RenpyExError::PathTraversal { ref entry, .. } if entry == "../escape.txt"
    ));
    assert!(!escaped.exists(), "archive wrote outside output root");
    assert!(
        !output.exists() || fs::read_dir(&output).unwrap().next().is_none(),
        "traversal preflight left partial output"
    );
}
