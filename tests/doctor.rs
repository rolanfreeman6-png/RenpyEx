//! Doctor CLI integration checks.

use std::process::Command;

#[test]
fn doctor_json_is_parseable_when_findings_exist() {
    let temp = tempfile::tempdir().expect("tempdir");
    let game = temp.path().join("game");
    std::fs::create_dir_all(game.join("images")).expect("create game");
    std::fs::write(
        game.join("script.rpy"),
        "image missing = \"images/missing.png\"\nimage dynamic = \"images/%s.png\"\n",
    )
    .expect("write source");
    let output = Command::new(env!("CARGO_BIN_EXE_renpyex"))
        .args(["doctor", game.to_str().expect("utf8 path"), "--json"])
        .output()
        .expect("run doctor");
    assert!(!output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON stdout");
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["summary"]["missing_references"], 1);
    assert_eq!(report["summary"]["dynamic_references"], 1);
    assert!(!output.stderr.is_empty());
}

#[test]
fn doctor_json_is_byte_deterministic_across_processes() {
    let temp = tempfile::tempdir().expect("tempdir");
    let game = temp.path().join("game");
    std::fs::create_dir_all(game.join("images")).expect("create game");
    std::fs::write(
        game.join("script.rpy"),
        "image z = \"images/z.png\"\nimage a = \"images/a.png\"\n",
    )
    .expect("write source");

    let mut baseline = None;
    for _ in 0..8 {
        let output = Command::new(env!("CARGO_BIN_EXE_renpyex"))
            .args(["doctor", game.to_str().expect("utf8 path"), "--json"])
            .output()
            .expect("run doctor");
        assert!(!output.status.success());
        if let Some(expected) = &baseline {
            assert_eq!(&output.stdout, expected, "Doctor JSON changed between runs");
        } else {
            baseline = Some(output.stdout);
        }
    }
}
