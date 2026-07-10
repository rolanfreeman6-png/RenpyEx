//! Feature-gated smoke test for the GUI binary: only compiled/run when
//! `cargo test --features gui` is used, since `renpyex-gui` itself only
//! exists as a build target under that feature.
#![cfg(feature = "gui")]

#[test]
fn probe_reports_ok_headless() {
    let exe = env!("CARGO_BIN_EXE_renpyex-gui");
    let output = std::process::Command::new(exe)
        .arg("--probe")
        .output()
        .expect("failed to run renpyex-gui --probe");

    assert!(
        output.status.success(),
        "probe exited non-zero: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("renpyex-gui probe ok"),
        "unexpected probe output: {stdout}"
    );
    assert!(stdout.contains("python_available="));
}
