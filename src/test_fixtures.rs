//! Shared test fixtures. Currently a stub — the byte-perfect test in
//! `archive::rpa` will skip when the fixture is absent so this is safe to
//! keep empty.

use std::path::PathBuf;

/// Returns the path to a synthetic RPA-3.0 archive for testing.
///
/// The fixture is **not** checked in (git ignores binary test fixtures);
/// tests that depend on it skip when not present.
#[allow(dead_code)]
pub fn rpa_v3_fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sample.rpa")
}
