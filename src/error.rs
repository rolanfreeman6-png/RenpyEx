//! Error types for the crate.
//!
//! All user-visible errors flow through [`RenpyExError`]. Each variant includes
//! enough context to be actionable without requiring a debugger.

use std::io;
use std::path::PathBuf;

/// All errors that can be produced by RenpyEx operations.
#[derive(Debug, thiserror::Error)]
pub enum RenpyExError {
    /// Wrapped I/O error with the offending path attached for context.
    #[error("I/O error at {path}: {source}")]
    Io {
        /// Path that triggered the I/O error.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// File too small to even hold the expected header.
    #[error("file {path} is too small ({size} bytes; minimum is {min} bytes)")]
    TooSmall {
        /// Path to offending file.
        path: PathBuf,
        /// Actual file size.
        size: u64,
        /// Minimum expected.
        min: u64,
    },

    /// Magic bytes in a header did not match the expected signature.
    #[error("bad magic in {path}: expected {expected:?}, got {actual:?}")]
    BadMagic {
        /// Path to offending file.
        path: PathBuf,
        /// Expected first N bytes (hex-decoded preview as ASCII).
        expected: String,
        /// Actual first N bytes as ASCII (lossy-converted for display).
        actual: String,
    },

    /// Numeric field could not be parsed.
    #[error("parse error in {path} at offset {offset}: {message}")]
    Parse {
        /// Path to offending file.
        path: PathBuf,
        /// Offset in bytes where parsing failed.
        offset: u64,
        /// Human-readable failure description.
        message: String,
    },

    /// Archive entry path attempted directory traversal (`..`).
    #[error("path traversal attempt in archive {archive}: entry {entry}")]
    PathTraversal {
        /// Containing archive.
        archive: PathBuf,
        /// Offending entry path.
        entry: String,
    },

    /// Archive claims file size larger than expected or impossible.
    #[error("file size mismatch in {archive} at entry {entry}: claimed {claimed}, available {available}")]
    SizeMismatch {
        /// Containing archive.
        archive: PathBuf,
        /// Offending entry path.
        entry: String,
        /// Size claimed by archive metadata.
        claimed: u64,
        /// Size actually available in archive body.
        available: u64,
    },

    /// Image codec decode/encode failure.
    #[error("image error at {path}: {message}")]
    Image {
        /// Path to offending file.
        path: PathBuf,
        /// Description of failure.
        message: String,
    },

    /// Verifying integrity failed: hashes did not match.
    #[error("integrity check failed: {message}")]
    Integrity {
        /// Description of which entry failed.
        message: String,
    },

    /// External tool (e.g. Python or `unrpyc`) failed or was not found.
    #[error("external tool failure for {tool}: {message}")]
    External {
        /// Name of the tool (`python`, `unrpyc`, ...).
        tool: String,
        /// Failure message.
        message: String,
    },

    /// User input is malformed (e.g. CLI arguments, path format).
    #[error("invalid input: {0}")]
    Invalid(String),
}

impl RenpyExError {
    /// Wrap an `io::Error` with the path that caused it.
    pub fn io(path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }

    /// Construct an "invalid input" error.
    pub fn invalid(msg: impl Into<String>) -> Self {
        Self::Invalid(msg.into())
    }
}
