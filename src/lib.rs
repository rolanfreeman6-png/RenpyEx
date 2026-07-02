//! RenpyEx — Ren'Py archive extractor with byte-perfect extraction.
//!
//! Core invariants:
//! - Extracted files are byte-perfect copies of source.
//! - All cryptographic checks (SHA-256) are computed before and after extraction.
//! - Magic-byte detection catches truncation and corruption.
//! - No `unsafe` code is allowed (enforced via lints).
//!
//! See README for CLI usage.

#![forbid(unsafe_code)]
#![deny(unused_must_use)]
#![warn(missing_docs)]

pub mod archive;
pub mod cli;
pub mod convert;
pub mod error;
pub mod key;
pub mod output;
pub mod test_fixtures;
pub mod verify;

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, error::RenpyExError>;

/// Re-export commonly used items at crate root for ergonomic imports.
pub use error::RenpyExError;
