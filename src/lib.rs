//! RenpyEx — Ren'Py archive extractor with byte-perfect extraction.
//!
//! Core invariants:
//! - Copy and RPA extraction paths do not transcode logical payload bytes.
//! - Extraction emits SHA-256 sums for written files, and verification checks
//!   those sums against a supplied manifest.
//! - Supported extensions are checked against bounded signatures; recognized
//!   image headers are also parsed for dimensions.
//! - Traversal, normalized aliases, file/directory conflicts, and case-only
//!   aliases on Windows/macOS are rejected before output is written.
//! - No `unsafe` code is allowed (enforced via lints).
//!
//! See README for CLI usage.

#![forbid(unsafe_code)]
#![deny(unused_must_use)]
#![warn(missing_docs)]

pub mod archive;
pub mod cli;
pub mod convert;
pub mod doctor;
pub mod error;
#[cfg(feature = "gui")]
pub mod gui;
pub mod key;
pub mod output;
pub mod sdk;
pub mod test_fixtures;
pub mod verify;

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, error::RenpyExError>;

/// Re-export commonly used items at crate root for ergonomic imports.
pub use error::RenpyExError;
