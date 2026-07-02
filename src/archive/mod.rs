//! Ren'Py archive handling.
//!
//! Currently implemented:
//! - `.rpa` (RPA-3.0) file parsing: byte-perfect extraction of archived entries.
//! - `.rpyc`: detection + decompile via external Python `unrpyc` if present.
//! - `game/` directory traversal for inventory and progress reporting.

pub mod rpa;
pub mod rpyc;
pub mod walker;

pub use rpa::{
    extract_rpa, list_rpa, read_entry, Length, Offset, RpaEntry, RpaExtracted, RpaVersion,
};
pub use rpyc::{decompile_rpyc, find_unrpyc, RpycDecompileOptions};
pub use walker::{GameInventory, GameWalker};
