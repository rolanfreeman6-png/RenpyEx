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
    Length, Offset, RpaEntry, RpaExtracted, RpaVersion, ensure_python_available, extract_rpa,
    list_rpa, read_entry,
};
pub use rpyc::{
    RpycDecompileOptions, collect_rpyc_files, decompile_rpyc, decompile_rpyc_to, find_unrpyc,
    preflight_archive_decompilation,
};
pub use walker::{GameInventory, GameWalker, require_directory, resolve_game_dir};
