//! Walk a Ren'Py game's directory layout and produce an inventory.
//!
//! A Ren'Py game layout looks like:
//!
//! ```text
//! game-name/
//! ├── game/                 <- main game directory
//! │   ├── script.rpy
//! │   ├── images/
//! │   ├── audio/
//! │   └── ...
//! ├── archive.rpa           <- packed archive file (legacy naming)
//! └── game/updates/         <- optional update archives
//! ```
//!
//! For our purposes we walk every file under `root` (assumed to be either
//! the game's `game/` directory directly, or the game's project root with
//! a `game/` subfolder). We lean on `verify::magic::detect` to classify
//! each file.

use std::fs;
use std::path::{Path, PathBuf};

use crate::error::RenpyExError;
use crate::Result;
use crate::verify::magic::{detect_with_ext, Magic};

/// A single file entry discovered by the walker.
#[derive(Debug, Clone)]
pub struct FileEntry {
    /// Path relative to the walker's root.
    pub rel: PathBuf,
    /// Absolute path on disk.
    pub abs: PathBuf,
    /// File size in bytes.
    pub size: u64,
    /// Magic-byte classification (may require extension hint).
    pub magic: Magic,
}

/// Inventory produced by walking a game directory.
#[derive(Debug, Clone)]
pub struct GameInventory {
    /// Root that was walked.
    pub root: PathBuf,
    /// All files discovered.
    pub files: Vec<FileEntry>,
    /// Total bytes observed.
    pub total_bytes: u64,
}

/// Decide which directory to walk given a user-provided input.
///
/// If `input` contains a `game/` subdirectory, return it; otherwise treat
/// `input` itself as the game directory.
#[must_use]
pub fn resolve_game_dir(input: &Path) -> PathBuf {
    let game_subdir = input.join("game");
    if game_subdir.is_dir() {
        return game_subdir;
    }
    input.to_path_buf()
}

/// Directory walker that produces an inventory.
pub struct GameWalker {
    root: PathBuf,
    /// Skip `.git`, hidden files, and these patterns.
    skip: Vec<String>,
}

impl GameWalker {
    /// Construct a new walker rooted at `root`.
    #[must_use]
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            skip: vec![
                ".git".into(),
                ".github".into(),
                ".vscode".into(),
                "__pycache__".into(),
                ".DS_Store".into(),
            ],
        }
    }

    /// Walk and produce an inventory.
    pub fn walk(&self) -> Result<GameInventory> {
        let mut files = Vec::new();
        let mut total: u64 = 0;
        visit(&self.root, &self.root, &self.skip, &mut files, &mut total)?;
        Ok(GameInventory {
            root: self.root.clone(),
            files,
            total_bytes: total,
        })
    }
}

fn visit(
    root: &Path,
    dir: &Path,
    skip: &[String],
    files: &mut Vec<FileEntry>,
    total: &mut u64,
) -> Result<()> {
    for entry in fs::read_dir(dir).map_err(|e| RenpyExError::io(dir, e))? {
        let entry = entry.map_err(|e| RenpyExError::io(dir, e))?;
        let path = entry.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };
        if name.starts_with('.') || skip.iter().any(|s| s == name) {
            continue;
        }
        let ft = entry.file_type().map_err(|e| RenpyExError::io(&path, e))?;
        if ft.is_dir() {
            visit(root, &path, skip, files, total)?;
        } else if ft.is_file() {
            let md = entry.metadata().map_err(|e| RenpyExError::io(&path, e))?;
            let rel = path.strip_prefix(root).map_err(|_| RenpyExError::Invalid(format!(
                "walker produced path not under root: {}",
                path.display()
            )))?;
            let ext = rel.extension().and_then(|s| s.to_str());
            // Read a small magic-byte snippet (first 16 bytes) without
            // loading the whole file.
            let mut buf = [0u8; 16];
            let n = {
                use std::io::Read;
                let mut f = fs::File::open(&path).map_err(|e| RenpyExError::io(&path, e))?;
                let n = f.read(&mut buf).map_err(|e| RenpyExError::io(&path, e))?;
                n
            };
            let magic = detect_with_ext(&buf[..n], ext);
            files.push(FileEntry {
                rel: rel.to_path_buf(),
                abs: path,
                size: md.len(),
                magic,
            });
            *total = total.saturating_add(md.len());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs as sfs;
    use tempfile::tempdir;

    #[test]
    fn resolve_game_dir_picks_subdir() {
        let td = tempdir().unwrap();
        let root = td.path();
        sfs::create_dir_all(root.join("game")).unwrap();
        sfs::write(root.join("game").join("script.rpy"), b"#").unwrap();
        let resolved = resolve_game_dir(root);
        assert!(resolved.ends_with("game"));
    }

    #[test]
    fn walker_iterates_files() {
        let td = tempdir().unwrap();
        let root = td.path();
        sfs::write(root.join("a.rpy"), b"label a: pass\n").unwrap();
        sfs::write(root.join("b.png"), &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]).unwrap();
        sfs::create_dir(root.join("sub")).unwrap();
        sfs::write(root.join("sub").join("c.txt"), b"hello").unwrap();

        let inv = GameWalker::new(root.to_path_buf()).walk().unwrap();
        assert_eq!(inv.files.len(), 3);
        let by_name: std::collections::HashMap<String, &FileEntry> = inv
            .files
            .iter()
            .map(|f| (f.rel.to_string_lossy().to_string(), f))
            .collect();
        assert!(by_name.get("a.rpy").unwrap().magic == Magic::Text
            || by_name.get("a.rpy").unwrap().magic == Magic::Unknown);
        assert_eq!(by_name.get("b.png").unwrap().magic, Magic::Png);
    }

    #[test]
    fn walker_skips_hidden() {
        let td = tempdir().unwrap();
        let root = td.path();
        sfs::create_dir(root.join(".git")).unwrap();
        sfs::write(root.join(".git").join("HEAD"), b"ref: heads/main").unwrap();
        sfs::write(root.join("visible.txt"), b"hi").unwrap();
        let inv = GameWalker::new(root.to_path_buf()).walk().unwrap();
        assert_eq!(inv.files.len(), 1);
        assert_eq!(inv.files[0].rel.to_string_lossy(), "visible.txt");
    }
}
