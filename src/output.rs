//! Output management: prepare an output folder, write files, summarise
//! progress safely.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::Result;
use crate::error::RenpyExError;

#[derive(Debug)]
struct DestinationClaim {
    source: String,
    destination: PathBuf,
}

/// Preflight registry that rejects two logical inputs mapping to the same
/// output path, including file/directory ancestor conflicts.
#[derive(Debug)]
pub struct DestinationRegistry {
    root: PathBuf,
    claims: std::collections::BTreeMap<String, DestinationClaim>,
}

impl DestinationRegistry {
    /// Start a registry for destinations rooted below `root`.
    #[must_use]
    pub fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            claims: std::collections::BTreeMap::new(),
        }
    }

    /// Claim `destination` for `source`, failing before any output is written
    /// if another source already owns the same filesystem path.
    pub fn claim(&mut self, source: impl Into<String>, destination: &Path) -> Result<()> {
        let source = source.into();
        let relative = destination.strip_prefix(&self.root).map_err(|_| {
            RenpyExError::Invalid(format!(
                "destination {} is outside output root {}",
                destination.display(),
                self.root.display()
            ))
        })?;
        let key = destination_key(relative)?;

        if let Some(existing) = self.claims.get(&key) {
            return Err(destination_collision(&source, destination, existing));
        }
        for (index, _) in key.match_indices('/') {
            if let Some(existing) = self.claims.get(&key[..index]) {
                return Err(destination_collision(&source, destination, existing));
            }
        }
        let descendant_prefix = format!("{key}/");
        if let Some((other_key, existing)) = self.claims.range(descendant_prefix.clone()..).next()
            && other_key.starts_with(&descendant_prefix)
        {
            return Err(destination_collision(&source, destination, existing));
        }

        self.claims.insert(
            key,
            DestinationClaim {
                source,
                destination: destination.to_path_buf(),
            },
        );
        Ok(())
    }
}

/// Reject collisions and manifest-incompatible source paths before an output
/// directory is created or cleared.
pub fn preflight_extraction_destinations<'a>(
    out_root: &Path,
    relative_paths: impl IntoIterator<Item = &'a Path>,
    include_rpa: bool,
    decompile_rpyc: bool,
) -> Result<()> {
    let mut destinations = DestinationRegistry::new(out_root);
    destinations.claim(
        "generated SHA256 manifest",
        &out_root.join("SHA256SUMS.txt"),
    )?;

    for relative in relative_paths {
        crate::verify::portable_manifest_path(relative)?;
        let copied = safe_join_path(out_root, relative)?;
        destinations.claim(format!("source file {}", relative.display()), &copied)?;

        let extension = relative.extension().and_then(|value| value.to_str());
        if include_rpa && extension.is_some_and(|value| value.eq_ignore_ascii_case("rpa")) {
            let unpacked_relative = Path::new("rpa").join(relative);
            let unpacked = safe_join_path(out_root, &unpacked_relative)?;
            destinations.claim(
                format!("unpacked archive {}", relative.display()),
                &unpacked,
            )?;
        }
        if decompile_rpyc && extension == Some("rpyc") {
            destinations.claim(
                format!("decompiled script {}", relative.display()),
                &copied.with_extension("rpy"),
            )?;
        }
    }
    Ok(())
}

fn destination_collision(
    source: &str,
    destination: &Path,
    existing: &DestinationClaim,
) -> RenpyExError {
    RenpyExError::Invalid(format!(
        "output path collision: {source:?} maps to {}, already claimed by {:?} as {}",
        destination.display(),
        existing.source,
        existing.destination.display()
    ))
}

fn destination_key(path: &Path) -> Result<String> {
    let mut pieces = Vec::new();
    for component in path.components() {
        let std::path::Component::Normal(piece) = component else {
            return Err(RenpyExError::Invalid(format!(
                "destination is not a normalized relative path: {}",
                path.display()
            )));
        };
        pieces.push(destination_component_key(piece));
    }
    if pieces.is_empty() {
        return Err(RenpyExError::Invalid(
            "destination must contain a file name".into(),
        ));
    }
    Ok(pieces.join("/"))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn destination_component_key(component: &std::ffi::OsStr) -> String {
    use std::os::unix::ffi::OsStrExt;

    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = component.as_bytes();
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0F) as usize] as char);
    }
    encoded
}

#[cfg(any(windows, target_os = "macos"))]
fn destination_component_key(component: &std::ffi::OsStr) -> String {
    component.to_string_lossy().to_lowercase()
}

#[cfg(not(any(unix, windows)))]
fn destination_component_key(component: &std::ffi::OsStr) -> String {
    component.to_string_lossy().into_owned()
}

/// Prepare an output directory for use.
///
/// If `path` does not exist, create it. If it exists and is empty, reuse.
/// If it exists and is non-empty, return an error unless `overwrite` is set.
pub fn prepare_output(path: &Path, overwrite: bool) -> Result<()> {
    match fs::metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(path).map_err(|e| RenpyExError::io(path, e))?;
            Ok(())
        }
        Err(e) => Err(RenpyExError::io(path, e)),
        Ok(md) if md.is_dir() => {
            if overwrite {
                wipe(path)?;
                Ok(())
            } else {
                let read = fs::read_dir(path).map_err(|e| RenpyExError::io(path, e))?;
                if read.count() > 0 {
                    Err(RenpyExError::Invalid(format!(
                        "output directory {} is non-empty; pass --overwrite to delete its contents",
                        path.display()
                    )))
                } else {
                    Ok(())
                }
            }
        }
        Ok(_) => Err(RenpyExError::Invalid(format!(
            "output path {} exists but is not a directory",
            path.display()
        ))),
    }
}

/// Wipe the contents of an output directory under `--overwrite`.
pub fn wipe(path: &Path) -> Result<()> {
    for entry in fs::read_dir(path).map_err(|e| RenpyExError::io(path, e))? {
        let entry = entry.map_err(|e| RenpyExError::io(path, e))?;
        let entry_path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|e| RenpyExError::io(&entry_path, e))?;
        let result = if file_type.is_dir() {
            fs::remove_dir_all(&entry_path)
        } else {
            fs::remove_file(&entry_path)
        };
        result.map_err(|e| RenpyExError::io(&entry_path, e))?;
    }
    Ok(())
}

/// Ensure that `dest` has its parent directory created.
pub fn ensure_parent(dest: &Path) -> Result<()> {
    if let Some(parent) = dest.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        fs::create_dir_all(parent).map_err(|e| RenpyExError::io(parent, e))?;
    }
    Ok(())
}

/// Join a user- or archive-provided relative path below `out_root`.
/// Separators and `.` components are normalized; absolute paths, traversal,
/// empty paths, and names that cannot be created portably are rejected.
pub fn safe_join(out_root: &Path, relative: &str) -> Result<PathBuf> {
    let normalized = relative.replace('\\', "/");
    if normalized.starts_with('/') {
        return Err(RenpyExError::PathTraversal {
            archive: out_root.to_path_buf(),
            entry: relative.into(),
        });
    }

    let mut joined = out_root.to_path_buf();
    let mut component_count = 0usize;
    for component in normalized
        .split('/')
        .filter(|component| !component.is_empty())
    {
        match component {
            "." => continue,
            ".." => {
                return Err(RenpyExError::PathTraversal {
                    archive: out_root.to_path_buf(),
                    entry: relative.into(),
                });
            }
            _ => validate_component(component)?,
        }
        joined.push(component);
        component_count += 1;
    }
    if component_count == 0 {
        return Err(RenpyExError::Invalid(format!(
            "output path is empty after normalization: {relative:?}"
        )));
    }
    Ok(joined)
}

/// Join an existing filesystem-relative path without converting its native
/// name representation through UTF-8.
pub fn safe_join_path(out_root: &Path, relative: &Path) -> Result<PathBuf> {
    if relative.is_absolute() {
        return Err(RenpyExError::PathTraversal {
            archive: out_root.to_path_buf(),
            entry: relative.to_string_lossy().into_owned(),
        });
    }
    let mut joined = out_root.to_path_buf();
    let mut component_count = 0usize;
    for component in relative.components() {
        match component {
            std::path::Component::CurDir => continue,
            std::path::Component::Normal(name) => {
                #[cfg(windows)]
                validate_component(name.to_str().ok_or_else(|| {
                    RenpyExError::invalid(format!(
                        "Windows output path is not valid Unicode: {}",
                        relative.display()
                    ))
                })?)?;
                joined.push(name);
                component_count += 1;
            }
            _ => {
                return Err(RenpyExError::PathTraversal {
                    archive: out_root.to_path_buf(),
                    entry: relative.to_string_lossy().into_owned(),
                });
            }
        }
    }
    if component_count == 0 {
        return Err(RenpyExError::invalid(
            "output path must contain a file name",
        ));
    }
    Ok(joined)
}

fn validate_component(component: &str) -> Result<()> {
    if let Some(character) = component.chars().find(|character| {
        character.is_control() || matches!(character, '<' | '>' | ':' | '"' | '|' | '?' | '*')
    }) {
        return Err(RenpyExError::Invalid(format!(
            "forbidden character {character:?} in path component {component:?}"
        )));
    }
    #[cfg(windows)]
    validate_windows_component(component)?;
    Ok(())
}

#[cfg(windows)]
fn validate_windows_component(component: &str) -> Result<()> {
    if component.ends_with([' ', '.']) {
        return Err(RenpyExError::Invalid(format!(
            "Windows path component cannot end in a space or period: {component:?}"
        )));
    }
    let stem = component
        .split_once('.')
        .map_or(component, |(stem, _extension)| stem)
        .to_ascii_uppercase();
    let is_device = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || stem.strip_prefix("COM").is_some_and(|suffix| {
            matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
        })
        || stem.strip_prefix("LPT").is_some_and(|suffix| {
            matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
        });
    if is_device {
        return Err(RenpyExError::Invalid(format!(
            "reserved Windows device name in path component: {component:?}"
        )));
    }
    Ok(())
}

/// Write `bytes` to `dest`. Atomic via temp-file-and-rename where possible.
pub fn write_atomic(dest: &Path, bytes: &[u8]) -> Result<()> {
    ensure_parent(dest)?;
    let (tmp, mut file) = create_temporary(dest)?;
    let result = file
        .write_all(bytes)
        .and_then(|()| file.flush())
        .map_err(|error| RenpyExError::io(&tmp, error));
    drop(file);
    if let Err(error) = result {
        let _ = fs::remove_file(&tmp);
        return Err(error);
    }
    commit_temporary(&tmp, dest)
}

/// Build `dest` through a temporary file and publish it only if `write` and
/// the final flush both succeed.
pub fn write_atomic_with(
    dest: &Path,
    write: impl FnOnce(&mut fs::File) -> Result<()>,
) -> Result<()> {
    ensure_parent(dest)?;
    let (tmp, mut file) = create_temporary(dest)?;
    let result =
        write(&mut file).and_then(|()| file.flush().map_err(|error| RenpyExError::io(&tmp, error)));
    drop(file);
    if let Err(error) = result {
        let _ = fs::remove_file(&tmp);
        return Err(error);
    }
    commit_temporary(&tmp, dest)
}

/// Reject output paths equal to or nested under a source tree.
///
/// This must run before [`prepare_output`] so `--overwrite` cannot remove
/// source data or an active walk cannot observe output files as input.
pub fn reject_output_within_source(source: &Path, output: &Path) -> Result<()> {
    let lexical_source = absolute_lexical(source)?;
    let lexical_output = absolute_lexical(output)?;
    if is_same_or_child(&lexical_output, &lexical_source)
        || is_same_or_child(&lexical_source, &lexical_output)
    {
        return Err(RenpyExError::Invalid(format!(
            "output directory {} overlaps source directory {}",
            lexical_output.display(),
            lexical_source.display()
        )));
    }
    let canonical_source = source
        .canonicalize()
        .map_err(|e| RenpyExError::io(source, e))?;
    let resolved_output = canonicalize_with_existing_ancestor(&lexical_output)?;
    if is_same_or_child(&resolved_output, &canonical_source)
        || is_same_or_child(&canonical_source, &resolved_output)
    {
        return Err(RenpyExError::Invalid(format!(
            "output directory {} resolves overlapping source directory {}",
            resolved_output.display(),
            source.display()
        )));
    }
    Ok(())
}

fn canonicalize_with_existing_ancestor(path: &Path) -> Result<PathBuf> {
    let mut ancestor = path.to_path_buf();
    let mut suffix = Vec::new();
    while !ancestor.exists() {
        let name = ancestor.file_name().ok_or_else(|| {
            RenpyExError::Invalid(format!(
                "cannot resolve output path ancestor: {}",
                path.display()
            ))
        })?;
        suffix.push(name.to_os_string());
        if !ancestor.pop() {
            return Err(RenpyExError::Invalid(format!(
                "cannot resolve output path ancestor: {}",
                path.display()
            )));
        }
    }
    let mut resolved = ancestor
        .canonicalize()
        .map_err(|e| RenpyExError::io(&ancestor, e))?;
    for component in suffix.iter().rev() {
        resolved.push(component);
    }
    Ok(resolved)
}

#[cfg(windows)]
fn is_same_or_child(output: &Path, source: &Path) -> bool {
    let output = output
        .to_string_lossy()
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase();
    let source = source
        .to_string_lossy()
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase();
    output == source || output.starts_with(&(source + "\\"))
}

#[cfg(not(windows))]
fn is_same_or_child(output: &Path, source: &Path) -> bool {
    output.starts_with(source)
}

fn absolute_lexical(path: &Path) -> Result<PathBuf> {
    let input = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| RenpyExError::io("<current-dir>", e))?
            .join(path)
    };
    let mut normalized = PathBuf::new();
    for component in input.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    Ok(normalized)
}

/// Copy `source` into `dest` atomically without buffering its whole contents.
pub fn copy_atomic(source: &Path, dest: &Path) -> Result<()> {
    ensure_parent(dest)?;
    let mut source_file =
        fs::File::open(source).map_err(|error| RenpyExError::io(source, error))?;
    let permissions = source_file
        .metadata()
        .map_err(|error| RenpyExError::io(source, error))?
        .permissions();
    let (tmp, mut temporary_file) = create_temporary(dest)?;
    let result = std::io::copy(&mut source_file, &mut temporary_file)
        .and_then(|_| temporary_file.flush())
        .map_err(|error| RenpyExError::io(source, error));
    drop(temporary_file);
    if let Err(error) = result {
        let _ = fs::remove_file(&tmp);
        return Err(error);
    }
    if let Err(error) = fs::set_permissions(&tmp, permissions) {
        let _ = fs::remove_file(&tmp);
        return Err(RenpyExError::io(&tmp, error));
    }
    commit_temporary(&tmp, dest)
}

fn create_temporary(dest: &Path) -> Result<(PathBuf, fs::File)> {
    // RenpyEx resource policy: 1,024 exclusive-create attempts bound work
    // while leaving ample room for concurrent writers and stale temp files.
    const TEMP_FILE_ATTEMPTS: u32 = 1024;

    let parent = dest
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    for attempt in 0..TEMP_FILE_ATTEMPTS {
        let path = parent.join(format!(".renpyex-{}-{attempt}.tmp", std::process::id()));
        // `create_new` is atomic even when another process selects the same
        // candidate: https://doc.rust-lang.org/std/fs/struct.OpenOptions.html#method.create_new
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(RenpyExError::io(&path, error)),
        }
    }
    Err(RenpyExError::invalid(format!(
        "could not reserve a temporary output file beside {} after {TEMP_FILE_ATTEMPTS} attempts",
        dest.display()
    )))
}

fn commit_temporary(tmp: &Path, dest: &Path) -> Result<()> {
    if let Err(error) = fs::rename(tmp, dest) {
        let _ = fs::remove_file(tmp);
        return Err(RenpyExError::io(dest, error));
    }
    Ok(())
}

/// Convert any relative path to absolute path anchored at `base`.
pub fn relative_to(base: &Path, p: &Path) -> PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        base.join(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn prepare_creates_new() {
        let td = tempdir().unwrap();
        let out = td.path().join("fresh");
        prepare_output(&out, false).unwrap();
        assert!(out.is_dir());
    }

    #[test]
    fn prepare_rejects_non_empty() {
        let td = tempdir().unwrap();
        let out = td.path().join("used");
        fs::create_dir(&out).unwrap();
        fs::write(out.join("x"), b"hi").unwrap();
        assert!(prepare_output(&out, false).is_err());
        prepare_output(&out, true).unwrap();
        assert!(fs::read_dir(&out).unwrap().next().is_none());
    }

    #[test]
    fn copy_atomic_preserves_exact_source_bytes() {
        let td = tempdir().unwrap();
        let source = td.path().join("source.bin");
        let destination = td.path().join("nested/destination.bin");
        fs::write(&source, [0, 1, 2, 255]).unwrap();
        copy_atomic(&source, &destination).unwrap();
        assert_eq!(fs::read(&destination).unwrap(), [0, 1, 2, 255]);
        assert!(!destination.with_extension("bin.tmp").exists());
    }

    #[test]
    fn copy_atomic_preserves_sibling_whose_name_matches_old_temp_pattern() {
        let temp = tempdir().unwrap();
        let source = temp.path().join("source");
        let output = temp.path().join("output");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&output).unwrap();
        fs::write(source.join("asset.txt"), b"primary").unwrap();
        fs::write(source.join("asset.txt.tmp"), b"sibling").unwrap();

        copy_atomic(&source.join("asset.txt.tmp"), &output.join("asset.txt.tmp")).unwrap();
        copy_atomic(&source.join("asset.txt"), &output.join("asset.txt")).unwrap();

        assert_eq!(fs::read(output.join("asset.txt")).unwrap(), b"primary");
        assert_eq!(
            fs::read(output.join("asset.txt.tmp")).unwrap(),
            b"sibling",
            "publishing asset.txt consumed a legitimate sibling"
        );
    }

    #[test]
    fn write_atomic_with_removes_partial_file_when_writer_fails() {
        let td = tempdir().unwrap();
        let destination = td.path().join("result.bin");
        let error = write_atomic_with(&destination, |file| {
            file.write_all(b"partial")
                .map_err(|source| RenpyExError::io(&destination, source))?;
            Err(RenpyExError::invalid("injected writer failure"))
        })
        .expect_err("writer failure must propagate");
        assert!(error.to_string().contains("injected writer failure"));
        assert!(!destination.exists());
        assert!(!destination.with_extension("bin.tmp").exists());
        assert_eq!(fs::read_dir(td.path()).unwrap().count(), 0);
    }

    #[test]
    fn reject_output_within_source_blocks_overwrite_risk() {
        let td = tempdir().unwrap();
        let source = td.path().join("game");
        fs::create_dir(&source).unwrap();
        assert!(reject_output_within_source(&source, &source).is_err());
        assert!(reject_output_within_source(&source, &source.join("out")).is_err());
        assert!(reject_output_within_source(&source, td.path()).is_err());
    }

    #[test]
    fn absolute_lexical_normalizes_parent_segments() {
        let td = tempdir().unwrap();
        let normalized = absolute_lexical(&td.path().join("a/../b")).unwrap();
        assert!(normalized.ends_with("b"));
        assert!(!normalized.ends_with("a/../b"));
    }

    #[test]
    fn destination_registry_rejects_normalized_duplicates() {
        let root = Path::new("out");
        let mut registry = DestinationRegistry::new(root);
        registry.claim("a//b", &root.join("a/b")).unwrap();
        let error = registry
            .claim("a/b", &root.join("a/b"))
            .expect_err("duplicate destination must fail");
        assert!(error.to_string().contains("a//b"));
        assert!(error.to_string().contains("a/b"));
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[test]
    fn destination_registry_uses_case_insensitive_target_semantics() {
        let root = Path::new("out");
        let mut registry = DestinationRegistry::new(root);
        registry.claim("Case.txt", &root.join("Case.txt")).unwrap();
        assert!(registry.claim("case.txt", &root.join("case.txt")).is_err());
    }

    #[test]
    fn destination_registry_rejects_file_directory_conflicts() {
        let root = Path::new("out");
        let mut registry = DestinationRegistry::new(root);
        registry.claim("file", &root.join("a")).unwrap();
        assert!(registry.claim("child", &root.join("a/b")).is_err());

        let mut reverse = DestinationRegistry::new(root);
        reverse.claim("child", &root.join("a/b")).unwrap();
        assert!(reverse.claim("file", &root.join("a")).is_err());
    }

    #[test]
    fn extraction_preflight_reserves_manifest_and_generated_paths() {
        let root = Path::new("out");
        let manifest = [Path::new("SHA256SUMS.txt")];
        assert!(
            preflight_extraction_destinations(root, manifest, false, false).is_err(),
            "source manifest would be replaced"
        );

        let sidecar = [Path::new("script.rpy"), Path::new("script.rpyc")];
        assert!(
            preflight_extraction_destinations(root, sidecar, false, true).is_err(),
            "decompiled script would replace copied source"
        );

        let archive_root = [Path::new("rpa"), Path::new("archive.rpa")];
        assert!(
            preflight_extraction_destinations(root, archive_root, true, false).is_err(),
            "archive output would descend through a copied file"
        );
    }

    #[cfg(unix)]
    #[test]
    fn safe_join_path_retains_non_utf8_component_bytes() {
        use std::ffi::OsString;
        use std::os::unix::ffi::{OsStrExt, OsStringExt};

        let root = Path::new("out");
        let name = OsString::from_vec(vec![b'f', 0x80]);
        let joined = safe_join_path(root, Path::new(&name)).unwrap();
        assert_eq!(joined.file_name().unwrap().as_bytes(), name.as_bytes());
    }

    #[cfg(unix)]
    #[test]
    fn extraction_preflight_rejects_paths_manifest_cannot_encode() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let root = Path::new("out");
        let non_utf8 = OsString::from_vec(vec![b'f', 0x80]);
        let non_utf8_paths = [Path::new(&non_utf8)];
        let error = preflight_extraction_destinations(root, non_utf8_paths, false, false)
            .expect_err("non-UTF path must fail before output");
        assert!(error.to_string().contains("UTF-8"), "{error}");

        let escaped_paths = [Path::new("line\nbreak.txt")];
        let error = preflight_extraction_destinations(root, escaped_paths, false, false)
            .expect_err("manifest escape path must fail before output");
        assert!(error.to_string().contains("escape"), "{error}");
    }
}
