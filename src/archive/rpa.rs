//! RPA-3.0 / RPA-2.0 archive parser.
//!
//! ## Format
//!
//! Format reference: Ren'Py `loader.py` (sources cited inline).
//!
//! **RPAv3** header layout (34 bytes, ending with newline):
//! - 8 bytes: `b"RPA-3.0 "` (no leading space)
//! - 16 hex chars: offset to zlib-compressed pickled index
//! - 1 space
//! - 8 hex chars: XOR key applied to obfuscate `(offset, dlen)` tuples
//! - trailing newline
//!
//! At the offset, the index is `zlib.decompress(file.read(index_len))` followed
//! by `pickle.loads(...)`. The result is a `dict[str, list[tuple]]` mapping
//! archive entry path → one or more `(offset, dlen)` tuples (or
//! `(offset, dlen, prefix_bytes)` triples for fragmented entries with an
//! inline byte prefix).
//!
//! **RPAv2** is a simpler subset (no XOR obfuscation, no inline prefix).
//!
//! ## Type design
//!
//! - [`Offset`] and [`Length`] are non-negative `u64` newtypes so it is
//!   impossible to mix them up in arithmetic or pass one where the other
//!   is expected.
//! - [`RpaEntry`] preserves each index chunk exactly, including optional
//!   inline prefix bytes and valid zero-length chunks.
//! - Parser and extraction boundaries reject offsets or lengths that cannot
//!   be represented safely by the supported file APIs.
//!
//! ## Process-extraction
//!
//! Python 3 pickle parsing is delegated to a constrained subprocess that
//! emits one bounded JSON record per line. Python 3 must be available on
//! `PATH` as `python` on Windows or `python3` on Linux/macOS.

use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use flate2::read::ZlibDecoder;

use crate::Result;
use crate::error::RenpyExError;
use crate::output;
use crate::verify::sha::sha256;

/// Magic prefix for RPA-3.0 archives (no leading space): exact 8 bytes
/// `b"RPA-3.0 "` per Ren'Py `loader.py:RPAv3ArchiveHandler.get_supported_headers`.
const RPA3_MAGIC: &[u8; 8] = b"RPA-3.0 ";

/// Ren'Py reads 40 bytes while sniffing the RPA3 header; 64 also covers RPA2
/// without a second read. Source: Ren'Py `renpy/loader.py`, commit
/// `da4d86679ceca69124dc2204098e1245968c9aa0`, lines 156-159 and 201-203.
const HEADER_PEEK: usize = 64;

// These are RenpyEx resource-policy limits, not fields from the RPA format.
// They bound attacker-controlled allocation while retaining room for large
// indexes; archive payloads themselves are copied as a stream.
const MAX_COMPRESSED_INDEX_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PICKLE_INDEX_BYTES: u64 = 128 * 1024 * 1024;
const MAX_HELPER_OUTPUT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_HELPER_STDERR_BYTES: u64 = 1024 * 1024;
const MAX_INDEX_PATH_BYTES: usize = 4096;
const MAX_INDEX_PATHS: usize = 1_000_000;
const MAX_INDEX_TUPLES: usize = 2_000_000;
const MAX_PREFIX_BYTES: usize = 16 * 1024 * 1024;
const MAX_IN_MEMORY_ENTRY_BYTES: u64 = 512 * 1024 * 1024;
const PICKLE_HELPER_TIMEOUT: Duration = Duration::from_secs(120);
const PYTHON_PREFLIGHT_TIMEOUT: Duration = Duration::from_secs(10);
/// `Child::try_wait` is non-blocking; a 10 ms poll caps ordinary deadline
/// overshoot while avoiding a CPU spin. API source:
/// <https://doc.rust-lang.org/std/process/struct.Child.html#method.try_wait>.
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Newtype for archive-internal byte offsets.
///
/// The raw value is retained exactly. Parser validation rejects offsets that
/// cannot be represented by the supported file APIs before extraction.
/// Mixing this with [`Length`] produces a compile error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Offset(u64);

impl Offset {
    /// Construct without silently changing the archived value.
    #[must_use]
    pub fn new(value: u64) -> Self {
        Self(value)
    }
    /// Construct from a `u64` value.
    #[must_use]
    pub fn new_strict(value: u64) -> Self {
        Self(value)
    }
    /// Raw value (use only when bridging to external APIs).
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for Offset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Offset({})", self.0)
    }
}

/// Newtype for archive-internal byte lengths.
///
/// Zero-length entries are valid archive data and are retained exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Length(u64);

impl Length {
    /// Construct without silently changing the archived value.
    #[must_use]
    pub fn new(value: u64) -> Self {
        Self(value)
    }
    /// Construct a zero length.
    #[must_use]
    pub const fn zero() -> Self {
        Self(0)
    }
    /// Raw value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for Length {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Length({})", self.0)
    }
}

/// A single archive entry, post-deobfuscation, ready for byte-perfect read.
///
/// Constructed from the cited Ren'Py source conventions:
///
/// - `path` uses forward slashes only.
/// - `offset` and `length` are non-negative.
/// - `prefix` is present iff the archive stores bytes inline (fragmented
///   entries have the leading chunk as `prefix` and the remainder at
///   `offset..offset+length`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpaEntry {
    /// Path inside the archive (e.g. `"images/bg.png"`).
    pub path: String,
    /// Absolute offset within the archive file at which the entry's data
    /// starts.
    pub offset: Offset,
    /// Length of the entry's data in bytes.
    pub length: Length,
    /// Optional inline prefix bytes prepended to the entry's data.
    pub prefix: Option<Vec<u8>>,
}

/// Result of [`list_rpa`] — enumeration of entries inside an archive.
#[derive(Debug, Clone)]
pub struct RpaExtracted {
    /// Path to the archive file.
    pub archive_path: PathBuf,
    /// Version.
    pub version: RpaVersion,
    /// All index chunks enumerated. Duplicate paths represent fragments that
    /// [`extract_rpa`] concatenates in archive index order.
    pub entries: Vec<RpaEntry>,
    /// Total uncompressed payload announced by the archive, including inline
    /// prefix bytes.
    pub total_uncompressed: u64,
}

/// RPA version recognised by the parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpaVersion {
    /// `"RPA-2.0 "` — common for older Ren'Py titles.
    V2,
    /// `"RPA-3.0 "` — common since Ren'Py 7.x.
    V3,
    /// `"RPA-1.0 "` — rare, only used by `.rpi` files (zlib-pickled
    /// directly, no header).
    V1,
}

impl fmt::Display for RpaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RpaVersion::V1 => f.write_str("RPA-1.0"),
            RpaVersion::V2 => f.write_str("RPA-2.0"),
            RpaVersion::V3 => f.write_str("RPA-3.0"),
        }
    }
}

/// Detect RPA version from header bytes; returns `None` if not RPA.
#[must_use]
pub fn detect_version(header: &[u8]) -> Option<RpaVersion> {
    if header.starts_with(RPA3_MAGIC) {
        Some(RpaVersion::V3)
    } else if header.starts_with(b"RPA-2.0") {
        Some(RpaVersion::V2)
    } else {
        None
    }
}

/// List all entries in an archive without reading their payload.
pub fn list_rpa(path: &Path, key: Option<u32>) -> Result<RpaExtracted> {
    let mut file = fs::File::open(path).map_err(|e| RenpyExError::io(path, e))?;
    let mut header = vec![0u8; HEADER_PEEK];
    let n = file
        .read(&mut header)
        .map_err(|e| RenpyExError::io(path, e))?;
    header.truncate(n);
    let version = detect_version(&header).ok_or_else(|| RenpyExError::BadMagic {
        path: path.to_path_buf(),
        expected: format!("{HEADER_PEEK}-byte RPA header"),
        actual: ascii_lossy(&header),
    })?;

    let (offset, archive_key) = match version {
        RpaVersion::V2 => parse_v2_header(&header, path)?,
        RpaVersion::V3 => parse_v3_header(&header, path)?,
        RpaVersion::V1 => {
            return Err(RenpyExError::Invalid(
                "RPAv1 (.rpi) archives use a different layout; not yet implemented".into(),
            ));
        }
    };

    let entries = read_index(&mut file, offset, archive_key, key, version, path)?;
    let total = entries.iter().try_fold(0u64, |acc, e| {
        let prefix = e.prefix.as_ref().map_or(0, |bytes| bytes.len() as u64);
        let size = e
            .length
            .get()
            .checked_add(prefix)
            .ok_or_else(|| RenpyExError::Integrity {
                message: format!("{}: entry size overflow", path.display()),
            })?;
        acc.checked_add(size)
            .ok_or_else(|| RenpyExError::Integrity {
                message: format!("{}: uncompressed size overflow", path.display()),
            })
    })?;

    Ok(RpaExtracted {
        archive_path: path.to_path_buf(),
        version,
        entries,
        total_uncompressed: total,
    })
}

/// Read the byte-perfect contents of a single entry.
pub fn read_entry(archive: &Path, entry: &RpaEntry) -> Result<Vec<u8>> {
    use std::io::Seek;

    let mut file = fs::File::open(archive).map_err(|e| RenpyExError::io(archive, e))?;
    let file_len = fs::metadata(archive)
        .map_err(|e| RenpyExError::io(archive, e))?
        .len();
    validate_entry_bounds(archive, entry, file_len)?;
    let off = entry.offset.get();
    let len = entry.length.get();
    let prefix_len = entry.prefix.as_ref().map_or(0, Vec::len);
    validate_in_memory_entry_size(archive, entry)?;
    let len_usize = usize::try_from(len).map_err(|_| RenpyExError::SizeMismatch {
        archive: archive.to_path_buf(),
        entry: entry.path.clone(),
        claimed: len,
        available: usize::MAX as u64,
    })?;
    let capacity = prefix_len
        .checked_add(len_usize)
        .ok_or_else(|| RenpyExError::Integrity {
            message: format!("{}: entry output size overflow", archive.display()),
        })?;

    file.seek(std::io::SeekFrom::Start(off))
        .map_err(|e| RenpyExError::io(archive, e))?;

    let mut buf = Vec::new();
    buf.try_reserve_exact(len_usize)
        .map_err(|error| RenpyExError::Integrity {
            message: format!(
                "{}: cannot reserve memory for entry {:?}: {error}",
                archive.display(),
                entry.path
            ),
        })?;
    file.take(len)
        .read_to_end(&mut buf)
        .map_err(|e| RenpyExError::io(archive, e))?;
    if (buf.len() as u64) != len {
        return Err(RenpyExError::SizeMismatch {
            archive: archive.to_path_buf(),
            entry: entry.path.clone(),
            claimed: len,
            available: buf.len() as u64,
        });
    }
    let mut full = Vec::new();
    full.try_reserve_exact(capacity)
        .map_err(|error| RenpyExError::Integrity {
            message: format!(
                "{}: cannot reserve output memory for entry {:?}: {error}",
                archive.display(),
                entry.path
            ),
        })?;
    if let Some(prefix) = &entry.prefix {
        full.extend_from_slice(prefix);
    }
    full.extend_from_slice(&buf);
    Ok(full)
}

/// Read and emit byte-perfect contents for every entry in the archive.
pub fn extract_rpa(archive: &Path, out_root: &Path, key: Option<u32>) -> Result<RpaExtracted> {
    let listed = list_rpa(archive, key)?;
    let file_len = fs::metadata(archive)
        .map_err(|error| RenpyExError::io(archive, error))?
        .len();
    let mut grouped: std::collections::BTreeMap<String, Vec<&RpaEntry>> =
        std::collections::BTreeMap::new();
    for entry in &listed.entries {
        grouped.entry(entry.path.clone()).or_default().push(entry);
    }
    let mut destinations = output::DestinationRegistry::new(out_root);
    let mut plans = Vec::with_capacity(grouped.len());
    for (path, fragments) in grouped {
        let _total =
            fragments.iter().try_fold(0u64, |acc, entry| {
                validate_entry_bounds(archive, entry, file_len)?;
                let prefix = entry.prefix.as_ref().map_or(0, Vec::len) as u64;
                let size = entry.length.get().checked_add(prefix).ok_or_else(|| {
                    RenpyExError::Integrity {
                        message: format!("{}: entry size overflow", archive.display()),
                    }
                })?;
                acc.checked_add(size)
                    .ok_or_else(|| RenpyExError::Integrity {
                        message: format!("{}: entry size overflow", archive.display()),
                    })
            })?;
        let dest = output::safe_join(out_root, &path)?;
        destinations.claim(format!("archive entry {path:?}"), &dest)?;
        plans.push((fragments, dest));
    }

    for (fragments, dest) in plans {
        output::write_atomic_with(&dest, |writer| {
            for entry in fragments {
                stream_entry(archive, entry, &dest, writer)?;
            }
            Ok(())
        })?;
    }
    Ok(listed)
}

fn validate_entry_bounds(archive: &Path, entry: &RpaEntry, file_len: u64) -> Result<()> {
    let offset = entry.offset.get();
    let length = entry.length.get();
    if offset > file_len || length > file_len - offset {
        return Err(RenpyExError::SizeMismatch {
            archive: archive.to_path_buf(),
            entry: entry.path.clone(),
            claimed: length,
            available: file_len.saturating_sub(offset),
        });
    }
    Ok(())
}

fn validate_in_memory_entry_size(archive: &Path, entry: &RpaEntry) -> Result<()> {
    let prefix_len = entry.prefix.as_ref().map_or(0, Vec::len) as u64;
    let output_len =
        entry
            .length
            .get()
            .checked_add(prefix_len)
            .ok_or_else(|| RenpyExError::Integrity {
                message: format!("{}: entry output size overflow", archive.display()),
            })?;
    if output_len > MAX_IN_MEMORY_ENTRY_BYTES {
        return Err(RenpyExError::Integrity {
            message: format!(
                "{}: entry {:?} is {output_len} bytes; read_entry limit is {MAX_IN_MEMORY_ENTRY_BYTES}; use extract_rpa for streaming extraction",
                archive.display(),
                entry.path
            ),
        });
    }
    Ok(())
}

fn stream_entry(
    archive: &Path,
    entry: &RpaEntry,
    destination: &Path,
    writer: &mut fs::File,
) -> Result<()> {
    use std::io::Seek;

    let mut file = fs::File::open(archive).map_err(|error| RenpyExError::io(archive, error))?;
    let file_len = file
        .metadata()
        .map_err(|error| RenpyExError::io(archive, error))?
        .len();
    validate_entry_bounds(archive, entry, file_len)?;
    if let Some(prefix) = &entry.prefix {
        writer
            .write_all(prefix)
            .map_err(|error| RenpyExError::io(destination, error))?;
    }
    file.seek(std::io::SeekFrom::Start(entry.offset.get()))
        .map_err(|error| RenpyExError::io(archive, error))?;
    let copied = std::io::copy(&mut file.take(entry.length.get()), writer)
        .map_err(|error| RenpyExError::io(destination, error))?;
    if copied != entry.length.get() {
        return Err(RenpyExError::SizeMismatch {
            archive: archive.to_path_buf(),
            entry: entry.path.clone(),
            claimed: entry.length.get(),
            available: copied,
        });
    }
    Ok(())
}

fn parse_v2_header(header: &[u8], path: &Path) -> Result<(u64, u32)> {
    require_len(header, 24, path, "v2 header minimum length")?;
    let off_str = std::str::from_utf8(&header[8..24]).map_err(|_| RenpyExError::Parse {
        path: path.to_path_buf(),
        offset: 8,
        message: "RPAv2 header offset not valid UTF-8".into(),
    })?;
    let offset = u64::from_str_radix(off_str.trim(), 16).map_err(|_| RenpyExError::Parse {
        path: path.to_path_buf(),
        offset: 8,
        message: format!("RPAv2 header offset {off_str:?} is not valid hex"),
    })?;
    Ok((offset, 0))
}

fn parse_v3_header(header: &[u8], path: &Path) -> Result<(u64, u32)> {
    // Per Ren'Py loader.py:
    //   bytes 0..8:   b"RPA-3.0 "
    //   bytes 8..24:  16 hex chars (offset)
    //   bytes 24:     ' '
    //   bytes 25..33: 8 hex chars (XOR key)
    //   byte 33:      '\n' in archives written by Ren'Py; field parsing only
    //                 depends on bytes 0..33, matching loader.py.
    require_len(header, 33, path, "v3 header minimum length")?;
    let off_str = std::str::from_utf8(&header[8..24]).map_err(|_| RenpyExError::Parse {
        path: path.to_path_buf(),
        offset: 8,
        message: "RPAv3 offset field not valid UTF-8".into(),
    })?;
    let key_str = std::str::from_utf8(&header[25..33]).map_err(|_| RenpyExError::Parse {
        path: path.to_path_buf(),
        offset: 25,
        message: "RPAv3 key field not valid UTF-8".into(),
    })?;
    let offset = u64::from_str_radix(off_str.trim(), 16).map_err(|_| RenpyExError::Parse {
        path: path.to_path_buf(),
        offset: 8,
        message: format!("RPAv3 offset {off_str:?} is not valid hex"),
    })?;
    let key = u32::from_str_radix(key_str.trim(), 16).map_err(|_| RenpyExError::Parse {
        path: path.to_path_buf(),
        offset: 25,
        message: format!("RPAv3 key {key_str:?} is not valid hex"),
    })?;
    Ok((offset, key))
}

fn require_len(buf: &[u8], needed: usize, path: &Path, context: &str) -> Result<()> {
    if buf.len() < needed {
        return Err(RenpyExError::TooSmall {
            path: path.to_path_buf(),
            size: buf.len() as u64,
            min: needed as u64,
        });
    }
    let _ = context;
    Ok(())
}

fn read_index(
    file: &mut fs::File,
    offset: u64,
    archive_key: u32,
    user_key: Option<u32>,
    version: RpaVersion,
    path: &Path,
) -> Result<Vec<RpaEntry>> {
    use std::io::Seek;

    let file_len = file
        .metadata()
        .map_err(|error| RenpyExError::io(path, error))?
        .len();
    if offset > file_len {
        return Err(RenpyExError::SizeMismatch {
            archive: path.to_path_buf(),
            entry: "<index>".into(),
            claimed: offset,
            available: file_len,
        });
    }
    let compressed_len = file_len - offset;
    if compressed_len > MAX_COMPRESSED_INDEX_BYTES {
        return Err(RenpyExError::Integrity {
            message: format!(
                "{}: compressed RPA index is {compressed_len} bytes; limit is {MAX_COMPRESSED_INDEX_BYTES}",
                path.display()
            ),
        });
    }
    file.seek(std::io::SeekFrom::Start(offset))
        .map_err(|e| RenpyExError::io(path, e))?;

    let mut zlib_bytes = Vec::new();
    file.take(MAX_COMPRESSED_INDEX_BYTES + 1)
        .read_to_end(&mut zlib_bytes)
        .map_err(|e| RenpyExError::io(path, e))?;
    if zlib_bytes.len() as u64 > MAX_COMPRESSED_INDEX_BYTES {
        return Err(RenpyExError::Integrity {
            message: format!(
                "{}: compressed RPA index grew beyond the {MAX_COMPRESSED_INDEX_BYTES}-byte limit while reading",
                path.display()
            ),
        });
    }

    let pickle_bytes = decompress_index(&zlib_bytes, path, MAX_PICKLE_INDEX_BYTES)?;

    parse_pickle_index(&pickle_bytes, archive_key, user_key, version, path)
}

fn decompress_index(zlib_bytes: &[u8], path: &Path, limit: u64) -> Result<Vec<u8>> {
    let decoder = ZlibDecoder::new(zlib_bytes);
    let mut pickle_bytes = Vec::new();
    decoder
        .take(limit + 1)
        .read_to_end(&mut pickle_bytes)
        .map_err(|error| RenpyExError::io(path, error))?;
    if pickle_bytes.len() as u64 > limit {
        return Err(RenpyExError::Integrity {
            message: format!(
                "{}: decompressed RPA index exceeds the {limit}-byte limit",
                path.display()
            ),
        });
    }
    Ok(pickle_bytes)
}

#[derive(serde::Deserialize)]
struct ParsedIndexTuple {
    offset: u64,
    length: u64,
    #[serde(default)]
    prefix: Option<String>,
}

#[derive(serde::Deserialize)]
struct ParsedIndexLine {
    path: String,
    #[cfg(any(windows, target_os = "macos"))]
    comparison_path: String,
    #[serde(default)]
    tuples: Vec<ParsedIndexTuple>,
}

#[derive(Debug)]
struct PythonOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// Confirm that the Python 3 interpreter required for RPA index parsing can
/// start and import the standard-library modules used by the helper.
pub fn ensure_python_available() -> Result<()> {
    let output = run_python_script(
        "import io, json, pickle, sys, unicodedata, zlib",
        &[],
        &[],
        PYTHON_PREFLIGHT_TIMEOUT,
        1024,
    )?;
    if output.status.success() {
        Ok(())
    } else {
        Err(RenpyExError::External {
            tool: "python".into(),
            message: format!(
                "RPA support requires Python 3 with pickle, json, unicodedata, and zlib; preflight exited with {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            ),
        })
    }
}

// Supported targets: Windows, Linux, and macOS. Only portable `std::process`
// APIs are used. The fixed helper script never launches descendants, so killing
// the direct Python child also closes every pipe owned by this operation.
fn run_python_script(
    script: &str,
    arguments: &[String],
    input: &[u8],
    timeout: Duration,
    stdout_limit: u64,
) -> Result<PythonOutput> {
    let mut command = std::process::Command::new(if cfg!(windows) { "python" } else { "python3" });
    command
        .arg("-c")
        .arg(script)
        .args(arguments)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = command.spawn().map_err(|error| RenpyExError::External {
        tool: "python".into(),
        message: format!(
            "failed to launch the Python 3 interpreter required for RPA support: {error}"
        ),
    })?;
    let stdin = child.stdin.take().expect("piped child stdin must exist");
    let stdout = child.stdout.take().expect("piped child stdout must exist");
    let stderr = child.stderr.take().expect("piped child stderr must exist");
    let deadline = std::time::Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| RenpyExError::invalid("Python helper timeout is too large"))?;

    std::thread::scope(|scope| {
        let input_thread = scope.spawn(move || {
            let mut stdin = stdin;
            stdin.write_all(input)
        });
        let stdout_thread =
            scope.spawn(move || read_bounded(stdout, stdout_limit, "Python helper stdout"));
        let stderr_thread = scope
            .spawn(move || read_bounded(stderr, MAX_HELPER_STDERR_BYTES, "Python helper stderr"));

        let mut timed_out = false;
        let mut wait_error = None;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) => {
                    let now = std::time::Instant::now();
                    if now >= deadline {
                        timed_out = true;
                        break None;
                    }
                    std::thread::sleep(
                        PROCESS_POLL_INTERVAL.min(deadline.saturating_duration_since(now)),
                    );
                }
                Err(error) => {
                    wait_error = Some(error);
                    break None;
                }
            }
        };

        if status.is_none() {
            let _ = child.kill();
            let _ = child.wait();
        }

        let input_result = input_thread.join().map_err(|_| RenpyExError::External {
            tool: "python".into(),
            message: "Python helper stdin thread panicked".into(),
        })?;
        let stdout = stdout_thread
            .join()
            .map_err(|_| RenpyExError::External {
                tool: "python".into(),
                message: "Python helper stdout thread panicked".into(),
            })?
            .map_err(|error| RenpyExError::External {
                tool: "python".into(),
                message: error.to_string(),
            })?;
        let stderr = stderr_thread
            .join()
            .map_err(|_| RenpyExError::External {
                tool: "python".into(),
                message: "Python helper stderr thread panicked".into(),
            })?
            .map_err(|error| RenpyExError::External {
                tool: "python".into(),
                message: error.to_string(),
            })?;

        if timed_out {
            return Err(RenpyExError::External {
                tool: "python".into(),
                message: format!("RPA pickle helper exceeded its {timeout:?} timeout"),
            });
        }
        if let Some(error) = wait_error {
            return Err(RenpyExError::External {
                tool: "python".into(),
                message: format!("failed while waiting for the RPA pickle helper: {error}"),
            });
        }
        let status = status.expect("completed child has an exit status");
        if status.success() {
            input_result.map_err(|error| RenpyExError::External {
                tool: "python".into(),
                message: format!("failed to send the RPA pickle index: {error}"),
            })?;
        }
        Ok(PythonOutput {
            status,
            stdout,
            stderr,
        })
    })
}

fn read_bounded(
    reader: impl Read,
    limit: u64,
    stream_name: &'static str,
) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{stream_name} exceeded its {limit}-byte limit"),
        ));
    }
    Ok(bytes)
}

/// Parses the Python pickle bytes that encode the archive's index dict
/// using a small Python subprocess. See module docs for rationale.
fn parse_pickle_index(
    pickle_bytes: &[u8],
    archive_key: u32,
    user_key: Option<u32>,
    version: RpaVersion,
    path: &Path,
) -> Result<Vec<RpaEntry>> {
    let script = r#"
import _codecs, io, json, pickle, sys, unicodedata

max_paths = int(sys.argv[1])
max_tuples = int(sys.argv[2])
max_path_bytes = int(sys.argv[3])
max_prefix_bytes = int(sys.argv[4])
data = sys.stdin.buffer.read()

class SafeUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        # Pickle protocols < 4 represent `bytes` values through a
        # `_codecs.encode(str, "latin1")` reduce. The allowlist entry is a
        # stdlib str.encode wrapper with no code-execution capability; every
        # other global remains rejected.
        if module == "_codecs" and name == "encode":
            return _codecs.encode
        raise pickle.UnpicklingError("global objects are not permitted")

def decode_path(value):
    if isinstance(value, str):
        value.encode("utf-8", "strict")
        return value
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", "strict")
        except UnicodeDecodeError:
            return value.decode("latin-1", "strict")
    raise pickle.UnpicklingError(f"archive path has unsupported type {type(value).__name__}")

try:
    obj = SafeUnpickler(io.BytesIO(data), fix_imports=True, encoding="bytes", errors="strict").load()
    if not isinstance(obj, dict):
        raise pickle.UnpicklingError("archive index root is not a dictionary")
    if len(obj) > max_paths:
        raise pickle.UnpicklingError(f"archive index has {len(obj)} paths; limit is {max_paths}")

    tuple_count = 0
    first = True
    for raw_path, raw_tuples in obj.items():
        path = decode_path(raw_path)
        path_size = len(path.encode("utf-8", "strict"))
        if path_size > max_path_bytes:
            raise pickle.UnpicklingError(f"archive path is {path_size} bytes; limit is {max_path_bytes}")
        comparison_path = unicodedata.normalize("NFD", path).casefold()
        if not isinstance(raw_tuples, (list, tuple)):
            raise pickle.UnpicklingError(f"entry {path!r} does not contain a tuple list")

        items = []
        for value in raw_tuples:
            tuple_count += 1
            if tuple_count > max_tuples:
                raise pickle.UnpicklingError(f"archive index has more than {max_tuples} tuples")
            if not isinstance(value, (list, tuple)) or len(value) not in (2, 3):
                raise pickle.UnpicklingError(f"entry {path!r} contains an invalid tuple")
            offset, length = value[0], value[1]
            if type(offset) is not int or type(length) is not int or offset < 0 or length < 0:
                raise pickle.UnpicklingError(f"entry {path!r} has invalid offset or length")
            item = {"offset": offset, "length": length}
            if len(value) == 3:
                prefix = value[2]
                if isinstance(prefix, str):
                    prefix = prefix.encode("latin-1", "strict")
                elif isinstance(prefix, bytearray):
                    prefix = bytes(prefix)
                elif not isinstance(prefix, bytes):
                    raise pickle.UnpicklingError(f"entry {path!r} has invalid prefix type")
                if len(prefix) > max_prefix_bytes:
                    raise pickle.UnpicklingError(
                        f"entry {path!r} prefix is {len(prefix)} bytes; limit is {max_prefix_bytes}"
                    )
                item["prefix"] = prefix.hex()
            items.append(item)

        if not first:
            sys.stdout.write("\n")
        first = False
        sys.stdout.write(json.dumps(
            {"path": path, "comparison_path": comparison_path, "tuples": items},
            separators=(",", ":")
        ))
except Exception as error:
    print("ERROR:", error, file=sys.stderr)
    sys.exit(1)
"#;

    let arguments = [
        MAX_INDEX_PATHS.to_string(),
        MAX_INDEX_TUPLES.to_string(),
        MAX_INDEX_PATH_BYTES.to_string(),
        MAX_PREFIX_BYTES.to_string(),
    ];
    let output = run_python_script(
        script,
        &arguments,
        pickle_bytes,
        PICKLE_HELPER_TIMEOUT,
        MAX_HELPER_OUTPUT_BYTES,
    )?;
    if !output.status.success() {
        return Err(RenpyExError::External {
            tool: "python".into(),
            message: format!(
                "python pickle helper exited with status {}\nstderr: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            ),
        });
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut entries: Vec<RpaEntry> = Vec::new();
    let mut decoded_paths = std::collections::BTreeSet::new();
    let mut path_count = 0usize;
    let mut tuple_count = 0usize;
    for line in stdout.lines() {
        if line.is_empty() {
            continue;
        }
        path_count = path_count
            .checked_add(1)
            .ok_or_else(|| RenpyExError::Integrity {
                message: format!("{}: RPA path count overflow", path.display()),
            })?;
        if path_count > MAX_INDEX_PATHS {
            return Err(RenpyExError::Integrity {
                message: format!(
                    "{}: RPA index exceeds the {MAX_INDEX_PATHS}-path limit",
                    path.display()
                ),
            });
        }
        let parsed: ParsedIndexLine =
            parse_json_line(line).map_err(|e| RenpyExError::External {
                tool: "python".into(),
                message: format!("failed to parse helper output: {e}; line={line}"),
            })?;
        if parsed.path.len() > MAX_INDEX_PATH_BYTES {
            return Err(RenpyExError::Integrity {
                message: format!(
                    "{}: RPA path is {} bytes; limit is {MAX_INDEX_PATH_BYTES}",
                    path.display(),
                    parsed.path.len()
                ),
            });
        }
        // Windows paths are case-insensitive, while default macOS filesystems
        // are also Unicode-normalization-insensitive. NFD + casefold is a
        // conservative common key computed by Python's versioned Unicode
        // database; Linux retains byte-distinct UTF-8 path semantics.
        #[cfg(any(windows, target_os = "macos"))]
        let comparison_path = &parsed.comparison_path;
        #[cfg(not(any(windows, target_os = "macos")))]
        let comparison_path = &parsed.path;
        if !decoded_paths.insert(comparison_path.clone()) {
            return Err(RenpyExError::Integrity {
                message: format!(
                    "{}: filesystem-equivalent decoded archive path collision for {:?}",
                    path.display(),
                    parsed.path
                ),
            });
        }
        for tup in &parsed.tuples {
            tuple_count = tuple_count
                .checked_add(1)
                .ok_or_else(|| RenpyExError::Integrity {
                    message: format!("{}: RPA tuple count overflow", path.display()),
                })?;
            if tuple_count > MAX_INDEX_TUPLES {
                return Err(RenpyExError::Integrity {
                    message: format!(
                        "{}: RPA index exceeds the {MAX_INDEX_TUPLES}-tuple limit",
                        path.display()
                    ),
                });
            }
            let off_raw = tup.offset;
            let len_raw = tup.length;
            let prefix_vec = tup.prefix.as_deref().map(decode_hex_bytes).transpose()?;

            let mut off = off_raw;
            let mut len = len_raw;
            if version == RpaVersion::V3 {
                let key = user_key.unwrap_or(archive_key);
                off ^= key as u64;
                len ^= key as u64;
            }

            if off > i64::MAX as u64 || len > i64::MAX as u64 {
                return Err(RenpyExError::Integrity {
                    message: format!(
                        "{}: entry {:?} exceeds supported offset/length range",
                        path.display(),
                        parsed.path
                    ),
                });
            }

            entries.push(RpaEntry {
                path: parsed.path.clone(),
                offset: Offset::new(off),
                length: Length::new(len),
                prefix: prefix_vec,
            });
        }
    }
    Ok(entries)
}

fn parse_json_line(s: &str) -> std::result::Result<ParsedIndexLine, String> {
    serde_json::from_str::<ParsedIndexLine>(s).map_err(|e| e.to_string())
}

fn decode_hex_bytes(value: &str) -> Result<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return Err(RenpyExError::External {
            tool: "python".into(),
            message: format!("pickle helper returned odd-length prefix hex: {value:?}"),
        });
    }
    if value.len() / 2 > MAX_PREFIX_BYTES {
        return Err(RenpyExError::External {
            tool: "python".into(),
            message: format!(
                "pickle helper returned a {}-byte prefix; limit is {MAX_PREFIX_BYTES}",
                value.len() / 2
            ),
        });
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = hex_nibble(pair[0]).ok_or_else(|| RenpyExError::External {
            tool: "python".into(),
            message: format!("pickle helper returned invalid prefix hex: {value:?}"),
        })?;
        let low = hex_nibble(pair[1]).ok_or_else(|| RenpyExError::External {
            tool: "python".into(),
            message: format!("pickle helper returned invalid prefix hex: {value:?}"),
        })?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn ascii_lossy(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| {
            if (0x20..0x7F).contains(b) {
                *b as char
            } else {
                '?'
            }
        })
        .collect()
}

/// Compute SHA-256 of a single entry's bytes (used by CLI to report).
pub fn entry_sha256(archive: &Path, entry: &RpaEntry) -> Result<[u8; 32]> {
    let bytes = read_entry(archive, entry)?;
    Ok(sha256(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixtures;

    fn write_collision_archive(path: &Path, mode: &str) {
        let script = r#"
import pickle, sys, zlib
mode = sys.argv[2]
if mode == "case":
    entries = [("Case.txt", b"UPPER"), ("case.txt", b"lower")]
elif mode == "normalization":
    entries = [("a//b.txt", b"double"), ("a/b.txt", b"single")]
elif mode == "single":
    entries = [("keyed.txt", b"official-key")]
elif mode == "encoding_collision":
    entries = [("café.txt", b"unicode"), (b"caf\xc3\xa9.txt", b"bytes")]
elif mode == "unicode_normalization_collision":
    entries = [("café.txt", b"composed"), ("cafe\u0301.txt", b"decomposed")]
elif mode == "legacy":
    payload = b"legacy"
    pickle_data = b"\x80\x02}q\x00U\x08caf\xe9.txtq\x01]q\x02K\x18K\x06\x86q\x03as."
    header = f"RPA-2.0 {24 + len(payload):016x}".encode("ascii")
    assert len(header) == 24
    open(sys.argv[1], "wb").write(header + payload + zlib.compress(pickle_data))
    sys.exit(0)
elif mode == "py2_bytes_prefix":
    # Protocol 2 on Python 3 encodes the bytes prefix through the
    # `_codecs.encode` global; the helper must accept exactly this global.
    payload = b"tail"
    key = 0x42424242
    index = {"prefixed.bin": [(34 ^ key, len(payload) ^ key, b"head-")]}
    pickle_data = pickle.dumps(index, protocol=2)
    header = f"RPA-3.0 {34 + len(payload):016x} {key:08x}\n".encode("ascii")
    assert len(header) == 34
    open(sys.argv[1], "wb").write(header + payload + zlib.compress(pickle_data))
    sys.exit(0)
else:
    raise ValueError(mode)
key = 0x42424242
offset = 34
body = bytearray()
index = {}
for name, payload in entries:
    index[name] = [(offset ^ key, len(payload) ^ key)]
    body.extend(payload)
    offset += len(payload)
header = f"RPA-3.0 {offset:016x} {key:08x}\n".encode("ascii")
assert len(header) == 34
protocol = 4 if mode in ("encoding_collision", "unicode_normalization_collision") else 2
open(sys.argv[1], "wb").write(header + body + zlib.compress(pickle.dumps(index, protocol=protocol)))
"#;
        let status = std::process::Command::new(if cfg!(windows) { "python" } else { "python3" })
            .arg("-c")
            .arg(script)
            .arg(path)
            .arg(mode)
            .status()
            .expect("launch Python fixture builder");
        assert!(status.success(), "Python fixture builder failed");
    }

    fn assert_collision_is_rejected_before_writes(mode: &str) {
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("collision.rpa");
        let output = temp.path().join("output");
        write_collision_archive(&archive, mode);

        let error = extract_rpa(&archive, &output, None).expect_err("collision must fail");
        assert!(error.to_string().contains("collision"), "{error}");
        assert!(
            !output.exists() || std::fs::read_dir(&output).unwrap().next().is_none(),
            "collision preflight left partial output"
        );
    }

    #[test]
    fn detect_v3_magic() {
        let buf = b"RPA-3.0 0000000000000100 00000000 \n";
        assert_eq!(detect_version(buf), Some(RpaVersion::V3));
    }

    #[test]
    fn detect_v2_magic() {
        let buf = b"RPA-2.0 0000000000000100abc";
        assert_eq!(detect_version(buf), Some(RpaVersion::V2));
    }

    #[test]
    fn detect_rejects_non_rpa() {
        assert_eq!(detect_version(b"PK\x03\x04zip..."), None);
    }

    #[test]
    fn safe_join_blocks_traversal() {
        let root = PathBuf::from("/tmp/out");
        assert!(output::safe_join(&root, "../../etc/passwd").is_err());
        assert!(output::safe_join(&root, "sub/../escape").is_err());
        let ok = output::safe_join(&root, "images/bg.png").unwrap();
        assert!(ok.starts_with("/tmp/out"));
    }

    #[test]
    fn safe_join_rejects_nul() {
        let root = PathBuf::from("/tmp/out");
        assert!(output::safe_join(&root, "ab\0cd").is_err());
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[test]
    fn extraction_rejects_case_collisions_before_writing() {
        assert_collision_is_rejected_before_writes("case");
    }

    #[test]
    fn extraction_rejects_normalized_path_collisions_before_writing() {
        assert_collision_is_rejected_before_writes("normalization");
    }

    #[test]
    fn extraction_rejects_paths_that_decode_to_the_same_string() {
        assert_collision_is_rejected_before_writes("encoding_collision");
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[test]
    fn extraction_rejects_unicode_normalization_collisions_before_writing() {
        assert_collision_is_rejected_before_writes("unicode_normalization_collision");
    }

    #[test]
    fn user_key_replaces_header_key_for_nonstandard_archives() {
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("keyed.rpa");
        write_collision_archive(&archive, "single");

        let listed = list_rpa(&archive, Some(0x4242_4242)).unwrap();
        assert_eq!(listed.entries.len(), 1);
        assert_eq!(
            read_entry(&archive, &listed.entries[0]).unwrap(),
            b"official-key"
        );
    }

    #[test]
    fn rpa2_python2_latin1_path_is_materialized() {
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("legacy.rpa");
        write_collision_archive(&archive, "legacy");

        let listed = list_rpa(&archive, None).unwrap();
        assert_eq!(listed.entries[0].path, "café.txt");
        assert_eq!(read_entry(&archive, &listed.entries[0]).unwrap(), b"legacy");
    }

    #[test]
    fn protocol2_bytes_prefix_round_trips_through_codec_global() {
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("py2-prefix.rpa");
        write_collision_archive(&archive, "py2_bytes_prefix");

        let listed = list_rpa(&archive, None).unwrap();
        assert_eq!(listed.entries[0].path, "prefixed.bin");
        assert_eq!(
            read_entry(&archive, &listed.entries[0]).unwrap(),
            b"head-tail",
            "protocol-2 bytes prefix must decode via the allowlisted codec global"
        );
    }

    #[test]
    fn compressed_index_limit_is_checked_before_allocation() {
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("oversized-index.rpa");
        let mut file = std::fs::File::create(&archive).unwrap();
        file.write_all(b"RPA-3.0 0000000000000022 00000000\n")
            .unwrap();
        file.set_len(34 + MAX_COMPRESSED_INDEX_BYTES + 1).unwrap();
        drop(file);

        let error = list_rpa(&archive, None).expect_err("oversized index must fail");
        assert!(
            error.to_string().contains("compressed RPA index"),
            "{error}"
        );
    }

    #[test]
    fn decompressed_index_reader_stops_at_limit() {
        use flate2::Compression;
        use flate2::write::ZlibEncoder;

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&[b'x'; 65]).unwrap();
        let compressed = encoder.finish().unwrap();
        let error = decompress_index(&compressed, Path::new("bomb.rpa"), 64)
            .expect_err("decompression limit must fail");
        assert!(error.to_string().contains("64-byte limit"), "{error}");
    }

    #[test]
    fn read_entry_rejects_large_allocation_and_points_to_streaming_api() {
        let entry = RpaEntry {
            path: "large.bin".into(),
            offset: Offset::new(0),
            length: Length::new(MAX_IN_MEMORY_ENTRY_BYTES + 1),
            prefix: None,
        };

        let error = validate_in_memory_entry_size(Path::new("large.rpa"), &entry)
            .expect_err("large allocation must fail");
        assert!(error.to_string().contains("use extract_rpa"), "{error}");
    }

    #[test]
    fn python_helper_stdout_is_bounded() {
        let error = run_python_script(
            "import sys; sys.stdout.write('x' * 4096)",
            &[],
            &[],
            Duration::from_secs(5),
            64,
        )
        .expect_err("oversized helper output must fail");
        assert!(error.to_string().contains("64-byte limit"), "{error}");
    }

    #[test]
    fn python_helper_timeout_terminates_child() {
        let started = std::time::Instant::now();
        let error = run_python_script(
            "import time; time.sleep(60)",
            &[],
            &[],
            Duration::from_millis(100),
            64,
        )
        .expect_err("sleeping helper must time out");
        assert!(error.to_string().contains("timeout"), "{error}");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "timed-out helper was not terminated promptly"
        );
    }

    #[test]
    fn length_preserves_zero_entry() {
        let zero = Length::new(0);
        assert_eq!(zero.get(), 0);
        let ok = Length::new(128);
        assert_eq!(ok.get(), 128);
    }

    #[test]
    fn offset_new_preserves_archived_value() {
        let huge = Offset::new(u64::MAX);
        assert_eq!(huge.get(), u64::MAX);
    }

    #[test]
    fn rpa3_fixture_byte_perfect_extraction() {
        let archive = test_fixtures::rpa_v3_fixture_path();
        assert!(archive.is_file(), "fixture missing: {}", archive.display());
        let listed = list_rpa(&archive, None).expect("list ok");
        // Every entry must be byte-perfect, byte-for-byte, against the
        // expected payload committed alongside the fixture.
        let expected: &[(&str, &[u8])] = &[
            ("greeting.txt", b"hello renpyex!\n"),
            ("readme.md", b"# embedded file\n\nByte-perfect payload.\n"),
            ("short.txt", b"ok"),
        ];
        for (path, want) in expected {
            let sample = listed
                .entries
                .iter()
                .find(|e| e.path == *path)
                .unwrap_or_else(|| panic!("{path} missing from archive listing"));
            let bytes = read_entry(&archive, sample).unwrap_or_else(|e| panic!("read {path}: {e}"));
            assert_eq!(&bytes[..], *want, "byte-perfect mismatch for {path}");
        }
        // image_bytes.bin is a deterministic 0..255 sequence; verify it.
        let img = listed
            .entries
            .iter()
            .find(|e| e.path == "image_bytes.bin")
            .expect("image_bytes.bin missing");
        let bytes = read_entry(&archive, img).expect("read image_bytes.bin");
        let want: Vec<u8> = (0..=255u8).collect();
        assert_eq!(bytes, want, "image_bytes.bin should be 0..=255");

        let temp = tempfile::tempdir().unwrap();
        extract_rpa(&archive, temp.path(), None).unwrap();
        assert_eq!(
            std::fs::read(temp.path().join("fragmented.txt")).unwrap(),
            b"fragment-one-fragment-two"
        );
        assert_eq!(
            std::fs::read(temp.path().join("prefixed.txt")).unwrap(),
            b"prefix-tail"
        );
    }

    #[test]
    fn rpa3_fixture_extracted_sha_matches_source_sha() {
        // Critical property: extracting a file yields bytes whose own
        // SHA-256 equals the SHA-256 we would compute on the byte range
        // [offset, offset+length) of the source archive file directly.
        use std::io::{Read, Seek};
        let archive = test_fixtures::rpa_v3_fixture_path();
        assert!(archive.is_file(), "fixture missing: {}", archive.display());
        let listed = list_rpa(&archive, None).expect("list ok");
        let mut file = std::fs::File::open(&archive).expect("open");
        for e in listed.entries.iter().take(3) {
            let mut src = vec![0u8; e.length.get() as usize];
            file.seek(std::io::SeekFrom::Start(e.offset.get()))
                .expect("seek");
            file.read_exact(&mut src).expect("read source slice");
            let bytes = read_entry(&archive, e).expect("read entry");
            assert_eq!(
                sha256(&bytes),
                sha256(&src),
                "extracted bytes do not match source byte range for {}",
                e.path
            );
        }
    }
}
