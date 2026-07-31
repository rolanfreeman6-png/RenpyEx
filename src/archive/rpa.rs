//! RPA-3.0 / RPA-2.0 archive parser.
//!
//! ## Format
//!
//! Format reference: Ren'Py `loader.py` (sources cited inline).
//!
//! **RPAv3** header layout (40 bytes, ending with newline):
//! - 8 bytes: `b"RPA-3.0 "` (no leading space)
//! - 16 hex chars: offset to zlib-compressed pickled index
//! - 1 space
//! - 8 hex chars: XOR key applied to obfuscate `(offset, dlen)` tuples
//! - trailing space + newline
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
//! Python pickle parsing is delegated to a small subprocess that emits one
//! JSON record per line. This isolates pickling's security risks in a
//! separate process and lets us re-use Python's battle-tested pickling.

use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use flate2::read::ZlibDecoder;

use crate::Result;
use crate::error::RenpyExError;
use crate::output;
use crate::verify::sha::sha256;

/// Magic prefix for RPA-3.0 archives (no leading space): exact 8 bytes
/// `b"RPA-3.0 "` per Ren'Py `loader.py:RPAv3ArchiveHandler.get_supported_headers`.
const RPA3_MAGIC: &[u8; 8] = b"RPA-3.0 ";

/// How many header bytes we peek when sniffing an archive.
const HEADER_PEEK: usize = 64;

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
    let off = entry.offset.get();
    let len = entry.length.get();
    let file_len = fs::metadata(archive)
        .map_err(|e| RenpyExError::io(archive, e))?
        .len();
    if off > file_len || len > file_len - off {
        return Err(RenpyExError::SizeMismatch {
            archive: archive.to_path_buf(),
            entry: entry.path.clone(),
            claimed: len,
            available: file_len.saturating_sub(off),
        });
    }
    let len_usize = usize::try_from(len).map_err(|_| RenpyExError::SizeMismatch {
        archive: archive.to_path_buf(),
        entry: entry.path.clone(),
        claimed: len,
        available: usize::MAX as u64,
    })?;
    let prefix_len = entry.prefix.as_ref().map_or(0, Vec::len);
    let capacity = prefix_len
        .checked_add(len_usize)
        .ok_or_else(|| RenpyExError::Integrity {
            message: format!("{}: entry output size overflow", archive.display()),
        })?;

    file.seek(std::io::SeekFrom::Start(off))
        .map_err(|e| RenpyExError::io(archive, e))?;

    let mut buf = Vec::with_capacity(len_usize);
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
    let mut full = Vec::with_capacity(capacity);
    if let Some(prefix) = &entry.prefix {
        full.extend_from_slice(prefix);
    }
    full.extend_from_slice(&buf);
    Ok(full)
}

/// Read and emit byte-perfect contents for every entry in the archive.
pub fn extract_rpa(archive: &Path, out_root: &Path, key: Option<u32>) -> Result<RpaExtracted> {
    let listed = list_rpa(archive, key)?;
    let mut grouped: std::collections::BTreeMap<String, Vec<&RpaEntry>> =
        std::collections::BTreeMap::new();
    for entry in &listed.entries {
        grouped.entry(entry.path.clone()).or_default().push(entry);
    }
    for (path, fragments) in grouped {
        let total =
            fragments.iter().try_fold(0usize, |acc, entry| {
                let prefix = entry.prefix.as_ref().map_or(0, Vec::len);
                let length =
                    usize::try_from(entry.length.get()).map_err(|_| RenpyExError::Integrity {
                        message: format!("{}: entry is too large", archive.display()),
                    })?;
                acc.checked_add(prefix.checked_add(length).ok_or_else(|| {
                    RenpyExError::Integrity {
                        message: format!("{}: entry size overflow", archive.display()),
                    }
                })?)
                .ok_or_else(|| RenpyExError::Integrity {
                    message: format!("{}: entry size overflow", archive.display()),
                })
            })?;
        let mut bytes = Vec::with_capacity(total);
        for entry in fragments {
            bytes.extend_from_slice(&read_entry(archive, entry)?);
        }
        let dest = safe_join(out_root, &path)?;
        write_bytes(&bytes, &dest)?;
    }
    Ok(listed)
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
    //   bytes 33..:   ' \n' (terminator)
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

    file.seek(std::io::SeekFrom::Start(offset))
        .map_err(|e| RenpyExError::io(path, e))?;

    let mut zlib_bytes = Vec::new();
    file.read_to_end(&mut zlib_bytes)
        .map_err(|e| RenpyExError::io(path, e))?;

    let mut decoder = ZlibDecoder::new(&zlib_bytes[..]);
    let mut pickle_bytes = Vec::new();
    decoder
        .read_to_end(&mut pickle_bytes)
        .map_err(|e| RenpyExError::io(path, e))?;

    parse_pickle_index(&pickle_bytes, archive_key, user_key, version, path)
}

#[derive(serde::Deserialize)]
struct ParsedIndexTuple {
    #[serde(default)]
    offset: Option<u64>,
    #[serde(default)]
    length: Option<u64>,
    #[serde(default)]
    prefix: Option<String>,
}

#[derive(serde::Deserialize)]
struct ParsedIndexLine {
    path: String,
    #[serde(default)]
    tuples: Vec<ParsedIndexTuple>,
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
import io, json, pickle, sys
data = sys.stdin.buffer.read()
class SafeUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        raise pickle.UnpicklingError("global objects are not permitted")
try:
    obj = SafeUnpickler(io.BytesIO(data)).load()
except Exception as e:
    print("ERROR:", e, file=sys.stderr)
    sys.exit(1)
out = []
for k, v in obj.items():
    items = []
    for t in v:
        if isinstance(t, (list, tuple)):
            if len(t) == 2:
                items.append({"offset": int(t[0]), "length": int(t[1])})
            else:
                pfx = t[2]
                if isinstance(pfx, str):
                    pfx = pfx.encode('latin-1')
                items.append({"offset": int(t[0]), "length": int(t[1]), "prefix": pfx.hex()})
        else:
            items.append({"offset": int(t[0]), "length": int(t[1])})
    out.append({"path": str(k), "tuples": items})
sys.stdout.write('\n'.join(json.dumps(r) for r in out))
"#;

    let mut cmd = std::process::Command::new(if cfg!(windows) { "python" } else { "python3" });
    cmd.arg("-c")
        .arg(script)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| RenpyExError::External {
        tool: "python".into(),
        message: format!("failed to launch: {e}"),
    })?;
    let mut stdin = child.stdin.take().ok_or_else(|| RenpyExError::External {
        tool: "python".into(),
        message: "failed to open helper stdin".into(),
    })?;
    stdin
        .write_all(pickle_bytes)
        .map_err(|e| RenpyExError::External {
            tool: "python".into(),
            message: format!("failed to send pickle index: {e}"),
        })?;
    drop(stdin);
    let output = child
        .wait_with_output()
        .map_err(|e| RenpyExError::External {
            tool: "python".into(),
            message: format!("failed to collect helper output: {e}"),
        })?;
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
    for line in stdout.lines() {
        if line.is_empty() {
            continue;
        }
        let parsed: ParsedIndexLine =
            parse_json_line(line).map_err(|e| RenpyExError::External {
                tool: "python".into(),
                message: format!("failed to parse helper output: {e}; line={line}"),
            })?;
        for tup in &parsed.tuples {
            let off_raw = tup.offset.unwrap_or(0);
            let len_raw = tup.length.unwrap_or(0);
            let prefix_vec = tup.prefix.as_deref().map(decode_hex_bytes).transpose()?;

            let mut off = off_raw;
            let mut len = len_raw;
            if version == RpaVersion::V3 {
                let key = match user_key {
                    Some(k) => k ^ archive_key,
                    None => archive_key,
                };
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

/// Write bytes to a path atomically (creates parent dirs as needed).
fn write_bytes(bytes: &[u8], dest: &Path) -> Result<()> {
    output::write_atomic(dest, bytes)
}

/// Join `out_root` and `rel_path`, sanitising to forbid any `..` traversal
/// outside the output root.
fn safe_join(out_root: &Path, rel_path: &str) -> Result<PathBuf> {
    let mut joined = out_root.to_path_buf();
    let normalised = rel_path.replace('\\', "/");
    if normalised.starts_with('/') || normalised.starts_with("//") {
        return Err(RenpyExError::PathTraversal {
            archive: out_root.to_path_buf(),
            entry: rel_path.to_string(),
        });
    }
    for piece in normalised.split('/').filter(|s| !s.is_empty()) {
        match piece {
            "." => continue,
            ".." => {
                return Err(RenpyExError::PathTraversal {
                    archive: out_root.to_path_buf(),
                    entry: rel_path.to_string(),
                });
            }
            _ => {
                if piece.contains('\0') {
                    return Err(RenpyExError::Invalid(format!(
                        "NUL byte in path component {piece:?}"
                    )));
                }
                let mut bad = piece
                    .chars()
                    .find(|c| matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*'));
                if let Some(c) = bad.take() {
                    return Err(RenpyExError::Invalid(format!(
                        "forbidden character {c:?} in {piece:?}"
                    )));
                }
                joined.push(piece);
            }
        }
    }
    Ok(joined)
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

// (phantom marker; reserved for future cross-checks)
#[allow(dead_code)]
const _: () = ();

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixtures;

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
        assert!(safe_join(&root, "../../etc/passwd").is_err());
        assert!(safe_join(&root, "sub/../escape").is_err());
        let ok = safe_join(&root, "images/bg.png").unwrap();
        assert!(ok.starts_with("/tmp/out"));
    }

    #[test]
    fn safe_join_rejects_nul() {
        let root = PathBuf::from("/tmp/out");
        assert!(safe_join(&root, "ab\0cd").is_err());
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
        if !archive.exists() {
            return; // fixture absent — fixture is generated by tests/build_fixtures.sh
        }
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
        if !archive.exists() {
            return;
        }
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
