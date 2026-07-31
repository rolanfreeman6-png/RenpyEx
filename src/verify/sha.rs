//! SHA-256 digest helpers for byte-perfect integrity verification.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use sha2::{Digest, Sha256};

/// Compute SHA-256 of `data`.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// Compute SHA-256 from a reader using a fixed 64KiB buffer.
pub fn sha256_reader(reader: &mut impl Read) -> io::Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest);
    Ok(output)
}

/// Compute SHA-256 of a filesystem file without loading its complete contents.
pub fn sha256_file(path: &Path) -> io::Result<[u8; 32]> {
    let mut file = File::open(path)?;
    sha256_reader(&mut file)
}

/// Format `[u8; 32]` as lowercase hex.
#[must_use]
pub fn to_hex(sha: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for byte in sha {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

/// Parse 64-character hex back into 32-byte array.
///
/// Returns `None` for invalid input (length or non-hex character).
#[must_use]
pub fn from_hex(hex: &str) -> Option<[u8; 32]> {
    let bytes = hex.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = hex_nibble(bytes[2 * i])?;
        let lo = hex_nibble(bytes[2 * i + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

const fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(10 + b - b'a'),
        b'A'..=b'F' => Some(10 + b - b'A'),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_string_hash() {
        let h = sha256(b"");
        assert_eq!(
            to_hex(&h),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn known_string_hash() {
        let h = sha256(b"abc");
        assert_eq!(
            to_hex(&h),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hex_round_trip() {
        let h = sha256(b"hello");
        let s = to_hex(&h);
        let back = from_hex(&s).expect("valid hex");
        assert_eq!(h, back);
    }

    #[test]
    fn from_hex_rejects_garbage() {
        assert!(from_hex("00").is_none()); // too short
        assert!(from_hex(&"z".repeat(64)).is_none()); // non-hex
    }

    #[test]
    fn reader_hash_matches_in_memory_hash() {
        let mut data = std::io::Cursor::new(vec![0x5a; 100_000]);
        assert_eq!(sha256_reader(&mut data).unwrap(), sha256(&vec![0x5a; 100_000]));
    }
}
