//! Key detection from Ren'Py `options.rpy`.
//!
//! Ren'Py recognises archive encryption via a `key` variable in
//! `options.rpy` such as:
//!
//! ```python
//! init -1 python:
//!     config.key = "0123456789abcdef0123456789abcdef"
//! ```
//!
//! Or via `key64`, etc. We accept a hex string in the supported forms and
//! return the parsed key as a `u32` (RPAv3 keys are unsigned 32-bit XOR
//! values), or `None` if no key directive is found.

use std::path::Path;

/// Find a possible encryption key in an `options.rpy`/`options.rpyc` file.
///
/// `source` should be the verbatim text of the file (already decompiled if
/// it was a `.rpyc`). We do a generous regex search.
///
/// Ren'Py's archive key is a 32-bit unsigned XOR value. When users supply a
/// 64-bit hex key in `options.rpy`, we fold it down via `as u32`.
#[must_use]
pub fn detect_key_from_text(text: &str) -> Option<u32> {
    for word in keywords_with_strings(text) {
        let trimmed = word
            .strip_prefix("0x")
            .or_else(|| word.strip_prefix("0X"))
            .unwrap_or(word)
            .trim();
        if looks_like_hex(trimmed) {
            // Use u128 so 32-character hex keys fit; truncate to u32.
            if let Ok(v) = u128::from_str_radix(trimmed, 16) {
                return Some(v as u32);
            }
        }
    }
    None
}

/// Extract string literals that follow known key-related identifiers.
///
/// Yields raw content of strings — caller decides what to do with them.
fn keywords_with_strings(text: &str) -> Vec<&str> {
    // We accept:
    //   identifier '=' '"' <chars> '"'
    //   identifier '=' "'" <chars> "'"
    // Identifier candidates: config.key, key, config.crypto_key, arch_key.
    const TOKENS: &[&str] = &["config.key", "config.crypto_key", "arch_key"];

    let mut out = Vec::new();
    for token in TOKENS {
        let mut idx = 0;
        while let Some(pos) = text[idx..].find(token) {
            // Advance past the token.
            let abs = idx + pos + token.len();
            // Skip whitespace until '='.
            let after_eq = skip_ws_eq(&text[abs..]);
            let after_eq_abs = abs + after_eq;
            // Now expect a string literal.
            if let Some(s) = quoted_string(&text[after_eq_abs..]) {
                out.push(s);
            }
            idx = after_eq_abs + 1;
        }
    }
    out
}

/// Within `s`, return the length to advance past `identifier` and any
/// surrounding whitespace plus an `=` sign. Returns 0 if no `=` is found
/// within reasonable distance.
fn skip_ws_eq(s: &str) -> usize {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() && (bytes[i] as char).is_whitespace() {
        i += 1;
    }
    if i < bytes.len() && bytes[i] == b'=' {
        i += 1;
        while i < bytes.len() && (bytes[i] as char).is_whitespace() {
            i += 1;
        }
        return i;
    }
    0
}

/// If `s` starts with a quoted string, return its inner content.
fn quoted_string(s: &str) -> Option<&str> {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    let quote = bytes[0];
    if quote != b'"' && quote != b'\'' {
        return None;
    }
    let mut i = 1;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'\\' && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        if c == quote {
            return Some(&s[1..i]);
        }
        i += 1;
    }
    None
}

fn looks_like_hex(s: &str) -> bool {
    // Ren'Py key may be 8 or 16 (or 32 byte) hex chars. Accept any length
    // even number of hex digits, no NUL, bounded to a sane upper limit.
    if s.is_empty() || s.len() > 64 || s.len() % 2 != 0 {
        return false;
    }
    s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Try to read text from a file and then look for a key directive.
pub fn detect_key_in_file(path: &Path) -> std::io::Result<Option<u32>> {
    let text = std::fs::read_to_string(path)?;
    Ok(detect_key_from_text(&text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_config_key() {
        let s = r#"
init -1 python:
    config.key = "01234567"
"#;
        assert_eq!(detect_key_from_text(s), Some(0x01234567u32));
    }

    #[test]
    fn detects_short_hex() {
        let s = r#"config.key = "deadbeef""#;
        assert_eq!(detect_key_from_text(s), Some(0xdeadbeefu32));
    }

    #[test]
    fn detects_64bit_hex_truncates_low32() {
        // Long hex strings are truncated to lower 32 bits, matching
        // Ren'Py's own behaviour.
        let s = r#"config.key = "0123456789abcdef0123456789abcdef""#;
        assert_eq!(detect_key_from_text(s), Some(0x89abcdefu32));
    }

    #[test]
    fn returns_none_when_absent() {
        let s = "label start: pass";
        assert_eq!(detect_key_from_text(s), None);
    }

    #[test]
    fn ignores_non_hex_strings() {
        let s = r#"config.key = "hello world""#;
        assert_eq!(detect_key_from_text(s), None);
    }
}
