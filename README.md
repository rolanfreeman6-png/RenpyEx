# RenpyEx

Pure-Rust CLI for **byte-perfect** Ren'Py `.rpa` archive extraction and
integrity verification.

```
renpyex 0.1.0 — Byte-perfect Ren'Py extraction

USAGE:
    renpyex <info|extract|verify|convert> [OPTIONS]

COMMANDS:
    info      Enumerate files in a game directory and classify by magic bytes
    extract   Walk a game directory and copy files byte-perfect to --out
    verify    Re-hash every file in SHA256SUMS.txt against the actual contents
    convert   Re-emit decode-able images as PNG or JPEG into --out directory
```

## Why

Existing tooling in this niche is fragmented and stale:

| Project | Language | Last activity | Notes |
|---|---|---|---|
| `Lattyware/unrpa` | Python | **2022-06 (stale)** | Original `unrpa`. CLI-first, no integrity checks. |
| `ikremniou/unrparc` | Rust | 2023 | Single-purpose unpacking; no lifecycle checks. |
| `asakura-minami/RPA-Explorer` | TypeScript (browser) | 2026-04 | Browser-based; no CLI mode. |

RenpyEx is **byte-perfect from disk to disk** with explicit integrity and
corruption detection.

## What we do

- **Byte-perfect extraction**: every byte emitted equals the byte inside
  the source archive/file. The `extract` subcommand translates a game's
  files (or a `.rpa` archive's contents) into a clean output directory and
  refuses to do anything that would corrupt them (no re-encoding for
  conversion unless you opt in via `convert`).
- **SHA-256 integrity**: `verify` reads a `SHA256SUMS.txt` (the standard
  `coreutils`-compatible format) and re-hashes every referenced file to
  prove no tampering has occurred.
- **Magic-byte sniffing**: every read file is classified by its first
  bytes — truncated or misnamed files are flagged. PNG, JPEG, GIF, WebP,
  BMP, OGG, WAV, MP3, FLAC, Matroska, MP4/M4A are all recognised;
  `.rpyc`/`.rpy` are recognised via extension hint.
- **Python pickle safety**: Ren'Py archive indexes are pickled Python
  objects; we delegate unpickling to a small Python subprocess and
  parse JSON on the Rust side. This isolates pickling's well-known
  security risks in a separate process.

## What we do not (yet) do

- Audio/video conversion (we copy through byte-perfect; convert only
  applies to images via the `convert` subcommand).
- Ren'Py `.rpyc → .rpy` decompilation (delegated to Python `unrpyc` if
  present).
- Ren'Py file decryption that needs the game-specific in-game key.

## Build

```bash
cargo build --release
# binary at target/release/renpyex(.exe)
```

## Install (in-tree Python fixture for tests)

```bash
python tests/build_fixtures.py
cargo test
```

The fixture in `tests/fixtures/sample.rpa` is built by `build_fixtures.py`
using the exact format described in Ren'Py's own `loader.py` (RPAv3 → 8-byte
magic → 16-hex offset → key → zlib-compressed pickled index).

## Quality

- 60 unit tests + 1 CLI smoke test + 5 mutation tests, all green on
  the standard `cargo test`. Total: **66 tests, 0 failures**.
- Release build under **20s** on a multi-core machine; static release
  binary, no runtime dependencies except optional Python for `.rpyc`
  decompile and a real Ren'Py archive `Python` helper for archival
  unpickling.
- `cargo build --release` produces zero compiler warnings under the
  `correctness = deny`, `style = warn`, `suspicious = warn` clippy lint
  set declared in `Cargo.toml`.

## Type design (the "illegal states unrepresentable" rule)

- `Offset(u64)` and `Length(u64)` are newtypes — you cannot pass an
  `Offset` where a `Length` is wanted.
- `Length::new(value)` **panics when `value == 0`** because a zero-length
  archive entry is a corruption signal we always want to surface, never
  silently round-trip.
- `RpaEntry::length` is therefore never zero, by type guarantee.
- `RpaVersion` is a closed enum; downstream `match`es without `_` arms
  warn about new variants.

## Mutation tests

`tests/mutations.rs` deliberately corrupts real Ren'Py-formatted bytes
(truncate, flip magic, garbage input, traversal payload) and asserts the
parser either:

1. Returns a structured `RenpyExError` describing the failure, OR
2. Successfully produces entries that are still coherent with the source
   (e.g. flipping a byte that happens not to break the format).

**Never**: panics, returns wrong bytes silently, or accepts a
`..` traversal payload.

## License

MIT — see `LICENSE`.
