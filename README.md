<div align="center">

# ⚔️ RenpyEx

**Ren'Py project doctor, extractor, verifier, and converter — Rust CLI/GUI with isolated Python index parsing.**

[![Release](https://img.shields.io/github/v/release/rolanfreeman6-png/RenpyEx?style=flat-square&color=ffd166)](https://github.com/rolanfreeman6-png/RenpyEx/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2024_edition-orange?style=flat-square&logo=rust)](https://www.rust-lang.org/)

*Inspect, extract, verify, and convert Ren'Py game assets — with byte-perfect
copy paths and explicit read-only health checks.*

[📥 Download](#-download) • [🚀 Quick start](#-quick-start) • [🖥️ GUI](#%EF%B8%8F-gui) • [🛠️ Build](#%EF%B8%8F-build-from-source) • [🧪 Quality](#-quality)

</div>

---

## ✨ Features

| | Feature | Description |
|---|---|---|
| 📦 | **Byte-perfect extraction** | Copy and RPA extraction paths preserve source payload bytes; conversion and decompilation remain explicit opt-ins |
| 🔐 | **SHA-256 integrity** | `verify` re-hashes every manifest entry, rejects extension/signature mismatches, and parses recognized image headers for dimensions |
| 🔍 | **Magic-byte sniffing** | PNG, JPEG, GIF, WebP, BMP, OGG, WAV, MP3, FLAC, Matroska, MP4/M4A are classified from bounded prefixes; this is not full audio/video decoding |
| 🖼️ | **Image conversion** | Opt-in `convert` re-emits decodable images as PNG or JPEG (quality-adjustable) |
| 🧠 | **Streaming SHA-256** | Verification, manifests, and duplicate checks process large files in fixed-size chunks |
| 🩺 | **Project Doctor** | Read-only JSON/text audit for media signatures, static asset paths, translation structure, duplicate media, and orphan candidates |
| 🧰 | **SDK adapter** | Shell-free adapter for the official Ren'Py `lint`, `compile`, `test`, `translate`, `dialogue`, and `distribute` commands |
| 🐍 | **Pickle safety** | Ren'Py archive indexes are pickled Python objects — unpickling is isolated in a separate Python subprocess, JSON-parsed on the Rust side |
| 🖥️ | **Native GUI** | Optional egui desktop front-end with a retro 16-bit RPG look and a translucent overlay window |

## 📥 Download

Grab the latest Windows binaries from the
[**Releases page**](https://github.com/rolanfreeman6-png/RenpyEx/releases/latest):

- `renpyex.exe` — command-line tool
- `renpyex-gui.exe` — desktop GUI

No installer is required. Python 3 is required for `.rpa` unpacking because
Ren'Py stores archive indexes as Python pickles; optional `.rpyc` decompilation
also requires a compatible `unrpyc` script or executable.

## 🚀 Quick start

```text
renpyex 0.2.1 — Ren'Py project health and extraction

USAGE:
    renpyex <info|extract|verify|convert|doctor|sdk> [OPTIONS]

COMMANDS:
    info      Enumerate files in a game directory and classify by magic bytes
    extract   Walk a game directory and copy files byte-perfect to --out
    verify    Re-hash every file in SHA256SUMS.txt against the actual contents
    convert   Re-emit decode-able images as PNG or JPEG into --out directory
    doctor    Read-only health report for assets, media, translations, and duplicates
    sdk       Run an official SDK action with an explicit SDK directory
```

```bash
# Inventory a game directory
renpyex info "C:/Games/MyVN"

# Extract everything byte-perfect (unpack .rpa archives too)
renpyex extract "C:/Games/MyVN" --out ./extracted --rpa

# Replace an existing output directory
renpyex extract "C:/Games/MyVN" --out ./extracted --rpa --overwrite

# Prove the extraction is intact
renpyex verify ./extracted

# Read-only health report (JSON is suitable for CI)
renpyex doctor "C:/Games/MyVN" --json > doctor.json

# Optional decompile into the output tree, never next to the source game
renpyex extract "C:/Games/MyVN" --out ./extracted --rpyc --python python --unrpyc unrpyc.py

# Run official Ren'Py lint without shell interpolation
renpyex sdk "C:/Games/MyVN" --sdk "C:/renpy-sdk" lint --all-problems

# Re-emit images as PNG
renpyex convert ./extracted --out ./png --to png
```

## 🖥️ GUI

`renpyex-gui.exe` is a native desktop front-end — a thin egui/eframe layer
over the same library API the CLI uses, so the core
extraction/verification/conversion code stays the single source of truth.

- 🎨 **Retro 16-bit console-RPG theme** — deep royal-blue panels, gold
  headings, light-periwinkle borders, hand-painted steel buttons with a
  semi-glossy convex bevel
- 🪟 **Translucent overlay window** — borderless, blended with your desktop
  at the OS level (`WS_EX_LAYERED`); drag the toolbar to move, double-click
  it to maximize, 🗕/❌ buttons top-right
- ⚙️ **Five local operations** — Scan / Extract / Verify / Convert / Doctor,
  path pickers, `.rpa` unpacking, optional `.rpyc` decompile, XOR key entry,
  and a JPEG quality slider; SDK commands remain CLI-only
- 🧵 **Background execution** — the status bar receives live progress events;
  the complete color-coded terminal log is appended when the operation ends
- 💾 **Remembers your paths** — persisted to `%APPDATA%\renpyex\config.json`
  (Windows) or `$XDG_CONFIG_HOME/renpyex/config.json` (Linux/macOS)

## 🛠️ Build from source

Rust 1.95 or newer is required. Python 3 is required to regenerate fixtures
and to run RPA extraction tests.

```bash
# CLI (lean — no GUI dependencies)
cargo build --release
# → target/release/renpyex(.exe)

# GUI
cargo build --release --features gui --bin renpyex-gui
# → target/release/renpyex-gui(.exe)

# Headless GUI smoke check (no window; for CI on displayless machines)
renpyex-gui --probe
```

The default `cargo build` / `cargo test` do **not** compile the GUI stack,
so the core CLI stays lean.

### Runtime limits and manifest format

RPA parsing applies explicit resource limits: 64 MiB compressed and 128 MiB
decompressed indexes, 1,000,000 paths, 2,000,000 chunks, 4,096 UTF-8 bytes per
path, and 16 MiB per inline prefix. The pickle helper has a 120-second timeout
(10 seconds for its startup preflight), with stdout/stderr capped at
256 MiB/1 MiB. Archive payload extraction is streamed; the library's direct
in-memory single-entry API is capped at 512 MiB.

SDK commands default to `--timeout 1800` seconds and cap stdout and stderr at
16 MiB each. On timeout RenpyEx terminates the launched process group/tree and
returns an error.

`SHA256SUMS.txt` uses a deliberately portable UTF-8 subset: normalized relative
paths with `/` separators and standard 64-hex SHA-256 records. Absolute paths,
traversal, exact duplicates, file/directory conflicts, case-only aliases on
Windows/macOS, Unicode-normalization aliases in RPA indexes on those targets,
empty/dot/repeated components, and escaped or non-UTF filenames are rejected.
It is not a complete implementation of coreutils filename escaping. Extraction
reserves the output root's `SHA256SUMS.txt` for its generated manifest and
rejects an input that would map to that path before creating or clearing the
output directory.

### Test fixtures

```bash
python tests/build_fixtures.py
cargo test
```

The fixture in `tests/fixtures/sample.rpa` is built by `build_fixtures.py`
using the exact format described in Ren'Py's own `loader.py` (RPAv3 → 8-byte
magic → 16-hex offset → key → zlib-compressed pickled index).

## 🧪 Quality

- ✅ **Release gates**: deterministic fixture regeneration, repository-wide
  rustfmt, all-target/all-feature tests, clippy with warnings denied, release
  builds, and CLI/GUI probes
- 🌐 **Cross-platform CI**: the same tests and release builds run on current
  GitHub-hosted Windows, Linux, and macOS images
- 🧬 **Adversarial coverage**: tests exercise official RPA2/RPA3 layouts,
  nonzero XOR keys, legacy names, fragments, resource boundaries, traversal,
  destination collisions, partial failures, process timeouts, and deterministic
  Doctor JSON
- 🚫 **Clippy warnings denied** under `correctness`, `style`, `complexity`,
  and `suspicious` across the library, CLI, GUI, and tests
- 🔒 **`unsafe` locked down**: denied crate-wide; the single exception is
  the GUI's documented Win32 layered-window setup
- 🧱 **Explicit archive invariants**: `Offset(u64)` / `Length(u64)` newtypes
  cannot be swapped; parser bounds checks reject unsupported offsets/lengths;
  `RpaVersion` is a closed enum

## 🗺️ Comparison

| Project | Language | Notes |
|---|---|---|
| **RenpyEx** | 🦀 Rust | Byte-perfect, integrity-checked, CLI + GUI |
| [`Lattyware/unrpa`](https://github.com/Lattyware/unrpa) | 🐍 Python | Original `unrpa`; CLI-only, no integrity checks, stale since 2022 |
| [`ikremniou/unrparc`](https://github.com/ikremniou/unrparc) | 🦀 Rust | Single-purpose unpacking, no lifecycle checks |
| [`asakura-minami/RPA-Explorer`](https://github.com/asakura-minami/RPA-Explorer) | 🌐 TypeScript | Browser-based, no CLI mode |

## 🚧 Out of scope (for now)

- Audio/video conversion — everything is copied through byte-perfect;
  `convert` only re-encodes images, and only when you ask it to
- `.rpyc → .rpy` decompilation is delegated to Python
  [`unrpyc`](https://github.com/CensoredUsername/unrpyc) when present
- Game-specific in-game decryption keys

## 📄 License

[MIT](LICENSE)
