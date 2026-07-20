<div align="center">

# ⚔️ RenpyEx

**Byte-perfect Ren'Py archive extractor & integrity verifier — pure Rust.**

[![Release](https://img.shields.io/github/v/release/rolanfreeman6-png/RenpyEx?style=flat-square&color=ffd166)](https://github.com/rolanfreeman6-png/RenpyEx/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2024_edition-orange?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![Tests](https://img.shields.io/badge/tests-67_passing-brightgreen?style=flat-square)](#-quality)

*Extract, verify, and convert Ren'Py game assets — with a guarantee that
every byte out equals every byte in.*

[📥 Download](#-download) • [🚀 Quick start](#-quick-start) • [🖥️ GUI](#%EF%B8%8F-gui) • [🛠️ Build](#%EF%B8%8F-build-from-source) • [🧪 Quality](#-quality)

</div>

---

## ✨ Features

| | Feature | Description |
|---|---|---|
| 📦 | **Byte-perfect extraction** | Every emitted byte equals the byte inside the source archive — no silent re-encoding, ever |
| 🔐 | **SHA-256 integrity** | `verify` re-hashes every file against a `SHA256SUMS.txt` (coreutils-compatible format) to prove nothing was tampered with |
| 🔍 | **Magic-byte sniffing** | PNG, JPEG, GIF, WebP, BMP, OGG, WAV, MP3, FLAC, Matroska, MP4/M4A recognised by their first bytes; truncated or misnamed files get flagged |
| 🖼️ | **Image conversion** | Opt-in `convert` re-emits decodable images as PNG or JPEG (quality-adjustable) |
| 🐍 | **Pickle safety** | Ren'Py archive indexes are pickled Python objects — unpickling is isolated in a separate Python subprocess, JSON-parsed on the Rust side |
| 🖥️ | **Native GUI** | Optional egui desktop front-end with a retro 16-bit RPG look and a translucent overlay window |

## 📥 Download

Grab the latest Windows binaries from the
[**Releases page**](https://github.com/rolanfreeman6-png/RenpyEx/releases/latest):

- `renpyex.exe` — command-line tool
- `renpyex-gui.exe` — desktop GUI

No installer, no runtime dependencies. Python is only needed if you want
optional `.rpyc` decompilation (via `unrpyc`).

## 🚀 Quick start

```text
renpyex 0.1.0 — Byte-perfect Ren'Py extraction

USAGE:
    renpyex <info|extract|verify|convert> [OPTIONS]

COMMANDS:
    info      Enumerate files in a game directory and classify by magic bytes
    extract   Walk a game directory and copy files byte-perfect to --out
    verify    Re-hash every file in SHA256SUMS.txt against the actual contents
    convert   Re-emit decode-able images as PNG or JPEG into --out directory
```

```bash
# Inventory a game directory
renpyex info "C:/Games/MyVN"

# Extract everything byte-perfect (unpack .rpa archives too)
renpyex extract "C:/Games/MyVN" --out ./extracted --rpa

# Prove the extraction is intact
renpyex verify ./extracted

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
- ⚙️ **Everything the CLI does** — Scan / Extract / Verify / Convert, path
  pickers, `.rpa` unpacking, optional `.rpyc` decompile, XOR key entry,
  JPEG quality slider
- 🧵 **Never freezes** — long operations run on a background thread; the
  color-coded log streams into the central pane
- 💾 **Remembers your paths** — persisted to `%APPDATA%\renpyex\config.json`
  (Windows) or `$XDG_CONFIG_HOME/renpyex/config.json` (Linux/macOS)

## 🛠️ Build from source

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

### Test fixtures

```bash
python tests/build_fixtures.py
cargo test
```

The fixture in `tests/fixtures/sample.rpa` is built by `build_fixtures.py`
using the exact format described in Ren'Py's own `loader.py` (RPAv3 → 8-byte
magic → 16-hex offset → key → zlib-compressed pickled index).

## 🧪 Quality

- ✅ **67 tests, 0 failures** on `cargo test --features gui` — unit tests,
  CLI smoke test, GUI smoke test, and mutation tests
- 🧬 **Mutation testing**: `tests/mutations.rs` deliberately corrupts real
  Ren'Py-formatted bytes (truncation, magic flips, garbage input, `..`
  traversal payloads) and asserts the parser fails with a structured error —
  never panics, never emits wrong bytes silently, never writes outside the
  output directory
- 🚫 **Zero clippy warnings** under `correctness = deny`, `style`,
  `complexity`, `suspicious` — across the library, CLI, GUI, and tests
- 🔒 **`unsafe` locked down**: denied crate-wide; the single exception is
  the GUI's documented Win32 layered-window setup
- 🧱 **Illegal states unrepresentable**: `Offset(u64)` / `Length(u64)`
  newtypes can't be swapped; `Length` is never zero by construction;
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
