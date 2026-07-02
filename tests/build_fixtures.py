#!/usr/bin/env python3
"""Generate a synthetic RPA-3.0 archive for testing renpyex.

Builds a deterministic archive with a few known files. Used by the
`rpa3_fixture_byte_perfect_extraction` Rust integration test.

Run from repo root:
    python tests/build_fixtures.py

Layout produced:
    [header 35 bytes]        -- "RPA-3.0 " + offset_hex(16) + " " + key_hex(8) + " \n"
    [pad to 256 bytes]       -- zero-fill
    [data blocks]            -- entry payloads, contiguous
    [zlib-compressed index]   -- pickeld dict mapping path -> [(offset, length)]
"""
from __future__ import annotations

import pickle
import struct
import sys
import zlib
from pathlib import Path


def build_archive(out_path: Path) -> None:
    entries = [
        ("greeting.txt", b"hello renpyex!\n"),
        ("image_bytes.bin", bytes(range(256))),
        ("readme.md", b"# embedded file\n\nByte-perfect payload.\n"),
        ("short.txt", b"ok"),
    ]
    entries.sort(key=lambda kv: kv[0])

    data_start = 0x100  # 256 bytes from file start (after header+pad block)
    # Lay out entries and build honest index.
    index: dict[str, list[tuple[int, int]]] = {}
    cursor = data_start
    for path, payload in entries:
        index[path] = [(cursor, len(payload))]
        cursor += len(payload)
    index_offset = cursor

    # Pickle + zlib compress the index (we omit XOR obfuscation with key=0).
    pickle_bytes = pickle.dumps(index)
    compressed = zlib.compress(pickle_bytes, level=9)
    key = 0

    header_prefix = b" RPA-3.0 "
    # Ren'Py uses b"RPA-3.0 " exactly (no leading space) — adjust.
    header_prefix = b"RPA-3.0 "
    header_body = f"{index_offset:016x}".encode("ascii") + b" " + f"{key:08x}".encode("ascii") + b" \n"
    header = header_prefix + header_body
    if len(header) > data_start:
        raise RuntimeError(f"Header too long: {len(header)}")
    pad = b"\x00" * (data_start - len(header))

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("wb") as f:
        f.write(header)
        f.write(pad)
        for _path, payload in entries:
            f.write(payload)
        f.write(compressed)


def main() -> int:
    here = Path(__file__).resolve().parent
    out = here / "fixtures" / "sample.rpa"
    build_archive(out)
    print(f"wrote {out}")
    print(f"size: {out.stat().st_size} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
