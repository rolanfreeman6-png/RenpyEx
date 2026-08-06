#!/usr/bin/env python3
"""Generate a synthetic RPA-3.0 archive for testing renpyex.

Builds a deterministic archive with a few known files. Used by the
`rpa3_fixture_byte_perfect_extraction` Rust integration test.

Run from repo root:
    python tests/build_fixtures.py

Layout produced:
    [header 34 bytes]        -- "RPA-3.0 " + offset_hex(16) + " " + key_hex(8) + "\n"
    [pad to 256 bytes]       -- zero-fill
    [data blocks]            -- entry payloads, contiguous
    [zlib-compressed index]   -- pickled dict mapping path -> [(offset, length)]
"""
from __future__ import annotations

import pickle
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
    index: dict[str, list[tuple[int, int] | tuple[int, int, bytes]]] = {}
    cursor = data_start
    for path, payload in entries:
        index[path] = [(cursor, len(payload))]
        cursor += len(payload)
    # One file made of two index chunks validates fragment concatenation.
    first = b"fragment-one-"
    second = b"fragment-two"
    index["fragmented.txt"] = [(cursor, len(first)), (cursor + len(first), len(second))]
    cursor += len(first) + len(second)
    prefixed_tail = b"tail"
    index["prefixed.txt"] = [(cursor, len(prefixed_tail), b"prefix-")]
    cursor += len(prefixed_tail)
    index_offset = cursor

    # Source: Ren'Py launcher/game/archiver.rpy lines 49-83 at commit
    # da4d86679ceca69124dc2204098e1245968c9aa0.
    key = 0x42424242
    encoded_index: dict[str, list[tuple[int, int] | tuple[int, int, bytes]]] = {}
    for path, chunks in index.items():
        encoded_chunks = []
        for chunk in chunks:
            if len(chunk) == 2:
                offset, length = chunk
                encoded_chunks.append((offset ^ key, length ^ key))
            else:
                offset, length, prefix = chunk
                encoded_chunks.append((offset ^ key, length ^ key, prefix))
        encoded_index[path] = encoded_chunks
    pickle_bytes = pickle.dumps(encoded_index, protocol=4)
    compressed = zlib.compress(pickle_bytes, level=9)

    header = f"RPA-3.0 {index_offset:016x} {key:08x}\n".encode("ascii")
    if len(header) != 34:
        raise RuntimeError(f"Unexpected header length: {len(header)}")
    if len(header) > data_start:
        raise RuntimeError(f"Header too long: {len(header)}")
    pad = b"\x00" * (data_start - len(header))

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("wb") as f:
        f.write(header)
        f.write(pad)
        for _path, payload in entries:
            f.write(payload)
        f.write(first)
        f.write(second)
        f.write(prefixed_tail)
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
