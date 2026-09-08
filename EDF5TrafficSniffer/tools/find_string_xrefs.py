#!/usr/bin/env python3
"""Find candidate x64 RIP-relative references to ASCII strings in a PE file."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

from pe_inventory import PE


def offset_to_rva(pe: PE, offset: int) -> int:
    for section in pe.sections:
        start = section["raw_address"]
        if start <= offset < start + section["raw_size"]:
            return section["virtual_address"] + offset - start
    raise ValueError(f"file offset 0x{offset:x} does not map to a section")


def function_bounds(pe: PE, rva: int) -> tuple[int, int] | None:
    exception_rva, exception_size = pe.directories[3]
    if not exception_rva or exception_size < 12:
        return None
    table = pe.rva_offset(exception_rva)
    for offset in range(table, table + exception_size - 11, 12):
        begin, end, _ = struct.unpack_from("<III", pe.data, offset)
        if begin <= rva < end:
            return begin, end
    return None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("pe", type=Path)
    parser.add_argument("--utf16", action="store_true")
    parser.add_argument("strings", nargs="+")
    args = parser.parse_args()

    pe = PE(args.pe)
    text = next((item for item in pe.sections if item["name"] == ".text"), None)
    if not text:
        raise SystemExit("PE has no .text section")
    text_start = text["raw_address"]
    text_end = text_start + text["raw_size"]

    for requested in args.strings:
        needle = (requested.encode("utf-16le") + b"\0\0"
                  if args.utf16 else requested.encode("ascii") + b"\0")
        string_offset = pe.data.find(needle)
        if string_offset < 0:
            print(f"{requested}: not found")
            continue
        string_rva = offset_to_rva(pe, string_offset)
        references: list[tuple[int, int]] = []
        for displacement_at in range(text_start, text_end - 3):
            displacement = struct.unpack_from("<i", pe.data, displacement_at)[0]
            next_rva = text["virtual_address"] + displacement_at - text_start + 4
            if next_rva + displacement == string_rva:
                references.append((displacement_at, next_rva - 4))
        print(
            f"{requested}: string_file=0x{string_offset:x} string_rva=0x{string_rva:x} "
            f"candidate_xrefs={len(references)}"
        )
        for file_offset, rva in references:
            begin = max(text_start, file_offset - 16)
            end = min(text_end, file_offset + 20)
            bounds = function_bounds(pe, rva)
            function = (
                f"0x{bounds[0]:x}-0x{bounds[1]:x} ({bounds[1] - bounds[0]} bytes)"
                if bounds
                else "unknown"
            )
            print(
                f"  displacement_file=0x{file_offset:x} displacement_rva=0x{rva:x} "
                f"function={function} context={pe.data[begin:end].hex()}"
            )


if __name__ == "__main__":
    main()
