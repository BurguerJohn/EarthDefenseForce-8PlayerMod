#!/usr/bin/env python3
"""Locate x64 indirect vtable calls with a selected displacement."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

from find_string_xrefs import function_bounds, offset_to_rva
from pe_inventory import PE


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("pe", type=Path)
    parser.add_argument("displacements", nargs="+", type=lambda value: int(value, 0))
    parser.add_argument("--near-hex", help="Only show calls with these bytes in the preceding 32 bytes")
    args = parser.parse_args()
    pe = PE(args.pe)
    text = next(item for item in pe.sections if item["name"] == ".text")
    text_start = text["raw_address"]
    text_end = text_start + text["raw_size"]

    for displacement in args.displacements:
        matches: list[int] = []
        encoded = struct.pack("<I", displacement)
        for register in range(8):
            patterns = [bytes((0xFF, 0x90 + register)) + encoded]
            if 0 <= displacement <= 0x7F:
                patterns.append(bytes((0xFF, 0x50 + register, displacement)))
            for pattern in patterns:
                cursor = text_start
                while True:
                    cursor = pe.data.find(pattern, cursor, text_end)
                    if cursor < 0:
                        break
                    matches.append(cursor)
                    cursor += len(pattern)
        print(f"displacement=0x{displacement:x} candidate_calls={len(matches)}")
        for file_offset in sorted(matches):
            if args.near_hex:
                required = bytes.fromhex(args.near_hex)
                if required not in pe.data[max(text_start, file_offset - 32) : file_offset]:
                    continue
            rva = offset_to_rva(pe, file_offset)
            bounds = function_bounds(pe, rva)
            function = (
                f"0x{bounds[0]:x}-0x{bounds[1]:x}"
                if bounds
                else "unknown"
            )
            begin = max(text_start, file_offset - 20)
            end = min(text_end, file_offset + 26)
            print(
                f"  call_rva=0x{rva:x} function={function} "
                f"context={pe.data[begin:end].hex()}"
            )


if __name__ == "__main__":
    main()
