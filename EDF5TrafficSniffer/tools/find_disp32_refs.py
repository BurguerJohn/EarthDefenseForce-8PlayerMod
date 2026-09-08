#!/usr/bin/env python3
"""Find occurrences of a little-endian 32-bit displacement in PE .text."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

from find_string_xrefs import function_bounds, offset_to_rva
from pe_inventory import PE


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("pe", type=Path)
    parser.add_argument("value", type=lambda value: int(value, 0))
    args = parser.parse_args()

    pe = PE(args.pe)
    text = next(item for item in pe.sections if item["name"] == ".text")
    begin = text["raw_address"]
    end = begin + text["raw_size"]
    needle = struct.pack("<I", args.value & 0xffffffff)
    cursor = begin
    matches: list[int] = []
    while True:
        cursor = pe.data.find(needle, cursor, end)
        if cursor < 0:
            break
        matches.append(cursor)
        cursor += 1
    print(f"disp32=0x{args.value & 0xffffffff:08x} matches={len(matches)}")
    for offset in matches:
        rva = offset_to_rva(pe, offset)
        bounds = function_bounds(pe, rva)
        function = f"0x{bounds[0]:x}-0x{bounds[1]:x}" if bounds else "unknown"
        context_begin = max(begin, offset - 12)
        context_end = min(end, offset + 20)
        print(f"  disp_rva=0x{rva:x} function={function} "
              f"context={pe.data[context_begin:context_end].hex()}")


if __name__ == "__main__":
    main()
