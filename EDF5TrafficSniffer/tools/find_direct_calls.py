#!/usr/bin/env python3
"""Find x64 direct-call references to selected PE RVAs."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

from find_string_xrefs import function_bounds, offset_to_rva
from pe_inventory import PE


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("pe", type=Path)
    parser.add_argument("targets", nargs="+", type=lambda value: int(value, 0))
    args = parser.parse_args()

    pe = PE(args.pe)
    text = next(item for item in pe.sections if item["name"] == ".text")
    text_start = text["raw_address"]
    text_end = text_start + text["raw_size"]

    for target in args.targets:
        matches: list[tuple[int, int]] = []
        cursor = text_start
        while cursor < text_end - 5:
            cursor = pe.data.find(b"\xe8", cursor, text_end - 4)
            if cursor < 0:
                break
            caller = offset_to_rva(pe, cursor)
            displacement = struct.unpack_from("<i", pe.data, cursor + 1)[0]
            if caller + 5 + displacement == target:
                matches.append((cursor, caller))
            cursor += 1

        print(f"target_rva=0x{target:x} direct_calls={len(matches)}")
        for file_offset, caller in matches:
            bounds = function_bounds(pe, caller)
            function = (
                f"0x{bounds[0]:x}-0x{bounds[1]:x}" if bounds else "unknown"
            )
            begin = max(text_start, file_offset - 24)
            end = min(text_end, file_offset + 29)
            print(
                f"  call_rva=0x{caller:x} function={function} "
                f"context={pe.data[begin:end].hex()}"
            )


if __name__ == "__main__":
    main()
