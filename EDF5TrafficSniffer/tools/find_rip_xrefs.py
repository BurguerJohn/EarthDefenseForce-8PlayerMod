#!/usr/bin/env python3
"""Find x64 RIP-relative references to one or more PE RVAs."""

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
        references: list[tuple[int, int]] = []
        for displacement_at in range(text_start, text_end - 3):
            displacement = struct.unpack_from("<i", pe.data, displacement_at)[0]
            instruction_end_rva = (
                text["virtual_address"] + displacement_at + 4 - text_start
            )
            if instruction_end_rva + displacement == target:
                references.append((displacement_at, instruction_end_rva - 4))

        print(f"target_rva=0x{target:x} candidate_xrefs={len(references)}")
        for file_offset, displacement_rva in references:
            bounds = function_bounds(pe, displacement_rva)
            function = (
                f"0x{bounds[0]:x}-0x{bounds[1]:x}" if bounds else "unknown"
            )
            begin = max(text_start, file_offset - 20)
            end = min(text_end, file_offset + 28)
            print(
                f"  displacement_rva=0x{displacement_rva:x} "
                f"function={function} context={pe.data[begin:end].hex()}"
            )


if __name__ == "__main__":
    main()
