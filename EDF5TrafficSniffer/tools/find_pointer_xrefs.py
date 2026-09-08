#!/usr/bin/env python3
"""Find absolute pointer-table entries and RIP-relative code references to them."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

from find_string_xrefs import function_bounds, offset_to_rva
from pe_inventory import PE


def image_base(pe: PE) -> int:
    pe_offset = pe.u32(0x3C)
    optional = pe_offset + 4 + 20
    return struct.unpack_from("<Q", pe.data, optional + 24)[0]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("pe", type=Path)
    parser.add_argument("targets", nargs="+", type=lambda value: int(value, 0))
    args = parser.parse_args()

    pe = PE(args.pe)
    base = image_base(pe)
    text = next(item for item in pe.sections if item["name"] == ".text")
    text_start = text["raw_address"]
    text_end = text_start + text["raw_size"]

    target_entries: list[tuple[int, list[tuple[int, int]]]] = []
    all_entry_rvas: set[int] = set()
    for target in args.targets:
        encoded = struct.pack("<Q", base + target)
        table_entries: list[tuple[int, int]] = []
        cursor = 0
        while True:
            cursor = pe.data.find(encoded, cursor)
            if cursor < 0:
                break
            table_entries.append((cursor, offset_to_rva(pe, cursor)))
            cursor += 1

        target_entries.append((target, table_entries))
        all_entry_rvas.update(rva for _, rva in table_entries)

    refs_by_entry: dict[int, list[int]] = {rva: [] for rva in all_entry_rvas}
    for disp_at in range(text_start + 1, text_end - 3):
        displacement = struct.unpack_from("<i", pe.data, disp_at)[0]
        instruction_end_rva = (
            text["virtual_address"] + disp_at + 4 - text_start
        )
        destination = instruction_end_rva + displacement
        if destination in refs_by_entry:
            refs_by_entry[destination].append(disp_at)

    for target, table_entries in target_entries:
        print(f"target_rva=0x{target:x} pointer_entries={len(table_entries)}")
        for entry_offset, entry_rva in table_entries:
            refs = refs_by_entry[entry_rva]
            print(f"  entry_rva=0x{entry_rva:x} code_refs={len(refs)}")
            begin = max(0, entry_offset - 40)
            end = min(len(pe.data), entry_offset + 48)
            print(f"    table_context={pe.data[begin:end].hex()}")
            for disp_at in refs:
                ref_rva = offset_to_rva(pe, disp_at)
                bounds = function_bounds(pe, ref_rva)
                function = (
                    f"0x{bounds[0]:x}-0x{bounds[1]:x}" if bounds else "unknown"
                )
                context_begin = max(text_start, disp_at - 20)
                context_end = min(text_end, disp_at + 28)
                print(
                    f"    disp_rva=0x{ref_rva:x} function={function} "
                    f"context={pe.data[context_begin:context_end].hex()}"
                )


if __name__ == "__main__":
    main()
