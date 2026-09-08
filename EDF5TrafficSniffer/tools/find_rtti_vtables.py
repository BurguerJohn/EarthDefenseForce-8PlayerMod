#!/usr/bin/env python3
"""Locate MSVC x64 RTTI complete-object locators and their vftables."""

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
    parser.add_argument("types", nargs="+")
    parser.add_argument("--entries", type=int, default=24)
    args = parser.parse_args()

    pe = PE(args.pe)
    base = image_base(pe)
    text = next(item for item in pe.sections if item["name"] == ".text")
    text_start = text["raw_address"]
    text_end = text_start + text["raw_size"]

    for requested in args.types:
        name = requested if requested.startswith(".") else "." + requested
        name_bytes = name.encode("ascii") + b"\0"
        name_at = pe.data.find(name_bytes)
        if name_at < 0:
            print(f"{requested}: type descriptor not found")
            continue
        descriptor_at = name_at - 16
        descriptor_rva = offset_to_rva(pe, descriptor_at)
        locators: list[tuple[int, int]] = []
        encoded_type = struct.pack("<I", descriptor_rva)
        cursor = 0
        while True:
            cursor = pe.data.find(encoded_type, cursor)
            if cursor < 0:
                break
            candidate_at = cursor - 12
            if candidate_at >= 0:
                try:
                    candidate_rva = offset_to_rva(pe, candidate_at)
                except ValueError:
                    candidate_rva = -1
                if candidate_rva >= 0 and candidate_at + 24 <= len(pe.data):
                    signature, _, _, type_rva, _, self_rva = struct.unpack_from(
                        "<IIIIII", pe.data, candidate_at
                    )
                    if signature == 1 and type_rva == descriptor_rva and self_rva == candidate_rva:
                        locators.append((candidate_at, candidate_rva))
            cursor += 1

        print(
            f"{name}: descriptor_rva=0x{descriptor_rva:x} "
            f"complete_object_locators={len(locators)}"
        )
        for _, locator_rva in locators:
            encoded_locator = struct.pack("<Q", base + locator_rva)
            cursor = 0
            while True:
                cursor = pe.data.find(encoded_locator, cursor)
                if cursor < 0:
                    break
                try:
                    locator_pointer_rva = offset_to_rva(pe, cursor)
                except ValueError:
                    cursor += 1
                    continue
                vtable_rva = locator_pointer_rva + 8
                vtable_at = cursor + 8
                print(
                    f"  locator_rva=0x{locator_rva:x} vtable_rva=0x{vtable_rva:x}"
                )
                for index in range(args.entries):
                    entry_at = vtable_at + index * 8
                    if entry_at + 8 > len(pe.data):
                        break
                    value = struct.unpack_from("<Q", pe.data, entry_at)[0]
                    if not (base <= value < base + 0x2000000):
                        break
                    function_rva = value - base
                    bounds = function_bounds(pe, function_rva)
                    function = (
                        f"0x{bounds[0]:x}-0x{bounds[1]:x}" if bounds else "unknown"
                    )
                    print(
                        f"    [{index:02d}] function_rva=0x{function_rva:x} "
                        f"bounds={function}"
                    )

                references: list[int] = []
                for disp_at in range(text_start, text_end - 3):
                    displacement = struct.unpack_from("<i", pe.data, disp_at)[0]
                    instruction_end = text["virtual_address"] + disp_at - text_start + 4
                    if instruction_end + displacement == vtable_rva:
                        references.append(instruction_end - 4)
                for reference in references:
                    bounds = function_bounds(pe, reference)
                    function = (
                        f"0x{bounds[0]:x}-0x{bounds[1]:x}" if bounds else "unknown"
                    )
                    print(f"    code_ref_rva=0x{reference:x} function={function}")
                cursor += 1


if __name__ == "__main__":
    main()
