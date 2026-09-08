#!/usr/bin/env python3
"""Describe MSVC x64 vftables by RVA without loading the target PE."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

from find_string_xrefs import function_bounds
from pe_inventory import PE


def image_base(pe: PE) -> int:
    pe_offset = pe.u32(0x3C)
    optional = pe_offset + 4 + 20
    return struct.unpack_from("<Q", pe.data, optional + 24)[0]


def pointer_at_rva(pe: PE, rva: int) -> int:
    return struct.unpack_from("<Q", pe.data, pe.rva_offset(rva))[0]


def type_name(pe: PE, base: int, vtable_rva: int) -> str:
    try:
        locator_va = pointer_at_rva(pe, vtable_rva - 8)
        locator_rva = locator_va - base
        locator = pe.rva_offset(locator_rva)
        signature, _, _, descriptor_rva, _, self_rva = struct.unpack_from(
            "<IIIIII", pe.data, locator
        )
        if signature != 1 or self_rva != locator_rva:
            return "<invalid-rtti>"
        return pe.cstring(pe.rva_offset(descriptor_rva) + 16)
    except (ValueError, struct.error):
        return "<missing-rtti>"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("pe", type=Path)
    parser.add_argument("vtables", nargs="+", type=lambda value: int(value, 0))
    parser.add_argument("--entries", type=int, default=16)
    args = parser.parse_args()

    pe = PE(args.pe)
    base = image_base(pe)
    for vtable_rva in args.vtables:
        print(
            f"vtable_rva=0x{vtable_rva:x} type={type_name(pe, base, vtable_rva)}"
        )
        for index in range(args.entries):
            try:
                value = pointer_at_rva(pe, vtable_rva + index * 8)
            except (ValueError, struct.error):
                break
            if not (base <= value < base + 0x2000000):
                print(f"  [{index:02d}] value=0x{value:x} <not image code>")
                break
            function_rva = value - base
            bounds = function_bounds(pe, function_rva)
            bounds_text = (
                f"0x{bounds[0]:x}-0x{bounds[1]:x}" if bounds else "unknown"
            )
            print(
                f"  [{index:02d}] function_rva=0x{function_rva:x} "
                f"bounds={bounds_text}"
            )


if __name__ == "__main__":
    main()
