#!/usr/bin/env python3
"""Resolve an MSVC x64 vftable RVA to its RTTI type and method entries.

The helper reads a PE image as data.  It is intentionally small so a vftable
captured in a minidump can be tied back to its complete-object locator without
loading or executing the target image.
"""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

from find_string_xrefs import function_bounds
from pe_inventory import PE


def parse_integer(value: str) -> int:
    return int(value, 0)


def image_base(pe: PE) -> int:
    pe_offset = pe.u32(0x3C)
    optional = pe_offset + 4 + 20
    return struct.unpack_from("<Q", pe.data, optional + 24)[0]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("pe", type=Path)
    parser.add_argument("vtable_rva", type=parse_integer)
    parser.add_argument("--entries", type=int, default=32)
    args = parser.parse_args()

    pe = PE(args.pe)
    base = image_base(pe)
    vtable_at = pe.rva_offset(args.vtable_rva)
    locator_va = struct.unpack_from("<Q", pe.data, vtable_at - 8)[0]
    locator_rva = locator_va - base
    locator_at = pe.rva_offset(locator_rva)
    signature, object_offset, ctor_offset, type_rva, hierarchy_rva, self_rva = (
        struct.unpack_from("<IIIIII", pe.data, locator_at)
    )
    if signature != 1 or self_rva != locator_rva:
        raise ValueError("vftable does not reference a valid x64 RTTI locator")
    type_at = pe.rva_offset(type_rva)
    name_begin = type_at + 16
    name_end = pe.data.index(b"\0", name_begin)
    name = pe.data[name_begin:name_end].decode("ascii", "replace")
    print(
        f"vtable_rva=0x{args.vtable_rva:x} locator_rva=0x{locator_rva:x} "
        f"type_rva=0x{type_rva:x} hierarchy_rva=0x{hierarchy_rva:x} "
        f"object_offset=0x{object_offset:x} ctor_offset=0x{ctor_offset:x} "
        f"type={name}"
    )
    for index in range(args.entries):
        entry_at = vtable_at + index * 8
        value = struct.unpack_from("<Q", pe.data, entry_at)[0]
        function_rva = value - base
        bounds = function_bounds(pe, function_rva)
        if bounds is None:
            break
        print(
            f"  [{index:02d}] function_rva=0x{function_rva:x} "
            f"bounds=0x{bounds[0]:x}-0x{bounds[1]:x}"
        )


if __name__ == "__main__":
    main()
