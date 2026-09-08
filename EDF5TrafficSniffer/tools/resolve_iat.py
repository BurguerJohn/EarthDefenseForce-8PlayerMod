#!/usr/bin/env python3
"""Resolve selected PE import-address-table RVAs to imported names."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

from pe_inventory import PE


def imports_by_iat(pe: PE) -> dict[int, tuple[str, str]]:
    result: dict[int, tuple[str, str]] = {}
    descriptor_rva, _ = pe.directories[1]
    if not descriptor_rva:
        return result
    descriptor = pe.rva_offset(descriptor_rva)
    ordinal_mask = 1 << (pe.pointer_size * 8 - 1)
    stride = pe.pointer_size
    while True:
        original, _, _, name_rva, first = struct.unpack_from(
            "<IIIII", pe.data, descriptor
        )
        if not any((original, name_rva, first)):
            break
        dll = pe.cstring(pe.rva_offset(name_rva))
        names_at = pe.rva_offset(original or first)
        index = 0
        while True:
            value = pe.ptr(names_at + index * stride)
            if not value:
                break
            if value & ordinal_mask:
                name = f"#{value & 0xffff}"
            else:
                name = pe.cstring(pe.rva_offset(value) + 2)
            result[first + index * stride] = (dll, name)
            index += 1
        descriptor += 20
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("pe", type=Path)
    parser.add_argument("rvas", nargs="*", type=lambda value: int(value, 0))
    parser.add_argument(
        "--dll",
        help="list only imports from this DLL when no RVA is supplied",
    )
    args = parser.parse_args()
    mapping = imports_by_iat(PE(args.pe))
    if not args.rvas:
        requested_dll = args.dll.casefold() if args.dll else None
        for rva, (dll, name) in sorted(mapping.items()):
            if requested_dll and dll.casefold() != requested_dll:
                continue
            print(f"0x{rva:x}: {dll}!{name}")
        return
    for rva in args.rvas:
        resolved = mapping.get(rva)
        if resolved:
            print(f"0x{rva:x}: {resolved[0]}!{resolved[1]}")
        else:
            print(f"0x{rva:x}: not an imported IAT slot")


if __name__ == "__main__":
    main()
