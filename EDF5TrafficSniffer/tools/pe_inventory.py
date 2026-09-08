#!/usr/bin/env python3
"""Small dependency-free PE import/export inventory helper."""

from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path


class PE:
    def __init__(self, path: Path):
        self.path = path
        self.data = path.read_bytes()
        if self.data[:2] != b"MZ":
            raise ValueError("not a PE file")
        pe = self.u32(0x3C)
        if self.data[pe : pe + 4] != b"PE\0\0":
            raise ValueError("invalid PE signature")
        coff = pe + 4
        self.machine, self.section_count = struct.unpack_from("<HH", self.data, coff)
        optional_size = self.u16(coff + 16)
        optional = coff + 20
        magic = self.u16(optional)
        if magic == 0x20B:
            self.pointer_size = 8
            directories = optional + 112
        elif magic == 0x10B:
            self.pointer_size = 4
            directories = optional + 96
        else:
            raise ValueError(f"unknown optional-header magic 0x{magic:x}")
        self.directories = [
            struct.unpack_from("<II", self.data, directories + i * 8)
            for i in range(16)
        ]
        sections_at = optional + optional_size
        self.sections = []
        for i in range(self.section_count):
            off = sections_at + i * 40
            name = self.data[off : off + 8].split(b"\0", 1)[0].decode("ascii", "replace")
            virtual_size, virtual_address, raw_size, raw_address = struct.unpack_from(
                "<IIII", self.data, off + 8
            )
            self.sections.append(
                {
                    "name": name,
                    "virtual_size": virtual_size,
                    "virtual_address": virtual_address,
                    "raw_size": raw_size,
                    "raw_address": raw_address,
                }
            )

    def u16(self, offset: int) -> int:
        return struct.unpack_from("<H", self.data, offset)[0]

    def u32(self, offset: int) -> int:
        return struct.unpack_from("<I", self.data, offset)[0]

    def ptr(self, offset: int) -> int:
        return struct.unpack_from("<Q" if self.pointer_size == 8 else "<I", self.data, offset)[0]

    def cstring(self, offset: int) -> str:
        end = self.data.find(b"\0", offset)
        if end < 0:
            end = len(self.data)
        return self.data[offset:end].decode("utf-8", "replace")

    def rva_offset(self, rva: int) -> int:
        for section in self.sections:
            start = section["virtual_address"]
            length = max(section["virtual_size"], section["raw_size"])
            if start <= rva < start + length:
                return section["raw_address"] + rva - start
        # Header RVAs map directly.
        if 0 <= rva < len(self.data):
            return rva
        raise ValueError(f"RVA 0x{rva:x} does not map to a section")

    def imports(self) -> dict[str, list[str]]:
        result: dict[str, list[str]] = {}
        rva, _ = self.directories[1]
        if not rva:
            return result
        descriptor = self.rva_offset(rva)
        while True:
            original, _, _, name_rva, first = struct.unpack_from("<IIIII", self.data, descriptor)
            if not any((original, name_rva, first)):
                break
            dll = self.cstring(self.rva_offset(name_rva))
            thunk_rva = original or first
            thunk = self.rva_offset(thunk_rva)
            names: list[str] = []
            ordinal_mask = 1 << (self.pointer_size * 8 - 1)
            while True:
                value = self.ptr(thunk)
                if not value:
                    break
                if value & ordinal_mask:
                    names.append(f"#{value & 0xFFFF}")
                else:
                    hint_name = self.rva_offset(value)
                    names.append(self.cstring(hint_name + 2))
                thunk += self.pointer_size
            result[dll] = names
            descriptor += 20
        return result

    def exports(self) -> list[str]:
        rva, _ = self.directories[0]
        if not rva:
            return []
        export = self.rva_offset(rva)
        name_count = self.u32(export + 24)
        names_rva = self.u32(export + 32)
        names_at = self.rva_offset(names_rva)
        return [
            self.cstring(self.rva_offset(self.u32(names_at + i * 4)))
            for i in range(name_count)
        ]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("files", nargs="+", type=Path)
    parser.add_argument("--dll", help="Only show imports from this DLL (case-insensitive)")
    parser.add_argument("--exports", action="store_true", help="Show named exports")
    args = parser.parse_args()
    output = {}
    for path in args.files:
        pe = PE(path)
        record = {
            "machine": f"0x{pe.machine:04x}",
            "pointer_size": pe.pointer_size,
            "imports": pe.imports(),
        }
        if args.dll:
            record["imports"] = {
                name: funcs
                for name, funcs in record["imports"].items()
                if name.casefold() == args.dll.casefold()
            }
        if args.exports:
            record["exports"] = pe.exports()
        output[str(path)] = record
    print(json.dumps(output, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
