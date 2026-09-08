#!/usr/bin/env python3
"""Map direct call sites in an MSVC PE image back to owning RTTI types.

This is a static, best-effort helper. It never loads the image. A caller is
associated with a type when the containing function is present in one of that
type's vftables. Functions shared by several types are reported for each one.
"""

from __future__ import annotations

import argparse
import bisect
import struct
from collections import defaultdict
from pathlib import Path

from find_string_xrefs import offset_to_rva
from pe_inventory import PE


def parse_integer(value: str) -> int:
    return int(value, 0)


def image_base(pe: PE) -> int:
    pe_offset = pe.u32(0x3C)
    optional = pe_offset + 4 + 20
    return struct.unpack_from("<Q", pe.data, optional + 24)[0]


def direct_calls(pe: PE, target_rva: int) -> list[int]:
    text = next(item for item in pe.sections if item["name"] == ".text")
    begin = text["raw_address"]
    end = begin + text["raw_size"]
    calls: list[int] = []
    cursor = begin
    while cursor < end - 5:
        cursor = pe.data.find(b"\xe8", cursor, end - 4)
        if cursor < 0:
            break
        caller_rva = offset_to_rva(pe, cursor)
        displacement = struct.unpack_from("<i", pe.data, cursor + 1)[0]
        if caller_rva + 5 + displacement == target_rva:
            calls.append(caller_rva)
        cursor += 1
    return calls


def runtime_functions(pe: PE) -> tuple[list[int], list[tuple[int, int]]]:
    exception_rva, exception_size = pe.directories[3]
    if not exception_rva or exception_size < 12:
        return [], []
    table = pe.rva_offset(exception_rva)
    ranges = [
        struct.unpack_from("<II", pe.data, offset)
        for offset in range(table, table + exception_size - 11, 12)
    ]
    ranges.sort()
    return [begin for begin, _ in ranges], ranges


def lookup_function(
        starts: list[int], ranges: list[tuple[int, int]], rva: int
) -> tuple[int, int] | None:
    index = bisect.bisect_right(starts, rva) - 1
    if index >= 0:
        begin, end = ranges[index]
        if begin <= rva < end:
            return begin, end
    return None


def iter_type_descriptors(pe: PE):
    for section in pe.sections:
        if section["name"] not in (".data", ".rdata"):
            continue
        begin = section["raw_address"]
        end = begin + section["raw_size"]
        cursor = begin
        while cursor < end:
            av = pe.data.find(b".?AV", cursor, end)
            au = pe.data.find(b".?AU", cursor, end)
            candidates = [item for item in (av, au) if item >= 0]
            if not candidates:
                break
            name_at = min(candidates)
            descriptor_at = name_at - 16
            if descriptor_at >= begin:
                try:
                    descriptor_rva = offset_to_rva(pe, descriptor_at)
                    yield descriptor_rva, pe.cstring(name_at)
                except ValueError:
                    pass
            cursor = name_at + 4


def rtti_method_owners(
        pe: PE,
        max_entries: int,
        starts: list[int],
        ranges: list[tuple[int, int]],
) -> dict[tuple[int, int], set[str]]:
    """Return (function begin, end) -> RTTI type names."""
    base = image_base(pe)
    text = next(item for item in pe.sections if item["name"] == ".text")
    text_begin = text["virtual_address"]
    text_end = text_begin + max(text["virtual_size"], text["raw_size"])
    owners: dict[tuple[int, int], set[str]] = defaultdict(set)
    descriptors = dict(iter_type_descriptors(pe))
    locator_names: dict[int, str] = {}

    # Complete-object locators are fixed 24-byte records aligned to four
    # bytes. Scanning them once is far cheaper than searching the full image
    # independently for every type descriptor.
    for section in pe.sections:
        if section["name"] not in (".data", ".rdata"):
            continue
        begin = section["raw_address"]
        end = begin + section["raw_size"]
        for locator_at in range(begin, end - 23, 4):
            signature, _, _, type_rva, _, self_rva = struct.unpack_from(
                "<IIIIII", pe.data, locator_at
            )
            name = descriptors.get(type_rva)
            if signature != 1 or name is None:
                continue
            locator_rva = section["virtual_address"] + locator_at - begin
            if self_rva == locator_rva:
                locator_names[base + locator_rva] = name

    # The locator pointer immediately precedes each vftable and is naturally
    # qword-aligned in this PE32+ image.
    seen_vtables: set[int] = set()
    for section in pe.sections:
        if section["name"] not in (".data", ".rdata"):
            continue
        begin = section["raw_address"]
        end = begin + section["raw_size"]
        first = begin + ((-begin) & 7)
        for locator_pointer_at in range(first, end - 15, 8):
            locator_va = struct.unpack_from("<Q", pe.data, locator_pointer_at)[0]
            name = locator_names.get(locator_va)
            if name is None:
                continue
            pointer_rva = (
                section["virtual_address"] + locator_pointer_at - begin
            )
            vtable_rva = pointer_rva + 8
            if vtable_rva in seen_vtables:
                continue
            seen_vtables.add(vtable_rva)
            entry_at = locator_pointer_at + 8
            for index in range(max_entries):
                offset = entry_at + index * 8
                if offset + 8 > end:
                    break
                function_va = struct.unpack_from("<Q", pe.data, offset)[0]
                function_rva = function_va - base
                if not (text_begin <= function_rva < text_end):
                    break
                bounds = lookup_function(starts, ranges, function_rva)
                if bounds:
                    owners[bounds].add(name)
    return owners


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("pe", type=Path)
    parser.add_argument("targets", nargs="+", type=parse_integer)
    parser.add_argument("--max-vtable-entries", type=int, default=96)
    args = parser.parse_args()

    pe = PE(args.pe)
    starts, ranges = runtime_functions(pe)
    owners = rtti_method_owners(
        pe, args.max_vtable_entries, starts, ranges
    )
    for target in args.targets:
        calls = direct_calls(pe, target)
        print(f"target_rva=0x{target:x} direct_calls={len(calls)}")
        for call in calls:
            bounds = lookup_function(starts, ranges, call)
            if bounds:
                names = sorted(owners.get(bounds, ()))
                bounds_text = f"0x{bounds[0]:x}-0x{bounds[1]:x}"
            else:
                names = []
                bounds_text = "unknown"
            type_text = ", ".join(names) if names else "<unmapped>"
            print(
                f"  call_rva=0x{call:x} function={bounds_text} "
                f"types={type_text}"
            )


if __name__ == "__main__":
    main()
