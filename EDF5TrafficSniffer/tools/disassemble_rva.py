#!/usr/bin/env python3
"""Disassemble an RVA range or find direct call sites in a PE32+ image."""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path


def parse_integer(value: str) -> int:
    return int(value, 0)


def pe_sections(image: bytes) -> list[tuple[str, int, int, int, int]]:
    if image[:2] != b"MZ":
        raise ValueError("not a PE image")
    pe_offset = struct.unpack_from("<I", image, 0x3C)[0]
    if image[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError("invalid PE signature")
    section_count = struct.unpack_from("<H", image, pe_offset + 6)[0]
    optional_size = struct.unpack_from("<H", image, pe_offset + 20)[0]
    section_offset = pe_offset + 24 + optional_size
    sections = []
    for index in range(section_count):
        offset = section_offset + index * 40
        name = image[offset : offset + 8].split(b"\0", 1)[0].decode(
            "ascii", errors="replace"
        )
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
            "<IIII", image, offset + 8
        )
        sections.append(
            (name, virtual_address, virtual_size, raw_offset, raw_size)
        )
    return sections


def image_slice(image: bytes, rva: int, size: int) -> bytes:
    for _, virtual_address, virtual_size, raw_offset, raw_size in pe_sections(image):
        mapped_size = max(virtual_size, raw_size)
        if virtual_address <= rva < virtual_address + mapped_size:
            relative = rva - virtual_address
            available = max(0, raw_size - relative)
            length = min(size, available)
            return image[raw_offset + relative : raw_offset + relative + length]
    raise ValueError(f"RVA 0x{rva:x} is not backed by a PE section")


def find_direct_calls(image: bytes, target: int) -> list[int]:
    """Find x64 E8 rel32 encodings whose target is the requested RVA.

    This deliberately reports byte-level candidates. Callers can disassemble
    around the small result set to reject any occurrence embedded in data or
    another instruction.
    """
    results = []
    for _, virtual_address, _, raw_offset, raw_size in pe_sections(image):
        section = image[raw_offset : raw_offset + raw_size]
        for relative in range(max(0, len(section) - 4)):
            if section[relative] != 0xE8:
                continue
            displacement = struct.unpack_from("<i", section, relative + 1)[0]
            call_rva = virtual_address + relative
            if call_rva + 5 + displacement == target:
                results.append(call_rva)
    return results


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("image", type=Path)
    parser.add_argument("rva", type=parse_integer, nargs="?")
    parser.add_argument("size", type=parse_integer, nargs="?")
    parser.add_argument("--calls-to", type=parse_integer, metavar="RVA")
    parser.add_argument("--xrefs-to", type=parse_integer, metavar="RVA")
    args = parser.parse_args()

    search_mode = args.calls_to is not None or args.xrefs_to is not None
    if not search_mode and (args.rva is None or args.size is None):
        parser.error(
            "rva and size are required unless --calls-to or --xrefs-to is used"
        )
    if args.calls_to is not None and args.xrefs_to is not None:
        parser.error("--calls-to and --xrefs-to are mutually exclusive")

    image = args.image.read_bytes()
    if args.calls_to is not None:
        for call_rva in find_direct_calls(image, args.calls_to):
            print(f"{call_rva:08x}  call -> {args.calls_to:08x}")
        return 0

    project = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(project / "third_party" / "pycapstone"))
    from capstone import CS_ARCH_X86, CS_MODE_64, Cs
    from capstone.x86 import X86_OP_MEM, X86_REG_RIP

    if args.xrefs_to is not None:
        decoder = Cs(CS_ARCH_X86, CS_MODE_64)
        decoder.detail = True
        for name, section_rva, _, raw_offset, raw_size in pe_sections(image):
            if name != ".text":
                continue
            code = image[raw_offset : raw_offset + raw_size]
            # Sequential decoding can lose synchronization across embedded
            # jump tables. First identify overlapping disp32 candidates whose
            # computed next-IP is close to the displacement, then decode only
            # the handful of possible instruction starts around each one.
            candidates = set()
            for phase in range(4):
                usable = (len(code) - phase) & ~3
                values = struct.iter_unpack("<i", code[phase : phase + usable])
                for index, (displacement,) in enumerate(values):
                    displacement_offset = phase + index * 4
                    next_ip = args.xrefs_to - displacement
                    after_disp = section_rva + displacement_offset + 4
                    if next_ip - after_disp not in (0, 1, 2, 4, 8):
                        continue
                    for prefix in range(1, 9):
                        start_offset = displacement_offset - prefix
                        if start_offset < 0:
                            continue
                        start_rva = section_rva + start_offset
                        for instruction in decoder.disasm(
                                code[start_offset : start_offset + 15],
                                start_rva, count=1):
                            if instruction.address + instruction.size != next_ip:
                                continue
                            for operand in instruction.operands:
                                if (operand.type == X86_OP_MEM and
                                        operand.mem.base == X86_REG_RIP and
                                        next_ip + operand.mem.disp ==
                                        args.xrefs_to):
                                    candidates.add(
                                        (instruction.address,
                                         instruction.bytes.hex(" "),
                                         instruction.mnemonic,
                                         instruction.op_str)
                                    )
                                    break
        for address, encoded, mnemonic, op_str in sorted(candidates):
            print(
                f"{address:08x}  {encoded:<30} "
                f"{mnemonic:<9} {op_str}"
            )
        return 0

    code = image_slice(image, args.rva, args.size)
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    decoder.skipdata = True
    for instruction in decoder.disasm(code, args.rva):
        encoded = instruction.bytes.hex(" ")
        print(
            f"{instruction.address:08x}  {encoded:<30} "
            f"{instruction.mnemonic:<9} {instruction.op_str}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
