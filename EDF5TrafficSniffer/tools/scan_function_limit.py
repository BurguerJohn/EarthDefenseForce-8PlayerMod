#!/usr/bin/env python3
"""Show candidate immediate integer 4 uses inside selected PE functions."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from pe_inventory import PE


PATTERNS = {
    "imm32": re.compile(rb"\x04\x00\x00\x00"),
    "cmp-reg-imm8": re.compile(rb"\x83[\xf8-\xff]\x04"),
    "push-imm8": re.compile(rb"\x6a\x04"),
    "mov-reg-imm32": re.compile(rb"(?:\x41)?[\xb8-\xbf]\x04\x00\x00\x00"),
}


def parse_range(value: str) -> tuple[int, int]:
    begin_text, end_text = value.split("-", 1)
    return int(begin_text, 0), int(end_text, 0)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("pe", type=Path)
    parser.add_argument("ranges", nargs="+", type=parse_range)
    args = parser.parse_args()
    pe = PE(args.pe)

    for begin_rva, end_rva in args.ranges:
        begin_file = pe.rva_offset(begin_rva)
        function = pe.data[begin_file : begin_file + end_rva - begin_rva]
        print(f"function=0x{begin_rva:x}-0x{end_rva:x} bytes={len(function)}")
        found: set[tuple[int, str]] = set()
        for label, pattern in PATTERNS.items():
            for match in pattern.finditer(function):
                rva = begin_rva + match.start()
                key = (rva, label)
                if key in found:
                    continue
                found.add(key)
                context_begin = max(0, match.start() - 12)
                context_end = min(len(function), match.end() + 12)
                print(
                    f"  rva=0x{rva:x} kind={label} "
                    f"context={function[context_begin:context_end].hex()}"
                )
        if not found:
            print("  no candidate immediate 4")


if __name__ == "__main__":
    main()
