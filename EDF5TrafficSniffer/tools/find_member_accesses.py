#!/usr/bin/env python3
"""Find decoded x64 memory accesses with selected member displacements.

The scan is bounded by the PE exception-directory function table so embedded
jump tables do not desynchronise the decoder.  It is a reverse-engineering
helper only: the image is read as data and is never loaded or executed.
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

from map_callers_to_rtti import runtime_functions
from pe_inventory import PE


def parse_integer(value: str) -> int:
    return int(value, 0)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("image", type=Path)
    parser.add_argument("displacements", nargs="+", type=parse_integer)
    parser.add_argument(
        "--access", choices=("any", "read", "write"), default="any"
    )
    args = parser.parse_args()

    project = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(project / "third_party" / "pycapstone"))
    from capstone import CS_AC_READ, CS_AC_WRITE, CS_ARCH_X86, CS_MODE_64, Cs
    from capstone.x86 import X86_OP_MEM, X86_REG_RIP

    pe = PE(args.image)
    starts, ranges = runtime_functions(pe)
    del starts
    wanted = set(args.displacements)
    encoded_displacements = tuple(
        struct.pack("<i", value) for value in wanted
    )
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True

    matches = []
    for begin, end in ranges:
        try:
            offset = pe.rva_offset(begin)
        except ValueError:
            continue
        code = pe.data[offset:offset + end - begin]
        if not any(encoded in code for encoded in encoded_displacements):
            continue
        for instruction in decoder.disasm(code, begin):
            for operand in instruction.operands:
                if operand.type != X86_OP_MEM:
                    continue
                if operand.mem.base == X86_REG_RIP:
                    continue
                if operand.mem.disp not in wanted:
                    continue
                access = operand.access
                if args.access == "read" and not access & CS_AC_READ:
                    continue
                if args.access == "write" and not access & CS_AC_WRITE:
                    continue
                access_text = (
                    ("r" if access & CS_AC_READ else "") +
                    ("w" if access & CS_AC_WRITE else "") or "?"
                )
                matches.append((
                    instruction.address,
                    begin,
                    end,
                    operand.mem.disp,
                    access_text,
                    instruction.bytes.hex(" "),
                    instruction.mnemonic,
                    instruction.op_str,
                ))

    for address, begin, end, displacement, access, encoded, mnemonic, op_str in matches:
        print(
            f"{address:08x} function=0x{begin:x}-0x{end:x} "
            f"disp=0x{displacement:x} access={access:<2} "
            f"{encoded:<30} {mnemonic:<9} {op_str}"
        )
    print(
        f"summary matches={len(matches)} functions={len(ranges)} "
        f"access={args.access} displacements=" +
        ",".join(f"0x{value:x}" for value in sorted(wanted))
    )


if __name__ == "__main__":
    main()
