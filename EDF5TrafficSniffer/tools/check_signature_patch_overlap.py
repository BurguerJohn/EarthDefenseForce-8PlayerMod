#!/usr/bin/env python3
"""Fail if a startup signature check covers bytes the plugin itself patches.

game_patches installs capacity/relay patches before more_players validates
its hook signatures. A plain SignatureMatches over a patched byte therefore
fails in the real EDF5.exe and quarantines the whole plugin, while every
offline harness still passes (0.6.66 regression at 0x42F7C9). Relay-aware
checks (ParserSignatureMatches) are exempt. Source-only; no game binary.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
SOURCES = sorted((PROJECT / "src" / "games" / "edf5").rglob("*.cpp"))

# Every runtime-patched code range not covered by a capacity/scaling census.
# (constant naming the first patched byte, byte offset, patched length)
PATCHED = (
    ("kMissionSpawnTransformLoopCompareRva", 0, 6),
    ("kMissionLoadoutParserBlockOffsetRva", 0, 7),
    ("kMissionLoadoutParserRecordOffsetRva", 0, 7),
    ("kMissionLoadoutParserBulkBoundRva", 0, 3),
    ("kMissionRecordRedirectRva", 0, 8),
    ("kMissionRecordExistingRedirectRva", 0, 10),
    ("kMissionRecordAppendRedirectRva", 0, 7),
    ("kMissionScriptRecordReadARva", 0, 12),
    ("kMissionScriptRecordReadBRva", 0, 19),
    ("kCalibanSeatRva", 0, 14),
    ("kCarSeatRva", 0, 14),
)
MESSAGE_RESERVE_RVAS = (0x43309E, 0x432D65)  # imm32 bytes 1..4 patched


def main() -> int:
    text = {path: path.read_text(encoding="utf-8") for path in SOURCES}
    constants: dict[str, int] = {}
    sizes: dict[str, int] = {}
    for source in text.values():
        for match in re.finditer(
                r"constexpr uintptr_t (k\w+)\s*=\s*(0x[0-9a-fA-F]+|\d+);",
                source):
            constants[match.group(1)] = int(match.group(2), 0)
        for match in re.finditer(
                r"constexpr (?:uint8_t|std::array<uint8_t,\s*\d+>) (k\w+)"
                r"(?:\[\])?\s*=\s*\{+(.*?)\}+;", source, re.S):
            sizes[match.group(1)] = len(
                re.findall(r"0x[0-9a-fA-F]{2}\b", match.group(2)))

    patched: list[tuple[int, int, str]] = []
    for name, offset, length in PATCHED:
        if name not in constants:
            print(f"FAIL patched constant {name} not found")
            return 1
        patched.append((constants[name] + offset, length, name))
    for rva in MESSAGE_RESERVE_RVAS:
        patched.append((rva + 1, 4, f"message reserve 0x{rva:x}"))
    health = "".join(text.values())
    health = health[health.index("kHealthScalingSites = {{"):]
    health = health[:health.index("}};")]
    for rva, size in re.findall(r"\{(0x[0-9a-f]+), \{[^}]*\}, (\d)\}", health):
        patched.append((int(rva, 16), int(size), f"health scaling {rva}"))

    checks = 0
    problems: list[str] = []
    for path, source in text.items():
        for match in re.finditer(
                r"(?<!\w)SignatureMatches\(\s*\w+,\s*\w+,\s*([^,]+?),\s*"
                r"(k\w+),\s*sizeof\((k\w+)\)\)", source, re.S):
            expression, signature = match.group(1).strip(), match.group(2)
            try:
                rva = eval(expression, {"__builtins__": {}}, constants)
            except Exception:  # noqa: BLE001 - report and fail closed
                problems.append(f"unresolved RVA expression {expression}")
                continue
            size = sizes.get(signature)
            if size is None:
                problems.append(f"unknown signature size {signature}")
                continue
            checks += 1
            for begin, length, name in patched:
                if rva < begin + length and begin < rva + size:
                    problems.append(
                        f"{signature} at 0x{rva:x}+{size} overlaps {name} "
                        f"(0x{begin:x}+{length}) in {path.name}")
    for problem in problems:
        print(f"FAIL {problem}")
    if problems:
        return 1
    print(f"PASS signature_patch_overlap checks={checks} "
          f"patched_ranges={len(patched)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
