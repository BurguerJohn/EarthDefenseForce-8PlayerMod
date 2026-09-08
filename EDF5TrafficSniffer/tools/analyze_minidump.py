#!/usr/bin/env python3
"""Small dependency-free Windows x64 minidump inspector.

Prints the exception context, loaded modules, memory around important registers,
and return-address candidates found on the crashing thread's stack.
"""

from __future__ import annotations

import argparse
import struct
from dataclasses import dataclass
from pathlib import Path


THREAD_LIST_STREAM = 3
MODULE_LIST_STREAM = 4
MEMORY_LIST_STREAM = 5
EXCEPTION_STREAM = 6
MEMORY64_LIST_STREAM = 9


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def u64(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


@dataclass
class MemoryRange:
    start: int
    size: int
    file_offset: int


@dataclass
class Module:
    base: int
    size: int
    name: str

    def contains(self, address: int) -> bool:
        return self.base <= address < self.base + self.size


class Dump:
    def __init__(self, path: Path):
        self.path = path
        self.data = path.read_bytes()
        if self.data[:4] != b"MDMP":
            raise ValueError("not a Windows minidump")
        stream_count = u32(self.data, 8)
        directory_rva = u32(self.data, 12)
        self.streams: dict[int, tuple[int, int]] = {}
        for index in range(stream_count):
            at = directory_rva + index * 12
            stream_type, size, rva = struct.unpack_from("<III", self.data, at)
            self.streams[stream_type] = (rva, size)
        self.memory = self._read_memory_ranges()
        self.modules = self._read_modules()

    def _read_string(self, rva: int) -> str:
        size = u32(self.data, rva)
        return self.data[rva + 4 : rva + 4 + size].decode("utf-16-le", "replace")

    def _read_memory_ranges(self) -> list[MemoryRange]:
        result: list[MemoryRange] = []
        if MEMORY64_LIST_STREAM in self.streams:
            rva, _ = self.streams[MEMORY64_LIST_STREAM]
            count = u64(self.data, rva)
            file_offset = u64(self.data, rva + 8)
            for index in range(count):
                at = rva + 16 + index * 16
                start, size = struct.unpack_from("<QQ", self.data, at)
                result.append(MemoryRange(start, size, file_offset))
                file_offset += size
        if MEMORY_LIST_STREAM in self.streams:
            rva, _ = self.streams[MEMORY_LIST_STREAM]
            count = u32(self.data, rva)
            for index in range(count):
                at = rva + 4 + index * 16
                start = u64(self.data, at)
                size, file_offset = struct.unpack_from("<II", self.data, at + 8)
                result.append(MemoryRange(start, size, file_offset))
        return result

    def _read_modules(self) -> list[Module]:
        if MODULE_LIST_STREAM not in self.streams:
            return []
        rva, _ = self.streams[MODULE_LIST_STREAM]
        count = u32(self.data, rva)
        result = []
        for index in range(count):
            at = rva + 4 + index * 108
            base = u64(self.data, at)
            size = u32(self.data, at + 8)
            name_rva = u32(self.data, at + 20)
            result.append(Module(base, size, self._read_string(name_rva)))
        return result

    def read(self, address: int, size: int) -> bytes | None:
        for item in self.memory:
            if item.start <= address and address + size <= item.start + item.size:
                begin = item.file_offset + address - item.start
                return self.data[begin : begin + size]
        return None

    def module_at(self, address: int) -> tuple[Module, int] | None:
        for module in self.modules:
            if module.contains(address):
                return module, address - module.base
        return None


def compact_name(path: str) -> str:
    return path.replace("/", "\\").rsplit("\\", 1)[-1]


def hex_dump(dump: Dump, address: int, size: int = 64) -> str:
    raw = dump.read(address, size)
    if raw is None:
        return "<not captured>"
    rows = []
    for offset in range(0, len(raw), 16):
        part = raw[offset : offset + 16]
        text = " ".join(f"{byte:02x}" for byte in part)
        ascii_text = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in part)
        rows.append(f"  {address + offset:016x}  {text:<47}  {ascii_text}")
    return "\n".join(rows)


def parse_memory(value: str) -> tuple[int, int]:
    try:
        address_text, separator, size_text = value.partition(":")
        address = int(address_text, 0)
        size = int(size_text, 0) if separator else 0x80
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "memory must be ADDRESS[:SIZE], for example 0x12340000:0x100"
        ) from error
    if address <= 0 or size <= 0 or size > 0x10000:
        raise argparse.ArgumentTypeError(
            "memory address and size must be positive; size is capped at 0x10000"
        )
    return address, size


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("dump", type=Path)
    parser.add_argument("--stack-bytes", type=lambda value: int(value, 0), default=0x800)
    parser.add_argument(
        "--stack-hex",
        action="store_true",
        help="print the captured crashing-thread stack as qwords",
    )
    parser.add_argument(
        "--memory",
        action="append",
        default=[],
        type=parse_memory,
        metavar="ADDRESS[:SIZE]",
        help="dump an additional captured virtual-memory range (repeatable)",
    )
    parser.add_argument(
        "--safe",
        action="store_true",
        help="print only exception/module metadata; omit paths, registers and memory",
    )
    args = parser.parse_args()

    dump = Dump(args.dump)
    display_path = args.dump.name if args.safe else args.dump
    print(f"dump={display_path} size={len(dump.data)} streams={sorted(dump.streams)}")

    exception_rva, _ = dump.streams[EXCEPTION_STREAM]
    thread_id = u32(dump.data, exception_rva)
    code = u32(dump.data, exception_rva + 8)
    flags = u32(dump.data, exception_rva + 12)
    exception_address = u64(dump.data, exception_rva + 24)
    parameter_count = u32(dump.data, exception_rva + 32)
    parameters = [u64(dump.data, exception_rva + 40 + index * 8) for index in range(parameter_count)]
    context_size = u32(dump.data, exception_rva + 160)
    context_rva = u32(dump.data, exception_rva + 164)
    context = dump.data[context_rva : context_rva + context_size]
    register_offsets = {
        "rax": 120,
        "rcx": 128,
        "rdx": 136,
        "rbx": 144,
        "rsp": 152,
        "rbp": 160,
        "rsi": 168,
        "rdi": 176,
        "r8": 184,
        "r9": 192,
        "r10": 200,
        "r11": 208,
        "r12": 216,
        "r13": 224,
        "r14": 232,
        "r15": 240,
        "rip": 248,
    }
    registers = {name: u64(context, offset) for name, offset in register_offsets.items()}

    location = dump.module_at(exception_address)
    where = ""
    if location:
        where = f" {compact_name(location[0].name)}+0x{location[1]:x}"
    if args.safe:
        print(
            f"exception thread={thread_id} code=0x{code:08x} flags=0x{flags:x} "
            f"location={where.strip() or '<unknown module>'} "
            f"parameter_count={parameter_count}"
        )
        print("modules=" + ", ".join(compact_name(module.name) for module in dump.modules))
        return
    print(
        f"exception thread={thread_id} code=0x{code:08x} flags=0x{flags:x} "
        f"address=0x{exception_address:016x}{where} params={[hex(item) for item in parameters]}"
    )
    for row in ("rax rcx rdx rbx", "rsp rbp rsi rdi", "r8 r9 r10 r11", "r12 r13 r14 r15", "rip"):
        print(" ".join(f"{name}={registers[name]:016x}" for name in row.split()))

    print("\nmodules:")
    for module in dump.modules:
        print(f"  {module.base:016x}-{module.base + module.size:016x} {compact_name(module.name)}")

    print("\nregister memory:")
    for name in ("rcx", "rdx", "rbx", "r9", "rsp", "rbp", "rsi", "rdi"):
        address = registers[name]
        print(f"{name} @ 0x{address:016x}")
        print(hex_dump(dump, address, 64))

    for address, size in args.memory:
        print(f"memory @ 0x{address:016x} size=0x{size:x}")
        print(hex_dump(dump, address, size))

    stack_start = registers["rsp"]
    stack = dump.read(stack_start, args.stack_bytes)
    if args.stack_hex:
        print("\nstack qwords:")
        if stack is None:
            print("  <stack not captured>")
        else:
            for offset in range(0, len(stack) - 7, 8):
                value = u64(stack, offset)
                target = dump.module_at(value)
                suffix = ""
                if target:
                    module, module_offset = target
                    suffix = (
                        f" {compact_name(module.name)}+0x{module_offset:x}"
                    )
                print(f"  rsp+0x{offset:04x} 0x{value:016x}{suffix}")
    print("\nstack code-pointer candidates:")
    if stack is None:
        print("  <stack not captured>")
        return
    for offset in range(0, len(stack) - 7, 8):
        value = u64(stack, offset)
        target = dump.module_at(value)
        if target:
            module, module_offset = target
            print(
                f"  rsp+0x{offset:04x} 0x{value:016x} "
                f"{compact_name(module.name)}+0x{module_offset:x}"
            )


if __name__ == "__main__":
    main()
