#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "hde64.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <vector>

namespace {

struct TextSection {
    uint32_t rva = 0;
    uint32_t offset = 0;
    uint32_t size = 0;
};

struct Instruction {
    uint32_t rva = 0;
    uint32_t offset = 0;
    hde64s decoded{};
};

bool ReadImage(const wchar_t* path, std::vector<uint8_t>& image,
               TextSection& text) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) return false;
    const std::streamsize size = file.tellg();
    file.seekg(0);
    image.resize(static_cast<size_t>(size));
    if (!file.read(reinterpret_cast<char*>(image.data()), size) ||
        image.size() < sizeof(IMAGE_DOS_HEADER)) {
        return false;
    }
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0) return false;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        image.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return false;
    }
    const auto* sections = IMAGE_FIRST_SECTION(nt);
    for (unsigned index = 0; index < nt->FileHeader.NumberOfSections; ++index) {
        char name[9]{};
        std::memcpy(name, sections[index].Name, 8);
        if (std::strcmp(name, ".text") != 0) continue;
        text.rva = sections[index].VirtualAddress;
        text.offset = sections[index].PointerToRawData;
        text.size = sections[index].SizeOfRawData;
        return static_cast<size_t>(text.offset) + text.size <= image.size();
    }
    return false;
}

bool IsRipRelative(const hde64s& decoded) {
    return (decoded.flags & F_MODRM) && (decoded.flags & F_DISP32) &&
        decoded.modrm_mod == 0 && decoded.modrm_rm == 5;
}

bool CallsIat(const Instruction& instruction, uint32_t target) {
    const hde64s& decoded = instruction.decoded;
    if (decoded.opcode != 0xff || decoded.modrm_reg != 2 ||
        !IsRipRelative(decoded)) {
        return false;
    }
    const uint32_t resolved = static_cast<uint32_t>(
        static_cast<int64_t>(instruction.rva + decoded.len) +
        static_cast<int32_t>(decoded.disp.disp32));
    return resolved == target;
}

bool InterfaceSlotCall(const hde64s& decoded, unsigned max_slot,
                       unsigned& slot) {
    if (decoded.opcode != 0xff || !(decoded.flags & F_MODRM) ||
        decoded.modrm_reg != 2 || decoded.modrm_mod == 3 ||
        IsRipRelative(decoded)) {
        return false;
    }
    int64_t displacement = 0;
    if (decoded.flags & F_DISP8) {
        displacement = static_cast<int8_t>(decoded.disp.disp8);
    } else if (decoded.flags & F_DISP32) {
        displacement = static_cast<int32_t>(decoded.disp.disp32);
    } else if (decoded.modrm_mod != 0) {
        return false;
    }
    if (displacement < 0 || displacement % 8 != 0 ||
        displacement / 8 > max_slot) {
        return false;
    }
    slot = static_cast<unsigned>(displacement / 8);
    return true;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc < 3 || argc > 4) {
        std::fwprintf(
            stderr,
            L"usage: steam_accessor_scanner.exe <pe> <accessor-iat-rva> "
            L"[max-slot]\n");
        return 2;
    }
    wchar_t* end = nullptr;
    const uint32_t target = static_cast<uint32_t>(
        std::wcstoul(argv[2], &end, 0));
    if (!end || *end) return 3;
    const unsigned max_slot = argc == 4
        ? static_cast<unsigned>(std::wcstoul(argv[3], &end, 0))
        : 63u;
    if (!end || *end) return 3;

    std::vector<uint8_t> image;
    TextSection text{};
    if (!ReadImage(argv[1], image, text)) return 4;
    std::vector<Instruction> instructions;
    uint32_t rva = text.rva;
    uint32_t offset = text.offset;
    while (rva < text.rva + text.size) {
        hde64s decoded{};
        unsigned length = hde64_disasm(image.data() + offset, &decoded);
        if (!length || length > 15) length = 1;
        instructions.push_back({rva, offset, decoded});
        rva += length;
        offset += length;
    }

    unsigned accessor_calls = 0;
    unsigned slot_candidates = 0;
    for (size_t index = 0; index < instructions.size(); ++index) {
        if (!CallsIat(instructions[index], target)) continue;
        ++accessor_calls;
        unsigned local_candidates = 0;
        for (size_t cursor = index + 1; cursor < instructions.size(); ++cursor) {
            const Instruction& candidate = instructions[cursor];
            if (candidate.rva > instructions[index].rva + 0x40) break;
            if (candidate.decoded.opcode == 0xc3 ||
                candidate.decoded.opcode == 0xc2) {
                break;
            }
            unsigned slot = 0;
            if (!InterfaceSlotCall(candidate.decoded, max_slot, slot)) continue;
            ++local_candidates;
            ++slot_candidates;
            std::printf(
                "accessor_call=0x%x vcall=0x%x delta=0x%x slot=%u "
                "byte_offset=0x%x\n",
                instructions[index].rva, candidate.rva,
                candidate.rva - instructions[index].rva, slot, slot * 8);
        }
        if (!local_candidates) {
            std::printf("accessor_call=0x%x vcall=none\n",
                        instructions[index].rva);
        }
    }
    std::printf(
        "summary accessor_iat_rva=0x%x accessor_calls=%u "
        "nearby_slot_candidates=%u window=0x40\n",
        target, accessor_calls, slot_candidates);
    return 0;
}
