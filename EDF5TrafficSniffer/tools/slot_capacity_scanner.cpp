#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "hde64.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <set>
#include <string>
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

constexpr std::array<uint32_t, 20> kKnownCapacitySites = {
    0x419789, 0x4197a4, 0x4197bc, 0x41bb36, 0x41bb52, 0x41bb76,
    0x41bc0d, 0x432af9, 0x432b14, 0x432b2c, 0x436996, 0x4369b2,
    0x4369db, 0x436aac, 0x44894b, 0x448961, 0x5a59fc, 0x5a5a14,
    0x5a7261, 0x5a726d,
};

constexpr std::array<uint32_t, 2> kKnownCapacitySitesTail = {
    0x5a7281, 0x5a72dc,
};

constexpr std::array<uint32_t, 24> kExperimentalReserveAnchors = {
    0x14958d, 0x1cdcf2, 0x1ce773, 0x1d8176, 0x1d95ad, 0x1f7d70,
    0x1fbf2a, 0x1fc508, 0x25d408, 0x263925, 0x2769a2, 0x282612,
    0x29cba2, 0x2a27a5, 0x2a6f6f, 0x2b0242, 0x2b837d, 0x2bb10d,
    0x2c4b67, 0x2d17f3, 0x34eaa0, 0x35037a, 0x47a4cf, 0x4aecfe,
};

constexpr std::array<uint32_t, 11> kDeferredFourAnchors = {
    0x5b6c1, 0xd2238, 0xd25b6, 0x2bd3cf, 0x971940, 0x9722c7,
    0xc3b97c, 0xc3b9fa, 0xc3ba2d, 0xc3bc1a, 0xc3bc76,
};

constexpr std::array<uint32_t, 6> kReviewedNonRosterAnchors = {
    0x4594cc, 0x4b8bc0, 0x4b8fe6, 0x4bcdc8, 0x4bd536, 0x4bd7c1,
};

template <size_t Size>
bool Contains(const std::array<uint32_t, Size>& values, uint32_t rva) {
    return std::find(values.begin(), values.end(), rva) != values.end();
}

bool IsKnown(uint32_t rva) {
    return std::find(kKnownCapacitySites.begin(), kKnownCapacitySites.end(),
                     rva) != kKnownCapacitySites.end() ||
           std::find(kKnownCapacitySitesTail.begin(), kKnownCapacitySitesTail.end(),
                     rva) != kKnownCapacitySitesTail.end();
}

const char* Classification(uint32_t rva) {
    if (IsKnown(rva)) return "proven";
    if (Contains(kExperimentalReserveAnchors, rva)) {
        return "experimental_reserve";
    }
    if (Contains(kDeferredFourAnchors, rva)) return "deferred";
    if (Contains(kReviewedNonRosterAnchors, rva)) return "reviewed_non_roster";
    return "unclassified";
}

bool ReadImage(const wchar_t* path, std::vector<uint8_t>& image,
               TextSection& text) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) return false;
    const std::streamsize file_size = file.tellg();
    if (file_size <= 0) return false;
    file.seekg(0);
    image.resize(static_cast<size_t>(file_size));
    if (!file.read(reinterpret_cast<char*>(image.data()), file_size)) return false;
    if (image.size() < sizeof(IMAGE_DOS_HEADER)) return false;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 ||
        static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) >
            image.size()) {
        return false;
    }
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

bool ImmediateFour(const hde64s& decoded) {
    return ((decoded.flags & F_IMM8) && decoded.imm.imm8 == 4) ||
           ((decoded.flags & F_IMM16) && decoded.imm.imm16 == 4) ||
           ((decoded.flags & F_IMM32) && decoded.imm.imm32 == 4) ||
           ((decoded.flags & F_IMM64) && decoded.imm.imm64 == 4);
}

bool CapacityCompare(const hde64s& decoded) {
    if (decoded.opcode != 0x83 || !(decoded.flags & F_MODRM) ||
        decoded.modrm_reg != 7 || decoded.modrm_mod == 3 ||
        !(decoded.flags & F_IMM8) || decoded.imm.imm8 != 4) {
        return false;
    }
    if ((decoded.flags & F_DISP8) && decoded.disp.disp8 == 0x10) return true;
    return (decoded.flags & F_DISP32) && decoded.disp.disp32 == 0x10;
}

bool AllocationCountLea(const hde64s& decoded, unsigned& element_size) {
    if (decoded.opcode != 0x8d || !(decoded.flags & F_MODRM) ||
        decoded.modrm_mod != 1 || decoded.modrm_reg != 1 ||
        decoded.modrm_rm != 2 || !(decoded.flags & F_DISP8)) {
        return false;
    }
    const int displacement = static_cast<int8_t>(decoded.disp.disp8);
    const int inferred = 4 - displacement;
    if (inferred != 16 && inferred != 24 && inferred != 32 &&
        inferred != 40 && inferred != 48 && inferred != 64 &&
        inferred != 80 && inferred != 96 && inferred != 128) {
        return false;
    }
    element_size = static_cast<unsigned>(inferred);
    return true;
}

uint32_t PreviousPaddingBoundary(const std::vector<uint8_t>& image,
                                 const TextSection& text, uint32_t rva) {
    uint32_t cursor = rva;
    const uint32_t minimum = rva > 0x400 ? rva - 0x400 : text.rva;
    while (cursor > minimum && cursor > text.rva) {
        const uint32_t offset = text.offset + cursor - text.rva;
        if (offset >= 4 && image[offset - 1] == 0xcc &&
            image[offset - 2] == 0xcc && image[offset - 3] == 0xcc &&
            image[offset - 4] == 0xcc) {
            while (cursor < rva) {
                const uint32_t at = text.offset + cursor - text.rva;
                if (at >= image.size() || image[at] != 0xcc) break;
                ++cursor;
            }
            return cursor;
        }
        --cursor;
    }
    return 0;
}

void PrintBytes(const std::vector<uint8_t>& image, const Instruction& instruction) {
    for (unsigned index = 0; index < instruction.decoded.len; ++index) {
        std::printf("%02x", image[instruction.offset + index]);
    }
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) {
        std::fwprintf(stderr,
                      L"usage: slot_capacity_scanner.exe <pe> [target-rva ...]\n");
        return 2;
    }

    std::vector<uint8_t> image;
    TextSection text{};
    if (!ReadImage(argv[1], image, text)) {
        std::fwprintf(stderr, L"could not read a valid x64 PE .text section\n");
        return 3;
    }

    std::vector<Instruction> instructions;
    uint32_t cursor_rva = text.rva;
    uint32_t cursor_offset = text.offset;
    const uint32_t text_end = text.rva + text.size;
    while (cursor_rva < text_end && cursor_offset < text.offset + text.size) {
        hde64s decoded{};
        unsigned length = hde64_disasm(image.data() + cursor_offset, &decoded);
        if (!length || length > 15) length = 1;
        instructions.push_back({cursor_rva, cursor_offset, decoded});
        cursor_rva += length;
        cursor_offset += length;
    }

    std::vector<size_t> anchors;
    std::vector<size_t> allocation_leas;
    size_t immediate_four_count = 0;
    for (size_t index = 0; index < instructions.size(); ++index) {
        if (ImmediateFour(instructions[index].decoded)) ++immediate_four_count;
        if (CapacityCompare(instructions[index].decoded)) anchors.push_back(index);
        unsigned element_size = 0;
        if (AllocationCountLea(instructions[index].decoded, element_size)) {
            allocation_leas.push_back(index);
        }
    }

    std::printf("scan_version=1 text_rva=0x%x text_size=0x%x instructions=%zu "
                "immediate_four=%zu capacity_compare_anchors=%zu "
                "allocation_count_leas=%zu\n",
                text.rva, text.size, instructions.size(), immediate_four_count,
                anchors.size(), allocation_leas.size());

    std::set<uint32_t> contextual_immediates;
    size_t known_anchor_count = 0;
    for (size_t anchor_index : anchors) {
        const Instruction& anchor = instructions[anchor_index];
        if (IsKnown(anchor.rva)) ++known_anchor_count;
        const uint32_t function = PreviousPaddingBoundary(image, text, anchor.rva);
        size_t nearby_four = 0;
        size_t nearby_calls = 0;
        const uint32_t begin = anchor.rva > 0x100 ? anchor.rva - 0x100 : text.rva;
        const uint32_t end = anchor.rva + 0x100;
        for (const auto& instruction : instructions) {
            if (instruction.rva < begin) continue;
            if (instruction.rva > end) break;
            if (ImmediateFour(instruction.decoded)) {
                ++nearby_four;
                contextual_immediates.insert(instruction.rva);
            }
            if (instruction.decoded.opcode == 0xe8 &&
                (instruction.decoded.flags & F_RELATIVE)) {
                ++nearby_calls;
            }
        }
        std::printf("anchor rva=0x%x function=", anchor.rva);
        if (function) std::printf("0x%x", function);
        else std::printf("unknown");
        std::printf(" known=%s classification=%s nearby_four=%zu "
                    "nearby_calls=%zu bytes=",
                    IsKnown(anchor.rva) ? "true" : "false",
                    Classification(anchor.rva), nearby_four, nearby_calls);
        PrintBytes(image, anchor);
        std::printf("\n");
    }

    for (size_t instruction_index : allocation_leas) {
        const Instruction& instruction = instructions[instruction_index];
        unsigned element_size = 0;
        AllocationCountLea(instruction.decoded, element_size);
        const bool close_to_anchor = std::any_of(
            anchors.begin(), anchors.end(), [&](size_t anchor_index) {
                const uint32_t anchor_rva = instructions[anchor_index].rva;
                const uint32_t distance = anchor_rva > instruction.rva
                    ? anchor_rva - instruction.rva
                    : instruction.rva - anchor_rva;
                return distance <= 0x100;
            });
        if (!close_to_anchor) continue;
        std::printf("allocation_lea rva=0x%x element_size=%u known=%s bytes=",
                    instruction.rva, element_size,
                    IsKnown(instruction.rva) ? "true" : "false");
        PrintBytes(image, instruction);
        std::printf("\n");
    }

    std::printf("summary known_capacity_anchors=%zu unknown_capacity_anchors=%zu "
                "experimental_reserve_anchors=%zu deferred_four_anchors=%zu "
                "reviewed_non_roster_anchors=%zu contextual_immediates=%zu\n",
                known_anchor_count, anchors.size() - known_anchor_count,
                kExperimentalReserveAnchors.size(),
                kDeferredFourAnchors.size(),
                kReviewedNonRosterAnchors.size(), contextual_immediates.size());

    for (int argument = 2; argument < argc; ++argument) {
        wchar_t* end = nullptr;
        const uint32_t target = static_cast<uint32_t>(
            std::wcstoul(argv[argument], &end, 0));
        if (!end || *end) {
            std::fwprintf(stderr, L"invalid target RVA: %ls\n", argv[argument]);
            return 4;
        }
        size_t caller_count = 0;
        for (const auto& instruction : instructions) {
            if (instruction.decoded.opcode != 0xe8 ||
                !(instruction.decoded.flags & F_RELATIVE) ||
                !(instruction.decoded.flags & F_IMM32)) {
                continue;
            }
            const int32_t relative =
                static_cast<int32_t>(instruction.decoded.imm.imm32);
            const uint32_t observed_target = static_cast<uint32_t>(
                static_cast<int64_t>(instruction.rva) +
                instruction.decoded.len + relative);
            if (observed_target != target) continue;
            ++caller_count;
            const uint32_t function = PreviousPaddingBoundary(
                image, text, instruction.rva);
            std::printf("caller target=0x%x rva=0x%x function=", target,
                        instruction.rva);
            if (function) std::printf("0x%x", function);
            else std::printf("unknown");
            std::printf("\n");
        }
        std::printf("caller_summary target=0x%x count=%zu\n", target,
                    caller_count);
    }
    return 0;
}
