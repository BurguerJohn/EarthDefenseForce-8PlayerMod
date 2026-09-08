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

struct FunctionRange {
    uint32_t begin = 0;
    uint32_t end = 0;
};

struct Seed {
    const char* name;
    uint32_t rva;
};

// These are not assumed to be the only player-related routines. They are the
// dump- and call-flow-backed roots from which the audit starts.
constexpr std::array<Seed, 9> kSeeds = {{
    {"mission_player_builder", 0x11ce60},
    {"mission_record_pipeline", 0x11d860},
    {"mission_participant_vector", 0x126c90},
    {"mission_source_consumer", 0x3123a0},
    {"mission_script_update", 0x3e1890},
    {"room_player_info_builder", 0x421ea0},
    {"lobby_roster_enumerator", 0x457290},
    {"room_update", 0x5617f0},
    {"room_panel_update", 0x5a5bd0},
}};

constexpr uint32_t kIndexedSharedHandleLookupRva = 0x7e240;
constexpr std::array<uint32_t, 3> kConfirmedMissionLookupCalls = {
    0x11cf08, 0x11dfce, 0x11e057,
};
constexpr uint32_t kReceiveRouteRegisterRva = 0x433bd0;
constexpr uint32_t kReceiveRouteUnregisterRva = 0x433dd0;
constexpr uint32_t kReceiveRouteRegisterCallRva = 0x451b64;
constexpr uint32_t kReceiveRouteUnregisterCallRva = 0x451af6;
constexpr uint32_t kReceiveRouteObjectConstructorRva = 0x435da0;
constexpr uint32_t kReceiveRouteObjectConstructorCallRva = 0x433cea;
constexpr uint32_t kReceiveRouteUserControlCopyRva = 0x435e37;
constexpr uint32_t kReceiveParserConstructorRva = 0x4351f0;
constexpr uint32_t kReceiveParserConstructorCallRva = 0x435fc0;
constexpr uint32_t kReceiveParserOwnerStoreRva = 0x4352f0;
constexpr uint32_t kReceiveParserCallRva = 0x4339dc;
constexpr std::array<uint8_t, 18> kReceiveRouteRegisterSignature = {{
    0x48, 0x89, 0x54, 0x24, 0x10,
    0x53, 0x55, 0x56, 0x57, 0x41, 0x56,
    0x48, 0x81, 0xec, 0x80, 0x00, 0x00, 0x00,
}};
constexpr std::array<uint8_t, 15> kReceiveRouteUnregisterSignature = {{
    0x48, 0x89, 0x5c, 0x24, 0x18,
    0x48, 0x89, 0x6c, 0x24, 0x20,
    0x57, 0x48, 0x83, 0xec, 0x40,
}};
constexpr std::array<uint8_t, 22> kReceiveRouteObjectConstructorSignature = {{
    0x48, 0x8b, 0xc4, 0x48, 0x89, 0x48, 0x08,
    0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56,
    0x41, 0x57, 0x48, 0x83, 0xec, 0x30,
}};
constexpr std::array<uint8_t, 31> kReceiveRouteUserControlCopySignature = {{
    0x48, 0x8b, 0x46, 0x18, 0x48, 0x89, 0x47, 0x58,
    0x48, 0x8b, 0x46, 0x20,
    0x48, 0x8b, 0x80, 0xc4, 0x00, 0x00, 0x00,
    0x48, 0x89, 0x47, 0x60,
    0x48, 0x8b, 0x46, 0x10, 0x48, 0x89, 0x47, 0x68,
}};
constexpr std::array<uint8_t, 22> kReceiveParserConstructorSignature = {{
    0x48, 0x89, 0x4c, 0x24, 0x08, 0x56, 0x57, 0x41, 0x56,
    0x48, 0x83, 0xec, 0x30,
    0x48, 0xc7, 0x44, 0x24, 0x20, 0xfe, 0xff, 0xff, 0xff,
}};
constexpr std::array<uint8_t, 28> kReceiveParserOwnerStoreSignature = {{
    0x48, 0x89, 0xaf, 0x98, 0x04, 0x00, 0x00,
    0x48, 0x8b, 0x06,
    0x48, 0x89, 0x87, 0xa0, 0x04, 0x00, 0x00,
    0x48, 0xc7, 0x87, 0xa8, 0x04, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff,
}};
constexpr std::array<uint8_t, 12> kReceiveParserCallSignature = {{
    0x48, 0x8b, 0x88, 0x88, 0x00, 0x00, 0x00,
    0xe8, 0x8f, 0x1c, 0x00, 0x00,
}};

bool ReadImage(const wchar_t* path, std::vector<uint8_t>& image,
               TextSection& text) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) return false;
    const std::streamsize file_size = file.tellg();
    if (file_size <= 0) return false;
    file.seekg(0);
    image.resize(static_cast<size_t>(file_size));
    if (!file.read(reinterpret_cast<char*>(image.data()), file_size) ||
        image.size() < sizeof(IMAGE_DOS_HEADER)) {
        return false;
    }
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

bool TextOffset(const TextSection& text, uint32_t rva, uint32_t& offset) {
    if (rva < text.rva || rva >= text.rva + text.size) return false;
    offset = text.offset + rva - text.rva;
    return true;
}

template <size_t N>
bool BytesMatch(const std::vector<uint8_t>& image, const TextSection& text,
                uint32_t rva, const std::array<uint8_t, N>& expected) {
    uint32_t offset = 0;
    return TextOffset(text, rva, offset) &&
        static_cast<size_t>(offset) + expected.size() <= image.size() &&
        std::memcmp(image.data() + offset, expected.data(),
                    expected.size()) == 0;
}

bool FourInt3(const std::vector<uint8_t>& image, const TextSection& text,
              uint32_t rva) {
    uint32_t offset = 0;
    return TextOffset(text, rva, offset) &&
           static_cast<size_t>(offset) + 4 <= image.size() &&
           image[offset] == 0xcc && image[offset + 1] == 0xcc &&
           image[offset + 2] == 0xcc && image[offset + 3] == 0xcc;
}

FunctionRange EnclosingFunction(const std::vector<uint8_t>& image,
                                const TextSection& text, uint32_t seed) {
    constexpr uint32_t kSearchDistance = 0x10000;
    const uint32_t minimum = seed > kSearchDistance
        ? std::max(text.rva, seed - kSearchDistance) : text.rva;
    const uint32_t maximum = std::min(text.rva + text.size,
                                      seed + kSearchDistance);
    uint32_t begin = seed;
    for (uint32_t cursor = seed; cursor > minimum; --cursor) {
        if (!FourInt3(image, text, cursor - 1)) continue;
        begin = cursor + 3;
        uint32_t offset = 0;
        while (begin < seed && TextOffset(text, begin, offset) &&
               image[offset] == 0xcc) {
            ++begin;
        }
        break;
    }
    uint32_t end = maximum;
    for (uint32_t cursor = std::max(seed, begin + 1); cursor + 4 < maximum;
         ++cursor) {
        if (FourInt3(image, text, cursor)) {
            end = cursor;
            break;
        }
    }
    if (begin >= end || seed < begin || seed >= end) return {};
    return {begin, end};
}

bool DirectCallTarget(const Instruction& instruction, uint32_t& target) {
    if (instruction.decoded.opcode != 0xe8 ||
        !(instruction.decoded.flags & F_RELATIVE) ||
        !(instruction.decoded.flags & F_IMM32)) {
        return false;
    }
    const int32_t relative =
        static_cast<int32_t>(instruction.decoded.imm.imm32);
    target = static_cast<uint32_t>(
        static_cast<int64_t>(instruction.rva) + instruction.decoded.len +
        relative);
    return true;
}

bool CompareImmediateFour(const hde64s& decoded) {
    if ((decoded.opcode == 0x83 || decoded.opcode == 0x81) &&
        (decoded.flags & F_MODRM) && decoded.modrm_reg == 7) {
        return ((decoded.flags & F_IMM8) && decoded.imm.imm8 == 4) ||
               ((decoded.flags & F_IMM32) && decoded.imm.imm32 == 4);
    }
    return decoded.opcode == 0x3d && (decoded.flags & F_IMM32) &&
           decoded.imm.imm32 == 4;
}

int AndMask(const hde64s& decoded) {
    if ((decoded.opcode == 0x83 || decoded.opcode == 0x81) &&
        (decoded.flags & F_MODRM) && decoded.modrm_reg == 4) {
        if ((decoded.flags & F_IMM8) &&
            (decoded.imm.imm8 == 3 || decoded.imm.imm8 == 0x0f)) {
            return decoded.imm.imm8;
        }
        if ((decoded.flags & F_IMM32) &&
            (decoded.imm.imm32 == 3 || decoded.imm.imm32 == 0x0f)) {
            return static_cast<int>(decoded.imm.imm32);
        }
    }
    if (decoded.opcode == 0x25 && (decoded.flags & F_IMM32) &&
        (decoded.imm.imm32 == 3 || decoded.imm.imm32 == 0x0f)) {
        return static_cast<int>(decoded.imm.imm32);
    }
    return -1;
}

bool VariableBitShift(const hde64s& decoded) {
    return decoded.opcode == 0xd3 && (decoded.flags & F_MODRM) &&
           (decoded.modrm_reg == 4 || decoded.modrm_reg == 5 ||
            decoded.modrm_reg == 7);
}

bool BitIndexOperation(const hde64s& decoded) {
    if (decoded.opcode != 0x0f) return false;
    if (decoded.opcode2 == 0xa3 || decoded.opcode2 == 0xab ||
        decoded.opcode2 == 0xb3 || decoded.opcode2 == 0xbb) {
        return true;
    }
    return decoded.opcode2 == 0xba && (decoded.flags & F_MODRM) &&
           decoded.modrm_reg >= 4 && decoded.modrm_reg <= 7;
}

bool ScaledIndex(const hde64s& decoded, unsigned& scale) {
    if ((decoded.opcode == 0x0f && decoded.opcode2 == 0x1f) ||
        !(decoded.flags & F_SIB) || decoded.modrm_mod == 3 ||
        decoded.sib_index == 4) {
        return false;
    }
    scale = 1U << decoded.sib_scale;
    return true;
}

void PrintBytes(const std::vector<uint8_t>& image,
                const Instruction& instruction) {
    for (unsigned index = 0; index < instruction.decoded.len; ++index) {
        std::printf("%02x", image[instruction.offset + index]);
    }
}

const Instruction* FindInstruction(const std::vector<Instruction>& instructions,
                                   uint32_t rva) {
    const auto found = std::lower_bound(
        instructions.begin(), instructions.end(), rva,
        [](const Instruction& instruction, uint32_t value) {
            return instruction.rva < value;
        });
    return found != instructions.end() && found->rva == rva ? &*found
                                                             : nullptr;
}

const char* LookupClassification(uint32_t call_rva) {
    if (std::find(kConfirmedMissionLookupCalls.begin(),
                  kConfirmedMissionLookupCalls.end(), call_rva) !=
        kConfirmedMissionLookupCalls.end()) {
        return "confirmed_mission_context";
    }
    if (call_rva == 0x126d24) return "participant_vector_consumer";
    return "deferred_generic_context";
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) {
        std::fwprintf(stderr,
                      L"usage: player_flow_scanner.exe <pe> [observed-rva ...]\n");
        return 2;
    }
    std::vector<uint8_t> image;
    TextSection text{};
    if (!ReadImage(argv[1], image, text)) {
        std::fwprintf(stderr, L"could not read a valid x64 PE .text section\n");
        return 3;
    }

    std::vector<Instruction> instructions;
    uint32_t rva = text.rva;
    uint32_t offset = text.offset;
    while (rva < text.rva + text.size && offset < text.offset + text.size) {
        hde64s decoded{};
        unsigned length = hde64_disasm(image.data() + offset, &decoded);
        if (!length || length > 15) length = 1;
        instructions.push_back({rva, offset, decoded});
        rva += length;
        offset += length;
    }

    std::printf("player_flow_scan_version=1 text_rva=0x%x text_size=0x%x "
                "instructions=%zu\n", text.rva, text.size,
                instructions.size());

    size_t lookup_callers = 0;
    size_t confirmed_lookup_callers = 0;
    for (const auto& instruction : instructions) {
        uint32_t target = 0;
        if (!DirectCallTarget(instruction, target) ||
            target != kIndexedSharedHandleLookupRva) {
            continue;
        }
        ++lookup_callers;
        const char* classification = LookupClassification(instruction.rva);
        if (std::strcmp(classification, "confirmed_mission_context") == 0) {
            ++confirmed_lookup_callers;
        }
        const FunctionRange function = EnclosingFunction(
            image, text, instruction.rva);
        std::printf("indexed_lookup_call rva=0x%x function=0x%x "
                    "classification=%s bytes=", instruction.rva,
                    function.begin, classification);
        PrintBytes(image, instruction);
        std::printf("\n");
    }

    const bool route_register_signature = BytesMatch(
        image, text, kReceiveRouteRegisterRva,
        kReceiveRouteRegisterSignature);
    const bool route_unregister_signature = BytesMatch(
        image, text, kReceiveRouteUnregisterRva,
        kReceiveRouteUnregisterSignature);
    const bool route_object_constructor_signature = BytesMatch(
        image, text, kReceiveRouteObjectConstructorRva,
        kReceiveRouteObjectConstructorSignature);
    const bool route_user_control_copy_signature = BytesMatch(
        image, text, kReceiveRouteUserControlCopyRva,
        kReceiveRouteUserControlCopySignature);
    const bool parser_constructor_signature = BytesMatch(
        image, text, kReceiveParserConstructorRva,
        kReceiveParserConstructorSignature);
    const bool parser_owner_store_signature = BytesMatch(
        image, text, kReceiveParserOwnerStoreRva,
        kReceiveParserOwnerStoreSignature);
    const bool parser_call_signature = BytesMatch(
        image, text, kReceiveParserCallRva - 7,
        kReceiveParserCallSignature);
    std::set<uint32_t> route_register_callers;
    std::set<uint32_t> route_unregister_callers;
    std::set<uint32_t> route_object_constructor_callers;
    std::set<uint32_t> parser_constructor_callers;
    size_t unexpected_route_callers = 0;
    for (const auto& instruction : instructions) {
        uint32_t target = 0;
        if (!DirectCallTarget(instruction, target)) continue;
        if (target == kReceiveRouteRegisterRva) {
            route_register_callers.insert(instruction.rva);
            if (instruction.rva != kReceiveRouteRegisterCallRva) {
                ++unexpected_route_callers;
            }
            std::printf("receive_route_call action=register rva=0x%x "
                        "expected=%s\n", instruction.rva,
                        instruction.rva == kReceiveRouteRegisterCallRva
                            ? "true" : "false");
        } else if (target == kReceiveRouteUnregisterRva) {
            route_unregister_callers.insert(instruction.rva);
            if (instruction.rva != kReceiveRouteUnregisterCallRva) {
                ++unexpected_route_callers;
            }
            std::printf("receive_route_call action=unregister rva=0x%x "
                        "expected=%s\n", instruction.rva,
                        instruction.rva == kReceiveRouteUnregisterCallRva
                            ? "true" : "false");
        } else if (target == kReceiveRouteObjectConstructorRva) {
            route_object_constructor_callers.insert(instruction.rva);
            std::printf("receive_owner_call action=route_object_constructor "
                        "rva=0x%x expected=%s\n", instruction.rva,
                        instruction.rva ==
                                kReceiveRouteObjectConstructorCallRva
                            ? "true" : "false");
        } else if (target == kReceiveParserConstructorRva) {
            parser_constructor_callers.insert(instruction.rva);
            std::printf("receive_owner_call action=parser_constructor "
                        "rva=0x%x expected=%s\n", instruction.rva,
                        instruction.rva == kReceiveParserConstructorCallRva
                            ? "true" : "false");
        }
    }
    const bool receive_route_lifecycle_valid =
        route_register_signature && route_unregister_signature &&
        route_register_callers ==
            std::set<uint32_t>{kReceiveRouteRegisterCallRva} &&
        route_unregister_callers ==
            std::set<uint32_t>{kReceiveRouteUnregisterCallRva} &&
        unexpected_route_callers == 0;
    const bool receive_owner_chain_valid =
        route_object_constructor_signature &&
        route_user_control_copy_signature && parser_constructor_signature &&
        parser_owner_store_signature && parser_call_signature &&
        route_object_constructor_callers ==
            std::set<uint32_t>{kReceiveRouteObjectConstructorCallRva} &&
        parser_constructor_callers ==
            std::set<uint32_t>{kReceiveParserConstructorCallRva};

    std::vector<Seed> seeds(kSeeds.begin(), kSeeds.end());
    for (int argument = 2; argument < argc; ++argument) {
        wchar_t* end = nullptr;
        const uint32_t observed = static_cast<uint32_t>(
            std::wcstoul(argv[argument], &end, 0));
        if (!end || *end || observed < text.rva ||
            observed >= text.rva + text.size) {
            std::fwprintf(stderr, L"invalid observed RVA: %ls\n",
                          argv[argument]);
            return 4;
        }
        seeds.push_back({"observed_p2p_caller", observed});
    }

    std::set<uint32_t> visited_functions;
    size_t cmp_four = 0;
    size_t mask_three = 0;
    size_t mask_fifteen = 0;
    size_t bit_index = 0;
    size_t variable_shift = 0;
    size_t scaled_index = 0;
    size_t indexed_near_four = 0;
    size_t direct_calls = 0;
    for (const auto& seed : seeds) {
        const FunctionRange function = EnclosingFunction(image, text, seed.rva);
        if (!function.begin || !visited_functions.insert(function.begin).second) {
            continue;
        }
        std::vector<uint32_t> local_cmp_four;
        size_t local_scaled = 0;
        size_t local_calls = 0;
        for (const auto& instruction : instructions) {
            if (instruction.rva < function.begin) continue;
            if (instruction.rva >= function.end) break;
            uint32_t target = 0;
            if (DirectCallTarget(instruction, target)) {
                ++direct_calls;
                ++local_calls;
            }
            if (CompareImmediateFour(instruction.decoded)) {
                ++cmp_four;
                local_cmp_four.push_back(instruction.rva);
                std::printf("candidate kind=compare_four seed=%s rva=0x%x bytes=",
                            seed.name, instruction.rva);
                PrintBytes(image, instruction);
                std::printf("\n");
            }
            const int mask = AndMask(instruction.decoded);
            if (mask == 3 || mask == 0x0f) {
                if (mask == 3) ++mask_three;
                else ++mask_fifteen;
                std::printf("candidate kind=and_mask_%x seed=%s rva=0x%x bytes=",
                            mask, seed.name, instruction.rva);
                PrintBytes(image, instruction);
                std::printf("\n");
            }
            if (BitIndexOperation(instruction.decoded)) {
                ++bit_index;
                std::printf("candidate kind=bit_index seed=%s rva=0x%x bytes=",
                            seed.name, instruction.rva);
                PrintBytes(image, instruction);
                std::printf("\n");
            }
            if (VariableBitShift(instruction.decoded)) {
                ++variable_shift;
                std::printf("candidate kind=variable_shift seed=%s rva=0x%x bytes=",
                            seed.name, instruction.rva);
                PrintBytes(image, instruction);
                std::printf("\n");
            }
            unsigned scale = 0;
            if (ScaledIndex(instruction.decoded, scale)) {
                ++scaled_index;
                ++local_scaled;
                const bool near_four = std::any_of(
                    local_cmp_four.begin(), local_cmp_four.end(),
                    [&](uint32_t compare_rva) {
                        const uint32_t distance = compare_rva > instruction.rva
                            ? compare_rva - instruction.rva
                            : instruction.rva - compare_rva;
                        return distance <= 0x80;
                    });
                if (near_four) {
                    ++indexed_near_four;
                    std::printf("candidate kind=indexed_near_four seed=%s "
                                "rva=0x%x scale=%u bytes=", seed.name,
                                instruction.rva, scale);
                    PrintBytes(image, instruction);
                    std::printf("\n");
                }
            }
        }
        std::printf("seed name=%s requested_rva=0x%x function=0x%x end=0x%x "
                    "bytes=%u direct_calls=%zu scaled_indexes=%zu\n",
                    seed.name, seed.rva, function.begin, function.end,
                    function.end - function.begin, local_calls, local_scaled);
    }

    std::printf("summary seed_functions=%zu indexed_lookup_callers=%zu "
                "confirmed_mission_lookup_callers=%zu compare_four=%zu "
                "and_mask_3=%zu and_mask_f=%zu bit_index=%zu "
                "variable_shift=%zu scaled_index=%zu "
                "indexed_near_four=%zu direct_calls=%zu "
                "receive_route_register_signature=%s "
                "receive_route_unregister_signature=%s "
                "receive_route_register_callers=%zu "
                "receive_route_unregister_callers=%zu "
                "unexpected_route_callers=%zu "
                "receive_route_object_constructor_signature=%s "
                "receive_route_user_control_copy_signature=%s "
                "receive_parser_constructor_signature=%s "
                "receive_parser_owner_store_signature=%s "
                "receive_parser_call_signature=%s "
                "receive_route_object_constructor_callers=%zu "
                "receive_parser_constructor_callers=%zu "
                "receive_owner_chain_valid=%s\n",
                visited_functions.size(), lookup_callers,
                confirmed_lookup_callers, cmp_four, mask_three,
                mask_fifteen, bit_index, variable_shift, scaled_index,
                indexed_near_four, direct_calls,
                route_register_signature ? "true" : "false",
                route_unregister_signature ? "true" : "false",
                route_register_callers.size(),
                route_unregister_callers.size(),
                unexpected_route_callers,
                route_object_constructor_signature ? "true" : "false",
                route_user_control_copy_signature ? "true" : "false",
                parser_constructor_signature ? "true" : "false",
                parser_owner_store_signature ? "true" : "false",
                parser_call_signature ? "true" : "false",
                route_object_constructor_callers.size(),
                parser_constructor_callers.size(),
                receive_owner_chain_valid ? "true" : "false");
    return lookup_callers == 28 && confirmed_lookup_callers == 3 &&
                   receive_route_lifecycle_valid && receive_owner_chain_valid
               ? 0 : 5;
}
