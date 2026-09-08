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
#include <vector>

namespace {

struct TextSection {
    uint32_t rva = 0;
    uint32_t offset = 0;
    uint32_t size = 0;
};

struct AuditRange {
    const char* name;
    uint32_t begin;
    uint32_t end;
};

struct ExpectedSite {
    uint32_t rva;
    uint8_t value;
    const char* classification;
    std::array<uint8_t, 9> bytes;
    uint8_t size;
};

struct ExpectedCall {
    uint32_t rva;
    const char* classification;
};

// Full native bodies/fragments that form the observed result path. The two
// underlying reward implementations contain multiple unwind fragments, so
// their audited ranges intentionally cover the complete contiguous bodies
// established by the prior disassembly rather than only one .pdata entry.
constexpr std::array<AuditRange, 12> kRanges = {{
    {"result_sync_begin_wrapper", 0x42ac40, 0x42ac55},
    {"mission_result_exec_begin", 0x42fd20, 0x4306e0},
    {"named_sync_begin", 0x41f820, 0x41f920},
    {"named_sync_poll", 0x41f920, 0x41f9d5},
    {"resolve_result_wrapper", 0x3e3150, 0x3e3160},
    {"apply_result_wrapper", 0x3e3160, 0x3e3189},
    {"resolve_result_impl", 0x1991d0, 0x199ccd},
    {"apply_result_impl", 0x199d50, 0x199ec7},
    {"mission_sync_res", 0x42d8a0, 0x42e19f},
    {"net_game_status", 0x430c20, 0x4312fe},
    {"script_sync_caller", 0x3e2ca0, 0x3e2e45},
    {"network_sync_caller", 0x42c0d6, 0x42c1ed},
}};

constexpr uint32_t kMissionResultExecBeginRva = 0x42fd20;
constexpr std::array<ExpectedCall, 2> kExpectedExecBeginCalls = {{
    {0x1153ee, "mission_script_dispatch"},
    {0x42ac48, "result_sync_begin_wrapper"},
}};
constexpr std::array<uint8_t, 21> kResultSyncBeginWrapper = {{
    0x40, 0x53, 0x48, 0x83, 0xec, 0x20, 0x8b, 0xd9,
    0xe8, 0xd3, 0x50, 0x00, 0x00, 0x8b, 0xc3,
    0x48, 0x83, 0xc4, 0x20, 0x5b, 0xc3,
}};
constexpr uint32_t kMissionResultExecUpdateRva = 0x430c20;
constexpr std::array<ExpectedCall, 2> kExpectedExecUpdateCalls = {{
    {0x42ac9f, "result_sync_update_wrapper"},
    {0x12aa8d, "native_mission_consumer"},
}};
constexpr std::array<uint8_t, 17> kResultSyncUpdateWrapperPrefix = {{
    0x48, 0x89, 0x5c, 0x24, 0x08, 0x57,
    0x48, 0x83, 0xec, 0x60, 0x8b, 0xf9,
    0xe8, 0xaf, 0xf9, 0x79, 0x00,
}};
constexpr std::array<uint8_t, 9> kResultSyncUpdateCallAndBranch = {{
    0xe8, 0x7c, 0x5f, 0x00, 0x00, 0x84, 0xc0, 0x74, 0x23,
}};
constexpr uint32_t kMissionResultExecFinallyRva = 0x42f090;
constexpr std::array<ExpectedCall, 2> kExpectedExecFinallyCalls = {{
    {0x42ac28, "result_sync_finally_wrapper"},
    {0x12aaa9, "native_mission_consumer"},
}};
constexpr std::array<uint8_t, 22> kResultSyncFinallyWrapper = {{
    0x40, 0x53, 0x48, 0x83, 0xec, 0x20, 0x8b, 0xd9,
    0xe8, 0x63, 0x44, 0x00, 0x00, 0x8d, 0x43, 0x01,
    0x48, 0x83, 0xc4, 0x20, 0x5b, 0xc3,
}};

constexpr std::array<ExpectedSite, 15> kExpectedSites = {{
    {0x1993d1, 4, "dynamic_stride_16",
     {0x48, 0xc1, 0xe0, 0x04}, 4},
    {0x1994e7, 3, "aggregate_divide_8",
     {0x49, 0xc1, 0xf8, 0x03}, 4},
    {0x199503, 4, "dynamic_stride_16",
     {0x48, 0xc1, 0xe1, 0x04}, 4},
    {0x199da3, 4, "result_state_bit_flag",
     {0x41, 0x83, 0x8c, 0x81, 0x0c, 0xea, 0x00, 0x00, 0x04}, 9},
    {0x3e2d13, 15, "named_sync_constant",
     {0x48, 0xc7, 0x44, 0x24, 0x40, 0x0f, 0x00, 0x00, 0x00}, 9},
    {0x3e2d9a, 15, "named_sync_constant",
     {0x48, 0xc7, 0x44, 0x24, 0x40, 0x0f, 0x00, 0x00, 0x00}, 9},
    {0x41f86e, 15, "named_sync_constant",
     {0x48, 0xc7, 0x44, 0x24, 0x50, 0x0f, 0x00, 0x00, 0x00}, 9},
    {0x42da7f, 4, "dynamic_vector_initial_reserve",
     {0xba, 0x04, 0x00, 0x00, 0x00}, 5},
    {0x42db4c, 4, "online_participant_filter",
     {0x83, 0xf8, 0x04}, 3},
    {0x42dc03, 4, "dynamic_stride_16",
     {0x48, 0xc1, 0xe3, 0x04}, 4},
    {0x42e0ee, 4, "dynamic_stride_16",
     {0x48, 0xc1, 0xe0, 0x04}, 4},
    {0x430268, 4, "dynamic_stride_16",
     {0x48, 0xc1, 0xe2, 0x04}, 4},
    {0x430365, 4, "dynamic_stride_16",
     {0x48, 0xc1, 0xe2, 0x04}, 4},
    {0x430ef6, 4, "fixed_item_accumulator_count",
     {0x83, 0xfb, 0x04}, 3},
    {0x430f23, 4, "online_participant_filter",
     {0x83, 0xfb, 0x04}, 3},
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

bool SmallImmediate(const hde64s& decoded, uint8_t& value) {
    if (decoded.flags & F_RELATIVE) return false;
    uint64_t immediate = 0;
    if (decoded.flags & F_IMM8) immediate = decoded.imm.imm8;
    else if (decoded.flags & F_IMM16) immediate = decoded.imm.imm16;
    else if (decoded.flags & F_IMM32) immediate = decoded.imm.imm32;
    else if (decoded.flags & F_IMM64) immediate = decoded.imm.imm64;
    else return false;
    if (immediate != 3 && immediate != 4 && immediate != 15) return false;
    value = static_cast<uint8_t>(immediate);
    return true;
}

bool CapacityMask(const hde64s& decoded, uint8_t value) {
    if (value != 3 && value != 15) return false;
    if ((decoded.opcode == 0x83 || decoded.opcode == 0x81) &&
        (decoded.flags & F_MODRM) && decoded.modrm_reg == 4) {
        return true;
    }
    return decoded.opcode == 0x25;
}

const ExpectedSite* FindExpected(uint32_t rva) {
    const auto found = std::find_if(
        kExpectedSites.begin(), kExpectedSites.end(),
        [=](const ExpectedSite& site) { return site.rva == rva; });
    return found == kExpectedSites.end() ? nullptr : &*found;
}

void PrintBytes(const uint8_t* bytes, unsigned size) {
    for (unsigned index = 0; index < size; ++index) {
        std::printf("%02x", bytes[index]);
    }
}

template <size_t N>
const ExpectedCall* FindExpectedCall(
    const std::array<ExpectedCall, N>& expected_calls, uint32_t rva) {
    const auto found = std::find_if(
        expected_calls.begin(), expected_calls.end(),
        [=](const ExpectedCall& call) { return call.rva == rva; });
    return found == expected_calls.end() ? nullptr : &*found;
}

struct DirectCallAudit {
    std::set<uint32_t> observed;
    size_t unexpected = 0;
    size_t missing = 0;
};

template <size_t N>
DirectCallAudit AuditDirectCalls(
    const std::vector<uint8_t>& image, const TextSection& text,
    uint32_t target_rva,
    const std::array<ExpectedCall, N>& expected_calls,
    const char* pipeline_name) {
    DirectCallAudit audit;
    for (uint32_t relative = 0; relative + 5 <= text.size; ++relative) {
        const size_t offset = static_cast<size_t>(text.offset) + relative;
        if (image[offset] != 0xe8) continue;
        int32_t displacement = 0;
        std::memcpy(&displacement, image.data() + offset + 1,
                    sizeof(displacement));
        const uint32_t call_rva = text.rva + relative;
        const int64_t target = static_cast<int64_t>(call_rva) + 5 +
            static_cast<int64_t>(displacement);
        if (target != target_rva) continue;
        const ExpectedCall* expected_call = FindExpectedCall(
            expected_calls, call_rva);
        if (!expected_call || !audit.observed.insert(call_rva).second) {
            ++audit.unexpected;
        }
        std::printf("%s_call rva=0x%x classification=%s expected=%s\n",
                    pipeline_name, call_rva,
                    expected_call ? expected_call->classification
                                  : "unclassified",
                    expected_call ? "true" : "false");
    }
    for (const auto& expected_call : expected_calls) {
        if (audit.observed.count(expected_call.rva) != 0) continue;
        ++audit.missing;
        std::printf("missing_%s_call rva=0x%x classification=%s\n",
                    pipeline_name, expected_call.rva,
                    expected_call.classification);
    }
    return audit;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc != 2) {
        std::fwprintf(stderr, L"usage: result_pipeline_scanner.exe <pe>\n");
        return 2;
    }
    std::vector<uint8_t> image;
    TextSection text{};
    if (!ReadImage(argv[1], image, text)) {
        std::fwprintf(stderr, L"could not read a valid x64 PE .text section\n");
        return 3;
    }

    std::set<uint32_t> observed;
    size_t value_three = 0;
    size_t value_four = 0;
    size_t value_fifteen = 0;
    size_t capacity_masks = 0;
    size_t decode_errors = 0;
    size_t unexpected = 0;
    size_t decoded_instructions = 0;
    for (const auto& range : kRanges) {
        uint32_t offset = 0;
        if (range.begin >= range.end || !TextOffset(text, range.begin, offset) ||
            range.end > text.rva + text.size ||
            static_cast<size_t>(offset) + range.end - range.begin >
                image.size()) {
            std::printf("FAIL range=%s invalid=1\n", range.name);
            return 4;
        }
        uint32_t rva = range.begin;
        size_t range_candidates = 0;
        while (rva < range.end) {
            hde64s decoded{};
            const unsigned length = hde64_disasm(image.data() + offset,
                                                  &decoded);
            if (!length || length > 15 || rva + length > range.end) {
                ++decode_errors;
                break;
            }
            ++decoded_instructions;
            if (decoded.flags & F_ERROR) ++decode_errors;
            uint8_t value = 0;
            if (SmallImmediate(decoded, value)) {
                ++range_candidates;
                if (value == 3) ++value_three;
                else if (value == 4) ++value_four;
                else ++value_fifteen;
                if (CapacityMask(decoded, value)) ++capacity_masks;
                const ExpectedSite* expected = FindExpected(rva);
                const bool bytes_match = expected &&
                    expected->value == value && expected->size == length &&
                    std::memcmp(image.data() + offset,
                                expected->bytes.data(), length) == 0;
                if (!bytes_match || !observed.insert(rva).second) {
                    ++unexpected;
                }
                std::printf("candidate range=%s rva=0x%x value=%u "
                            "classification=%s expected=%s bytes=",
                            range.name, rva, value,
                            expected ? expected->classification : "unclassified",
                            bytes_match ? "true" : "false");
                PrintBytes(image.data() + offset, length);
                std::printf("\n");
            }
            rva += length;
            offset += length;
        }
        std::printf("range name=%s begin=0x%x end=0x%x bytes=%u "
                    "small_immediates=%zu\n", range.name, range.begin,
                    range.end, range.end - range.begin, range_candidates);
    }

    size_t missing = 0;
    for (const auto& expected : kExpectedSites) {
        if (observed.count(expected.rva) == 0) {
            ++missing;
            std::printf("missing rva=0x%x classification=%s\n",
                        expected.rva, expected.classification);
        }
    }

    uint32_t wrapper_offset = 0;
    const bool result_sync_begin_wrapper =
        TextOffset(text, 0x42ac40, wrapper_offset) &&
        static_cast<size_t>(wrapper_offset) + kResultSyncBeginWrapper.size() <=
            image.size() &&
        std::memcmp(image.data() + wrapper_offset,
                    kResultSyncBeginWrapper.data(),
                    kResultSyncBeginWrapper.size()) == 0;
    uint32_t update_wrapper_offset = 0;
    uint32_t update_call_offset = 0;
    const bool result_sync_update_wrapper =
        TextOffset(text, 0x42ac60, update_wrapper_offset) &&
        TextOffset(text, 0x42ac9f, update_call_offset) &&
        static_cast<size_t>(update_wrapper_offset) +
                kResultSyncUpdateWrapperPrefix.size() <= image.size() &&
        static_cast<size_t>(update_call_offset) +
                kResultSyncUpdateCallAndBranch.size() <= image.size() &&
        std::memcmp(image.data() + update_wrapper_offset,
                    kResultSyncUpdateWrapperPrefix.data(),
                    kResultSyncUpdateWrapperPrefix.size()) == 0 &&
        std::memcmp(image.data() + update_call_offset,
                    kResultSyncUpdateCallAndBranch.data(),
                    kResultSyncUpdateCallAndBranch.size()) == 0;
    uint32_t finally_wrapper_offset = 0;
    const bool result_sync_finally_wrapper =
        TextOffset(text, 0x42ac20, finally_wrapper_offset) &&
        static_cast<size_t>(finally_wrapper_offset) +
                kResultSyncFinallyWrapper.size() <= image.size() &&
        std::memcmp(image.data() + finally_wrapper_offset,
                    kResultSyncFinallyWrapper.data(),
                    kResultSyncFinallyWrapper.size()) == 0;

    const DirectCallAudit exec_begin_calls = AuditDirectCalls(
        image, text, kMissionResultExecBeginRva,
        kExpectedExecBeginCalls, "exec_begin");
    const DirectCallAudit exec_update_calls = AuditDirectCalls(
        image, text, kMissionResultExecUpdateRva,
        kExpectedExecUpdateCalls, "exec_update");
    const DirectCallAudit exec_finally_calls = AuditDirectCalls(
        image, text, kMissionResultExecFinallyRva,
        kExpectedExecFinallyCalls, "exec_finally");
    const size_t unexpected_calls = exec_begin_calls.unexpected +
        exec_update_calls.unexpected + exec_finally_calls.unexpected;
    const size_t missing_calls = exec_begin_calls.missing +
        exec_update_calls.missing + exec_finally_calls.missing;
    std::printf(
        "summary ranges=%zu decoded_instructions=%zu small_immediates=15 "
        "value_3=%zu value_4=%zu value_15=%zu dynamic_stride_16=6 "
        "aggregate_divide_8=1 result_state_bit_flag=1 "
        "dynamic_vector_initial_reserve=1 online_participant_filters=2 "
        "fixed_item_accumulator_count=1 named_sync_constants=3 "
        "exec_begin_direct_callers=%zu result_sync_begin_wrapper=%s "
        "exec_update_direct_callers=%zu result_sync_update_wrapper=%s "
        "exec_finally_direct_callers=%zu result_sync_finally_wrapper=%s "
        "capacity_masks=%zu unexpected=%zu missing=%zu "
        "unexpected_calls=%zu missing_calls=%zu decode_errors=%zu\n",
        kRanges.size(), decoded_instructions, value_three, value_four,
        value_fifteen, exec_begin_calls.observed.size(),
        result_sync_begin_wrapper ? "true" : "false",
        exec_update_calls.observed.size(),
        result_sync_update_wrapper ? "true" : "false",
        exec_finally_calls.observed.size(),
        result_sync_finally_wrapper ? "true" : "false", capacity_masks,
        unexpected, missing, unexpected_calls, missing_calls, decode_errors);
    return value_three == 1 && value_four == 11 && value_fifteen == 3 &&
                   capacity_masks == 0 && unexpected == 0 && missing == 0 &&
                   unexpected_calls == 0 && missing_calls == 0 &&
                   result_sync_begin_wrapper &&
                   result_sync_update_wrapper &&
                   result_sync_finally_wrapper && decode_errors == 0
               ? 0
               : 5;
}
