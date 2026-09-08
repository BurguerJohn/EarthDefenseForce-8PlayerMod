#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "native_roster_patch.h"

#include "logger.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <iterator>
#include <limits>
#include <string>

namespace edf41::native_roster_patch {
namespace {

constexpr unsigned kNativeCapacity = 4;
constexpr unsigned kMaximumCapacity = 8;
constexpr unsigned kSessionEntryBytes = 16;

enum class OperandKind : uint8_t {
    Capacity,
    SessionAllocationTailBytes,
};

struct PatchSite {
    uintptr_t rva;
    std::array<uint8_t, 8> original;
    size_t length;
    size_t operand_offset;
    size_t operand_width;
    OperandKind kind;
};

// net::SessionController owns a vector-like object at +0xC8 whose allocation,
// capacity and logical size live at +0xD0/+0xD8/+0xE0. Its reserve helper is
// specialized for four 16-byte shared-pointer records, so every one of its
// coherent capacity operands must change together. net::Users independently
// owns the pointer vector at +0xC8 mapped by the first P5 crash.
constexpr std::array<PatchSite, 8> kPatchSites{{
    {0x00394B58, {{0x48, 0x83, 0x7F, 0x10, 0x04}}, 5, 4, 1,
     OperandKind::Capacity},
    {0x00394B70, {{0xBA, 0x04, 0x00, 0x00, 0x00}}, 5, 1, 4,
     OperandKind::Capacity},
    {0x00398F26, {{0x48, 0x83, 0x79, 0x10, 0x04}}, 5, 4, 1,
     OperandKind::Capacity},
    {0x00398F42, {{0x8D, 0x4A, 0x30}}, 3, 2, 1,
     OperandKind::SessionAllocationTailBytes},
    {0x00398F5C, {{0xBD, 0x04, 0x00, 0x00, 0x00}}, 5, 1, 4,
     OperandKind::Capacity},
    {0x00398FEA, {{0x48, 0xC7, 0x47, 0x10, 0x04, 0x00, 0x00, 0x00}}, 8, 4,
     4, OperandKind::Capacity},
    {0x003AA5C2, {{0x8D, 0x56, 0x04}}, 3, 2, 1,
     OperandKind::Capacity},
    {0x003AA5D6, {{0x8D, 0x56, 0x04}}, 3, 2, 1,
     OperandKind::Capacity},
}};

constexpr uintptr_t kPatchBeginRva = 0x00394B58;
constexpr uintptr_t kPatchEndRva = 0x004C5CD2;
constexpr unsigned kSessionControllerSites = 6;
constexpr unsigned kUsersSites = 2;

// UiOnlineRoom::refresh_members owns four weak references to
// UiOnlineRoom_MemberWindow at owner+0x240..+0x258. Index four instead names
// the next, unrelated xgs::ui::Object at +0x260; index five reads non-pointer
// layout state. The original function blindly locks those weak references and
// later dynamic_casts the result. Extra network members therefore remain
// intentionally headless until a real eight-row room layout exists.
constexpr uintptr_t kUiWeakLockCallRva = 0x004C5C04;
constexpr uintptr_t kUiWeakLockTargetRva = 0x000B29D0;
constexpr std::array<uint8_t, 5> kUiWeakLockCallOriginal{{
    0xE8, 0xC7, 0xCD, 0xBE, 0xFF,
}};
constexpr uintptr_t kUiFillerBranchRva = 0x004C5CCC;
constexpr std::array<uint8_t, 6> kUiFillerBranchOriginal{{
    0x0F, 0x84, 0xF2, 0x00, 0x00, 0x00,
}};
constexpr uint8_t kUiFillerBranchExpandedOpcode = 0x83;  // jae, not je
constexpr unsigned kUiMemberWindows = 4;
constexpr unsigned kUiPatchSites = 2;
constexpr size_t kUiRelayBytes = 37;

SRWLOCK g_patch_lock = SRWLOCK_INIT;
std::atomic<bool> g_ready{false};
bool g_installed = false;
bool g_harness_simulation = false;
uint8_t g_installed_capacity = 0;
void* g_ui_relay = nullptr;

bool ProcessNameEquals(const wchar_t* expected) {
    wchar_t path[32768]{};
    const DWORD length = GetModuleFileNameW(
        nullptr, path, static_cast<DWORD>(std::size(path)));
    if (!length || length >= std::size(path)) return false;
    const wchar_t* filename = std::wcsrchr(path, L'\\');
    filename = filename ? filename + 1 : path;
    return _wcsicmp(filename, expected) == 0;
}

bool ImageContains(HMODULE module, uintptr_t rva, size_t bytes) {
    if (!module) return false;
    const auto* image = reinterpret_cast<const uint8_t*>(module);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 ||
        dos->e_lfanew > 0x100000) {
        return false;
    }
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        image + static_cast<size_t>(dos->e_lfanew));
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return false;
    }
    const size_t image_size = nt->OptionalHeader.SizeOfImage;
    return rva <= image_size && bytes <= image_size - rva;
}

uint32_t OperandValue(const PatchSite& site, uint8_t capacity) {
    if (site.kind == OperandKind::SessionAllocationTailBytes) {
        return static_cast<uint32_t>(capacity) * kSessionEntryBytes -
               kSessionEntryBytes;
    }
    return capacity;
}

void WriteOperand(uint8_t* bytes, const PatchSite& site, uint8_t capacity) {
    const uint32_t value = OperandValue(site, capacity);
    for (size_t index = 0; index < site.operand_width; ++index) {
        bytes[site.operand_offset + index] = static_cast<uint8_t>(
            (value >> (index * 8)) & 0xFFU);
    }
}

std::array<uint8_t, kUiRelayBytes> BuildUiWeakLockRelay(
        uintptr_t weak_lock_target) {
    // lea r10,[r15+260h]       ; first non-MemberWindow child
    // cmp rcx,r10              ; rcx = address of weak-ref slot
    // jae headless
    // mov rax,weak_lock_target ; tail-call the native weak_ptr lock helper
    // jmp rax
    // headless: zero the output shared handle and return it
    std::array<uint8_t, kUiRelayBytes> relay{{
        0x4D, 0x8D, 0x97, 0x60, 0x02, 0x00, 0x00,
        0x4C, 0x39, 0xD1,
        0x73, 0x0C,
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xE0,
        0x31, 0xC0,
        0x48, 0x89, 0x02,
        0x48, 0x89, 0x42, 0x08,
        0x48, 0x8B, 0xC2,
        0xC3,
    }};
    static_assert(relay.size() == kUiRelayBytes,
                  "EDF4.1 room UI relay size changed");
    std::memcpy(relay.data() + 14, &weak_lock_target,
                sizeof(weak_lock_target));
    return relay;
}

bool BuildRelativeCall(uintptr_t call_address, uintptr_t target,
                       std::array<uint8_t, 5>& call) {
    const int64_t displacement = static_cast<int64_t>(target) -
        static_cast<int64_t>(call_address + call.size());
    if (displacement < std::numeric_limits<int32_t>::min() ||
        displacement > std::numeric_limits<int32_t>::max()) {
        return false;
    }
    call = {{0xE8, 0, 0, 0, 0}};
    const int32_t relative = static_cast<int32_t>(displacement);
    std::memcpy(call.data() + 1, &relative, sizeof(relative));
    return true;
}

void* AllocateRelayNear(const void* target) {
    SYSTEM_INFO info{};
    GetSystemInfo(&info);
    const uintptr_t granularity = info.dwAllocationGranularity;
    const uintptr_t target_address = reinterpret_cast<uintptr_t>(target);
    const uintptr_t center = target_address & ~(granularity - 1);
    const uintptr_t minimum = reinterpret_cast<uintptr_t>(
        info.lpMinimumApplicationAddress);
    const uintptr_t maximum = reinterpret_cast<uintptr_t>(
        info.lpMaximumApplicationAddress);
    constexpr uintptr_t kMaximumDistance = 0x7FFF0000ULL;

    for (uintptr_t distance = granularity;
         distance <= kMaximumDistance; distance += granularity) {
        const uintptr_t candidates[2]{
            center >= distance ? center - distance : 0,
            center <= maximum - distance ? center + distance : 0,
        };
        for (const uintptr_t candidate : candidates) {
            if (candidate < minimum || candidate > maximum ||
                candidate + kUiRelayBytes < candidate) {
                continue;
            }
            void* allocation = VirtualAlloc(
                reinterpret_cast<void*>(candidate), kUiRelayBytes,
                MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            if (!allocation) continue;
            const int64_t call_displacement =
                reinterpret_cast<int64_t>(allocation) -
                static_cast<int64_t>(target_address + 5);
            if (call_displacement >= std::numeric_limits<int32_t>::min() &&
                call_displacement <= std::numeric_limits<int32_t>::max()) {
                return allocation;
            }
            VirtualFree(allocation, 0, MEM_RELEASE);
        }
    }
    return nullptr;
}

void* PrepareUiRelay(uint8_t* image) {
    uint8_t* const call_address = image + kUiWeakLockCallRva;
    void* relay_memory = AllocateRelayNear(call_address);
    if (!relay_memory) return nullptr;

    const auto relay = BuildUiWeakLockRelay(
        reinterpret_cast<uintptr_t>(image + kUiWeakLockTargetRva));
    std::memcpy(relay_memory, relay.data(), relay.size());
    DWORD previous = 0;
    if (!VirtualProtect(relay_memory, relay.size(), PAGE_EXECUTE_READ,
                        &previous)) {
        VirtualFree(relay_memory, 0, MEM_RELEASE);
        return nullptr;
    }
    FlushInstructionCache(GetCurrentProcess(), relay_memory, relay.size());
    return relay_memory;
}

bool MatchesSite(const uint8_t* address, const PatchSite& site,
                 uint8_t capacity) {
    auto expected = site.original;
    WriteOperand(expected.data(), site, capacity);
    return std::memcmp(address, expected.data(), site.length) == 0;
}

bool MatchesUiOriginal(const uint8_t* image) {
    return std::memcmp(image + kUiWeakLockCallRva,
                       kUiWeakLockCallOriginal.data(),
                       kUiWeakLockCallOriginal.size()) == 0 &&
           std::memcmp(image + kUiFillerBranchRva,
                       kUiFillerBranchOriginal.data(),
                       kUiFillerBranchOriginal.size()) == 0;
}

bool MatchesUiExpanded(const uint8_t* image, const void* relay) {
    std::array<uint8_t, 5> expected_call{};
    if (!relay || !BuildRelativeCall(
            reinterpret_cast<uintptr_t>(image + kUiWeakLockCallRva),
            reinterpret_cast<uintptr_t>(relay), expected_call)) {
        return false;
    }
    return std::memcmp(image + kUiWeakLockCallRva, expected_call.data(),
                       expected_call.size()) == 0 &&
           image[kUiFillerBranchRva] == 0x0F &&
           image[kUiFillerBranchRva + 1] ==
               kUiFillerBranchExpandedOpcode &&
           std::memcmp(image + kUiFillerBranchRva + 2,
                       kUiFillerBranchOriginal.data() + 2,
                       kUiFillerBranchOriginal.size() - 2) == 0;
}

bool ImageContainsAllSites(HMODULE executable) {
    if (!ImageContains(executable, kPatchBeginRva,
                       kPatchEndRva - kPatchBeginRva)) {
        return false;
    }
    for (const PatchSite& site : kPatchSites) {
        if (!ImageContains(executable, site.rva, site.length)) return false;
    }
    return ImageContains(executable, kUiWeakLockCallRva,
                         kUiWeakLockCallOriginal.size()) &&
           ImageContains(executable, kUiFillerBranchRva,
                         kUiFillerBranchOriginal.size()) &&
           ImageContains(executable, kUiWeakLockTargetRva, 1);
}

bool ValidateSites(const uint8_t* image, uint8_t capacity) {
    for (const PatchSite& site : kPatchSites) {
        if (!MatchesSite(image + site.rva, site, capacity)) return false;
    }
    return true;
}

void SetSites(uint8_t* image, uint8_t capacity) {
    for (const PatchSite& site : kPatchSites) {
        WriteOperand(image + site.rva, site, capacity);
    }
}

bool ValidateTransaction(const uint8_t* image, uint8_t capacity,
                         const void* relay) {
    return ValidateSites(image, capacity) &&
           (capacity == kNativeCapacity
                ? MatchesUiOriginal(image)
                : MatchesUiExpanded(image, relay));
}

bool SetTransaction(uint8_t* image, uint8_t capacity, const void* relay) {
    SetSites(image, capacity);
    if (capacity == kNativeCapacity) {
        std::memcpy(image + kUiWeakLockCallRva,
                    kUiWeakLockCallOriginal.data(),
                    kUiWeakLockCallOriginal.size());
        std::memcpy(image + kUiFillerBranchRva,
                    kUiFillerBranchOriginal.data(),
                    kUiFillerBranchOriginal.size());
        return true;
    }

    std::array<uint8_t, 5> call{};
    if (!BuildRelativeCall(
            reinterpret_cast<uintptr_t>(image + kUiWeakLockCallRva),
            reinterpret_cast<uintptr_t>(relay), call)) {
        return false;
    }
    std::memcpy(image + kUiWeakLockCallRva, call.data(), call.size());
    image[kUiFillerBranchRva + 1] = kUiFillerBranchExpandedOpcode;
    return true;
}

bool WriteSites(uint8_t* image, uint8_t from, uint8_t to,
                const void* relay) {
    if (!ValidateTransaction(image, from, relay)) return false;
    uint8_t* const begin = image + kPatchBeginRva;
    const size_t bytes = kPatchEndRva - kPatchBeginRva;
    DWORD previous = 0;
    if (!VirtualProtect(begin, bytes, PAGE_EXECUTE_READWRITE, &previous)) {
        return false;
    }

    bool success = SetTransaction(image, to, relay);
    FlushInstructionCache(GetCurrentProcess(), begin, bytes);
    success = success && ValidateTransaction(image, to, relay);
    if (!success) {
        SetTransaction(image, from, relay);
        FlushInstructionCache(GetCurrentProcess(), begin, bytes);
    }

    DWORD ignored = 0;
    if (!VirtualProtect(begin, bytes, previous, &ignored)) {
        if (success) {
            SetTransaction(image, from, relay);
            FlushInstructionCache(GetCurrentProcess(), begin, bytes);
        }
        DWORD retry_ignored = 0;
        VirtualProtect(begin, bytes, previous, &retry_ignored);
        success = false;
    }
    return success;
}

void LogResult(const char* event, bool requested, bool signature_matched,
               unsigned capacity, bool harness, bool success) {
    EDF5_CAPTURE_EVENT(
        success ? capture::Level::Info : capture::Level::Error,
        "edf41_native_roster", event,
        capture::Fields().Bool("requested", requested)
            .Bool("signature_matched", signature_matched)
            .UInt("native_capacity", kNativeCapacity)
            .UInt("requested_capacity", capacity)
            .Bool("harness_simulation", harness)
            .Bool("transactional_sites", true)
            .UInt("session_controller_sites", kSessionControllerSites)
            .UInt("net_users_sites", kUsersSites)
            .UInt("room_ui_sites", kUiPatchSites)
            .UInt("room_ui_member_windows", kUiMemberWindows)
            .String("room_ui_overflow_mode", "headless")
            .UInt("patched_sites",
                  success ? kPatchSites.size() + kUiPatchSites : 0)
            .Bool("success", success));
}

}  // namespace

bool Install(unsigned capacity) {
    const uint8_t requested = static_cast<uint8_t>(
        std::max(kNativeCapacity + 1,
                 std::min(kMaximumCapacity, capacity)));
    AcquireSRWLockExclusive(&g_patch_lock);
    if (g_ready.load(std::memory_order_relaxed)) {
        const bool same = g_installed_capacity == requested;
        ReleaseSRWLockExclusive(&g_patch_lock);
        return same;
    }

    if (ProcessNameEquals(L"edf41_steam_harness.exe")) {
        std::string report;
        const bool success = SelfTest(report);
        g_harness_simulation = success;
        g_installed_capacity = success ? requested : 0;
        g_ready.store(success, std::memory_order_release);
        ReleaseSRWLockExclusive(&g_patch_lock);
        LogResult("install", true, success, requested, true, success);
        return success;
    }

    HMODULE executable = GetModuleHandleW(nullptr);
    const bool image_valid = ProcessNameEquals(L"EDF41.exe") &&
                             ImageContainsAllSites(executable);
    auto* image = reinterpret_cast<uint8_t*>(executable);
    const bool signature_matched =
        image_valid && ValidateTransaction(image, kNativeCapacity, nullptr);
    void* relay = signature_matched ? PrepareUiRelay(image) : nullptr;
    const bool success = relay &&
        WriteSites(image, static_cast<uint8_t>(kNativeCapacity), requested,
                   relay);
    if (!success && relay) {
        VirtualFree(relay, 0, MEM_RELEASE);
        relay = nullptr;
    }
    g_ui_relay = success ? relay : nullptr;
    g_installed = success;
    g_installed_capacity = success ? requested : 0;
    g_ready.store(success, std::memory_order_release);
    ReleaseSRWLockExclusive(&g_patch_lock);
    LogResult("install", true, signature_matched, requested, false, success);
    return success;
}

bool Restore() {
    AcquireSRWLockExclusive(&g_patch_lock);
    if (g_harness_simulation) {
        g_harness_simulation = false;
        g_installed_capacity = 0;
        g_ready.store(false, std::memory_order_release);
        ReleaseSRWLockExclusive(&g_patch_lock);
        return true;
    }
    if (!g_installed) {
        g_ready.store(false, std::memory_order_release);
        ReleaseSRWLockExclusive(&g_patch_lock);
        return true;
    }

    HMODULE executable = GetModuleHandleW(nullptr);
    auto* image = reinterpret_cast<uint8_t*>(executable);
    const bool image_valid = ProcessNameEquals(L"EDF41.exe") &&
                             ImageContainsAllSites(executable);
    const uint8_t installed_capacity = g_installed_capacity;
    const bool signature_matched =
        image_valid &&
        ValidateTransaction(image, installed_capacity, g_ui_relay);
    const bool success = signature_matched &&
        WriteSites(image, installed_capacity,
                   static_cast<uint8_t>(kNativeCapacity), g_ui_relay);
    if (success) {
        if (g_ui_relay) {
            VirtualFree(g_ui_relay, 0, MEM_RELEASE);
            g_ui_relay = nullptr;
        }
        g_installed = false;
        g_installed_capacity = 0;
        g_ready.store(false, std::memory_order_release);
    }
    ReleaseSRWLockExclusive(&g_patch_lock);
    LogResult("restore", true, signature_matched, installed_capacity, false,
              success);
    return success;
}

bool Ready() {
    return g_ready.load(std::memory_order_acquire);
}

bool SelfTest(std::string& report) {
    std::array<std::array<uint8_t, 8>, kPatchSites.size()> buffers{};
    for (size_t index = 0; index < kPatchSites.size(); ++index) {
        buffers[index] = kPatchSites[index].original;
        if (!MatchesSite(buffers[index].data(), kPatchSites[index],
                         kNativeCapacity)) {
            report = "edf41_native_roster=fail original_signature";
            return false;
        }
    }

    for (size_t index = 0; index < kPatchSites.size(); ++index) {
        WriteOperand(buffers[index].data(), kPatchSites[index],
                     kMaximumCapacity);
        if (!MatchesSite(buffers[index].data(), kPatchSites[index],
                         kMaximumCapacity)) {
            report = "edf41_native_roster=fail expand_transaction";
            return false;
        }
    }
    if (buffers[3][2] != 0x70) {
        report = "edf41_native_roster=fail session_allocation_bytes";
        return false;
    }

    constexpr uintptr_t kTestImage = 0x0000000140000000ULL;
    constexpr uintptr_t kTestRelay = 0x0000000141000000ULL;
    std::array<uint8_t, 5> redirected_call{};
    if (!BuildRelativeCall(kTestImage + kUiWeakLockCallRva, kTestRelay,
                           redirected_call) ||
        redirected_call[0] != 0xE8 ||
        redirected_call == kUiWeakLockCallOriginal) {
        report = "edf41_native_roster=fail room_ui_redirect";
        return false;
    }
    const auto relay = BuildUiWeakLockRelay(
        kTestImage + kUiWeakLockTargetRva);
    uintptr_t encoded_target = 0;
    std::memcpy(&encoded_target, relay.data() + 14,
                sizeof(encoded_target));
    if (relay[0] != 0x4D || relay[10] != 0x73 || relay[11] != 0x0C ||
        encoded_target != kTestImage + kUiWeakLockTargetRva ||
        relay[24] != 0x31 || relay.back() != 0xC3 ||
        kUiFillerBranchOriginal[1] != 0x84 ||
        kUiFillerBranchExpandedOpcode != 0x83) {
        report = "edf41_native_roster=fail room_ui_headless_relay";
        return false;
    }

    for (size_t index = 0; index < kPatchSites.size(); ++index) {
        WriteOperand(buffers[index].data(), kPatchSites[index],
                     kNativeCapacity);
        if (!MatchesSite(buffers[index].data(), kPatchSites[index],
                         kNativeCapacity)) {
            report = "edf41_native_roster=fail restore_transaction";
            return false;
        }
    }
    buffers[3][0] ^= 0x01;
    if (MatchesSite(buffers[3].data(), kPatchSites[3], kNativeCapacity)) {
        report = "edf41_native_roster=fail mismatch_accepted";
        return false;
    }
    report =
        "edf41_native_roster=pass owners=net::Users,net::SessionController "
        "sites=10 capacity=8 session_bytes=128 ui_rows=4 "
        "ui_overflow=headless";
    return true;
}

}  // namespace edf41::native_roster_patch
