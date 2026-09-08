#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "version_guard.h"

#include "logger.h"

#include <cstdint>
#include <cwchar>
#include <iterator>

namespace edf41::sniffer {
namespace {

struct PeIdentity {
    uint32_t timestamp = 0;
    uint32_t size_of_image = 0;
    uint32_t entry_rva = 0;
};

constexpr PeIdentity kEdf41Identity{0x57AAB039u, 0x00D98000u, 0x00666B20u};
constexpr PeIdentity kSteamIdentity{0x5627DE8Au, 0x00037000u, 0x00008624u};

bool ReadIdentity(HMODULE module, PeIdentity& identity) {
    if (!module) return false;
    const auto* base = reinterpret_cast<const uint8_t*>(module);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 ||
        dos->e_lfanew > 0x100000) {
        return false;
    }
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        base + static_cast<size_t>(dos->e_lfanew));
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return false;
    }
    identity.timestamp = nt->FileHeader.TimeDateStamp;
    identity.size_of_image = nt->OptionalHeader.SizeOfImage;
    identity.entry_rva = nt->OptionalHeader.AddressOfEntryPoint;
    return true;
}

bool Matches(const PeIdentity& observed, const PeIdentity& expected) {
    return observed.timestamp == expected.timestamp &&
        observed.size_of_image == expected.size_of_image &&
        observed.entry_rva == expected.entry_rva;
}

void LogIdentity(const char* component, const PeIdentity& observed,
                 const PeIdentity& expected, bool parsed, bool matched) {
    EDF5_CAPTURE_EVENT(
        matched ? capture::Level::Info : capture::Level::Error,
        "edf41_version", "pe_identity",
        capture::Fields().String("component", component)
            .Bool("parsed", parsed)
            .UInt("observed_timestamp", observed.timestamp)
            .UInt("expected_timestamp", expected.timestamp)
            .UInt("observed_size_of_image", observed.size_of_image)
            .UInt("expected_size_of_image", expected.size_of_image)
            .UInt("observed_entry_rva", observed.entry_rva)
            .UInt("expected_entry_rva", expected.entry_rva)
            .Bool("matched", matched));
}

}  // namespace

bool ValidateSupportedBuild() {
    wchar_t process_path[32768]{};
    const DWORD length = GetModuleFileNameW(
        nullptr, process_path, static_cast<DWORD>(std::size(process_path)));
    if (!length || length >= std::size(process_path)) return false;
    const wchar_t* filename = std::wcsrchr(process_path, L'\\');
    filename = filename ? filename + 1 : process_path;

    // This exact executable contains only synthetic Steam interfaces and is
    // part of the offline build gate. No general environment-variable bypass
    // exists in distributed builds.
    if (_wcsicmp(filename, L"edf41_steam_harness.exe") == 0) {
        EDF5_CAPTURE_EVENT(capture::Level::Info, "edf41_version",
                           "integration_harness_accepted");
        return true;
    }
    if (_wcsicmp(filename, L"EDF41.exe") != 0) {
        EDF5_CAPTURE_EVENT(
            capture::Level::Error, "edf41_version", "unexpected_process",
            capture::Fields().String("process_name",
                                     capture::WideToUtf8(filename)));
        return false;
    }

    PeIdentity executable{};
    const bool executable_parsed =
        ReadIdentity(GetModuleHandleW(nullptr), executable);
    const bool executable_matches =
        executable_parsed && Matches(executable, kEdf41Identity);
    LogIdentity("EDF41.exe", executable, kEdf41Identity, executable_parsed,
                executable_matches);

    PeIdentity steam{};
    const bool steam_parsed =
        ReadIdentity(GetModuleHandleW(L"steam_api64.dll"), steam);
    const bool steam_matches = steam_parsed && Matches(steam, kSteamIdentity);
    LogIdentity("steam_api64.dll", steam, kSteamIdentity, steam_parsed,
                steam_matches);
    return executable_matches && steam_matches;
}

}  // namespace edf41::sniffer
