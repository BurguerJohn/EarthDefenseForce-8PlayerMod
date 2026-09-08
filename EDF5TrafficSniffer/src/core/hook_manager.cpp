#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "hook_manager.h"
#include "logger.h"

#include <MinHook.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <unordered_map>

namespace hooks {
namespace {

SRWLOCK g_lock = SRWLOCK_INIT;
bool g_initialized = false;
struct SharedHook { void* detour; void* trampoline; };
std::unordered_map<void*, SharedHook> g_shared;

#if EDF5_COMPILE_DIAGNOSTICS
void AppendStartupFailure(const char* reason, int created = -1,
                          int enabled = -1) {
    if (!reason) reason = "unknown";
    CreateDirectoryW(L"Mods", nullptr);
    CreateDirectoryW(L"Mods\\TrafficSniffer", nullptr);
    HANDLE file = CreateFileW(
        L"Mods\\TrafficSniffer\\startup-failures.log",
        FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return;
    SYSTEMTIME utc{};
    GetSystemTime(&utc);
    char line[768]{};
    const int length = std::snprintf(
        line, sizeof(line),
        "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ pid=%lu reason=%s "
        "create_status=%d enable_status=%d\r\n",
        utc.wYear, utc.wMonth, utc.wDay, utc.wHour, utc.wMinute,
        utc.wSecond, utc.wMilliseconds,
        static_cast<unsigned long>(GetCurrentProcessId()), reason, created,
        enabled);
    if (length > 0) {
        DWORD written = 0;
        WriteFile(file, line,
                  static_cast<DWORD>(std::min<int>(
                      length, static_cast<int>(sizeof(line) - 1))),
                  &written, nullptr);
        FlushFileBuffers(file);
    }
    CloseHandle(file);
}
#endif

}  // namespace

bool Initialize() {
    AcquireSRWLockExclusive(&g_lock);
    if (g_initialized) {
        ReleaseSRWLockExclusive(&g_lock);
        return true;
    }
    const MH_STATUS status = MH_Initialize();
    g_initialized = status == MH_OK || status == MH_ERROR_ALREADY_INITIALIZED;
    ReleaseSRWLockExclusive(&g_lock);
    EDF5_CAPTURE_EVENT("sniffer", "minhook_initialize",
                   capture::Fields().Int("status", status).Bool("success", g_initialized));
    return g_initialized;
}

void Shutdown() {
    AcquireSRWLockExclusive(&g_lock);
    if (!g_initialized) {
        ReleaseSRWLockExclusive(&g_lock);
        return;
    }
    const MH_STATUS disabled = MH_DisableHook(MH_ALL_HOOKS);
    const MH_STATUS uninitialized = MH_Uninitialize();
    g_shared.clear();
    g_initialized = false;
    ReleaseSRWLockExclusive(&g_lock);
    EDF5_CAPTURE_EVENT("sniffer", "minhook_shutdown",
                   capture::Fields().Int("disable_status", disabled)
                       .Int("uninitialize_status", uninitialized));
}

void ReportStartupFailure(const char* reason) {
#if EDF5_COMPILE_DIAGNOSTICS
    AppendStartupFailure(reason);
#else
    (void)reason;
#endif
}

bool Address(void* target, void* detour, void** original, const char* label, bool required) {
#if !EDF5_COMPILE_DIAGNOSTICS
    (void)label;
    (void)required;
#endif
    if (!target || !detour || !original) return false;
    const MH_STATUS created = MH_CreateHook(target, detour, original);
    MH_STATUS enabled = MH_UNKNOWN;
    if (created == MH_OK) enabled = MH_EnableHook(target);
    const bool success = created == MH_OK && (enabled == MH_OK || enabled == MH_ERROR_ENABLED);
    EDF5_CAPTURE_EVENT("sniffer", "hook_install",
                   capture::Fields().String("target", label)
                       .String("address", capture::HexPointer(target))
                       .Int("create_status", created)
                       .Int("enable_status", enabled)
                       .Bool("required", required)
                       .Bool("success", success));
#if EDF5_COMPILE_DIAGNOSTICS
    if (!success) {
        AppendStartupFailure(label, static_cast<int>(created),
                             static_cast<int>(enabled));
    }
#endif
    return success;
}

bool Export(const wchar_t* module, const char* name, void* detour, void** original, bool required) {
    HMODULE handle = GetModuleHandleW(module);
    if (!handle) handle = LoadLibraryW(module);
    void* target = handle ? reinterpret_cast<void*>(GetProcAddress(handle, name)) : nullptr;
    if (!target) {
        EDF5_CAPTURE_EVENT("sniffer", "hook_missing_export",
                       capture::Fields().String("module", capture::WideToUtf8(module))
                           .String("export", name)
                           .Bool("required", required));
        return false;
    }
    return Address(target, detour, original, name, required);
}

void* SharedAddress(void* target, void* detour, const char* label) {
#if !EDF5_COMPILE_DIAGNOSTICS
    (void)label;
#endif
    if (!target) return nullptr;
    AcquireSRWLockExclusive(&g_lock);
    auto found = g_shared.find(target);
    if (found != g_shared.end()) {
        void* trampoline = found->second.detour == detour ? found->second.trampoline : nullptr;
        ReleaseSRWLockExclusive(&g_lock);
        return trampoline;
    }
    void* trampoline = nullptr;
    const MH_STATUS created = MH_CreateHook(target, detour, &trampoline);
    const MH_STATUS enabled = created == MH_OK ? MH_EnableHook(target) : MH_UNKNOWN;
    if (created == MH_OK && (enabled == MH_OK || enabled == MH_ERROR_ENABLED)) {
        g_shared.emplace(target, SharedHook{detour, trampoline});
    } else {
        trampoline = nullptr;
    }
    ReleaseSRWLockExclusive(&g_lock);
    EDF5_CAPTURE_EVENT("sniffer", "dynamic_hook_install",
                   capture::Fields().String("target", label)
                       .String("address", capture::HexPointer(target))
                       .Int("create_status", created)
                       .Int("enable_status", enabled)
                       .Bool("success", trampoline != nullptr));
    return trampoline;
}

}  // namespace hooks
