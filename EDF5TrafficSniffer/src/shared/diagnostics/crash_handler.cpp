#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <dbghelp.h>

#include "crash_handler.h"

#include "logger.h"
#include "win32_handle.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <string>

namespace crash_capture {
namespace {

constexpr unsigned kBreadcrumbCount = 512;
constexpr DWORD kCrashWriterTimeoutMs = 5000;
constexpr uint64_t kRepeatedStallWarningMs = 30000;

using MiniDumpWriteDumpFn = BOOL(WINAPI*)(
    HANDLE, DWORD, HANDLE, MINIDUMP_TYPE,
    const MINIDUMP_EXCEPTION_INFORMATION*, const MINIDUMP_USER_STREAM_INFORMATION*,
    const MINIDUMP_CALLBACK_INFORMATION*);

struct BreadcrumbSlot {
    std::atomic_flag writing = ATOMIC_FLAG_INIT;
    std::atomic<uint64_t> committed{0};
    std::atomic<uint64_t> tick{0};
    std::atomic<DWORD> thread_id{0};
    std::array<std::atomic<uint64_t>, 4> component{};
    std::array<std::atomic<uint64_t>, 6> operation{};
    std::array<std::atomic<uint64_t>, 4> phase{};
    std::atomic<uint64_t> value_a{0};
    std::atomic<uint64_t> value_b{0};
};

struct CrashJob {
    EXCEPTION_RECORD record{};
    CONTEXT context{};
    EXCEPTION_POINTERS pointers{};
    DWORD thread_id = 0;
    HookContext hook{};
};

std::array<BreadcrumbSlot, kBreadcrumbCount> g_breadcrumbs{};
std::atomic<uint64_t> g_breadcrumb_sequence{0};
thread_local HookContext g_hook_context{};
std::atomic<bool> g_initialized{false};
std::atomic<bool> g_running{false};
std::atomic<bool> g_crash_pending{false};
std::atomic<bool> g_snapshot_pending{false};
std::atomic<bool> g_crash_handled{false};
std::atomic<bool> g_stopped{false};
std::atomic<bool> g_filter_installed{false};
std::atomic<uint64_t> g_snapshot_sequence{0};
std::atomic<uint64_t> g_last_stall_report_tick{0};
std::atomic<uint64_t> g_first_chance_sequence{0};
std::atomic_flag g_first_chance_writing = ATOMIC_FLAG_INIT;
HANDLE g_stop_event = nullptr;
HANDLE g_crash_event = nullptr;
HANDLE g_crash_done_event = nullptr;
HANDLE g_snapshot_event = nullptr;
HANDLE g_worker_thread = nullptr;
HANDLE g_hotkey_thread = nullptr;
HMODULE g_dbghelp = nullptr;
MiniDumpWriteDumpFn g_minidump_write = nullptr;
LPTOP_LEVEL_EXCEPTION_FILTER g_previous_filter = nullptr;
PVOID g_vectored_handler = nullptr;
CrashJob g_crash_job{};
wchar_t g_crashes_directory[32768]{};
wchar_t g_snapshots_directory[32768]{};
wchar_t g_emergency_path[32768]{};
wchar_t g_first_chance_emergency_path[32768]{};
char g_snapshot_source[32]{"api"};
SRWLOCK g_snapshot_source_lock = SRWLOCK_INIT;

void ReleaseCrashResources() {
    win32_handle::CloseNullable(g_hotkey_thread);
    win32_handle::CloseNullable(g_worker_thread);
    win32_handle::CloseNullable(g_stop_event);
    win32_handle::CloseNullable(g_crash_event);
    win32_handle::CloseNullable(g_crash_done_event);
    win32_handle::CloseNullable(g_snapshot_event);
    if (g_dbghelp) FreeLibrary(g_dbghelp);
    g_dbghelp = nullptr;
    g_minidump_write = nullptr;
}

bool FailInitialization() {
    const DWORD win32_error = GetLastError();
    g_running.store(false, std::memory_order_release);
    if (g_stop_event) SetEvent(g_stop_event);
    const bool hotkey_stopped =
        win32_handle::ThreadStopped(g_hotkey_thread, 2000);
    const bool worker_stopped =
        win32_handle::ThreadStopped(g_worker_thread, 5000);
    if (hotkey_stopped && worker_stopped) {
        ReleaseCrashResources();
        g_initialized.store(false, std::memory_order_release);
    }
    SetLastError(win32_error);
    return false;
}

template <typename T>
T Resolve(HMODULE module, const char* name) {
    FARPROC raw = module ? GetProcAddress(module, name) : nullptr;
    T result = nullptr;
    static_assert(sizeof(result) == sizeof(raw), "function pointer size mismatch");
    std::memcpy(&result, &raw, sizeof(result));
    return result;
}

void CopyText(char* destination, size_t capacity, const char* source) {
    if (!destination || !capacity) return;
    std::snprintf(destination, capacity, "%s", source ? source : "");
}

size_t FormattedTextSize(int result, size_t capacity) {
    if (result <= 0 || capacity == 0) return 0;
    return std::min(static_cast<size_t>(result), capacity - 1);
}

template <size_t WordCount>
void StoreAtomicText(std::array<std::atomic<uint64_t>, WordCount>& destination,
                     const char* source) {
    std::array<char, WordCount * sizeof(uint64_t)> text{};
    CopyText(text.data(), text.size(), source);
    std::array<uint64_t, WordCount> words{};
    std::memcpy(words.data(), text.data(), text.size());
    for (size_t index = 0; index < WordCount; ++index) {
        destination[index].store(words[index], std::memory_order_relaxed);
    }
}

template <size_t WordCount>
void LoadAtomicText(const std::array<std::atomic<uint64_t>, WordCount>& source,
                    char* destination, size_t capacity) {
    std::array<uint64_t, WordCount> words{};
    for (size_t index = 0; index < WordCount; ++index) {
        words[index] = source[index].load(std::memory_order_relaxed);
    }
    std::array<char, WordCount * sizeof(uint64_t)> text{};
    std::memcpy(text.data(), words.data(), text.size());
    CopyText(destination, capacity, text.data());
}

bool WriteAll(HANDLE file, const void* data, size_t size) {
    if (file == INVALID_HANDLE_VALUE || !data) return size == 0;
    const auto* cursor = static_cast<const uint8_t*>(data);
    while (size) {
        const DWORD chunk =
            static_cast<DWORD>(std::min<size_t>(size, 0x7ffff000u));
        DWORD written = 0;
        if (!WriteFile(file, cursor, chunk, &written, nullptr) ||
            written != chunk)
            return false;
        cursor += written;
        size -= written;
    }
    return true;
}

const wchar_t* ExtendedLengthPath(const wchar_t* path, wchar_t* buffer,
                                  size_t capacity) {
    if (!path || !buffer || capacity < 8 ||
        std::wcsncmp(path, L"\\\\?\\", 4) == 0) {
        return path;
    }
    const wchar_t* source = path;
    std::wstring absolute;
    const bool drive_absolute = path[0] && path[1] == L':' &&
        (path[2] == L'\\' || path[2] == L'/');
    const bool unc_absolute = path[0] == L'\\' && path[1] == L'\\';
    if (!drive_absolute && !unc_absolute) {
        const DWORD required = GetFullPathNameW(path, 0, nullptr, nullptr);
        if (required > 1 && required < capacity) {
            absolute.resize(required);
            const DWORD written = GetFullPathNameW(
                path, required, absolute.data(), nullptr);
            if (written && written < required) source = absolute.c_str();
        }
    }
    if (std::wcslen(source) < MAX_PATH - 1) return path;
    int written = -1;
    if (source[0] == L'\\' && source[1] == L'\\') {
        written = std::swprintf(buffer, capacity, L"\\\\?\\UNC\\%ls",
                                source + 2);
    } else if (source[0] && source[1] == L':') {
        written = std::swprintf(buffer, capacity, L"\\\\?\\%ls", source);
    }
    return written > 0 && static_cast<size_t>(written) < capacity
        ? buffer : path;
}

bool WriteText(const wchar_t* path, const char* text, size_t size) {
    wchar_t extended_path[32768]{};
    HANDLE file = CreateFileW(
        ExtendedLengthPath(path, extended_path, std::size(extended_path)),
        GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    const bool result = WriteAll(file, text, size);
    FlushFileBuffers(file);
    CloseHandle(file);
    return result;
}

void Timestamp(wchar_t* wide, size_t wide_capacity, char* narrow,
               size_t narrow_capacity) {
    SYSTEMTIME st{};
    GetSystemTime(&st);
    if (wide && wide_capacity) {
        std::swprintf(wide, wide_capacity,
                      L"%04u%02u%02uT%02u%02u%02u.%03uZ", st.wYear,
                      st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
                      st.wMilliseconds);
    }
    if (narrow && narrow_capacity) {
        std::snprintf(narrow, narrow_capacity,
                      "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ", st.wYear,
                      st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
                      st.wMilliseconds);
    }
}

const wchar_t* BaseName(const wchar_t* path) {
    if (!path) return L"";
    const wchar_t* slash = std::wcsrchr(path, L'\\');
    const wchar_t* slash2 = std::wcsrchr(path, L'/');
    if (!slash || (slash2 && slash2 > slash)) slash = slash2;
    return slash ? slash + 1 : path;
}

void AddressInfo(uintptr_t address, wchar_t* module_name,
                 size_t module_capacity, uintptr_t& module_rva) {
    module_rva = 0;
    if (module_name && module_capacity) module_name[0] = L'\0';
    MEMORY_BASIC_INFORMATION information{};
    if (!address || !VirtualQuery(reinterpret_cast<void*>(address),
                                  &information, sizeof(information)))
        return;
    const auto base = reinterpret_cast<uintptr_t>(information.AllocationBase);
    if (!base || address < base) return;
    module_rva = address - base;
    wchar_t path[32768]{};
    if (!GetModuleFileNameW(reinterpret_cast<HMODULE>(base), path,
                            static_cast<DWORD>(std::size(path))))
        return;
    module_rva = address - base;
    std::wcsncpy(module_name, BaseName(path), module_capacity - 1);
    module_name[module_capacity - 1] = L'\0';
}

MINIDUMP_TYPE DumpType(bool full) {
    ULONG flags = MiniDumpNormal | MiniDumpWithThreadInfo |
                  MiniDumpWithUnloadedModules |
                  MiniDumpWithIndirectlyReferencedMemory;
    if (full) {
        flags |= MiniDumpWithFullMemory | MiniDumpWithHandleData |
                 MiniDumpWithFullMemoryInfo | MiniDumpWithProcessThreadData;
    }
    return static_cast<MINIDUMP_TYPE>(flags);
}

bool WriteDump(const wchar_t* path, const CrashJob* crash, bool full) {
    if (!g_minidump_write || capture::GetConfig().crash_dump_mode ==
                                 capture::CrashDumpMode::Off)
        return false;
    wchar_t extended_path[32768]{};
    HANDLE file = CreateFileW(
        ExtendedLengthPath(path, extended_path, std::size(extended_path)),
        GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    MINIDUMP_EXCEPTION_INFORMATION exception{};
    const MINIDUMP_EXCEPTION_INFORMATION* exception_pointer = nullptr;
    if (crash) {
        exception.ThreadId = crash->thread_id;
        exception.ExceptionPointers =
            const_cast<EXCEPTION_POINTERS*>(&crash->pointers);
        exception.ClientPointers = FALSE;
        exception_pointer = &exception;
    }
    const bool result = g_minidump_write(
                            GetCurrentProcess(), GetCurrentProcessId(), file,
                            DumpType(full), exception_pointer, nullptr, nullptr) !=
                        FALSE;
    FlushFileBuffers(file);
    CloseHandle(file);
    return result;
}

bool ReadBreadcrumb(uint64_t sequence, uint64_t& tick, DWORD& thread_id,
                    char* component, size_t component_size, char* operation,
                    size_t operation_size, char* phase, size_t phase_size,
                    uint64_t& value_a, uint64_t& value_b) {
    BreadcrumbSlot& slot = g_breadcrumbs[sequence % kBreadcrumbCount];
    if (slot.committed.load(std::memory_order_acquire) != sequence) return false;
    tick = slot.tick.load(std::memory_order_relaxed);
    thread_id = slot.thread_id.load(std::memory_order_relaxed);
    LoadAtomicText(slot.component, component, component_size);
    LoadAtomicText(slot.operation, operation, operation_size);
    LoadAtomicText(slot.phase, phase, phase_size);
    value_a = slot.value_a.load(std::memory_order_relaxed);
    value_b = slot.value_b.load(std::memory_order_relaxed);
    return slot.committed.load(std::memory_order_acquire) == sequence;
}

bool WriteBreadcrumbFile(const wchar_t* path) {
    wchar_t extended_path[32768]{};
    HANDLE file = CreateFileW(
        ExtendedLengthPath(path, extended_path, std::size(extended_path)),
        GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    const uint64_t newest =
        g_breadcrumb_sequence.load(std::memory_order_acquire);
    const uint64_t first = newest > kBreadcrumbCount
        ? newest - kBreadcrumbCount + 1
        : 1;
    bool ok = true;
    for (uint64_t sequence = first; sequence <= newest; ++sequence) {
        uint64_t tick = 0;
        DWORD thread_id = 0;
        char component[32]{};
        char operation[48]{};
        char phase[32]{};
        uint64_t value_a = 0;
        uint64_t value_b = 0;
        if (!ReadBreadcrumb(sequence, tick, thread_id, component,
                            sizeof(component), operation, sizeof(operation),
                            phase, sizeof(phase), value_a, value_b))
            continue;
        char line[512]{};
        const int length = std::snprintf(
            line, sizeof(line),
            "{\"schema\":2,\"seq\":%llu,\"tick_ms\":%llu,"
            "\"thread_id\":%lu,\"component\":\"%s\","
            "\"operation\":\"%s\",\"phase\":\"%s\","
            "\"value_a\":%llu,\"value_b\":%llu}\r\n",
            static_cast<unsigned long long>(sequence),
            static_cast<unsigned long long>(tick), thread_id, component,
            operation, phase, static_cast<unsigned long long>(value_a),
            static_cast<unsigned long long>(value_b));
        if (length <= 0 ||
            !WriteAll(file, line, FormattedTextSize(length, sizeof(line)))) {
            ok = false;
            break;
        }
    }
    FlushFileBuffers(file);
    CloseHandle(file);
    return ok;
}

void BuildRuntimeJson(char* output, size_t capacity,
                      const capture::RuntimeState& state) {
    std::snprintf(
        output, capacity,
        "\"runtime\":{\"flow_id\":%llu,\"phase\":\"%s\","
        "\"lobby_steam_id\":%llu,\"actual_members\":%d,"
        "\"synthetic_members\":%u,\"max_players\":%u,"
        "\"gameplay_contact_mask\":%u,\"real_gameplay_peers\":%u,"
        "\"ready_mask\":%u,"
        "\"mission_group_mask\":%u,\"mission_generation\":%llu,"
        "\"mission_ui_state\":%d,\"last_progress_tick\":%llu}",
        static_cast<unsigned long long>(state.flow_id), state.phase,
        static_cast<unsigned long long>(state.lobby_steam_id),
        state.actual_members, state.synthetic_members, state.max_players,
        state.gameplay_contact_mask, state.real_gameplay_peers,
        state.ready_mask,
        state.mission_group_mask,
        static_cast<unsigned long long>(state.mission_generation),
        state.mission_ui_state,
        static_cast<unsigned long long>(state.last_progress_tick));
}

void WriteCrashArtifacts() {
    capture::EmergencyFlush();
    wchar_t timestamp[64]{};
    char utc[64]{};
    Timestamp(timestamp, std::size(timestamp), utc, sizeof(utc));
    const size_t timestamp_length = std::wcslen(timestamp);
    if (timestamp_length && timestamp[timestamp_length - 1] == L'Z') {
        timestamp[timestamp_length - 1] = L'\0';
    }
    wchar_t base[32768]{};
    // The process id already lives in the JSON body and the UTC timestamp is
    // unique inside a per-process session directory. Omitting it here keeps
    // the longest `.breadcrumbs.jsonl` companion below legacy MAX_PATH in
    // common deep test/install roots, while ExtendedLengthPath still covers
    // genuinely long absolute paths.
    std::swprintf(base, std::size(base), L"%s\\crash-%s",
                  g_crashes_directory, timestamp);
    wchar_t json_path[32768]{};
    wchar_t dump_path[32768]{};
    wchar_t breadcrumb_path[32768]{};
    std::swprintf(json_path, std::size(json_path), L"%s.json", base);
    std::swprintf(dump_path, std::size(dump_path), L"%s.dmp", base);
    std::swprintf(breadcrumb_path, std::size(breadcrumb_path),
                  L"%s.breadcrumbs.jsonl", base);

    const uintptr_t address =
        reinterpret_cast<uintptr_t>(g_crash_job.record.ExceptionAddress);
    wchar_t module[260]{};
    uintptr_t rva = 0;
    AddressInfo(address, module, std::size(module), rva);
    const capture::RuntimeState state = capture::GetRuntimeState();
    char runtime[1024]{};
    BuildRuntimeJson(runtime, sizeof(runtime), state);
    char json[8192]{};
    int length = std::snprintf(
        json, sizeof(json),
        "{\r\n  \"schema\":2,\r\n  \"kind\":\"crash\",\r\n"
        "  \"utc\":\"%s\",\r\n  \"process_id\":%lu,\r\n"
        "  \"thread_id\":%lu,\r\n  \"exception_code\":%lu,\r\n"
        "  \"exception_flags\":%lu,\r\n  \"exception_address\":"
        "\"0x%llx\",\r\n  \"exception_parameter_0\":%llu,\r\n"
        "  \"module\":\"%ls\",\r\n"
        "  \"module_rva\":%llu,\r\n  \"hook\":{\"component\":"
        "\"%s\",\"operation\":\"%s\",\"phase\":\"%s\","
        "\"value_a\":%llu,\"value_b\":%llu},\r\n  %s,\r\n"
        "  \"dump_requested\":%s,\r\n  \"dump_ok\":false\r\n}\r\n",
        utc, GetCurrentProcessId(), g_crash_job.thread_id,
        g_crash_job.record.ExceptionCode, g_crash_job.record.ExceptionFlags,
        static_cast<unsigned long long>(address),
        static_cast<unsigned long long>(
            g_crash_job.record.NumberParameters
                ? g_crash_job.record.ExceptionInformation[0]
                : 0),
        module,
        static_cast<unsigned long long>(rva), g_crash_job.hook.component,
        g_crash_job.hook.operation, g_crash_job.hook.phase,
        static_cast<unsigned long long>(g_crash_job.hook.value_a),
        static_cast<unsigned long long>(g_crash_job.hook.value_b), runtime,
        capture::GetConfig().crash_dump_mode == capture::CrashDumpMode::Off
            ? "false"
            : "true");
    WriteText(json_path, json, FormattedTextSize(length, sizeof(json)));
    bool breadcrumb_ok = WriteBreadcrumbFile(breadcrumb_path);
    DWORD breadcrumb_error = breadcrumb_ok ? ERROR_SUCCESS : GetLastError();

    const capture::CrashDumpMode dump_mode =
        capture::GetConfig().crash_dump_mode;
    const bool full = dump_mode == capture::CrashDumpMode::Full;
    const bool dump_ok = WriteDump(dump_path, &g_crash_job, full);
    // A second snapshot also closes a small termination race observed when
    // dump mode is Off and the process can leave immediately after the crash
    // worker signals completion. CREATE_ALWAYS makes the retry idempotent.
    const bool final_breadcrumb_ok = WriteBreadcrumbFile(breadcrumb_path);
    if (!final_breadcrumb_ok) breadcrumb_error = GetLastError();
    breadcrumb_ok = breadcrumb_ok || final_breadcrumb_ok;
    if (breadcrumb_ok) breadcrumb_error = ERROR_SUCCESS;
    const char* dump_mode_name = dump_mode == capture::CrashDumpMode::Off
        ? "Off"
        : (full ? "Full" : "Mini");
    char dump_file_json[1024]{"null"};
    if (dump_mode != capture::CrashDumpMode::Off) {
        std::snprintf(dump_file_json, sizeof(dump_file_json),
                      "\"%ls.dmp\"", BaseName(base));
    }
    length = std::snprintf(
        json, sizeof(json),
        "{\r\n  \"schema\":2,\r\n  \"kind\":\"crash\",\r\n"
        "  \"utc\":\"%s\",\r\n  \"process_id\":%lu,\r\n"
        "  \"thread_id\":%lu,\r\n  \"exception_code\":%lu,\r\n"
        "  \"exception_flags\":%lu,\r\n  \"exception_address\":"
        "\"0x%llx\",\r\n  \"exception_parameter_0\":%llu,\r\n"
        "  \"module\":\"%ls\",\r\n"
        "  \"module_rva\":%llu,\r\n  \"hook\":{\"component\":"
        "\"%s\",\"operation\":\"%s\",\"phase\":\"%s\","
        "\"value_a\":%llu,\"value_b\":%llu},\r\n  %s,\r\n"
        "  \"dump_mode\":\"%s\",\r\n  \"dump_ok\":%s,\r\n"
        "  \"breadcrumbs_ok\":%s,\r\n"
        "  \"breadcrumbs_win32_error\":%lu,\r\n"
        "  \"dump_file\":%s\r\n}\r\n",
        utc, GetCurrentProcessId(), g_crash_job.thread_id,
        g_crash_job.record.ExceptionCode, g_crash_job.record.ExceptionFlags,
        static_cast<unsigned long long>(address),
        static_cast<unsigned long long>(
            g_crash_job.record.NumberParameters
                ? g_crash_job.record.ExceptionInformation[0]
                : 0),
        module,
        static_cast<unsigned long long>(rva), g_crash_job.hook.component,
        g_crash_job.hook.operation, g_crash_job.hook.phase,
        static_cast<unsigned long long>(g_crash_job.hook.value_a),
        static_cast<unsigned long long>(g_crash_job.hook.value_b), runtime,
        dump_mode_name, dump_ok ? "true" : "false",
        breadcrumb_ok ? "true" : "false", breadcrumb_error,
        dump_file_json);
    WriteText(json_path, json, FormattedTextSize(length, sizeof(json)));
    capture::MarkCrashed(g_crash_job.record.ExceptionCode,
                         capture::WideToUtf8(json_path));
    capture::EmergencyFlush();
}

void WriteSnapshotArtifacts() {
    wchar_t timestamp[64]{};
    char utc[64]{};
    Timestamp(timestamp, std::size(timestamp), utc, sizeof(utc));
    const uint64_t sequence =
        g_snapshot_sequence.fetch_add(1, std::memory_order_acq_rel) + 1;
    wchar_t directory[32768]{};
    std::swprintf(directory, std::size(directory),
                  L"%s\\%s_manual_%04llu", g_snapshots_directory, timestamp,
                  static_cast<unsigned long long>(sequence));
    if (!CreateDirectoryW(directory, nullptr) &&
        GetLastError() != ERROR_ALREADY_EXISTS) {
        capture::Event(capture::Level::Error, "diagnostics",
                       "snapshot_failed",
                       capture::Fields().String("reason", "CreateDirectory")
                           .UInt("win32_error", GetLastError()));
        return;
    }
    wchar_t json_path[32768]{};
    wchar_t dump_path[32768]{};
    wchar_t breadcrumb_path[32768]{};
    std::swprintf(json_path, std::size(json_path), L"%s\\state.json",
                  directory);
    std::swprintf(dump_path, std::size(dump_path), L"%s\\snapshot.dmp",
                  directory);
    std::swprintf(breadcrumb_path, std::size(breadcrumb_path),
                  L"%s\\breadcrumbs.jsonl", directory);
    char snapshot_source[32]{};
    AcquireSRWLockShared(&g_snapshot_source_lock);
    CopyText(snapshot_source, sizeof(snapshot_source), g_snapshot_source);
    ReleaseSRWLockShared(&g_snapshot_source_lock);
    capture::EmitNetworkSummary(true);
    capture::Flush();
    const capture::RuntimeState state = capture::GetRuntimeState();
    char runtime[1024]{};
    BuildRuntimeJson(runtime, sizeof(runtime), state);
    const bool dump_ok = WriteDump(dump_path, nullptr, false);
    char json[4096]{};
    const int length = std::snprintf(
        json, sizeof(json),
        "{\r\n  \"schema\":2,\r\n  \"kind\":\"live_snapshot\","
        "\r\n  \"utc\":\"%s\",\r\n  \"source\":\"%s\",\r\n"
        "  %s,\r\n  \"deep_capture_enabled\":%s,\r\n"
        "  \"dump_ok\":%s\r\n}\r\n",
        utc, snapshot_source, runtime,
        capture::DeepCaptureEnabled() ? "true" : "false",
        dump_ok ? "true" : "false");
    WriteText(json_path, json, FormattedTextSize(length, sizeof(json)));
    WriteBreadcrumbFile(breadcrumb_path);
    capture::Event(dump_ok ? capture::Level::Info : capture::Level::Warning,
                       "diagnostics", "snapshot_complete",
                   capture::Fields().String(
                       "directory", capture::WideToUtf8(directory))
                       .String("source", snapshot_source)
                       .Bool("dump_ok", dump_ok));
    capture::Flush();
    MessageBeep(dump_ok ? MB_OK : MB_ICONWARNING);
}

void WriteEmergencyContext() {
    char json[1024]{};
    const int length = std::snprintf(
        json, sizeof(json),
        "{\"schema\":2,\"kind\":\"crash_emergency\","
        "\"process_id\":%lu,\"thread_id\":%lu,"
        "\"exception_code\":%lu,\"exception_address\":\"0x%llx\","
        "\"hook_component\":\"%s\",\"hook_operation\":\"%s\","
        "\"hook_phase\":\"%s\"}\r\n",
        GetCurrentProcessId(), g_crash_job.thread_id,
        g_crash_job.record.ExceptionCode,
        static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(
            g_crash_job.record.ExceptionAddress)),
        g_crash_job.hook.component, g_crash_job.hook.operation,
        g_crash_job.hook.phase);
    WriteText(g_emergency_path, json,
              FormattedTextSize(length, sizeof(json)));
}

DWORD WINAPI WorkerMain(void*) {
    HANDLE events[] = {g_stop_event, g_crash_event, g_snapshot_event};
    while (g_running.load(std::memory_order_acquire)) {
        const DWORD result = WaitForMultipleObjects(
            static_cast<DWORD>(std::size(events)), events, FALSE, 1000);
        if (result == WAIT_OBJECT_0) break;
        if (result == WAIT_OBJECT_0 + 1) {
            WriteCrashArtifacts();
            g_crash_pending.store(false, std::memory_order_release);
            SetEvent(g_crash_done_event);
        } else if (result == WAIT_OBJECT_0 + 2) {
            WriteSnapshotArtifacts();
            g_snapshot_pending.store(false, std::memory_order_release);
        }
    }
    return 0;
}

bool SeriousException(uint32_t code) {
    switch (code) {
    case EXCEPTION_ACCESS_VIOLATION:
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
    case EXCEPTION_ILLEGAL_INSTRUCTION:
    case EXCEPTION_IN_PAGE_ERROR:
    case EXCEPTION_INT_DIVIDE_BY_ZERO:
    case EXCEPTION_PRIV_INSTRUCTION:
    case EXCEPTION_STACK_OVERFLOW:
    case 0xc0000374u:  // STATUS_HEAP_CORRUPTION
    case 0xc0000409u:  // STATUS_STACK_BUFFER_OVERRUN / fast-fail
        return true;
    default:
        return false;
    }
}

uintptr_t MainImageRva(uintptr_t address) {
    auto* base = reinterpret_cast<uint8_t*>(GetModuleHandleW(nullptr));
    if (!base || !address) return 0;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) return 0;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return 0;
    }
    const uintptr_t image_base = reinterpret_cast<uintptr_t>(base);
    if (address < image_base ||
        address - image_base >= nt->OptionalHeader.SizeOfImage) {
        return 0;
    }
    return address - image_base;
}

uintptr_t MainImageCodeRva(uintptr_t address) {
    auto* base = reinterpret_cast<const uint8_t*>(GetModuleHandleW(nullptr));
    if (!base) return 0;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) return 0;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return 0;
    }
    const uintptr_t image_base = reinterpret_cast<uintptr_t>(base);
    if (address < image_base) return 0;
    const uintptr_t rva = address - image_base;
    const IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt);
    for (unsigned index = 0; index < nt->FileHeader.NumberOfSections;
         ++index, ++section) {
        const uintptr_t begin = section->VirtualAddress;
        const uintptr_t size = std::max<uintptr_t>(
            section->Misc.VirtualSize, section->SizeOfRawData);
        if (rva >= begin && rva < begin + size &&
            (section->Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
            return rva;
        }
    }
    return 0;
}

const char* AccessType(const EXCEPTION_RECORD* record) {
    if (!record || record->NumberParameters < 1) return "unknown";
    switch (record->ExceptionInformation[0]) {
    case 0: return "read";
    case 1: return "write";
    case 8: return "execute";
    default: return "unknown";
    }
}

void WriteFirstChanceEmergency(EXCEPTION_POINTERS* pointers) {
    if (!pointers || !pointers->ExceptionRecord ||
        !pointers->ContextRecord || !g_first_chance_emergency_path[0] ||
        g_first_chance_writing.test_and_set(std::memory_order_acquire)) {
        return;
    }
    const EXCEPTION_RECORD* record = pointers->ExceptionRecord;
    const CONTEXT* context = pointers->ContextRecord;
    const uint64_t sequence = g_first_chance_sequence.fetch_add(
        1, std::memory_order_acq_rel) + 1;
    wchar_t module[260]{};
    uintptr_t module_rva = 0;
    const uintptr_t exception_address = reinterpret_cast<uintptr_t>(
        record->ExceptionAddress);
    AddressInfo(exception_address, module, std::size(module), module_rva);
    uintptr_t access_address = 0;
    if (record->NumberParameters >= 2) {
        access_address = static_cast<uintptr_t>(
            record->ExceptionInformation[1]);
    }
    constexpr size_t kEmergencyStackBytes = 0x800;
    constexpr size_t kEmergencyCodeCandidateCount = 8;
    std::array<uintptr_t,
               kEmergencyStackBytes / sizeof(uintptr_t)> stack_words{};
    std::array<uintptr_t, 4> return_addresses{};
    std::array<uintptr_t, kEmergencyCodeCandidateCount> stack_code_rvas{};
    std::array<size_t, kEmergencyCodeCandidateCount> stack_code_offsets{};
    SIZE_T stack_bytes = 0;
#if defined(_M_X64) || defined(__x86_64__)
    ReadProcessMemory(GetCurrentProcess(),
                      reinterpret_cast<const void*>(context->Rsp),
                      stack_words.data(), sizeof(stack_words),
                      &stack_bytes);
    std::copy_n(stack_words.begin(), return_addresses.size(),
                return_addresses.begin());
    size_t stack_code_count = 0;
    const size_t words_read = std::min<size_t>(
        stack_words.size(), stack_bytes / sizeof(uintptr_t));
    for (size_t index = 0;
         index < words_read &&
             stack_code_count < stack_code_rvas.size(); ++index) {
        const uintptr_t candidate_rva = MainImageCodeRva(stack_words[index]);
        if (!candidate_rva) continue;
        stack_code_rvas[stack_code_count] = candidate_rva;
        stack_code_offsets[stack_code_count] = index * sizeof(uintptr_t);
        ++stack_code_count;
    }
    char stack_code_json[1024]{};
    size_t stack_code_json_used = 0;
    stack_code_json_used += static_cast<size_t>(std::snprintf(
        stack_code_json, sizeof(stack_code_json), "["));
    for (size_t index = 0; index < stack_code_count; ++index) {
        if (stack_code_json_used >= sizeof(stack_code_json)) break;
        const int wrote = std::snprintf(
            stack_code_json + stack_code_json_used,
            sizeof(stack_code_json) - stack_code_json_used,
            "%s{\"stack_offset\":%llu,\"module_rva\":%llu}",
            index ? "," : "",
            static_cast<unsigned long long>(stack_code_offsets[index]),
            static_cast<unsigned long long>(stack_code_rvas[index]));
        if (wrote <= 0) break;
        stack_code_json_used += std::min<size_t>(
            static_cast<size_t>(wrote),
            sizeof(stack_code_json) - stack_code_json_used - 1);
    }
    if (stack_code_json_used < sizeof(stack_code_json) - 1) {
        stack_code_json[stack_code_json_used++] = ']';
        stack_code_json[stack_code_json_used] = '\0';
    } else {
        std::strcpy(stack_code_json, "[]");
    }
#else
    const char stack_code_json[] = "[]";
#endif
    char utc[64]{};
    Timestamp(nullptr, 0, utc, sizeof(utc));
    const HookContext hook = g_hook_context;
    char json[16384]{};
#if defined(_M_X64) || defined(__x86_64__)
    const int length = std::snprintf(
        json, sizeof(json),
        "{\r\n  \"schema\":2,\r\n  \"kind\":\"first_chance_emergency\",\r\n"
        "  \"sequence\":%llu,\r\n  \"utc\":\"%s\",\r\n"
        "  \"process_id\":%lu,\r\n  \"thread_id\":%lu,\r\n"
        "  \"exception_code\":%lu,\r\n  \"exception_flags\":%lu,\r\n"
        "  \"exception_address\":\"0x%llx\",\r\n"
        "  \"module\":\"%ls\",\r\n  \"module_rva\":%llu,\r\n"
        "  \"access_type\":\"%s\",\r\n"
        "  \"access_address\":\"0x%llx\",\r\n"
        "  \"instruction_pointer\":\"0x%llx\",\r\n"
        "  \"stack_pointer\":\"0x%llx\",\r\n"
        "  \"frame_pointer\":\"0x%llx\",\r\n"
        "  \"register_rax\":\"0x%llx\",\r\n"
        "  \"register_rbx\":\"0x%llx\",\r\n"
        "  \"register_rcx\":\"0x%llx\",\r\n"
        "  \"register_rdx\":\"0x%llx\",\r\n"
        "  \"register_rsi\":\"0x%llx\",\r\n"
        "  \"register_rdi\":\"0x%llx\",\r\n"
        "  \"register_r8\":\"0x%llx\",\r\n"
        "  \"register_r9\":\"0x%llx\",\r\n"
        "  \"register_r10\":\"0x%llx\",\r\n"
        "  \"register_r11\":\"0x%llx\",\r\n"
        "  \"register_r12\":\"0x%llx\",\r\n"
        "  \"register_r13\":\"0x%llx\",\r\n"
        "  \"register_r14\":\"0x%llx\",\r\n"
        "  \"register_r15\":\"0x%llx\",\r\n"
        "  \"return_address_0\":\"0x%llx\",\r\n"
        "  \"return_rva_0\":%llu,\r\n"
        "  \"return_address_1\":\"0x%llx\",\r\n"
        "  \"return_rva_1\":%llu,\r\n"
        "  \"return_address_2\":\"0x%llx\",\r\n"
        "  \"return_rva_2\":%llu,\r\n"
        "  \"return_address_3\":\"0x%llx\",\r\n"
        "  \"return_rva_3\":%llu,\r\n"
        "  \"stack_bytes_read\":%llu,\r\n"
        "  \"stack_code_candidates\":%s,\r\n"
        "  \"hook\":{\"component\":\"%s\",\"operation\":\"%s\","
        "\"phase\":\"%s\",\"value_a\":%llu,\"value_b\":%llu}\r\n}\r\n",
        static_cast<unsigned long long>(sequence), utc,
        GetCurrentProcessId(), GetCurrentThreadId(), record->ExceptionCode,
        record->ExceptionFlags,
        static_cast<unsigned long long>(exception_address), module,
        static_cast<unsigned long long>(module_rva), AccessType(record),
        static_cast<unsigned long long>(access_address),
        static_cast<unsigned long long>(context->Rip),
        static_cast<unsigned long long>(context->Rsp),
        static_cast<unsigned long long>(context->Rbp),
        static_cast<unsigned long long>(context->Rax),
        static_cast<unsigned long long>(context->Rbx),
        static_cast<unsigned long long>(context->Rcx),
        static_cast<unsigned long long>(context->Rdx),
        static_cast<unsigned long long>(context->Rsi),
        static_cast<unsigned long long>(context->Rdi),
        static_cast<unsigned long long>(context->R8),
        static_cast<unsigned long long>(context->R9),
        static_cast<unsigned long long>(context->R10),
        static_cast<unsigned long long>(context->R11),
        static_cast<unsigned long long>(context->R12),
        static_cast<unsigned long long>(context->R13),
        static_cast<unsigned long long>(context->R14),
        static_cast<unsigned long long>(context->R15),
        static_cast<unsigned long long>(return_addresses[0]),
        static_cast<unsigned long long>(MainImageRva(return_addresses[0])),
        static_cast<unsigned long long>(return_addresses[1]),
        static_cast<unsigned long long>(MainImageRva(return_addresses[1])),
        static_cast<unsigned long long>(return_addresses[2]),
        static_cast<unsigned long long>(MainImageRva(return_addresses[2])),
        static_cast<unsigned long long>(return_addresses[3]),
        static_cast<unsigned long long>(MainImageRva(return_addresses[3])),
        static_cast<unsigned long long>(stack_bytes), stack_code_json,
        hook.component,
        hook.operation, hook.phase,
        static_cast<unsigned long long>(hook.value_a),
        static_cast<unsigned long long>(hook.value_b));
#else
    const int length = std::snprintf(
        json, sizeof(json),
        "{\"schema\":2,\"kind\":\"first_chance_emergency\","
        "\"sequence\":%llu,\"utc\":\"%s\",\"process_id\":%lu,"
        "\"thread_id\":%lu,\"exception_code\":%lu,"
        "\"exception_address\":\"0x%llx\",\"module\":\"%ls\","
        "\"module_rva\":%llu}\r\n",
        static_cast<unsigned long long>(sequence), utc,
        GetCurrentProcessId(), GetCurrentThreadId(), record->ExceptionCode,
        static_cast<unsigned long long>(exception_address), module,
        static_cast<unsigned long long>(module_rva));
#endif
    WriteText(g_first_chance_emergency_path, json,
              FormattedTextSize(length, sizeof(json)));
    g_first_chance_writing.clear(std::memory_order_release);
}

LONG CALLBACK VectoredHandler(EXCEPTION_POINTERS* pointers) {
    if (pointers && pointers->ExceptionRecord &&
        SeriousException(pointers->ExceptionRecord->ExceptionCode)) {
        Breadcrumb("exception", "first_chance", "observed",
                   pointers->ExceptionRecord->ExceptionCode,
                   reinterpret_cast<uintptr_t>(
                       pointers->ExceptionRecord->ExceptionAddress));
        WriteFirstChanceEmergency(pointers);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

bool SubmitCrash(EXCEPTION_RECORD* record, CONTEXT* context) {
    if (!record || !context || !g_running.load(std::memory_order_acquire) ||
        !g_crash_event || !g_crash_done_event ||
        g_crash_handled.exchange(true, std::memory_order_acq_rel)) {
        return false;
    }
    g_crash_job.record = *record;
    g_crash_job.context = *context;
    g_crash_job.pointers.ExceptionRecord = &g_crash_job.record;
    g_crash_job.pointers.ContextRecord = &g_crash_job.context;
    g_crash_job.thread_id = GetCurrentThreadId();
    g_crash_job.hook = g_hook_context;
    g_crash_pending.store(true, std::memory_order_release);
    ResetEvent(g_crash_done_event);
    SetEvent(g_crash_event);
    const bool completed = WaitForSingleObject(
        g_crash_done_event, kCrashWriterTimeoutMs) == WAIT_OBJECT_0;
    if (!completed) WriteEmergencyContext();
    return completed;
}

LONG WINAPI TopLevelHandler(EXCEPTION_POINTERS* pointers) {
    if (pointers && pointers->ExceptionRecord && pointers->ContextRecord) {
        SubmitCrash(pointers->ExceptionRecord, pointers->ContextRecord);
    }
    if (g_previous_filter && g_previous_filter != TopLevelHandler)
        return g_previous_filter(pointers);
    return EXCEPTION_CONTINUE_SEARCH;
}

void CheckStall() {
    const capture::RuntimeState state = capture::GetRuntimeState();
    const uint64_t now = GetTickCount64();
    if (std::strcmp(state.phase, "matching") != 0 ||
        !state.last_progress_tick || now < state.last_progress_tick) {
        g_last_stall_report_tick.store(0, std::memory_order_release);
        return;
    }
    const uint64_t age = now - state.last_progress_tick;
    const uint64_t threshold =
        static_cast<uint64_t>(capture::GetConfig().stall_warning_seconds) *
        1000;
    if (age < threshold) return;
    const uint64_t previous =
        g_last_stall_report_tick.load(std::memory_order_acquire);
    if (previous && now >= previous &&
        now - previous < kRepeatedStallWarningMs)
        return;
    g_last_stall_report_tick.store(now, std::memory_order_release);
    Breadcrumb("flow", "matching", "stalled", age,
               state.gameplay_contact_mask);
    capture::Event(
        capture::Level::Warning, "diagnostics", "flow_stalled",
        capture::Fields().UInt("flow_id", state.flow_id)
            .String("phase", state.phase)
            .UInt("stalled_ms", age)
            .UInt("lobby_steam_id", state.lobby_steam_id)
            .Int("actual_members", state.actual_members)
            .UInt("synthetic_members", state.synthetic_members)
            .UInt("gameplay_contact_mask", state.gameplay_contact_mask)
            .UInt("real_gameplay_peers", state.real_gameplay_peers)
            .UInt("ready_mask", state.ready_mask)
            .UInt("mission_group_mask", state.mission_group_mask)
            .Int("mission_ui_state", state.mission_ui_state)
            .String("suggested_action", "press F9 for live snapshot"));
}

DWORD WINAPI HotkeyMain(void*) {
    bool snapshot_was_down = false;
    bool deep_was_down = false;
    while (g_running.load(std::memory_order_acquire)) {
        const bool snapshot_down =
            (GetAsyncKeyState(static_cast<int>(
                 capture::GetConfig().snapshot_hotkey_vk)) &
             0x8000) != 0;
        const bool deep_down =
            (GetAsyncKeyState(static_cast<int>(
                 capture::GetConfig().deep_capture_hotkey_vk)) &
             0x8000) != 0;
        if (snapshot_down && !snapshot_was_down) {
            if (!RequestSnapshot("F9")) MessageBeep(MB_ICONWARNING);
        }
        if (deep_down && !deep_was_down) {
            SetDeepCapture(!capture::DeepCaptureEnabled(), "F10");
            MessageBeep(capture::DeepCaptureEnabled() ? MB_OK
                                                       : MB_ICONASTERISK);
        }
        snapshot_was_down = snapshot_down;
        deep_was_down = deep_down;
        capture::EmitNetworkSummary(false);
        CheckStall();
        Sleep(40);
    }
    return 0;
}

}  // namespace

HookScope::HookScope(const char* component, const char* operation,
                     const char* phase, uint64_t value_a, uint64_t value_b)
    : previous_(g_hook_context) {
    CopyText(g_hook_context.component, sizeof(g_hook_context.component),
             component);
    CopyText(g_hook_context.operation, sizeof(g_hook_context.operation),
             operation);
    CopyText(g_hook_context.phase, sizeof(g_hook_context.phase), phase);
    g_hook_context.value_a = value_a;
    g_hook_context.value_b = value_b;
    Breadcrumb(component, operation, phase, value_a, value_b);
}

HookScope::~HookScope() {
    Breadcrumb(g_hook_context.component, g_hook_context.operation, "exit",
               g_hook_context.value_a, g_hook_context.value_b);
    g_hook_context = previous_;
}

void HookScope::Phase(const char* phase, uint64_t value_a, uint64_t value_b) {
    CopyText(g_hook_context.phase, sizeof(g_hook_context.phase), phase);
    g_hook_context.value_a = value_a;
    g_hook_context.value_b = value_b;
    Breadcrumb(g_hook_context.component, g_hook_context.operation, phase,
               value_a, value_b);
}

bool Initialize(HMODULE) {
    if (g_initialized.exchange(true, std::memory_order_acq_rel)) return true;
    g_stopped.store(false, std::memory_order_release);
    if (!capture::GetConfig().diagnostics_enabled ||
        capture::SessionDirectory().empty())
        return true;
    std::swprintf(g_crashes_directory, std::size(g_crashes_directory), L"%s\\crashes",
                  capture::SessionDirectory().c_str());
    std::swprintf(g_snapshots_directory, std::size(g_snapshots_directory),
                  L"%s\\snapshots", capture::SessionDirectory().c_str());
    std::swprintf(g_emergency_path, std::size(g_emergency_path),
                  L"%s\\crash-emergency.json", g_crashes_directory);
    std::swprintf(g_first_chance_emergency_path,
                  std::size(g_first_chance_emergency_path),
                  L"%s\\first-chance-emergency.json", g_crashes_directory);

    g_dbghelp = LoadLibraryW(L"dbghelp.dll");
    g_minidump_write = Resolve<MiniDumpWriteDumpFn>(
        g_dbghelp, "MiniDumpWriteDump");
    g_stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    g_crash_event = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    g_crash_done_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    g_snapshot_event = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (!g_stop_event || !g_crash_event || !g_crash_done_event ||
        !g_snapshot_event) {
        capture::Event(capture::Level::Error, "diagnostics",
                       "crash_handler_failed",
                       capture::Fields().String("reason", "CreateEvent")
                           .UInt("win32_error", GetLastError()));
        return FailInitialization();
    }
    g_running.store(true, std::memory_order_release);
    g_worker_thread = CreateThread(nullptr, 0, WorkerMain, nullptr, 0, nullptr);
    g_hotkey_thread = CreateThread(nullptr, 0, HotkeyMain, nullptr, 0, nullptr);
    if (!g_worker_thread || !g_hotkey_thread) {
        g_running.store(false, std::memory_order_release);
        SetEvent(g_stop_event);
        capture::Event(capture::Level::Error, "diagnostics",
                       "crash_handler_failed",
                       capture::Fields().String("reason", "CreateThread")
                           .UInt("win32_error", GetLastError()));
        return FailInitialization();
    }
    g_vectored_handler = AddVectoredExceptionHandler(1, VectoredHandler);
    g_previous_filter = SetUnhandledExceptionFilter(TopLevelHandler);
    g_filter_installed.store(true, std::memory_order_release);
    capture::Event(capture::Level::Info, "diagnostics",
                   "crash_handler_ready",
                   capture::Fields().Bool("dbghelp_loaded", g_dbghelp != nullptr)
                       .Bool("minidump_available", g_minidump_write != nullptr)
                       .Bool("vectored_handler",
                             g_vectored_handler != nullptr)
                       .Bool("first_chance_emergency", true)
                       .UInt("breadcrumb_capacity", kBreadcrumbCount)
                       .UInt("snapshot_hotkey_vk",
                             capture::GetConfig().snapshot_hotkey_vk)
                       .UInt("deep_capture_hotkey_vk",
                             capture::GetConfig().deep_capture_hotkey_vk));
    return true;
}

void RequestStop() {
    if (!g_running.exchange(false, std::memory_order_acq_rel)) return;
    if (g_stop_event) SetEvent(g_stop_event);
}

void Stop() {
    if (g_stopped.exchange(true, std::memory_order_acq_rel)) return;
    RequestStop();
    const bool hotkey_stopped =
        win32_handle::ThreadStopped(g_hotkey_thread, 2000);
    const bool worker_stopped =
        win32_handle::ThreadStopped(g_worker_thread, 5000);
    if (!hotkey_stopped || !worker_stopped) {
        // These threads use the events and dbghelp module below. Keep their
        // dependencies alive instead of introducing a shutdown use-after-free.
        OutputDebugStringW(
            L"EDF5_MultiSlotMod: crash-capture thread did not stop in time; "
            L"resources retained.\r\n");
        g_stopped.store(false, std::memory_order_release);
        return;
    }
    if (g_vectored_handler) RemoveVectoredExceptionHandler(g_vectored_handler);
    if (g_filter_installed.exchange(false, std::memory_order_acq_rel)) {
        const auto displaced = SetUnhandledExceptionFilter(g_previous_filter);
        if (displaced != TopLevelHandler) {
            SetUnhandledExceptionFilter(displaced);
        }
    }
    g_vectored_handler = nullptr;
    g_previous_filter = nullptr;
    ReleaseCrashResources();
}

bool RequestSnapshot(const char* source) {
    if (!g_running.load(std::memory_order_acquire) || !g_snapshot_event)
        return false;
    bool expected = false;
    if (!g_snapshot_pending.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel))
        return false;
    AcquireSRWLockExclusive(&g_snapshot_source_lock);
    CopyText(g_snapshot_source, sizeof(g_snapshot_source), source);
    ReleaseSRWLockExclusive(&g_snapshot_source_lock);
    Breadcrumb("diagnostics", "snapshot", "queued",
               g_snapshot_sequence.load(std::memory_order_acquire) + 1, 0);
    capture::Event(capture::Level::Info, "diagnostics", "snapshot_queued",
                   capture::Fields().String("source", source ? source : ""));
    if (!SetEvent(g_snapshot_event)) {
        g_snapshot_pending.store(false, std::memory_order_release);
        return false;
    }
    return true;
}

bool CaptureFastFail(uint32_t subcode, uintptr_t detection_address) {
    if (!detection_address) return false;
    Breadcrumb("exception", "fast_fail", "security_cookie",
               subcode, detection_address);
    CONTEXT context{};
    RtlCaptureContext(&context);
    EXCEPTION_RECORD record{};
    record.ExceptionCode = 0xc0000409u;  // STATUS_STACK_BUFFER_OVERRUN
    record.ExceptionFlags = EXCEPTION_NONCONTINUABLE;
    record.ExceptionAddress = reinterpret_cast<void*>(detection_address);
    record.NumberParameters = 1;
    record.ExceptionInformation[0] = subcode;
    return SubmitCrash(&record, &context);
}

bool SetDeepCapture(bool enabled, const char* source) {
    return capture::SetDeepCapture(enabled, source);
}

bool WaitForIdle(unsigned timeout_ms) {
    const uint64_t start = GetTickCount64();
    while (g_snapshot_pending.load(std::memory_order_acquire) ||
           g_crash_pending.load(std::memory_order_acquire)) {
        if (GetTickCount64() - start >= timeout_ms) return false;
        Sleep(10);
    }
    return true;
}

void Breadcrumb(const char* component, const char* operation,
                const char* phase, uint64_t value_a, uint64_t value_b) {
    const uint64_t sequence =
        g_breadcrumb_sequence.fetch_add(1, std::memory_order_acq_rel) + 1;
    BreadcrumbSlot& slot = g_breadcrumbs[sequence % kBreadcrumbCount];
    if (slot.writing.test_and_set(std::memory_order_acquire)) return;
    slot.committed.store(0, std::memory_order_release);
    slot.tick.store(GetTickCount64(), std::memory_order_relaxed);
    slot.thread_id.store(GetCurrentThreadId(), std::memory_order_relaxed);
    StoreAtomicText(slot.component, component);
    StoreAtomicText(slot.operation, operation);
    StoreAtomicText(slot.phase, phase);
    slot.value_a.store(value_a, std::memory_order_relaxed);
    slot.value_b.store(value_b, std::memory_order_relaxed);
    slot.committed.store(sequence, std::memory_order_release);
    slot.writing.clear(std::memory_order_release);
}

HookContext CurrentHookContext() { return g_hook_context; }

}  // namespace crash_capture
