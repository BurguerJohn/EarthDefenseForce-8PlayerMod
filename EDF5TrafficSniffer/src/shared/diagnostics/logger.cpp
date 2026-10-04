#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <windows.h>
#include <bcrypt.h>

#include "logger.h"

#include "mod_info.h"
#include "runtime_config.h"
#include "win32_handle.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <deque>
#include <limits>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace capture {
namespace {

constexpr unsigned kSchemaVersion = 2;
constexpr unsigned kCriticalQueueReserve = 256;
constexpr unsigned kNetworkSlotCount = 32;
constexpr unsigned kP2PCallsiteSlotCount = 64;
constexpr unsigned kGamePacketRouteSlotCount = 128;
constexpr unsigned kGameMessageRouteSlotCount = 256;
constexpr uint64_t kNetworkSummaryPeriodMs = 10000;

struct LastErrorGuard {
    DWORD win32 = GetLastError();
    int winsock = WSAGetLastError();
    ~LastErrorGuard() {
        WSASetLastError(winsock);
        SetLastError(win32);
    }
};

struct CapturedEvent {
    uint64_t sequence = 0;
    LARGE_INTEGER qpc{};
    FILETIME utc{};
    DWORD thread_id = 0;
    Level level = Level::Debug;
    std::string layer;
    std::string event;
    std::string fields;
    std::vector<uint8_t> payload;
    size_t payload_original_size = 0;
    size_t memory_bytes = 0;
};

struct NetworkSlot {
    std::atomic<uint64_t> key{0};
    std::atomic<uint64_t> pending_key{0};
    std::atomic<uint64_t> peer{0};
    std::atomic<int32_t> channel{0};
    std::atomic<bool> synthetic{false};
    std::atomic<uint64_t> tx_packets{0};
    std::atomic<uint64_t> tx_bytes{0};
    std::atomic<uint64_t> tx_failures{0};
    std::atomic<uint64_t> rx_packets{0};
    std::atomic<uint64_t> rx_bytes{0};
    std::atomic<uint64_t> rx_failures{0};
    std::atomic<uint64_t> last_tx_tick{0};
    std::atomic<uint64_t> last_rx_tick{0};
    std::atomic<uint64_t> emitted_tx_packets{0};
    std::atomic<uint64_t> emitted_rx_packets{0};
};

// A bounded, allocation-free inventory of the EDF5 routines that produce or
// consume logical Steam P2P packets. The key deliberately excludes peer IDs:
// one row describes a serializer/deserializer callsite, direction and channel
// across the whole session without exposing additional endpoint information.
struct P2PCallsiteSlot {
    std::atomic<uint64_t> key{0};
    std::atomic<uint64_t> pending_key{0};
    std::atomic<uint64_t> caller_rva{0};
    std::atomic<int32_t> channel{0};
    std::atomic<bool> outgoing{false};
    std::atomic<uint64_t> packets{0};
    std::atomic<uint64_t> bytes{0};
    std::atomic<uint64_t> failures{0};
    std::atomic<uint64_t> synthetic_packets{0};
    std::atomic<uint64_t> minimum_packet_bytes{
        std::numeric_limits<uint64_t>::max()};
    std::atomic<uint64_t> maximum_packet_bytes{0};
    std::atomic<uint64_t> emitted_packets{0};
};

// Correlates EDF5's high-level serializer and receive callback paths without
// retaining peer identities or payload bytes. Entries are bounded and updated
// without allocation because these functions execute on the game's network
// path and may also be the last useful breadcrumbs before a crash.
struct GamePacketRouteSlot {
    std::atomic<uint64_t> key{0};
    std::atomic<uint64_t> pending_key{0};
    std::atomic<uint64_t> producer_rva{0};
    std::atomic<uint64_t> handler_rva{0};
    std::atomic<uint64_t> handler_vtable_rva{0};
    std::atomic<int32_t> channel{0};
    std::atomic<bool> outgoing{false};
    std::atomic<uint64_t> packets{0};
    std::atomic<uint64_t> bytes{0};
    std::atomic<uint64_t> minimum_packet_bytes{
        std::numeric_limits<uint64_t>::max()};
    std::atomic<uint64_t> maximum_packet_bytes{0};
    std::atomic<uint64_t> emitted_packets{0};
};

// Privacy-safe inventory of EDF5 logical messages. Outgoing messages are
// observed before encrypted P2P packing; incoming messages are observed after
// the MissionScript dispatcher has decoded their type. Only protocol metadata,
// aggregate sizes when available, a process-relative route RVA and whether the
// optional shared context handle is populated are retained. Payload bytes and
// endpoint identities never enter this table.
struct GameMessageRouteSlot {
    std::atomic<uint64_t> key{0};
    std::atomic<uint64_t> pending_key{0};
    std::atomic<uint32_t> message_code{0};
    std::atomic<uint32_t> message_family{0};
    std::atomic<uint32_t> message_flags{0};
    std::atomic<bool> context_handle_present{false};
    std::atomic<bool> outgoing{false};
    std::atomic<bool> message_size_available{true};
    std::atomic<uint64_t> producer_rva{0};
    std::atomic<uint64_t> messages{0};
    std::atomic<uint64_t> bytes{0};
    std::atomic<uint64_t> header_unavailable{0};
    std::atomic<uint64_t> header_length_mismatches{0};
    std::atomic<uint64_t> known_multipart_messages{0};
    std::atomic<uint64_t> unexpected_framing_mismatches{0};
    std::atomic<uint64_t> minimum_message_bytes{
        std::numeric_limits<uint64_t>::max()};
    std::atomic<uint64_t> maximum_message_bytes{0};
    std::atomic<uint64_t> emitted_messages{0};
};

struct RetentionItem {
    std::wstring path;
    uint64_t bytes = 0;
    uint64_t write_time = 0;
};

struct AtomicRuntimeState {
    std::atomic<uint64_t> flow_id{0};
    std::atomic<uint64_t> lobby_steam_id{0};
    std::atomic<uint64_t> last_progress_tick{0};
    std::atomic<uint64_t> mission_generation{0};
    std::atomic<uint32_t> gameplay_contact_mask{0};
    std::atomic<unsigned> real_gameplay_peers{0};
    std::atomic<uint32_t> ready_mask{0};
    std::atomic<uint32_t> mission_group_mask{0};
    std::atomic<int32_t> actual_members{-1};
    std::atomic<int32_t> mission_ui_state{-1};
    std::atomic<unsigned> synthetic_members{0};
    std::atomic<unsigned> max_players{0};
    std::array<std::atomic<uint64_t>, 4> phase{};
};

Config g_config;
std::wstring g_session_directory;
std::string g_session_id;
HANDLE g_events_file = INVALID_HANDLE_VALUE;
HANDLE g_payload_file = INVALID_HANDLE_VALUE;
HANDLE g_queue_event = nullptr;
HANDLE g_writer_thread = nullptr;
DWORD g_writer_thread_id = 0;
SRWLOCK g_queue_lock = SRWLOCK_INIT;
SRWLOCK g_status_lock = SRWLOCK_INIT;
std::deque<CapturedEvent> g_queue;
size_t g_queue_bytes = 0;
std::atomic<uint64_t> g_current_queue_events{0};
std::atomic<uint64_t> g_current_queue_bytes{0};
std::atomic<bool> g_running{false};
std::atomic<bool> g_initialized{false};
std::atomic<bool> g_stopped{false};
std::atomic<bool> g_crashed{false};
std::atomic<bool> g_deep_capture{false};
std::atomic<bool> g_deep_limit_notice{false};
std::atomic<uint64_t> g_sequence{0};
std::atomic<uint64_t> g_flow_sequence{0};
std::atomic<uint64_t> g_dropped_events{0};
std::atomic<uint64_t> g_dropped_bytes{0};
std::atomic<uint64_t> g_write_errors{0};
std::atomic<uint64_t> g_peak_queue_events{0};
std::atomic<uint64_t> g_peak_queue_bytes{0};
std::atomic<uint64_t> g_payload_accepted_bytes{0};
std::atomic<uint64_t> g_socket_tx_packets{0};
std::atomic<uint64_t> g_socket_tx_bytes{0};
std::atomic<uint64_t> g_socket_rx_packets{0};
std::atomic<uint64_t> g_socket_rx_bytes{0};
std::atomic<uint64_t> g_last_network_emit_tick{0};
std::array<NetworkSlot, kNetworkSlotCount> g_network{};
std::array<P2PCallsiteSlot, kP2PCallsiteSlotCount> g_p2p_callsites{};
std::atomic<uint64_t> g_dropped_p2p_callsites{0};
std::array<GamePacketRouteSlot, kGamePacketRouteSlotCount>
    g_game_packet_routes{};
std::atomic<uint64_t> g_dropped_game_packet_routes{0};
std::array<GameMessageRouteSlot, kGameMessageRouteSlotCount>
    g_game_message_routes{};
std::atomic<uint64_t> g_dropped_game_message_routes{0};
LARGE_INTEGER g_qpc_frequency{};
LARGE_INTEGER g_start_qpc{};
uint64_t g_payload_offset = 0;
uint64_t g_event_file_bytes = 0;
uint64_t g_payload_file_bytes = 0;
unsigned g_event_part = 1;
unsigned g_payload_part = 1;
std::atomic<uint64_t> g_runtime_version{0};
AtomicRuntimeState g_runtime_state{};
thread_local bool g_inside_logger = false;
thread_local size_t g_payload_original_size_override = 0;

struct PayloadOriginalSizeScope {
    explicit PayloadOriginalSizeScope(size_t value)
        : previous(g_payload_original_size_override) {
        g_payload_original_size_override = value;
    }
    ~PayloadOriginalSizeScope() {
        g_payload_original_size_override = previous;
    }
    size_t previous = 0;
};

bool FailInitialization() {
    // Preserve the API error that explains the startup failure while undoing
    // every resource acquired before it. In particular, an abandoned session
    // directory must not make the crash handler believe the logger is usable.
    LastErrorGuard last_error;
    g_running.store(false, std::memory_order_release);
    if (g_queue_event) SetEvent(g_queue_event);
    if (g_writer_thread) {
        if (!win32_handle::ThreadStopped(g_writer_thread, 5000)) {
            return false;
        }
        win32_handle::CloseNullable(g_writer_thread);
    }
    win32_handle::CloseNullable(g_queue_event);
    win32_handle::CloseFile(g_payload_file);
    win32_handle::CloseFile(g_events_file);
    g_writer_thread_id = 0;
    g_session_directory.clear();
    g_session_id.clear();
    g_initialized.store(false, std::memory_order_release);
    return false;
}

bool EnsureDirectory(const std::wstring& path) {
    if (path.empty()) return false;
    const DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES) {
        return (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    }
    const size_t slash = path.find_last_of(L"\\/");
    if (slash != std::wstring::npos && slash > 0 &&
        !EnsureDirectory(path.substr(0, slash))) {
        return false;
    }
    return CreateDirectoryW(path.c_str(), nullptr) != FALSE ||
           GetLastError() == ERROR_ALREADY_EXISTS;
}

std::string FormatUtc(const FILETIME& file_time) {
    SYSTEMTIME st{};
    if (!FileTimeToSystemTime(&file_time, &st)) {
        return "1970-01-01T00:00:00.000Z";
    }
    char buffer[40]{};
    std::snprintf(buffer, sizeof(buffer),
                  "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ", st.wYear,
                  st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
                  st.wMilliseconds);
    return buffer;
}

std::wstring SessionName() {
    SYSTEMTIME st{};
    GetSystemTime(&st);
    wchar_t buffer[96]{};
    std::swprintf(buffer, std::size(buffer),
                  L"%04u%02u%02uT%02u%02u%02u.%03uZ_pid%lu", st.wYear,
                  st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
                  st.wMilliseconds, GetCurrentProcessId());
    return buffer;
}

bool WriteAll(HANDLE file, const void* data, size_t size) {
    if (file == INVALID_HANDLE_VALUE || !data) return size == 0;
    const auto* cursor = static_cast<const uint8_t*>(data);
    while (size) {
        const DWORD chunk =
            static_cast<DWORD>(std::min<size_t>(size, 0x7ffff000u));
        DWORD written = 0;
        if (!WriteFile(file, cursor, chunk, &written, nullptr) ||
            written != chunk) {
            return false;
        }
        cursor += written;
        size -= written;
    }
    return true;
}

bool WriteTextFile(const std::wstring& path, const std::string& text) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ,
                              nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                              nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    const bool result = WriteAll(file, text.data(), text.size());
    FlushFileBuffers(file);
    CloseHandle(file);
    return result;
}

uint32_t Crc32(const uint8_t* data, size_t size) {
    uint32_t crc = 0xffffffffu;
    for (size_t i = 0; i < size; ++i) {
        crc ^= data[i];
        for (unsigned bit = 0; bit < 8; ++bit) {
            crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1u)));
        }
    }
    return ~crc;
}

std::string HexPreview(const std::vector<uint8_t>& bytes, size_t limit) {
    static constexpr char hex[] = "0123456789abcdef";
    const size_t count = std::min(bytes.size(), limit);
    std::string result;
    result.reserve(count * 2);
    for (size_t i = 0; i < count; ++i) {
        result.push_back(hex[bytes[i] >> 4]);
        result.push_back(hex[bytes[i] & 15]);
    }
    return result;
}

std::string AsciiPreview(const std::vector<uint8_t>& bytes, size_t limit) {
    const size_t count = std::min(bytes.size(), limit);
    std::string result;
    result.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        const uint8_t c = bytes[i];
        result.push_back(c >= 32 && c <= 126 ? static_cast<char>(c) : '.');
    }
    return result;
}

std::wstring PartPath(const wchar_t* stem, const wchar_t* extension,
                      unsigned part) {
    if (part == 1) {
        return g_session_directory + L"\\" + stem + extension;
    }
    wchar_t suffix[48]{};
    std::swprintf(suffix, std::size(suffix), L"-%04u%s", part, extension);
    return g_session_directory + L"\\" + stem + suffix;
}

std::string PartName(const char* stem, const char* extension, unsigned part) {
    if (part == 1) return std::string(stem) + extension;
    char buffer[64]{};
    std::snprintf(buffer, sizeof(buffer), "%s-%04u%s", stem, part, extension);
    return buffer;
}

bool RotateEventsIfNeeded(size_t incoming) {
    const uint64_t limit = static_cast<uint64_t>(g_config.rotate_mib) << 20;
    if (!limit || g_event_file_bytes + incoming <= limit) return true;
    FlushFileBuffers(g_events_file);
    CloseHandle(g_events_file);
    g_events_file = INVALID_HANDLE_VALUE;
    ++g_event_part;
    const std::wstring path = PartPath(L"events", L".jsonl", g_event_part);
    g_events_file = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ,
                                nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL,
                                nullptr);
    g_event_file_bytes = 0;
    return g_events_file != INVALID_HANDLE_VALUE;
}

bool RotatePayloadIfNeeded(size_t incoming) {
    const uint64_t limit = static_cast<uint64_t>(g_config.rotate_mib) << 20;
    if (!limit || g_payload_file_bytes + incoming <= limit) return true;
    FlushFileBuffers(g_payload_file);
    CloseHandle(g_payload_file);
    g_payload_file = INVALID_HANDLE_VALUE;
    ++g_payload_part;
    const std::wstring path =
        PartPath(L"payloads", L".bin", g_payload_part);
    g_payload_file = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ,
                                 nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL,
                                 nullptr);
    g_payload_offset = 0;
    g_payload_file_bytes = 0;
    return g_payload_file != INVALID_HANDLE_VALUE;
}

void WriteEvent(CapturedEvent& item) {
    std::ostringstream line;
    const uint64_t mono_us = g_qpc_frequency.QuadPart > 0
        ? static_cast<uint64_t>((item.qpc.QuadPart - g_start_qpc.QuadPart) *
                                1000000LL / g_qpc_frequency.QuadPart)
        : 0;
    line << "{\"schema\":" << kSchemaVersion
         << ",\"seq\":" << item.sequence
         << ",\"utc\":\"" << FormatUtc(item.utc) << "\""
         << ",\"mono_us\":" << mono_us
         << ",\"process_id\":" << GetCurrentProcessId()
         << ",\"thread_id\":" << item.thread_id
         << ",\"level\":\"" << LevelName(item.level) << "\""
         << ",\"layer\":\"" << Escape(item.layer) << "\""
         << ",\"event\":\"" << Escape(item.event) << "\"";
    if (!item.fields.empty()) line << ',' << item.fields;

    if (!item.payload.empty()) {
        const bool ready = RotatePayloadIfNeeded(item.payload.size());
        const uint64_t offset = g_payload_offset;
        const bool written = ready &&
            WriteAll(g_payload_file, item.payload.data(), item.payload.size());
        if (written) {
            g_payload_offset += item.payload.size();
            g_payload_file_bytes += item.payload.size();
        } else {
            g_write_errors.fetch_add(1, std::memory_order_relaxed);
        }
        char crc[16]{};
        std::snprintf(crc, sizeof(crc), "%08x",
                      Crc32(item.payload.data(), item.payload.size()));
        line << ",\"payload\":{"
             << "\"file\":\""
             << PartName("payloads", ".bin", g_payload_part) << "\""
             << ",\"offset\":" << offset
             << ",\"length\":" << item.payload.size()
             << ",\"original_length\":" << item.payload_original_size
             << ",\"truncated\":"
             << (item.payload.size() < item.payload_original_size ? "true"
                                                                  : "false")
             << ",\"crc32\":\"" << crc << "\""
             << ",\"preview_hex\":\""
             << HexPreview(item.payload, g_config.payload_preview_bytes)
             << "\""
             << ",\"preview_ascii\":\""
             << Escape(AsciiPreview(item.payload,
                                    g_config.payload_preview_bytes))
             << "\""
             << ",\"write_ok\":" << (written ? "true" : "false") << '}';
    }
    line << "}\r\n";
    const std::string text = line.str();
    if (!RotateEventsIfNeeded(text.size()) ||
        !WriteAll(g_events_file, text.data(), text.size())) {
        g_write_errors.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    g_event_file_bytes += text.size();
}

CapturedEvent InternalEvent(Level level, const char* event,
                            const Fields& fields) {
    CapturedEvent item;
    item.sequence = g_sequence.fetch_add(1, std::memory_order_relaxed) + 1;
    QueryPerformanceCounter(&item.qpc);
    GetSystemTimeAsFileTime(&item.utc);
    item.thread_id = GetCurrentThreadId();
    item.level = level;
    item.layer = "diagnostics";
    item.event = event ? event : "";
    item.fields = fields.Json();
    return item;
}

void WriteHealthFile() {
    if (g_session_directory.empty()) return;
    const RuntimeState state = GetRuntimeState();
    std::ostringstream health;
    health << "{\r\n"
           << "  \"schema\": 2,\r\n"
           << "  \"queued_events\": "
           << g_current_queue_events.load(std::memory_order_relaxed)
           << ",\r\n"
           << "  \"queued_bytes\": "
           << g_current_queue_bytes.load(std::memory_order_relaxed)
           << ",\r\n"
           << "  \"peak_queue_events\": "
           << g_peak_queue_events.load(std::memory_order_relaxed) << ",\r\n"
           << "  \"peak_queue_bytes\": "
           << g_peak_queue_bytes.load(std::memory_order_relaxed) << ",\r\n"
           << "  \"dropped_events\": "
           << g_dropped_events.load(std::memory_order_relaxed) << ",\r\n"
           << "  \"dropped_bytes\": "
           << g_dropped_bytes.load(std::memory_order_relaxed) << ",\r\n"
           << "  \"write_errors\": "
           << g_write_errors.load(std::memory_order_relaxed) << ",\r\n"
           << "  \"deep_capture_enabled\": "
           << (g_deep_capture.load(std::memory_order_relaxed) ? "true"
                                                             : "false")
           << ",\r\n"
           << "  \"flow_id\": " << state.flow_id << ",\r\n"
           << "  \"phase\": \"" << Escape(state.phase) << "\",\r\n"
           << "  \"real_gameplay_peers\": " << state.real_gameplay_peers
           << ",\r\n"
           << "  \"synthetic_members\": " << state.synthetic_members
           << ",\r\n"
           << "  \"actual_members\": " << state.actual_members << "\r\n"
           << "}\r\n";
    WriteTextFile(g_session_directory + L"\\health.json", health.str());
}

void WriteStatus(const char* state, const std::string& extra = {}) {
    if (g_session_directory.empty()) return;
    AcquireSRWLockExclusive(&g_status_lock);
    FILETIME now{};
    GetSystemTimeAsFileTime(&now);
    std::ostringstream status;
    status << "{\r\n"
           << "  \"schema\": 2,\r\n"
           << "  \"state\": \"" << Escape(state ? state : "unknown")
           << "\",\r\n"
           << "  \"updated_utc\": \"" << FormatUtc(now) << "\",\r\n"
           << "  \"last_sequence\": "
           << g_sequence.load(std::memory_order_relaxed);
    if (!extra.empty()) status << ",\r\n" << extra;
    status << "\r\n}\r\n";
    const std::wstring final_path = g_session_directory + L"\\status.json";
    const std::wstring temp_path = g_session_directory + L"\\status.tmp";
    if (WriteTextFile(temp_path, status.str())) {
        MoveFileExW(temp_path.c_str(), final_path.c_str(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
    }
    ReleaseSRWLockExclusive(&g_status_lock);
}

DWORD WINAPI WriterMain(void*) {
    unsigned since_flush = 0;
    uint64_t reported_dropped = 0;
    uint64_t reported_errors = 0;
    for (;;) {
        WaitForSingleObject(g_queue_event, 1000);
        EmitNetworkSummary(false);
        std::deque<CapturedEvent> work;
        AcquireSRWLockExclusive(&g_queue_lock);
        work.swap(g_queue);
        g_queue_bytes = 0;
        g_current_queue_events.store(0, std::memory_order_release);
        g_current_queue_bytes.store(0, std::memory_order_release);
        const bool should_stop =
            !g_running.load(std::memory_order_acquire) && work.empty();
        ReleaseSRWLockExclusive(&g_queue_lock);

        for (auto& item : work) {
            WriteEvent(item);
            ++since_flush;
        }

        const uint64_t dropped =
            g_dropped_events.load(std::memory_order_acquire);
        const uint64_t errors = g_write_errors.load(std::memory_order_acquire);
        const bool deep_limit =
            g_deep_limit_notice.exchange(false, std::memory_order_acq_rel);
        if (dropped != reported_dropped || errors != reported_errors ||
            deep_limit) {
            CapturedEvent health = InternalEvent(
                dropped != reported_dropped ? Level::Warning : Level::Info,
                "logger_health",
                Fields().UInt("dropped_events", dropped)
                    .UInt("dropped_since_last", dropped - reported_dropped)
                    .UInt("dropped_bytes",
                          g_dropped_bytes.load(std::memory_order_relaxed))
                    .UInt("write_errors", errors)
                    .UInt("peak_queue_events",
                          g_peak_queue_events.load(std::memory_order_relaxed))
                    .UInt("peak_queue_bytes",
                          g_peak_queue_bytes.load(std::memory_order_relaxed))
                    .Bool("deep_capture_enabled",
                          g_deep_capture.load(std::memory_order_relaxed))
                    .Bool("deep_limit_reached", deep_limit));
            WriteEvent(health);
            reported_dropped = dropped;
            reported_errors = errors;
            ++since_flush;
        }

        if (since_flush >= g_config.flush_every_events ||
            (work.empty() && since_flush != 0)) {
            EmergencyFlush();
            since_flush = 0;
        }
        if (should_stop) break;
    }
    EmergencyFlush();
    return 0;
}

// "auto" or the configured multiple of the four-player enemy health.
std::string EnemyHealthSetting(float multiplier) {
    if (!(multiplier > 0.0f)) return "auto";
    char text[32]{};
    std::snprintf(text, sizeof(text), "%.3g",
                  static_cast<double>(multiplier));
    return text;
}

const char* ProfileName(DiagnosticProfile profile) {
    switch (profile) {
    case DiagnosticProfile::Essential: return "Essential";
    case DiagnosticProfile::Maximum: return "Maximum";
    default: return "Balanced";
    }
}

const char* DumpModeName(CrashDumpMode mode) {
    switch (mode) {
    case CrashDumpMode::Off: return "Off";
    case CrashDumpMode::Full: return "Full";
    default: return "Mini";
    }
}

bool IsNetworkLayer(const char* layer) {
    if (!layer) return false;
    return std::strncmp(layer, "steam", 5) == 0 ||
           std::strncmp(layer, "winsock", 7) == 0;
}

bool Contains(const char* value, const char* needle) {
    return value && needle && std::strstr(value, needle) != nullptr;
}

Level DefaultLevel(const char* layer, const char* event) {
    if (Contains(event, "failed") || Contains(event, "failure"))
        return Level::Error;
    if (Contains(event, "mismatch") || Contains(event, "rejected") ||
        Contains(event, "timed_out") || Contains(event, "overflow"))
        return Level::Warning;
    if (layer && std::strcmp(layer, "more_players") == 0) {
        if (Contains(event, "p2p_send") || Contains(event, "p2p_read") ||
            Contains(event, "scroll"))
            return Level::Debug;
        return Level::Info;
    }
    if (layer && std::strcmp(layer, "sniffer") == 0) {
        if (Contains(event, "hook_install")) return Level::Debug;
        return Level::Info;
    }
    if (layer && std::strcmp(layer, "steam") == 0) {
        if (Contains(event, "api_") || Contains(event, "context_init"))
            return Level::Info;
        return Level::Debug;
    }
    if (layer && std::strcmp(layer, "steam_matchmaking") == 0) {
        if (Contains(event, "create_lobby") || Contains(event, "join_lobby") ||
            Contains(event, "leave_lobby") ||
            Contains(event, "request_lobby_list") ||
            Contains(event, "set_member_limit") ||
            Contains(event, "send_lobby_chat"))
            return Level::Info;
        return Level::Debug;
    }
    if (layer && std::strcmp(layer, "steam_user") == 0)
        return Level::Info;
    if (layer && std::strcmp(layer, "steam_http") == 0) {
        if (Contains(event, "create_request") || Contains(event, "send_request") ||
            Contains(event, "timed_out"))
            return Level::Info;
        return Level::Debug;
    }
    if (layer && std::strcmp(layer, "winsock") == 0) {
        if (Contains(event, "connect") || Contains(event, "listen") ||
            Contains(event, "accept") || Contains(event, "shutdown") ||
            std::strcmp(event ? event : "", "close") == 0)
            return Level::Info;
        return Level::Debug;
    }
    if (layer && std::strcmp(layer, "winsock_dns") == 0)
        return Level::Info;
    if (layer && std::strcmp(layer, "steam_p2p") == 0) {
        if (Contains(event, "send") || Contains(event, "read") ||
            Contains(event, "available"))
            return Level::Trace;
        return Level::Debug;
    }
    return Level::Debug;
}

void RecordSocketTraffic(const char* layer, const char* event, size_t bytes) {
    if (!layer || !event || std::strcmp(layer, "winsock") != 0 || !bytes)
        return;
    if (Contains(event, "send")) {
        g_socket_tx_packets.fetch_add(1, std::memory_order_relaxed);
        g_socket_tx_bytes.fetch_add(bytes, std::memory_order_relaxed);
    } else if (Contains(event, "recv") || Contains(event, "receive")) {
        g_socket_rx_packets.fetch_add(1, std::memory_order_relaxed);
        g_socket_rx_bytes.fetch_add(bytes, std::memory_order_relaxed);
    }
}

using BCryptOpenAlgorithmProviderFn = NTSTATUS(WINAPI*)(
    BCRYPT_ALG_HANDLE*, LPCWSTR, LPCWSTR, ULONG);
using BCryptGetPropertyFn = NTSTATUS(WINAPI*)(BCRYPT_HANDLE, LPCWSTR, PUCHAR,
                                              ULONG, ULONG*, ULONG);
using BCryptCreateHashFn = NTSTATUS(WINAPI*)(BCRYPT_ALG_HANDLE,
                                             BCRYPT_HASH_HANDLE*, PUCHAR,
                                             ULONG, PUCHAR, ULONG, ULONG);
using BCryptHashDataFn = NTSTATUS(WINAPI*)(BCRYPT_HASH_HANDLE, PUCHAR, ULONG,
                                           ULONG);
using BCryptFinishHashFn = NTSTATUS(WINAPI*)(BCRYPT_HASH_HANDLE, PUCHAR, ULONG,
                                             ULONG);
using BCryptDestroyHashFn = NTSTATUS(WINAPI*)(BCRYPT_HASH_HANDLE);
using BCryptCloseAlgorithmProviderFn = NTSTATUS(WINAPI*)(BCRYPT_ALG_HANDLE,
                                                          ULONG);

template <typename T>
T ResolveProcedure(HMODULE module, const char* name) {
    static_assert(sizeof(T) == sizeof(FARPROC),
                  "Windows procedure pointers must have matching size");
    const FARPROC address = GetProcAddress(module, name);
    T procedure = nullptr;
    std::memcpy(&procedure, &address, sizeof(procedure));
    return procedure;
}

std::string Sha256File(const wchar_t* path) {
    if (!path || !*path) return {};
    HMODULE bcrypt = LoadLibraryW(L"bcrypt.dll");
    if (!bcrypt) return {};
    const auto open_algorithm = ResolveProcedure<BCryptOpenAlgorithmProviderFn>(
        bcrypt, "BCryptOpenAlgorithmProvider");
    const auto get_property = ResolveProcedure<BCryptGetPropertyFn>(
        bcrypt, "BCryptGetProperty");
    const auto create_hash = ResolveProcedure<BCryptCreateHashFn>(
        bcrypt, "BCryptCreateHash");
    const auto hash_data = ResolveProcedure<BCryptHashDataFn>(
        bcrypt, "BCryptHashData");
    const auto finish_hash = ResolveProcedure<BCryptFinishHashFn>(
        bcrypt, "BCryptFinishHash");
    const auto destroy_hash = ResolveProcedure<BCryptDestroyHashFn>(
        bcrypt, "BCryptDestroyHash");
    const auto close_algorithm =
        ResolveProcedure<BCryptCloseAlgorithmProviderFn>(
            bcrypt, "BCryptCloseAlgorithmProvider");
    if (!open_algorithm || !get_property || !create_hash || !hash_data ||
        !finish_hash || !destroy_hash || !close_algorithm) {
        FreeLibrary(bcrypt);
        return {};
    }

    HANDLE file = CreateFileW(path, GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE |
                                  FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                              nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        FreeLibrary(bcrypt);
        return {};
    }

    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    ULONG object_size = 0;
    ULONG hash_size = 0;
    ULONG returned = 0;
    std::vector<uint8_t> object;
    std::vector<uint8_t> digest;
    bool ok = open_algorithm(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0 &&
              get_property(algorithm, BCRYPT_OBJECT_LENGTH,
                           reinterpret_cast<PUCHAR>(&object_size),
                           sizeof(object_size), &returned, 0) >= 0 &&
              get_property(algorithm, BCRYPT_HASH_LENGTH,
                           reinterpret_cast<PUCHAR>(&hash_size),
                           sizeof(hash_size), &returned, 0) >= 0;
    if (ok) {
        object.resize(object_size);
        digest.resize(hash_size);
        ok = create_hash(algorithm, &hash, object.data(), object_size, nullptr,
                         0, 0) >= 0;
    }
    std::array<uint8_t, 65536> buffer{};
    while (ok) {
        DWORD read = 0;
        if (!ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()),
                      &read, nullptr)) {
            ok = false;
            break;
        }
        if (!read) break;
        if (hash_data(hash, buffer.data(), read, 0) < 0) ok = false;
    }
    if (ok) ok = finish_hash(hash, digest.data(), hash_size, 0) >= 0;
    if (hash) destroy_hash(hash);
    if (algorithm) close_algorithm(algorithm, 0);
    CloseHandle(file);
    FreeLibrary(bcrypt);
    if (!ok) return {};
    static constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(digest.size() * 2);
    for (uint8_t byte : digest) {
        result.push_back(hex[byte >> 4]);
        result.push_back(hex[byte & 15]);
    }
    return result;
}

uint64_t FileTimeValue(const FILETIME& value) {
    ULARGE_INTEGER converted{};
    converted.LowPart = value.dwLowDateTime;
    converted.HighPart = value.dwHighDateTime;
    return converted.QuadPart;
}

bool LooksLikeSessionName(const wchar_t* name) {
    if (!name || std::wcslen(name) < 20) return false;
    for (unsigned i = 0; i < 8; ++i) {
        if (name[i] < L'0' || name[i] > L'9') return false;
    }
    return std::wcsstr(name, L"_pid") != nullptr;
}

uint64_t DirectoryBytes(const std::wstring& path) {
    uint64_t result = 0;
    WIN32_FIND_DATAW data{};
    HANDLE find = FindFirstFileW((path + L"\\*").c_str(), &data);
    if (find == INVALID_HANDLE_VALUE) return 0;
    do {
        if (std::wcscmp(data.cFileName, L".") == 0 ||
            std::wcscmp(data.cFileName, L"..") == 0)
            continue;
        const std::wstring child = path + L"\\" + data.cFileName;
        if (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;
        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            result += DirectoryBytes(child);
        } else {
            ULARGE_INTEGER size{};
            size.HighPart = data.nFileSizeHigh;
            size.LowPart = data.nFileSizeLow;
            result += size.QuadPart;
        }
    } while (FindNextFileW(find, &data));
    FindClose(find);
    return result;
}

bool FileContains(const std::wstring& path, const char* needle,
                  bool tail_only = false) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE |
                                  FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                              nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER size{};
    GetFileSizeEx(file, &size);
    const DWORD count = static_cast<DWORD>(
        std::min<LONGLONG>(size.QuadPart, tail_only ? 4096 : 65536));
    if (tail_only && size.QuadPart > count) {
        LARGE_INTEGER offset{};
        offset.QuadPart = size.QuadPart - count;
        SetFilePointerEx(file, offset, nullptr, FILE_BEGIN);
    }
    std::string text(count, '\0');
    DWORD read = 0;
    const bool ok = ReadFile(file, text.data(), count, &read, nullptr) != FALSE;
    CloseHandle(file);
    text.resize(read);
    return ok && text.find(needle ? needle : "") != std::string::npos;
}

bool IsCleanSession(const std::wstring& path) {
    if (FileContains(path + L"\\status.json", "\"state\": \"clean\""))
        return true;
    return FileContains(path + L"\\events.jsonl", "api_shutdown_end", true);
}

bool DeleteTree(const std::wstring& root, const std::wstring& path) {
    wchar_t root_full[32768]{};
    wchar_t path_full[32768]{};
    if (!GetFullPathNameW(root.c_str(), static_cast<DWORD>(std::size(root_full)),
                          root_full, nullptr) ||
        !GetFullPathNameW(path.c_str(), static_cast<DWORD>(std::size(path_full)),
                          path_full, nullptr))
        return false;
    std::wstring prefix = root_full;
    if (!prefix.empty() && prefix.back() != L'\\') prefix.push_back(L'\\');
    if (_wcsnicmp(prefix.c_str(), path_full, prefix.size()) != 0 ||
        std::wcslen(path_full) <= prefix.size())
        return false;

    WIN32_FIND_DATAW data{};
    HANDLE find = FindFirstFileW((path + L"\\*").c_str(), &data);
    if (find != INVALID_HANDLE_VALUE) {
        do {
            if (std::wcscmp(data.cFileName, L".") == 0 ||
                std::wcscmp(data.cFileName, L"..") == 0)
                continue;
            const std::wstring child = path + L"\\" + data.cFileName;
            if (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
                DeleteFileW(child.c_str());
            } else if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (!DeleteTree(root, child)) {
                    FindClose(find);
                    return false;
                }
            } else if (!DeleteFileW(child.c_str())) {
                FindClose(find);
                return false;
            }
        } while (FindNextFileW(find, &data));
        FindClose(find);
    }
    return RemoveDirectoryW(path.c_str()) != FALSE;
}

void ApplyRetention() {
    WIN32_FIND_DATAW data{};
    HANDLE find = FindFirstFileW((g_config.log_root + L"\\*").c_str(), &data);
    if (find == INVALID_HANDLE_VALUE) return;
    std::vector<RetentionItem> clean;
    do {
        if (!(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
            (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
            !LooksLikeSessionName(data.cFileName))
            continue;
        const std::wstring path = g_config.log_root + L"\\" + data.cFileName;
        if (!IsCleanSession(path)) continue;
        clean.push_back({path, DirectoryBytes(path),
                         FileTimeValue(data.ftLastWriteTime)});
    } while (FindNextFileW(find, &data));
    FindClose(find);
    std::sort(clean.begin(), clean.end(),
              [](const RetentionItem& left, const RetentionItem& right) {
                  return left.write_time < right.write_time;
              });
    uint64_t total = 0;
    for (const auto& item : clean) total += item.bytes;
    const uint64_t maximum = static_cast<uint64_t>(g_config.max_total_mib) << 20;
    size_t first = 0;
    while (first < clean.size() &&
           ((clean.size() - first) >= g_config.max_sessions ||
            total > maximum)) {
        if (DeleteTree(g_config.log_root, clean[first].path)) {
            total = total >= clean[first].bytes ? total - clean[first].bytes : 0;
        }
        ++first;
    }
}

std::string ModuleMetadata(const char* key, const wchar_t* path) {
    WIN32_FILE_ATTRIBUTE_DATA attributes{};
    GetFileAttributesExW(path ? path : L"", GetFileExInfoStandard, &attributes);
    ULARGE_INTEGER size{};
    size.HighPart = attributes.nFileSizeHigh;
    size.LowPart = attributes.nFileSizeLow;
    std::ostringstream result;
    result << "    \"" << key << "\": {\"path\": \""
           << Escape(WideToUtf8(path ? path : L"")) << "\", \"bytes\": "
           << size.QuadPart << ", \"sha256\": \""
           << Sha256File(path ? path : L"") << "\"}";
    return result.str();
}

}  // namespace

void Fields::Key(const char* key) {
    if (!first_) json_ += ',';
    first_ = false;
    json_ += '\"';
    json_ += Escape(key ? key : "");
    json_ += "\":";
}

Fields& Fields::String(const char* key, const char* value) {
    Key(key);
    if (!value) {
        json_ += "null";
    } else {
        json_ += '\"';
        json_ += Escape(value);
        json_ += '\"';
    }
    return *this;
}

Fields& Fields::String(const char* key, const std::string& value) {
    return String(key, value.c_str());
}

Fields& Fields::UInt(const char* key, uint64_t value) {
    Key(key);
    json_ += std::to_string(value);
    return *this;
}

Fields& Fields::Int(const char* key, int64_t value) {
    Key(key);
    json_ += std::to_string(value);
    return *this;
}

Fields& Fields::Bool(const char* key, bool value) {
    Key(key);
    json_ += value ? "true" : "false";
    return *this;
}

Fields& Fields::Null(const char* key) {
    Key(key);
    json_ += "null";
    return *this;
}

Fields& Fields::Raw(const char* key, const std::string& json) {
    Key(key);
    json_ += json;
    return *this;
}

bool Initialize(HMODULE plugin_module) {
    if (g_initialized.exchange(true, std::memory_order_acq_rel)) return true;
    g_stopped.store(false, std::memory_order_release);
    g_config = runtime_config::Load(plugin_module);
    g_deep_capture.store(
        g_config.diagnostic_profile == DiagnosticProfile::Maximum,
        std::memory_order_release);
    if (!g_config.diagnostics_enabled) return true;
    if (!QueryPerformanceFrequency(&g_qpc_frequency) ||
        !QueryPerformanceCounter(&g_start_qpc))
        return FailInitialization();
    if (!EnsureDirectory(g_config.log_root)) return FailInitialization();
    ApplyRetention();
    const std::wstring session_name = SessionName();
    g_session_id = WideToUtf8(session_name.c_str());
    g_session_directory = g_config.log_root + L"\\" + session_name;
    if (!EnsureDirectory(g_session_directory) ||
        !EnsureDirectory(g_session_directory + L"\\crashes") ||
        !EnsureDirectory(g_session_directory + L"\\snapshots"))
        return FailInitialization();

    g_events_file = CreateFileW(PartPath(L"events", L".jsonl", 1).c_str(),
                                GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                                CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    g_payload_file = CreateFileW(PartPath(L"payloads", L".bin", 1).c_str(),
                                 GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                                 CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (g_events_file == INVALID_HANDLE_VALUE ||
        g_payload_file == INVALID_HANDLE_VALUE)
        return FailInitialization();

    wchar_t exe_path[32768]{};
    wchar_t plugin_path[32768]{};
    wchar_t steam_path[32768]{};
    wchar_t loader_path[32768]{};
    GetModuleFileNameW(nullptr, exe_path, static_cast<DWORD>(std::size(exe_path)));
    if (plugin_module) {
        GetModuleFileNameW(plugin_module, plugin_path,
                           static_cast<DWORD>(std::size(plugin_path)));
    }
    std::wstring game_directory = exe_path;
    const size_t slash = game_directory.find_last_of(L"\\/");
    if (slash != std::wstring::npos) game_directory.resize(slash + 1);
    std::wcsncpy(steam_path, (game_directory + L"steam_api64.dll").c_str(),
                 std::size(steam_path) - 1);
    std::wcsncpy(loader_path, (game_directory + L"winmm.dll").c_str(),
                 std::size(loader_path) - 1);

    FILETIME now{};
    GetSystemTimeAsFileTime(&now);
    MEMORYSTATUSEX memory{};
    memory.dwLength = sizeof(memory);
    GlobalMemoryStatusEx(&memory);
    SYSTEM_INFO system{};
    GetNativeSystemInfo(&system);
    std::ostringstream metadata;
    metadata << "{\r\n"
             << "  \"schema\": 2,\r\n"
             << "  \"plugin\": \""
             << mod_info::NameForGame(g_config.active_game) << "\",\r\n"
             << "  \"plugin_version\": \"" << mod_info::kVersion
             << "\",\r\n"
             << "  \"build_id\": \"" << mod_info::kBuildId << "\",\r\n"
             << "  \"session_id\": \"" << Escape(g_session_id) << "\",\r\n"
             << "  \"started_utc\": \"" << FormatUtc(now) << "\",\r\n"
             << "  \"process_id\": " << GetCurrentProcessId() << ",\r\n"
             << "  \"qpc_frequency\": " << g_qpc_frequency.QuadPart
             << ",\r\n"
             << "  \"logical_processors\": " << system.dwNumberOfProcessors
             << ",\r\n"
             << "  \"physical_memory_bytes\": " << memory.ullTotalPhys
             << ",\r\n"
             << "  \"game\": \"" << game::Name(g_config.active_game)
             << "\",\r\n"
             << "  \"sniffer_module_enabled\": "
             << (g_config.sniffer ? "true" : "false") << ",\r\n"
             << "  \"coop8_module_enabled\": "
             << (g_config.coop8 ? "true" : "false") << ",\r\n"
             << "  \"diagnostics_enabled\": true,\r\n"
             << "  \"diagnostic_profile\": \""
             << ProfileName(g_config.diagnostic_profile) << "\",\r\n"
             << "  \"crash_dump_mode\": \""
             << DumpModeName(g_config.crash_dump_mode) << "\",\r\n"
             << "  \"snapshot_hotkey_vk\": "
             << g_config.snapshot_hotkey_vk << ",\r\n"
             << "  \"deep_capture_hotkey_vk\": "
             << g_config.deep_capture_hotkey_vk << ",\r\n"
             << "  \"steam_enabled\": "
             << (g_config.steam ? "true" : "false") << ",\r\n"
             << "  \"steam_callbacks_enabled\": "
             << (g_config.steam_callbacks ? "true" : "false") << ",\r\n"
             << "  \"winsock_enabled\": "
             << (g_config.winsock ? "true" : "false") << ",\r\n"
             << "  \"more_players_enabled\": "
             << (g_config.more_players ? "true" : "false") << ",\r\n"
             << "  \"max_players\": " << g_config.max_players << ",\r\n"
             << "  \"experimental_enemy_spawn_multiplier\": "
             << (g_config.experimental_enemy_spawn_multiplier
                     ? "true" : "false") << ",\r\n"
             << "  \"enemy_spawn_multiplier\": "
             << g_config.enemy_spawn_multiplier << ",\r\n"
             << "  \"preallocated_roster_slots\": "
             << g_config.preallocated_roster_slots << ",\r\n"
             << "  \"experimental_reserve_patches\": "
             << (g_config.experimental_reserve_patches ? "true" : "false")
             << ",\r\n"
             << "  \"extended_enemy_health_scaling\": "
             << (g_config.extended_enemy_health_scaling ? "true" : "false")
             << ",\r\n"
             << "  \"enemy_health_players_5_to_8\": \""
             << EnemyHealthSetting(g_config.enemy_health_multipliers[0]) << "/"
             << EnemyHealthSetting(g_config.enemy_health_multipliers[1]) << "/"
             << EnemyHealthSetting(g_config.enemy_health_multipliers[2]) << "/"
             << EnemyHealthSetting(g_config.enemy_health_multipliers[3])
             << "\",\r\n"
             << "  \"bot_hotkey_vk\": " << g_config.bot_hotkey_vk
             << ",\r\n"
             << "  \"bot_remove_hotkey_vk\": "
             << g_config.bot_remove_hotkey_vk << ",\r\n"
             << "  \"bot_ready_hotkey_vk\": "
             << g_config.bot_ready_hotkey_vk << ",\r\n"
             << "  \"local_mission_harness_enabled\": "
             << (g_config.local_mission_harness_enabled ? "true" : "false")
             << ",\r\n"
             << "  \"local_mission_harness_hotkey_vk\": "
             << g_config.local_mission_harness_hotkey_vk << ",\r\n"
             << "  \"debug_stage_win_enabled\": "
             << (g_config.debug_stage_win_enabled ? "true" : "false")
             << ",\r\n"
             << "  \"debug_stage_win_hotkey_vk\": "
             << g_config.debug_stage_win_hotkey_vk << ",\r\n"
             << "  \"bot_steam_id\": " << g_config.bot_steam_id << ",\r\n"
             << "  \"modules\": {\r\n"
             << ModuleMetadata("executable", exe_path) << ",\r\n"
             << ModuleMetadata("plugin", plugin_path) << ",\r\n"
             << ModuleMetadata("steam_api64", steam_path) << ",\r\n"
             << ModuleMetadata("mod_loader", loader_path) << "\r\n"
             << "  }\r\n"
             << "}\r\n";
    if (!WriteTextFile(g_session_directory + L"\\session.json",
                       metadata.str()))
        return FailInitialization();
    WriteStatus("running");

    g_queue_event = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (!g_queue_event) return FailInitialization();
    g_running.store(true, std::memory_order_release);
    g_writer_thread =
        CreateThread(nullptr, 0, WriterMain, nullptr, 0, &g_writer_thread_id);
    if (!g_writer_thread) {
        g_running.store(false, std::memory_order_release);
        return FailInitialization();
    }
    Event(Level::Info, "diagnostics", "started",
          Fields().String("session_directory",
                          WideToUtf8(g_session_directory.c_str()))
              .String("profile", ProfileName(g_config.diagnostic_profile))
              .String("crash_dump_mode",
                      DumpModeName(g_config.crash_dump_mode))
              .UInt("queue_max_events", g_config.queue_max_events)
              .UInt("queue_max_mib", g_config.queue_max_mib)
              .UInt("rotate_mib", g_config.rotate_mib));
    return true;
}

void RequestStop() {
    if (!g_running.exchange(false, std::memory_order_acq_rel)) return;
    if (g_queue_event) SetEvent(g_queue_event);
}

void StopAndFlush() {
    if (g_stopped.exchange(true, std::memory_order_acq_rel)) return;
    const bool has_session = !g_session_directory.empty();
    if (g_running.load(std::memory_order_acquire)) {
        EmitNetworkSummary(true);
    }
    RequestStop();
    if (g_writer_thread && GetCurrentThreadId() != g_writer_thread_id &&
        !win32_handle::ThreadStopped(g_writer_thread, 5000)) {
        // Closing the queue and files while WriterMain may still use them is
        // more dangerous than retaining the handles for a later stop attempt.
        OutputDebugStringW(
            L"EDF5_MultiSlotMod: diagnostics writer did not stop in time; "
            L"resources retained.\r\n");
        g_stopped.store(false, std::memory_order_release);
        EmergencyFlush();
        return;
    }
    if (has_session) {
        EmergencyFlush();
        WriteHealthFile();
        if (!g_crashed.load(std::memory_order_acquire)) WriteStatus("clean");
    }
    win32_handle::CloseNullable(g_writer_thread);
    win32_handle::CloseNullable(g_queue_event);
    win32_handle::CloseFile(g_payload_file);
    win32_handle::CloseFile(g_events_file);
    g_writer_thread_id = 0;
}

void Flush() {
    if (!g_running.load(std::memory_order_acquire)) return;
    for (unsigned i = 0; i < 100; ++i) {
        if (!g_current_queue_events.load(std::memory_order_acquire)) break;
        SetEvent(g_queue_event);
        Sleep(1);
    }
    EmergencyFlush();
}

void EmergencyFlush() {
    if (g_payload_file != INVALID_HANDLE_VALUE) FlushFileBuffers(g_payload_file);
    if (g_events_file != INVALID_HANDLE_VALUE) FlushFileBuffers(g_events_file);
}

const Config& GetConfig() { return g_config; }
const std::wstring& SessionDirectory() { return g_session_directory; }
const std::string& SessionId() { return g_session_id; }

const char* LevelName(Level level) {
    switch (level) {
    case Level::Trace: return "trace";
    case Level::Debug: return "debug";
    case Level::Info: return "info";
    case Level::Warning: return "warn";
    case Level::Error: return "error";
    case Level::Fatal: return "fatal";
    default: return "unknown";
    }
}

bool ShouldLog(Level level) {
    if (!g_config.diagnostics_enabled ||
        !g_running.load(std::memory_order_acquire))
        return false;
    if (g_deep_capture.load(std::memory_order_acquire) ||
        g_config.diagnostic_profile == DiagnosticProfile::Maximum)
        return true;
    if (g_config.diagnostic_profile == DiagnosticProfile::Essential)
        return level >= Level::Warning;
    return level >= Level::Info;
}

bool DeepCaptureEnabled() {
    return g_deep_capture.load(std::memory_order_acquire);
}

bool SetDeepCapture(bool enabled, const char* source) {
    if (!g_config.diagnostics_enabled) return false;
    const uint64_t session_limit =
        static_cast<uint64_t>(g_config.deep_session_mib) << 20;
    if (enabled && g_payload_accepted_bytes.load(std::memory_order_acquire) >=
                       session_limit) {
        Event(Level::Warning, "diagnostics", "deep_capture_rejected",
              Fields().String("reason", "session payload limit reached")
                  .String("source", source ? source : "unknown")
                  .UInt("session_limit_mib", g_config.deep_session_mib));
        return false;
    }
    const bool previous = g_deep_capture.exchange(enabled,
                                                  std::memory_order_acq_rel);
    if (previous != enabled) {
        Event(Level::Info, "diagnostics", "deep_capture_changed",
              Fields().Bool("enabled", enabled)
                  .String("source", source ? source : "unknown")
                  .UInt("session_limit_mib", g_config.deep_session_mib)
                  .UInt("max_payload_bytes", g_config.max_payload_bytes));
    }
    return previous != enabled;
}

uint64_t NextFlowId() {
    return g_flow_sequence.fetch_add(1, std::memory_order_acq_rel) + 1;
}

void UpdateRuntimeState(const RuntimeState& state) {
    uint64_t version = g_runtime_version.load(std::memory_order_acquire);
    for (unsigned attempt = 0; attempt < 8; ++attempt) {
        if (version & 1) {
            YieldProcessor();
            version = g_runtime_version.load(std::memory_order_acquire);
            continue;
        }
        if (g_runtime_version.compare_exchange_weak(
                version, version + 1, std::memory_order_acq_rel,
                std::memory_order_acquire)) {
            g_runtime_state.flow_id.store(state.flow_id,
                                          std::memory_order_relaxed);
            g_runtime_state.lobby_steam_id.store(state.lobby_steam_id,
                                                 std::memory_order_relaxed);
            g_runtime_state.last_progress_tick.store(
                state.last_progress_tick, std::memory_order_relaxed);
            g_runtime_state.mission_generation.store(
                state.mission_generation, std::memory_order_relaxed);
            g_runtime_state.gameplay_contact_mask.store(
                state.gameplay_contact_mask, std::memory_order_relaxed);
            g_runtime_state.real_gameplay_peers.store(
                state.real_gameplay_peers, std::memory_order_relaxed);
            g_runtime_state.ready_mask.store(state.ready_mask,
                                             std::memory_order_relaxed);
            g_runtime_state.mission_group_mask.store(
                state.mission_group_mask, std::memory_order_relaxed);
            g_runtime_state.actual_members.store(state.actual_members,
                                                 std::memory_order_relaxed);
            g_runtime_state.mission_ui_state.store(
                state.mission_ui_state, std::memory_order_relaxed);
            g_runtime_state.synthetic_members.store(
                state.synthetic_members, std::memory_order_relaxed);
            g_runtime_state.max_players.store(state.max_players,
                                              std::memory_order_relaxed);
            std::array<uint64_t, 4> phase{};
            std::memcpy(phase.data(), state.phase, sizeof(state.phase));
            for (size_t index = 0; index < phase.size(); ++index) {
                g_runtime_state.phase[index].store(phase[index],
                                                   std::memory_order_relaxed);
            }
            g_runtime_version.store(version + 2, std::memory_order_release);
            return;
        }
    }
}

RuntimeState GetRuntimeState() {
    RuntimeState snapshot{};
    for (unsigned attempt = 0; attempt < 8; ++attempt) {
        const uint64_t before = g_runtime_version.load(std::memory_order_acquire);
        if (before & 1) continue;
        snapshot.flow_id =
            g_runtime_state.flow_id.load(std::memory_order_relaxed);
        snapshot.lobby_steam_id =
            g_runtime_state.lobby_steam_id.load(std::memory_order_relaxed);
        snapshot.last_progress_tick =
            g_runtime_state.last_progress_tick.load(std::memory_order_relaxed);
        snapshot.mission_generation =
            g_runtime_state.mission_generation.load(std::memory_order_relaxed);
        snapshot.gameplay_contact_mask =
            g_runtime_state.gameplay_contact_mask.load(
                std::memory_order_relaxed);
        snapshot.real_gameplay_peers =
            g_runtime_state.real_gameplay_peers.load(
                std::memory_order_relaxed);
        snapshot.ready_mask =
            g_runtime_state.ready_mask.load(std::memory_order_relaxed);
        snapshot.mission_group_mask =
            g_runtime_state.mission_group_mask.load(std::memory_order_relaxed);
        snapshot.actual_members =
            g_runtime_state.actual_members.load(std::memory_order_relaxed);
        snapshot.mission_ui_state =
            g_runtime_state.mission_ui_state.load(std::memory_order_relaxed);
        snapshot.synthetic_members =
            g_runtime_state.synthetic_members.load(std::memory_order_relaxed);
        snapshot.max_players =
            g_runtime_state.max_players.load(std::memory_order_relaxed);
        std::array<uint64_t, 4> phase{};
        for (size_t index = 0; index < phase.size(); ++index) {
            phase[index] = g_runtime_state.phase[index].load(
                std::memory_order_relaxed);
        }
        std::memcpy(snapshot.phase, phase.data(), sizeof(snapshot.phase));
        snapshot.phase[std::size(snapshot.phase) - 1] = '\0';
        const uint64_t after = g_runtime_version.load(std::memory_order_acquire);
        if (before == after && !(after & 1)) return snapshot;
    }
    return snapshot;
}

uint64_t P2PCallsiteKey(bool outgoing, uint64_t caller_rva, int channel) {
    uint64_t key = caller_rva ^
        (static_cast<uint64_t>(static_cast<uint32_t>(channel)) << 32) ^
        (outgoing ? 0x9e3779b97f4a7c15ULL : 0xd1b54a32d192ed03ULL);
    key ^= key >> 30;
    key *= 0xbf58476d1ce4e5b9ULL;
    key ^= key >> 27;
    key *= 0x94d049bb133111ebULL;
    key ^= key >> 31;
    return key ? key : 1;
}

uint64_t GamePacketRouteKey(bool outgoing, int channel,
                            uint64_t producer_rva, uint64_t handler_rva,
                            uint64_t handler_vtable_rva) {
    uint64_t key = producer_rva ^ (handler_rva * 0x9e3779b97f4a7c15ULL) ^
        (handler_vtable_rva * 0xd1b54a32d192ed03ULL) ^
        (static_cast<uint64_t>(static_cast<uint32_t>(channel)) << 32) ^
        (outgoing ? 0x94d049bb133111ebULL : 0xbf58476d1ce4e5b9ULL);
    key ^= key >> 30;
    key *= 0xbf58476d1ce4e5b9ULL;
    key ^= key >> 27;
    key *= 0x94d049bb133111ebULL;
    key ^= key >> 31;
    return key ? key : 1;
}

uint64_t GameMessageRouteKey(bool outgoing, uint32_t message_code,
                             uint32_t message_family,
                             uint32_t message_flags,
                             bool context_handle_present,
                             uint64_t producer_rva) {
    uint64_t key = producer_rva ^
        (static_cast<uint64_t>(message_code) * 0x9e3779b97f4a7c15ULL) ^
        (static_cast<uint64_t>(message_family) << 32) ^
        (static_cast<uint64_t>(message_flags) * 0xd1b54a32d192ed03ULL) ^
        (context_handle_present ? 0x94d049bb133111ebULL
                                : 0xbf58476d1ce4e5b9ULL) ^
        (outgoing ? 0xa0761d6478bd642fULL : 0xe7037ed1a0b428dbULL);
    key ^= key >> 30;
    key *= 0xbf58476d1ce4e5b9ULL;
    key ^= key >> 27;
    key *= 0x94d049bb133111ebULL;
    key ^= key >> 31;
    return key ? key : 1;
}

void UpdateAtomicMinimum(std::atomic<uint64_t>& target, uint64_t value) {
    uint64_t observed = target.load(std::memory_order_relaxed);
    while (value < observed && !target.compare_exchange_weak(
               observed, value, std::memory_order_relaxed,
               std::memory_order_relaxed)) {
    }
}

void UpdateAtomicMaximum(std::atomic<uint64_t>& target, uint64_t value) {
    uint64_t observed = target.load(std::memory_order_relaxed);
    while (value > observed && !target.compare_exchange_weak(
               observed, value, std::memory_order_relaxed,
               std::memory_order_relaxed)) {
    }
}

void RecordP2PCallsite(bool outgoing, int channel, size_t bytes,
                       bool success, bool synthetic, uint64_t caller_rva) {
    const uint64_t key = P2PCallsiteKey(outgoing, caller_rva, channel);
    P2PCallsiteSlot* selected = nullptr;
    for (unsigned probe = 0; probe < kP2PCallsiteSlotCount; ++probe) {
        P2PCallsiteSlot& slot =
            g_p2p_callsites[(key + probe) % kP2PCallsiteSlotCount];
        uint64_t observed = slot.key.load(std::memory_order_acquire);
        if (observed == key) {
            selected = &slot;
            break;
        }
        if (observed) continue;
        uint64_t pending = slot.pending_key.load(std::memory_order_acquire);
        if (pending == key) {
            for (unsigned spin = 0; spin < 64; ++spin) {
                observed = slot.key.load(std::memory_order_acquire);
                if (observed == key) {
                    selected = &slot;
                    break;
                }
                YieldProcessor();
            }
            if (selected) break;
            return;
        }
        if (pending) continue;
        if (slot.pending_key.compare_exchange_strong(
                pending, key, std::memory_order_acq_rel,
                std::memory_order_acquire)) {
            slot.caller_rva.store(caller_rva, std::memory_order_relaxed);
            slot.channel.store(channel, std::memory_order_relaxed);
            slot.outgoing.store(outgoing, std::memory_order_relaxed);
            slot.minimum_packet_bytes.store(
                std::numeric_limits<uint64_t>::max(),
                std::memory_order_relaxed);
            slot.key.store(key, std::memory_order_release);
            slot.pending_key.store(0, std::memory_order_release);
            selected = &slot;
            break;
        }
    }
    if (!selected) {
        g_dropped_p2p_callsites.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    const uint64_t packet_bytes = static_cast<uint64_t>(bytes);
    selected->packets.fetch_add(1, std::memory_order_relaxed);
    selected->bytes.fetch_add(packet_bytes, std::memory_order_relaxed);
    if (!success) selected->failures.fetch_add(1, std::memory_order_relaxed);
    if (synthetic) {
        selected->synthetic_packets.fetch_add(1,
                                               std::memory_order_relaxed);
    }
    UpdateAtomicMinimum(selected->minimum_packet_bytes, packet_bytes);
    UpdateAtomicMaximum(selected->maximum_packet_bytes, packet_bytes);
}

void RecordGamePacketRoute(bool outgoing, int channel, size_t bytes,
                           uint64_t producer_rva, uint64_t handler_rva,
                           uint64_t handler_vtable_rva) {
    const uint64_t key = GamePacketRouteKey(
        outgoing, channel, producer_rva, handler_rva, handler_vtable_rva);
    GamePacketRouteSlot* selected = nullptr;
    for (unsigned probe = 0; probe < kGamePacketRouteSlotCount; ++probe) {
        GamePacketRouteSlot& slot =
            g_game_packet_routes[(key + probe) % kGamePacketRouteSlotCount];
        uint64_t observed = slot.key.load(std::memory_order_acquire);
        if (observed == key) {
            selected = &slot;
            break;
        }
        if (observed) continue;
        uint64_t pending = slot.pending_key.load(std::memory_order_acquire);
        if (pending == key) {
            for (unsigned spin = 0; spin < 64; ++spin) {
                observed = slot.key.load(std::memory_order_acquire);
                if (observed == key) {
                    selected = &slot;
                    break;
                }
                YieldProcessor();
            }
            if (selected) break;
            return;
        }
        if (pending) continue;
        if (slot.pending_key.compare_exchange_strong(
                pending, key, std::memory_order_acq_rel,
                std::memory_order_acquire)) {
            slot.producer_rva.store(producer_rva,
                                    std::memory_order_relaxed);
            slot.handler_rva.store(handler_rva, std::memory_order_relaxed);
            slot.handler_vtable_rva.store(handler_vtable_rva,
                                           std::memory_order_relaxed);
            slot.channel.store(channel, std::memory_order_relaxed);
            slot.outgoing.store(outgoing, std::memory_order_relaxed);
            slot.minimum_packet_bytes.store(
                std::numeric_limits<uint64_t>::max(),
                std::memory_order_relaxed);
            slot.key.store(key, std::memory_order_release);
            slot.pending_key.store(0, std::memory_order_release);
            selected = &slot;
            break;
        }
    }
    if (!selected) {
        g_dropped_game_packet_routes.fetch_add(1,
                                                std::memory_order_relaxed);
        return;
    }
    const uint64_t packet_bytes = static_cast<uint64_t>(bytes);
    selected->packets.fetch_add(1, std::memory_order_relaxed);
    selected->bytes.fetch_add(packet_bytes, std::memory_order_relaxed);
    UpdateAtomicMinimum(selected->minimum_packet_bytes, packet_bytes);
    UpdateAtomicMaximum(selected->maximum_packet_bytes, packet_bytes);
}

void RecordGameMessageRoute(bool outgoing, uint32_t message_code,
                            uint32_t message_family,
                            uint32_t message_flags,
                            bool context_handle_present, size_t bytes,
                            uint64_t producer_rva, bool header_available,
                            bool header_length_matches,
                            bool known_multipart_container,
                            bool message_size_available) {
    const uint64_t key = GameMessageRouteKey(
        outgoing, message_code, message_family, message_flags,
        context_handle_present, producer_rva);
    GameMessageRouteSlot* selected = nullptr;
    for (unsigned probe = 0; probe < kGameMessageRouteSlotCount; ++probe) {
        GameMessageRouteSlot& slot =
            g_game_message_routes[(key + probe) % kGameMessageRouteSlotCount];
        uint64_t observed = slot.key.load(std::memory_order_acquire);
        if (observed == key) {
            selected = &slot;
            break;
        }
        if (observed) continue;
        uint64_t pending = slot.pending_key.load(std::memory_order_acquire);
        if (pending == key) {
            for (unsigned spin = 0; spin < 64; ++spin) {
                observed = slot.key.load(std::memory_order_acquire);
                if (observed == key) {
                    selected = &slot;
                    break;
                }
                YieldProcessor();
            }
            if (selected) break;
            return;
        }
        if (pending) continue;
        if (slot.pending_key.compare_exchange_strong(
                pending, key, std::memory_order_acq_rel,
                std::memory_order_acquire)) {
            slot.message_code.store(message_code, std::memory_order_relaxed);
            slot.message_family.store(message_family,
                                      std::memory_order_relaxed);
            slot.message_flags.store(message_flags,
                                     std::memory_order_relaxed);
            slot.context_handle_present.store(context_handle_present,
                                              std::memory_order_relaxed);
            slot.outgoing.store(outgoing, std::memory_order_relaxed);
            slot.message_size_available.store(message_size_available,
                                              std::memory_order_relaxed);
            slot.producer_rva.store(producer_rva,
                                    std::memory_order_relaxed);
            slot.minimum_message_bytes.store(
                std::numeric_limits<uint64_t>::max(),
                std::memory_order_relaxed);
            slot.key.store(key, std::memory_order_release);
            slot.pending_key.store(0, std::memory_order_release);
            selected = &slot;
            break;
        }
    }
    if (!selected) {
        g_dropped_game_message_routes.fetch_add(1,
                                                std::memory_order_relaxed);
        return;
    }
    const uint64_t message_bytes = static_cast<uint64_t>(bytes);
    selected->messages.fetch_add(1, std::memory_order_relaxed);
    if (message_size_available) {
        selected->bytes.fetch_add(message_bytes, std::memory_order_relaxed);
    }
    if (!header_available) {
        selected->header_unavailable.fetch_add(1,
                                               std::memory_order_relaxed);
    }
    if (header_available && !header_length_matches) {
        selected->header_length_mismatches.fetch_add(
            1, std::memory_order_relaxed);
    }
    if (known_multipart_container) {
        selected->known_multipart_messages.fetch_add(
            1, std::memory_order_relaxed);
    }
    if (!header_available ||
        (!header_length_matches && !known_multipart_container)) {
        selected->unexpected_framing_mismatches.fetch_add(
            1, std::memory_order_relaxed);
    }
    if (message_size_available) {
        UpdateAtomicMinimum(selected->minimum_message_bytes, message_bytes);
        UpdateAtomicMaximum(selected->maximum_message_bytes, message_bytes);
    }
}

void RecordP2P(bool outgoing, uint64_t peer, int channel, size_t bytes,
               bool success, bool synthetic, uint64_t caller_rva) {
    uint64_t key = peer ^ (static_cast<uint64_t>(static_cast<uint32_t>(channel))
                           << 32) ^ 0x9e3779b97f4a7c15ULL;
    if (!key) key = 1;
    NetworkSlot* selected = nullptr;
    for (unsigned probe = 0; probe < kNetworkSlotCount; ++probe) {
        NetworkSlot& slot = g_network[(key + probe) % kNetworkSlotCount];
        uint64_t observed = slot.key.load(std::memory_order_acquire);
        if (observed == key) {
            selected = &slot;
            break;
        }
        if (observed) continue;
        uint64_t pending = slot.pending_key.load(std::memory_order_acquire);
        if (pending == key) {
            for (unsigned spin = 0; spin < 64; ++spin) {
                observed = slot.key.load(std::memory_order_acquire);
                if (observed == key) {
                    selected = &slot;
                    break;
                }
                YieldProcessor();
            }
            if (selected) break;
            return;
        }
        if (pending) continue;
        if (slot.pending_key.compare_exchange_strong(
                pending, key, std::memory_order_acq_rel,
                std::memory_order_acquire)) {
            slot.peer.store(peer, std::memory_order_release);
            slot.channel.store(channel, std::memory_order_release);
            slot.synthetic.store(synthetic, std::memory_order_release);
            slot.key.store(key, std::memory_order_release);
            slot.pending_key.store(0, std::memory_order_release);
            selected = &slot;
            break;
        }
        if (pending == key) {
            for (unsigned spin = 0; spin < 64; ++spin) {
                observed = slot.key.load(std::memory_order_acquire);
                if (observed == key) {
                    selected = &slot;
                    break;
                }
                YieldProcessor();
            }
            if (selected) break;
            return;
        }
    }
    if (!selected) return;
    const uint64_t now = GetTickCount64();
    if (outgoing) {
        selected->tx_packets.fetch_add(1, std::memory_order_relaxed);
        selected->tx_bytes.fetch_add(bytes, std::memory_order_relaxed);
        if (!success) selected->tx_failures.fetch_add(1, std::memory_order_relaxed);
        selected->last_tx_tick.store(now, std::memory_order_release);
    } else {
        selected->rx_packets.fetch_add(1, std::memory_order_relaxed);
        selected->rx_bytes.fetch_add(bytes, std::memory_order_relaxed);
        if (!success) selected->rx_failures.fetch_add(1, std::memory_order_relaxed);
        selected->last_rx_tick.store(now, std::memory_order_release);
    }
    RecordP2PCallsite(outgoing, channel, bytes, success, synthetic,
                      caller_rva);
}

void EmitNetworkSummary(bool force) {
    if (!g_config.diagnostics_enabled) return;
    const uint64_t now = GetTickCount64();
    uint64_t expected =
        g_last_network_emit_tick.load(std::memory_order_acquire);
    if (!force && expected && now >= expected &&
        now - expected < kNetworkSummaryPeriodMs)
        return;
    if (!force && !g_last_network_emit_tick.compare_exchange_strong(
                      expected, now, std::memory_order_acq_rel))
        return;
    if (force) g_last_network_emit_tick.store(now, std::memory_order_release);
    for (auto& slot : g_network) {
        if (!slot.key.load(std::memory_order_acquire)) continue;
        const uint64_t tx = slot.tx_packets.load(std::memory_order_acquire);
        const uint64_t rx = slot.rx_packets.load(std::memory_order_acquire);
        const uint64_t old_tx = slot.emitted_tx_packets.exchange(
            tx, std::memory_order_acq_rel);
        const uint64_t old_rx = slot.emitted_rx_packets.exchange(
            rx, std::memory_order_acq_rel);
        if (!force && tx == old_tx && rx == old_rx) continue;
        const uint64_t last_tx =
            slot.last_tx_tick.load(std::memory_order_acquire);
        const uint64_t last_rx =
            slot.last_rx_tick.load(std::memory_order_acquire);
        Event(Level::Info, "network_summary", "p2p_channel",
              Fields().UInt("peer_steam_id",
                            slot.peer.load(std::memory_order_acquire))
                  .Int("channel", slot.channel.load(std::memory_order_acquire))
                  .Bool("synthetic",
                        slot.synthetic.load(std::memory_order_acquire))
                  .UInt("tx_packets", tx)
                  .UInt("tx_packets_delta", tx - old_tx)
                  .UInt("tx_bytes",
                        slot.tx_bytes.load(std::memory_order_acquire))
                  .UInt("tx_failures",
                        slot.tx_failures.load(std::memory_order_acquire))
                  .UInt("rx_packets", rx)
                  .UInt("rx_packets_delta", rx - old_rx)
                  .UInt("rx_bytes",
                        slot.rx_bytes.load(std::memory_order_acquire))
                  .UInt("rx_failures",
                        slot.rx_failures.load(std::memory_order_acquire))
                  .UInt("last_tx_age_ms",
                        last_tx && now >= last_tx ? now - last_tx : 0)
                  .UInt("last_rx_age_ms",
                        last_rx && now >= last_rx ? now - last_rx : 0));
    }
    for (auto& slot : g_p2p_callsites) {
        if (!slot.key.load(std::memory_order_acquire)) continue;
        const uint64_t packets =
            slot.packets.load(std::memory_order_acquire);
        const uint64_t old_packets = slot.emitted_packets.exchange(
            packets, std::memory_order_acq_rel);
        if (!force && packets == old_packets) continue;
        const uint64_t minimum =
            slot.minimum_packet_bytes.load(std::memory_order_acquire);
        Event(Level::Info, "network_summary", "p2p_callsite",
              Fields()
                  .String("direction",
                          slot.outgoing.load(std::memory_order_acquire)
                              ? "out" : "in")
                  .Int("channel",
                       slot.channel.load(std::memory_order_acquire))
                  .UInt("caller_rva",
                        slot.caller_rva.load(std::memory_order_acquire))
                  .Bool("caller_in_process_image",
                        slot.caller_rva.load(std::memory_order_acquire) != 0)
                  .UInt("packets", packets)
                  .UInt("packets_delta", packets - old_packets)
                  .UInt("bytes",
                        slot.bytes.load(std::memory_order_acquire))
                  .UInt("minimum_packet_bytes",
                        minimum == std::numeric_limits<uint64_t>::max()
                            ? 0 : minimum)
                  .UInt("maximum_packet_bytes",
                        slot.maximum_packet_bytes.load(
                            std::memory_order_acquire))
                  .UInt("failures",
                        slot.failures.load(std::memory_order_acquire))
                  .UInt("synthetic_packets",
                        slot.synthetic_packets.load(
                            std::memory_order_acquire)));
    }
    const uint64_t dropped_callsites =
        g_dropped_p2p_callsites.load(std::memory_order_acquire);
    if (force && dropped_callsites) {
        Event(Level::Warning, "network_summary", "p2p_callsite_overflow",
              Fields().UInt("dropped_observations", dropped_callsites)
                  .UInt("slot_capacity", kP2PCallsiteSlotCount));
    }
    for (auto& slot : g_game_packet_routes) {
        if (!slot.key.load(std::memory_order_acquire)) continue;
        const uint64_t packets =
            slot.packets.load(std::memory_order_acquire);
        const uint64_t old_packets = slot.emitted_packets.exchange(
            packets, std::memory_order_acq_rel);
        if (!force && packets == old_packets) continue;
        const uint64_t minimum =
            slot.minimum_packet_bytes.load(std::memory_order_acquire);
        Event(Level::Info, "network_summary", "game_packet_route",
              Fields()
                  .String("direction",
                          slot.outgoing.load(std::memory_order_acquire)
                              ? "out" : "in")
                  .Int("channel",
                       slot.channel.load(std::memory_order_acquire))
                  .UInt("producer_rva",
                        slot.producer_rva.load(std::memory_order_acquire))
                  .UInt("handler_rva",
                        slot.handler_rva.load(std::memory_order_acquire))
                  .UInt("handler_vtable_rva",
                        slot.handler_vtable_rva.load(
                            std::memory_order_acquire))
                  .UInt("packets", packets)
                  .UInt("packets_delta", packets - old_packets)
                  .UInt("bytes",
                        slot.bytes.load(std::memory_order_acquire))
                  .UInt("minimum_packet_bytes",
                        minimum == std::numeric_limits<uint64_t>::max()
                            ? 0 : minimum)
                  .UInt("maximum_packet_bytes",
                        slot.maximum_packet_bytes.load(
                            std::memory_order_acquire)));
    }
    const uint64_t dropped_routes =
        g_dropped_game_packet_routes.load(std::memory_order_acquire);
    if (force && dropped_routes) {
        Event(Level::Warning, "network_summary",
              "game_packet_route_overflow",
              Fields().UInt("dropped_observations", dropped_routes)
                  .UInt("slot_capacity", kGamePacketRouteSlotCount));
    }
    for (auto& slot : g_game_message_routes) {
        if (!slot.key.load(std::memory_order_acquire)) continue;
        const uint64_t messages =
            slot.messages.load(std::memory_order_acquire);
        const uint64_t old_messages = slot.emitted_messages.exchange(
            messages, std::memory_order_acq_rel);
        if (!force && messages == old_messages) continue;
        const uint64_t minimum =
            slot.minimum_message_bytes.load(std::memory_order_acquire);
        Event(Level::Info, "network_summary", "game_message_route",
              Fields()
                  .String("direction",
                          slot.outgoing.load(std::memory_order_acquire)
                              ? "out" : "in")
                  .String("observation_point",
                          slot.outgoing.load(std::memory_order_acquire)
                              ? "serialized_enqueue" : "decoded_dispatch")
                  .UInt("producer_rva",
                        slot.producer_rva.load(std::memory_order_acquire))
                  .Bool("message_size_available",
                        slot.message_size_available.load(
                            std::memory_order_acquire))
                  .UInt("message_code",
                        slot.message_code.load(std::memory_order_acquire))
                  .UInt("message_family",
                        slot.message_family.load(std::memory_order_acquire))
                  .UInt("message_flags",
                        slot.message_flags.load(std::memory_order_acquire))
                  .Bool("context_handle_present",
                        slot.context_handle_present.load(
                            std::memory_order_acquire))
                  .UInt("messages", messages)
                  .UInt("messages_delta", messages - old_messages)
                  .UInt("bytes",
                        slot.bytes.load(std::memory_order_acquire))
                  .UInt("minimum_message_bytes",
                        minimum == std::numeric_limits<uint64_t>::max()
                            ? 0 : minimum)
                  .UInt("maximum_message_bytes",
                        slot.maximum_message_bytes.load(
                            std::memory_order_acquire))
                  .UInt("header_unavailable",
                        slot.header_unavailable.load(
                            std::memory_order_acquire))
                  .UInt("header_length_mismatches",
                        slot.header_length_mismatches.load(
                            std::memory_order_acquire))
                  .UInt("known_multipart_messages",
                        slot.known_multipart_messages.load(
                            std::memory_order_acquire))
                  .UInt("unexpected_framing_mismatches",
                        slot.unexpected_framing_mismatches.load(
                            std::memory_order_acquire)));
    }
    const uint64_t dropped_messages =
        g_dropped_game_message_routes.load(std::memory_order_acquire);
    if (force && dropped_messages) {
        Event(Level::Warning, "network_summary",
              "game_message_route_overflow",
              Fields().UInt("dropped_observations", dropped_messages)
                  .UInt("slot_capacity", kGameMessageRouteSlotCount));
    }
    const uint64_t socket_tx =
        g_socket_tx_packets.load(std::memory_order_acquire);
    const uint64_t socket_rx =
        g_socket_rx_packets.load(std::memory_order_acquire);
    if (force || socket_tx || socket_rx) {
        Event(Level::Info, "network_summary", "winsock",
              Fields().UInt("tx_packets", socket_tx)
                  .UInt("tx_bytes",
                        g_socket_tx_bytes.load(std::memory_order_acquire))
                  .UInt("rx_packets", socket_rx)
                  .UInt("rx_bytes",
                        g_socket_rx_bytes.load(std::memory_order_acquire)));
    }
}

void MarkCrashed(uint32_t exception_code, const std::string& artifact) {
    g_crashed.store(true, std::memory_order_release);
    std::ostringstream extra;
    extra << "  \"exception_code\": " << exception_code << ",\r\n"
          << "  \"artifact\": \"" << Escape(artifact) << "\"";
    WriteHealthFile();
    WriteStatus("crashed", extra.str());
}

void Event(const char* layer, const char* event, const Fields& fields) {
    Event(DefaultLevel(layer, event), layer, event, fields, nullptr, 0);
}

void Event(const char* layer, const char* event, const Fields& fields,
           const void* payload, size_t payload_size) {
    Event(DefaultLevel(layer, event), layer, event, fields, payload,
          payload_size);
}

void Event(const char* layer, const char* event, const Fields& fields,
           std::vector<uint8_t>&& payload) {
    Event(DefaultLevel(layer, event), layer, event, fields,
          std::move(payload));
}

void Event(Level level, const char* layer, const char* event,
           const Fields& fields) {
    Event(level, layer, event, fields, nullptr, 0);
}

void Event(Level level, const char* layer, const char* event,
           const Fields& fields, const void* payload, size_t payload_size) {
    LastErrorGuard errors;
    RecordSocketTraffic(layer, event, payload_size);
    if (!ShouldLog(level)) return;
    std::vector<uint8_t> copy;
    const size_t original = payload && payload_size ? payload_size : 0;
    bool limit_reached = false;
    const bool deep_capture_active = DeepCaptureEnabled();
    if (payload && payload_size && deep_capture_active &&
        g_config.enabled && g_config.max_payload_bytes) {
        const uint64_t session_limit =
            static_cast<uint64_t>(g_config.deep_session_mib) << 20;
        uint64_t accepted =
            g_payload_accepted_bytes.load(std::memory_order_acquire);
        size_t count = 0;
        const size_t requested = std::min<size_t>(
            payload_size, g_config.max_payload_bytes);
        while (accepted < session_limit) {
            count = static_cast<size_t>(std::min<uint64_t>(
                requested, session_limit - accepted));
            if (g_payload_accepted_bytes.compare_exchange_weak(
                    accepted, accepted + count, std::memory_order_acq_rel,
                    std::memory_order_acquire)) {
                break;
            }
            count = 0;
        }
        if (count) {
            const auto* bytes = static_cast<const uint8_t*>(payload);
            copy.assign(bytes, bytes + count);
            limit_reached = accepted + count >= session_limit;
        } else {
            limit_reached = true;
        }
    }
    const size_t captured = copy.size();
    PayloadOriginalSizeScope original_size(original);
    Event(level, layer, event, fields, std::move(copy));
    if (deep_capture_active && original > captured) {
        Event(Level::Debug, "diagnostics", "payload_truncated",
              Fields().String("source_layer", layer ? layer : "")
                  .String("source_event", event ? event : "")
                  .UInt("original_bytes", original)
                  .UInt("captured_bytes", captured));
    }
    if (limit_reached) {
        g_deep_capture.store(false, std::memory_order_release);
        g_deep_limit_notice.store(true, std::memory_order_release);
        if (g_queue_event) SetEvent(g_queue_event);
    }
}

void Event(Level level, const char* layer, const char* event,
           const Fields& fields, std::vector<uint8_t>&& payload) {
    LastErrorGuard errors;
    if (!ShouldLog(level) || g_inside_logger) return;
    if (IsNetworkLayer(layer) && !g_config.enabled && level < Level::Warning)
        return;
    g_inside_logger = true;
    CapturedEvent item;
    item.sequence = g_sequence.fetch_add(1, std::memory_order_relaxed) + 1;
    QueryPerformanceCounter(&item.qpc);
    GetSystemTimeAsFileTime(&item.utc);
    item.thread_id = GetCurrentThreadId();
    item.level = level;
    item.layer = layer ? layer : "";
    item.event = event ? event : "";
    item.fields = fields.Json();
    item.payload_original_size = g_payload_original_size_override
                                     ? g_payload_original_size_override
                                     : payload.size();
    item.payload = std::move(payload);
    item.memory_bytes = sizeof(item) + item.layer.capacity() +
                        item.event.capacity() + item.fields.capacity() +
                        item.payload.capacity();

    const size_t maximum_bytes =
        static_cast<size_t>(g_config.queue_max_mib) << 20;
    bool accepted = false;
    AcquireSRWLockExclusive(&g_queue_lock);
    const bool normal_room =
        g_queue.size() < g_config.queue_max_events &&
        g_queue_bytes + item.memory_bytes <= maximum_bytes;
    const bool critical_room =
        level >= Level::Warning &&
        g_queue.size() < g_config.queue_max_events + kCriticalQueueReserve;
    if (normal_room || critical_room) {
        g_queue_bytes += item.memory_bytes;
        g_queue.push_back(std::move(item));
        accepted = true;
        const uint64_t events = g_queue.size();
        const uint64_t bytes = g_queue_bytes;
        g_current_queue_events.store(events, std::memory_order_release);
        g_current_queue_bytes.store(bytes, std::memory_order_release);
        uint64_t peak = g_peak_queue_events.load(std::memory_order_relaxed);
        while (events > peak && !g_peak_queue_events.compare_exchange_weak(
                                    peak, events, std::memory_order_relaxed)) {
        }
        peak = g_peak_queue_bytes.load(std::memory_order_relaxed);
        while (bytes > peak && !g_peak_queue_bytes.compare_exchange_weak(
                                   peak, bytes, std::memory_order_relaxed)) {
        }
    }
    ReleaseSRWLockExclusive(&g_queue_lock);
    if (!accepted) {
        g_dropped_events.fetch_add(1, std::memory_order_relaxed);
        g_dropped_bytes.fetch_add(item.memory_bytes, std::memory_order_relaxed);
    } else if (g_queue_event) {
        SetEvent(g_queue_event);
    }
    g_inside_logger = false;
}

std::string Escape(const char* value) {
    if (!value) return {};
    std::string result;
    for (const auto* cursor = reinterpret_cast<const unsigned char*>(value);
         *cursor; ++cursor) {
        const unsigned char c = *cursor;
        switch (c) {
        case '\"': result += "\\\""; break;
        case '\\': result += "\\\\"; break;
        case '\b': result += "\\b"; break;
        case '\f': result += "\\f"; break;
        case '\n': result += "\\n"; break;
        case '\r': result += "\\r"; break;
        case '\t': result += "\\t"; break;
        default:
            if (c < 0x20) {
                char escaped[8]{};
                std::snprintf(escaped, sizeof(escaped), "\\u%04x", c);
                result += escaped;
            } else {
                result.push_back(static_cast<char>(c));
            }
        }
    }
    return result;
}

std::string Escape(const std::string& value) { return Escape(value.c_str()); }

std::string WideToUtf8(const wchar_t* value) {
    if (!value) return {};
    const int needed = WideCharToMultiByte(CP_UTF8, 0, value, -1, nullptr, 0,
                                           nullptr, nullptr);
    if (needed <= 1) return {};
    std::string result(static_cast<size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value, -1, result.data(), needed, nullptr,
                        nullptr);
    result.pop_back();
    return result;
}

std::string HexPointer(const void* value) {
    char buffer[32]{};
    std::snprintf(buffer, sizeof(buffer), "0x%llx",
                  static_cast<unsigned long long>(
                      reinterpret_cast<uintptr_t>(value)));
    return buffer;
}

std::string IpV4(uint32_t network_order_ip) {
    const auto* bytes = reinterpret_cast<const uint8_t*>(&network_order_ip);
    char buffer[32]{};
    std::snprintf(buffer, sizeof(buffer), "%u.%u.%u.%u", bytes[0], bytes[1],
                  bytes[2], bytes[3]);
    return buffer;
}

}  // namespace capture
