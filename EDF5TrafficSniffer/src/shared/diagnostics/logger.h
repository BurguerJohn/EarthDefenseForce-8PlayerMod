#pragma once

#include "build_config.h"
#include "game_id.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace capture {

enum class Level : uint8_t {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warning = 3,
    Error = 4,
    Fatal = 5,
};

enum class DiagnosticProfile : uint8_t {
    Essential = 0,
    Balanced = 1,
    Maximum = 2,
};

enum class CrashDumpMode : uint8_t {
    Off = 0,
    Mini = 1,
    Full = 2,
};

struct Config {
    struct Modules {
        bool sniffer = false;
        bool coop8 = false;
    };

    Modules edf41;
    Modules edf5{build_config::kDiagnostics, true};
    Modules edf6;
    game::Id active_game = game::Id::Unknown;
    bool sniffer = build_config::kDiagnostics;
    bool coop8 = true;
    bool diagnostics_enabled = build_config::kDiagnostics;
    DiagnosticProfile diagnostic_profile = DiagnosticProfile::Balanced;
    CrashDumpMode crash_dump_mode = CrashDumpMode::Mini;
    unsigned snapshot_hotkey_vk = VK_F9;
    unsigned deep_capture_hotkey_vk = VK_F10;
    unsigned stall_warning_seconds = 15;
    unsigned max_sessions = 20;
    unsigned max_total_mib = 1024;
    unsigned queue_max_events = 8192;
    unsigned queue_max_mib = 16;
    unsigned rotate_mib = 64;
    unsigned deep_session_mib = 128;
    unsigned max_payload_bytes = 65536;
    bool enabled = build_config::kDiagnostics;
    bool steam = build_config::kDiagnostics;
    bool steam_callbacks = build_config::kDiagnostics;
    bool winsock = build_config::kDiagnostics;
    bool more_players = true;
    unsigned edf41_target_players = 8;
    unsigned edf41_native_safe_limit = 4;
    bool edf41_experimental_room_overfill = false;
    unsigned edf41_experimental_room_limit = 8;
    unsigned edf41_bot_hotkey_vk = VK_F8;
    unsigned edf41_bot_remove_hotkey_vk = VK_F7;
    uint64_t edf41_bot_steam_id = 76561202255232023ULL;
    unsigned max_players = 8;
    bool experimental_enemy_spawn_multiplier = false;
    unsigned enemy_spawn_multiplier = 1;
    unsigned preallocated_roster_slots = 8;
    bool experimental_reserve_patches = false;
    unsigned bot_hotkey_vk = VK_F8;
    unsigned bot_remove_hotkey_vk = VK_F7;
    unsigned bot_ready_hotkey_vk = VK_F6;
    unsigned invite_hotkey_vk = VK_F4;
    bool local_mission_harness_enabled = true;
    unsigned local_mission_harness_hotkey_vk = VK_F3;
    bool debug_stage_win_enabled = true;
    unsigned debug_stage_win_hotkey_vk = VK_F5;
    uint64_t bot_steam_id = 76561202255233023ULL;
    unsigned payload_preview_bytes = 64;
    unsigned flush_every_events = 32;
#if EDF5_COMPILE_DIAGNOSTICS
    std::wstring log_root = L"Mods\\TrafficSniffer\\logs";
#else
    std::wstring log_root;
#endif
};

struct RuntimeState {
    uint64_t flow_id = 0;
    uint64_t lobby_steam_id = 0;
    uint64_t last_progress_tick = 0;
    uint64_t mission_generation = 0;
    uint32_t gameplay_contact_mask = 0;
    unsigned real_gameplay_peers = 0;
    uint32_t ready_mask = 0;
    uint32_t mission_group_mask = 0;
    int32_t actual_members = -1;
    int32_t mission_ui_state = -1;
    unsigned synthetic_members = 0;
    unsigned max_players = 0;
    char phase[32]{};
};

#if EDF5_COMPILE_DIAGNOSTICS

class Fields {
public:
    Fields& String(const char* key, const char* value);
    Fields& String(const char* key, const std::string& value);
    Fields& UInt(const char* key, uint64_t value);
    Fields& Int(const char* key, int64_t value);
    Fields& Bool(const char* key, bool value);
    Fields& Null(const char* key);
    Fields& Raw(const char* key, const std::string& json);
    const std::string& Json() const { return json_; }

private:
    void Key(const char* key);
    std::string json_;
    bool first_ = true;
};

bool Initialize(HMODULE plugin_module);
void RequestStop();
void StopAndFlush();
void Flush();
void EmergencyFlush();
const Config& GetConfig();
const std::wstring& SessionDirectory();
const std::string& SessionId();

const char* LevelName(Level level);
bool ShouldLog(Level level);
bool DeepCaptureEnabled();
bool SetDeepCapture(bool enabled, const char* source = "api");
uint64_t NextFlowId();
void UpdateRuntimeState(const RuntimeState& state);
RuntimeState GetRuntimeState();
void RecordP2P(bool outgoing, uint64_t peer, int channel, size_t bytes,
               bool success, bool synthetic, uint64_t caller_rva = 0);
void RecordGamePacketRoute(bool outgoing, int channel, size_t bytes,
                           uint64_t producer_rva, uint64_t handler_rva,
                           uint64_t handler_vtable_rva = 0);
void RecordGameMessageRoute(bool outgoing, uint32_t message_code,
                            uint32_t message_family,
                            uint32_t message_flags,
                            bool context_handle_present, size_t bytes,
                            uint64_t producer_rva, bool header_available,
                            bool header_length_matches,
                            bool known_multipart_container,
                            bool message_size_available = true);
void EmitNetworkSummary(bool force = false);
void MarkCrashed(uint32_t exception_code, const std::string& artifact);

void Event(const char* layer, const char* event, const Fields& fields = Fields());
void Event(const char* layer, const char* event, const Fields& fields,
           const void* payload, size_t payload_size);
void Event(const char* layer, const char* event, const Fields& fields,
           std::vector<uint8_t>&& payload);
void Event(Level level, const char* layer, const char* event,
           const Fields& fields = Fields());
void Event(Level level, const char* layer, const char* event,
           const Fields& fields, const void* payload, size_t payload_size);
void Event(Level level, const char* layer, const char* event,
           const Fields& fields, std::vector<uint8_t>&& payload);

std::string Escape(const char* value);
std::string Escape(const std::string& value);
std::string WideToUtf8(const wchar_t* value);
std::string HexPointer(const void* value);
std::string IpV4(uint32_t network_order_ip);

#else

// Only configuration remains in a Users DLL. Event construction and every
// writer/capture API are removed at preprocessing time by the macros below.
class Fields {
public:
    Fields& String(const char*, const char*) { return *this; }
    Fields& String(const char*, const std::string&) { return *this; }
    Fields& UInt(const char*, uint64_t) { return *this; }
    Fields& Int(const char*, int64_t) { return *this; }
    Fields& Bool(const char*, bool) { return *this; }
    Fields& Null(const char*) { return *this; }
    Fields& Raw(const char*, const std::string&) { return *this; }
};

template <typename... Values>
inline void Discard(Values&&...) {}

inline std::string Escape(const char*) { return {}; }
inline std::string Escape(const std::string&) { return {}; }
inline std::string WideToUtf8(const wchar_t*) { return {}; }
inline std::string HexPointer(const void*) { return {}; }
inline std::string IpV4(uint32_t) { return {}; }

bool Initialize(HMODULE plugin_module);
const Config& GetConfig();

#endif

}  // namespace capture

#if EDF5_COMPILE_DIAGNOSTICS
#define EDF5_CAPTURE_EVENT(...) ::capture::Event(__VA_ARGS__)
#define EDF5_CAPTURE_FLUSH() ::capture::Flush()
#define EDF5_CAPTURE_REQUEST_STOP() ::capture::RequestStop()
#define EDF5_CAPTURE_STOP_AND_FLUSH() ::capture::StopAndFlush()
#define EDF5_CAPTURE_NEXT_FLOW_ID() ::capture::NextFlowId()
#define EDF5_CAPTURE_UPDATE_RUNTIME_STATE(...) \
    ::capture::UpdateRuntimeState(__VA_ARGS__)
#define EDF5_CAPTURE_RECORD_P2P(...) ::capture::RecordP2P(__VA_ARGS__)
#define EDF5_CAPTURE_RECORD_GAME_PACKET_ROUTE(...) \
    ::capture::RecordGamePacketRoute(__VA_ARGS__)
#define EDF5_CAPTURE_RECORD_GAME_MESSAGE_ROUTE(...) \
    ::capture::RecordGameMessageRoute(__VA_ARGS__)
#else
#define EDF5_CAPTURE_EVENT(...)                                      \
    do {                                                             \
        if constexpr (false) ::capture::Discard(__VA_ARGS__);        \
    } while (false)
#define EDF5_CAPTURE_FLUSH() ((void)0)
#define EDF5_CAPTURE_REQUEST_STOP() ((void)0)
#define EDF5_CAPTURE_STOP_AND_FLUSH() ((void)0)
#define EDF5_CAPTURE_NEXT_FLOW_ID() (uint64_t{0})
#define EDF5_CAPTURE_UPDATE_RUNTIME_STATE(...)                       \
    do {                                                             \
        if constexpr (false) ::capture::Discard(__VA_ARGS__);        \
    } while (false)
#define EDF5_CAPTURE_RECORD_P2P(...)                                 \
    do {                                                             \
        if constexpr (false) ::capture::Discard(__VA_ARGS__);        \
    } while (false)
#define EDF5_CAPTURE_RECORD_GAME_PACKET_ROUTE(...)                   \
    do {                                                             \
        if constexpr (false) ::capture::Discard(__VA_ARGS__);        \
    } while (false)
#define EDF5_CAPTURE_RECORD_GAME_MESSAGE_ROUTE(...)                  \
    do {                                                             \
        if constexpr (false) ::capture::Discard(__VA_ARGS__);        \
    } while (false)
#endif
