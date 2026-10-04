#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "runtime_config.h"

#include "build_config.h"

#include <algorithm>
#include <atomic>
#include <iterator>
#include <limits>
#include <string>

namespace runtime_config {
namespace {

constexpr const wchar_t* kLegacyConfigPath =
    L".\\Mods\\TrafficSniffer\\config.ini";

std::atomic<game::Id> g_selected_game{game::Id::Unknown};
std::wstring g_config_path = kLegacyConfigPath;

bool FileExists(const std::wstring& path) {
    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES &&
           (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

std::wstring ResolveConfigPath(HMODULE plugin_module) {
    if (plugin_module) {
        wchar_t module_path[32768]{};
        const DWORD length = GetModuleFileNameW(
            plugin_module, module_path,
            static_cast<DWORD>(std::size(module_path)));
        if (length > 0 && length < std::size(module_path)) {
            std::wstring adjacent(module_path, length);
            const size_t slash = adjacent.find_last_of(L"\\/");
            const size_t dot = adjacent.find_last_of(L'.');
            if (dot != std::wstring::npos &&
                (slash == std::wstring::npos || dot > slash)) {
                adjacent.resize(dot);
            }
            adjacent += L".ini";
            if (FileExists(adjacent)) return adjacent;
        }
    }
    return kLegacyConfigPath;
}

bool IniBool(const wchar_t* section, const wchar_t* key, bool fallback) {
    wchar_t value[32]{};
    GetPrivateProfileStringW(section, key, fallback ? L"true" : L"false",
                             value, static_cast<DWORD>(std::size(value)),
                             g_config_path.c_str());
    if (lstrcmpiW(value, L"true") == 0 || lstrcmpiW(value, L"yes") == 0 ||
        lstrcmpiW(value, L"on") == 0 || lstrcmpiW(value, L"1") == 0) {
        return true;
    }
    if (lstrcmpiW(value, L"false") == 0 || lstrcmpiW(value, L"no") == 0 ||
        lstrcmpiW(value, L"off") == 0 || lstrcmpiW(value, L"0") == 0) {
        return false;
    }
    return fallback;
}

bool IniBoolWithLegacy(const wchar_t* section, const wchar_t* legacy_section,
                       const wchar_t* key, bool fallback) {
    constexpr const wchar_t* kMissing = L"__missing__";
    wchar_t value[32]{};
    GetPrivateProfileStringW(section, key, kMissing, value,
                             static_cast<DWORD>(std::size(value)),
                             g_config_path.c_str());
    if (lstrcmpW(value, kMissing) == 0) {
        return IniBool(legacy_section, key, fallback);
    }
    return IniBool(section, key, fallback);
}

bool IniKeyExists(const wchar_t* section, const wchar_t* key) {
    constexpr const wchar_t* kMissing = L"__missing__";
    wchar_t value[32]{};
    GetPrivateProfileStringW(section, key, kMissing, value,
                             static_cast<DWORD>(std::size(value)),
                             g_config_path.c_str());
    return lstrcmpW(value, kMissing) != 0;
}

unsigned IniUInt(const wchar_t* section, const wchar_t* key,
                 unsigned fallback, unsigned minimum, unsigned maximum) {
    const UINT raw = GetPrivateProfileIntW(section, key,
                                           static_cast<int>(fallback),
                                           g_config_path.c_str());
    // Negative INI values wrap because GetPrivateProfileIntW returns UINT.
    const unsigned value =
        raw > static_cast<UINT>(std::numeric_limits<int>::max()) ? 0u : raw;
    return std::max(minimum, std::min(maximum, value));
}

unsigned IniUIntWithLegacy(const wchar_t* section,
                           const wchar_t* legacy_section,
                           const wchar_t* key, unsigned fallback,
                           unsigned minimum, unsigned maximum) {
    return IniUInt(IniKeyExists(section, key) ? section : legacy_section,
                   key, fallback, minimum, maximum);
}

std::wstring IniString(const wchar_t* section, const wchar_t* key,
                       const wchar_t* fallback) {
    wchar_t value[1024]{};
    GetPrivateProfileStringW(section, key, fallback, value,
                             static_cast<DWORD>(std::size(value)),
                             g_config_path.c_str());
    return value;
}

uint64_t IniUInt64(const wchar_t* section, const wchar_t* key,
                   uint64_t fallback) {
    wchar_t fallback_text[32]{};
    _ui64tow_s(fallback, fallback_text, std::size(fallback_text), 10);
    const std::wstring value = IniString(section, key, fallback_text);
    wchar_t* end = nullptr;
    const uint64_t parsed = _wcstoui64(value.c_str(), &end, 10);
    return end && *end == L'\0' && parsed != 0 ? parsed : fallback;
}

uint64_t IniUInt64WithLegacy(const wchar_t* section,
                             const wchar_t* legacy_section,
                             const wchar_t* key, uint64_t fallback) {
    return IniUInt64(IniKeyExists(section, key) ? section : legacy_section,
                     key, fallback);
}

#if EDF5_COMPILE_DIAGNOSTICS
capture::DiagnosticProfile ParseProfile(const std::wstring& value) {
    if (lstrcmpiW(value.c_str(), L"Essential") == 0) {
        return capture::DiagnosticProfile::Essential;
    }
    if (lstrcmpiW(value.c_str(), L"Maximum") == 0 ||
        lstrcmpiW(value.c_str(), L"Deep") == 0) {
        return capture::DiagnosticProfile::Maximum;
    }
    return capture::DiagnosticProfile::Balanced;
}

capture::CrashDumpMode ParseDumpMode(const std::wstring& value) {
    if (lstrcmpiW(value.c_str(), L"Off") == 0 ||
        lstrcmpiW(value.c_str(), L"None") == 0) {
        return capture::CrashDumpMode::Off;
    }
    if (lstrcmpiW(value.c_str(), L"Full") == 0) {
        return capture::CrashDumpMode::Full;
    }
    return capture::CrashDumpMode::Mini;
}
#endif

const capture::Config::Modules& ActiveModules(const capture::Config& config) {
    switch (config.active_game) {
    case game::Id::Edf41: return config.edf41;
    case game::Id::Edf6: return config.edf6;
    case game::Id::Edf5:
    case game::Id::Unknown:
        break;
    }
    return config.edf5;
}

}  // namespace

void SelectGame(game::Id game_id) {
    g_selected_game.store(game_id, std::memory_order_release);
}

game::Id SelectedGame() {
    return g_selected_game.load(std::memory_order_acquire);
}

// "auto" (also empty, 0 or anything unparsable) yields 0. Otherwise a
// decimal such as 1.5 or 1,5 with an optional trailing x, parsed without the
// process locale and clamped to [minimum, maximum].
float IniMultiplier(const wchar_t* section, const wchar_t* key,
                    float minimum, float maximum) {
    const std::wstring raw = IniString(section, key, L"auto");
    size_t begin = 0;
    size_t end = raw.size();
    while (begin < end && (raw[begin] == L' ' || raw[begin] == L'\t')) {
        ++begin;
    }
    while (end > begin && (raw[end - 1] == L' ' || raw[end - 1] == L'\t')) {
        --end;
    }
    if (end > begin && (raw[end - 1] == L'x' || raw[end - 1] == L'X')) --end;
    if (begin == end) return 0.0f;
    double value = 0.0;
    double scale = 0.0;
    bool digits = false;
    for (size_t at = begin; at < end; ++at) {
        const wchar_t ch = raw[at];
        if (ch >= L'0' && ch <= L'9') {
            const double digit = static_cast<double>(ch - L'0');
            digits = true;
            if (scale == 0.0) {
                value = value * 10.0 + digit;
            } else {
                value += digit * scale;
                scale /= 10.0;
            }
        } else if ((ch == L'.' || ch == L',') && scale == 0.0) {
            scale = 0.1;
        } else {
            return 0.0f;
        }
    }
    if (!digits || value <= 0.0) return 0.0f;
    const float result = static_cast<float>(value);
    return std::max(minimum, std::min(maximum, result));
}

capture::Config Load(HMODULE plugin_module) {
    g_config_path = ResolveConfigPath(plugin_module);
    capture::Config config;
    config.active_game = SelectedGame();

#if EDF5_COMPILE_DIAGNOSTICS
    config.edf41.sniffer =
        IniBool(L"EDF41.Sniffer", L"Enabled", true);
    config.edf5.sniffer =
        IniBool(L"EDF5.Sniffer", L"Enabled", true);
    config.edf6.sniffer =
        IniBool(L"EDF6.Sniffer", L"Enabled", false);
#else
    // A Users build does not link sniffer/logger sources. INI options cannot
    // re-enable code that is absent from the binary.
    config.edf41.sniffer = false;
    config.edf5.sniffer = false;
    config.edf6.sniffer = false;
#endif
    config.edf41.coop8 = IniBool(L"EDF41.Coop8", L"Enabled", false);
    config.edf5.coop8 = IniBoolWithLegacy(
        L"EDF5.Coop8", L"MorePlayers", L"Enabled", true);
    config.edf6.coop8 = IniBool(L"EDF6.Coop8", L"Enabled", false);

    const capture::Config::Modules& active = ActiveModules(config);
    config.sniffer = active.sniffer;
    config.coop8 = active.coop8;
    // Compatibility alias used inside the already-proven EDF5 Coop8 code.
    // New game profiles must use their own module instead of this field.
    config.more_players =
        (config.active_game == game::Id::Edf5 ||
         config.active_game == game::Id::Unknown) && config.coop8;

#if EDF5_COMPILE_DIAGNOSTICS
    config.diagnostics_enabled =
        config.sniffer && IniBool(L"Diagnostics", L"Enabled", true);
    config.diagnostic_profile = ParseProfile(
        IniString(L"Diagnostics", L"Profile", L"Balanced"));
    config.crash_dump_mode = ParseDumpMode(
        IniString(L"Diagnostics", L"CrashDumpMode", L"Mini"));
    config.snapshot_hotkey_vk = IniUInt(
        L"Diagnostics", L"SnapshotHotkeyVK", VK_F9, 1, 255);
    config.deep_capture_hotkey_vk = IniUInt(
        L"Diagnostics", L"DeepCaptureHotkeyVK", VK_F10, 1, 255);
    config.stall_warning_seconds = IniUInt(
        L"Diagnostics", L"StallWarningSeconds", 15, 5, 600);
    config.max_sessions = IniUInt(
        L"Diagnostics", L"MaxSessions", 20, 1, 1000);
    config.max_total_mib = IniUInt(
        L"Diagnostics", L"MaxTotalMiB", 1024, 64, 65536);
    config.queue_max_events = IniUInt(
        L"Diagnostics", L"QueueMaxEvents", 8192, 256, 1048576);
    config.queue_max_mib = IniUInt(
        L"Diagnostics", L"QueueMaxMiB", 16, 1, 4096);
    config.rotate_mib = IniUInt(
        L"Diagnostics", L"RotateMiB", 64, 1, 4096);
    config.deep_session_mib = IniUInt(
        L"Diagnostics", L"DeepSessionMiB", 128, 1, 16384);
    config.max_payload_bytes = IniUInt(
        L"Diagnostics", L"MaxPayloadBytes", 65536, 0, 16 * 1024 * 1024);
    config.enabled =
        config.sniffer && IniBool(L"Capture", L"Enabled", true);
    config.steam =
        config.sniffer && IniBool(L"Capture", L"Steam", true);
    config.steam_callbacks =
        config.sniffer && IniBool(L"Capture", L"SteamCallbacks", true);
    config.winsock =
        config.sniffer && IniBool(L"Capture", L"Winsock", true);
    config.payload_preview_bytes = IniUInt(
        L"Capture", L"PayloadPreviewBytes", 64, 0, 4096);
    config.flush_every_events = IniUInt(
        L"Capture", L"FlushEveryEvents", 32, 1, 4096);
    config.log_root = IniString(
        L"Capture", L"LogDirectory", L"Mods\\TrafficSniffer\\logs");
#else
    config.diagnostics_enabled = false;
    config.enabled = false;
    config.steam = false;
    config.steam_callbacks = false;
    config.winsock = false;
    config.log_root.clear();
#endif

    constexpr const wchar_t* kEdf41Coop8 = L"EDF41.Coop8.Settings";
    config.edf41_target_players = IniUInt(
        kEdf41Coop8, L"TargetPlayers", 8, 5, 8);
    config.edf41_native_safe_limit = IniUInt(
        kEdf41Coop8, L"NativeSafeLimit", 4, 2, 4);
    // Room-only probe. The EDF4.1 module may expand the pinned net::Users
    // pointer vector, but never the real Steam lobby, mission roster, spawn
    // table or result pipeline.
    config.edf41_experimental_room_overfill = IniBool(
        kEdf41Coop8, L"ExperimentalRoomOverfill", false);
    config.edf41_experimental_room_limit = IniUInt(
        kEdf41Coop8, L"ExperimentalRoomLimit", 8, 5, 8);
    config.edf41_bot_hotkey_vk = IniUInt(
        kEdf41Coop8, L"BotHotkeyVK", VK_F8, 1, 255);
    config.edf41_bot_remove_hotkey_vk = IniUInt(
        kEdf41Coop8, L"BotRemoveHotkeyVK", VK_F7, 1, 255);
    config.edf41_bot_steam_id = IniUInt64(
        kEdf41Coop8, L"BotSteamId", 76561202255232023ULL);

    constexpr const wchar_t* kCoop8 = L"EDF5.Coop8.Settings";
    constexpr const wchar_t* kLegacyCoop8 = L"MorePlayers";
    config.max_players = IniUIntWithLegacy(
        kCoop8, kLegacyCoop8, L"MaxPlayers", 8, 5, 8);
    config.experimental_enemy_spawn_multiplier = IniBoolWithLegacy(
        kCoop8, kLegacyCoop8, L"ExperimentalEnemySpawnMultiplier", false);
    config.enemy_spawn_multiplier = IniUIntWithLegacy(
        kCoop8, kLegacyCoop8, L"EnemySpawnMultiplier", 1, 1, 8);
    config.preallocated_roster_slots = IniUIntWithLegacy(
        kCoop8, kLegacyCoop8, L"PreallocatedRosterSlots", 8,
        config.max_players, 8);
    config.experimental_reserve_patches = IniBoolWithLegacy(
        kCoop8, kLegacyCoop8, L"ExperimentalReservePatches", false);
    config.bot_hotkey_vk = IniUIntWithLegacy(
        kCoop8, kLegacyCoop8, L"BotHotkeyVK", VK_F8, 1, 255);
    config.bot_remove_hotkey_vk = IniUIntWithLegacy(
        kCoop8, kLegacyCoop8, L"BotRemoveHotkeyVK", VK_F7, 1, 255);
    config.bot_ready_hotkey_vk = IniUIntWithLegacy(
        kCoop8, kLegacyCoop8, L"BotReadyHotkeyVK", VK_F6, 1, 255);
    config.invite_hotkey_vk = IniUIntWithLegacy(
        kCoop8, kLegacyCoop8, L"InviteHotkeyVK", VK_F4, 1, 255);
    config.local_mission_harness_enabled = IniBoolWithLegacy(
        kCoop8, kLegacyCoop8, L"LocalMissionHarnessEnabled", true);
    config.local_mission_harness_hotkey_vk = IniUIntWithLegacy(
        kCoop8, kLegacyCoop8, L"LocalMissionHarnessHotkeyVK", VK_F3, 1, 255);
    config.debug_stage_win_enabled = IniBoolWithLegacy(
        kCoop8, kLegacyCoop8, L"DebugStageWinEnabled", true);
    config.debug_stage_win_hotkey_vk = IniUIntWithLegacy(
        kCoop8, kLegacyCoop8, L"DebugStageWinHotkeyVK", VK_F5, 1, 255);
    config.damage_meter_enabled = IniBoolWithLegacy(
        kCoop8, kLegacyCoop8, L"DamageMeterEnabled", true);
    config.damage_meter_chat = IniBoolWithLegacy(
        kCoop8, kLegacyCoop8, L"DamageMeterChat", false);
    config.extended_enemy_health_scaling = IniBoolWithLegacy(
        kCoop8, kLegacyCoop8, L"ExtendedEnemyHealthScaling", true);
    constexpr const wchar_t* kEnemyHealthKeys[] = {
        L"EnemyHealth5Players", L"EnemyHealth6Players",
        L"EnemyHealth7Players", L"EnemyHealth8Players",
    };
    static_assert(std::size(kEnemyHealthKeys) ==
                      sizeof(capture::Config::enemy_health_multipliers) /
                          sizeof(float),
                  "one EnemyHealth key per extra participant count");
    for (size_t index = 0; index < std::size(kEnemyHealthKeys); ++index) {
        config.enemy_health_multipliers[index] =
            IniMultiplier(kCoop8, kEnemyHealthKeys[index], 0.1f, 20.0f);
    }
    config.bot_steam_id = IniUInt64WithLegacy(
        kCoop8, kLegacyCoop8, L"BotSteamId", 76561202255233023ULL);
    return config;
}

}  // namespace runtime_config

#if !EDF5_COMPILE_DIAGNOSTICS
namespace capture {
namespace {

Config g_user_config;
std::atomic<bool> g_user_config_loaded{false};

}  // namespace

bool Initialize(HMODULE plugin_module) {
    bool expected = false;
    if (g_user_config_loaded.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel)) {
        g_user_config = runtime_config::Load(plugin_module);
    }
    return true;
}

const Config& GetConfig() { return g_user_config; }

}  // namespace capture
#endif
