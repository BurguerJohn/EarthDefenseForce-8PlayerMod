#include "edf41_module.h"

#include "build_config.h"
#include "crash_handler.h"
#include "hook_manager.h"
#include "logger.h"
#include "native_roster_patch.h"
#include "room_bots.h"
#include "steam_bootstrap.h"
#include "version_guard.h"
#include "winsock_hooks.h"

namespace edf41 {
namespace {

#if EDF5_COMPILE_DIAGNOSTICS
bool Quarantine(const char* reason) {
    hooks::ReportStartupFailure(reason);
    EDF5_CAPTURE_EVENT(capture::Level::Error, "edf41_sniffer",
                       "startup_failed",
                       capture::Fields().String("reason", reason));
    room_bots::RequestStop();
    native_roster_patch::Restore();
    hooks::Shutdown();
    EDF5_CAPTURE_FLUSH();
    OutputDebugStringA("EDF4.1 sniffer was left loaded but inert: ");
    OutputDebugStringA(reason);
    OutputDebugStringA("\r\n");
    return true;
}
#endif

}  // namespace

bool Load(HMODULE plugin_module) {
    const bool diagnostics_ok = capture::Initialize(plugin_module);
    const capture::Config& config = capture::GetConfig();

    if (!config.sniffer && !config.coop8) return true;

#if EDF5_COMPILE_DIAGNOSTICS
    if (!diagnostics_ok) {
        return Quarantine("EDF 4.1 diagnostics initialization failed");
    }
    if (!sniffer::ValidateSupportedBuild()) {
        return Quarantine("unsupported EDF 4.1 executable or Steam API build");
    }
    const bool crash_handler_ok = crash_capture::Initialize(plugin_module);
    if (!crash_handler_ok) {
        EDF5_CAPTURE_EVENT(capture::Level::Warning, "edf41_sniffer",
                           "crash_handler_unavailable");
    }
    if (!hooks::Initialize()) {
        return Quarantine("EDF 4.1 MinHook initialization failed");
    }

    const bool native_roster_patch_requested =
        config.coop8 && config.edf41_experimental_room_overfill;
    const bool native_roster_patch_ok =
        !native_roster_patch_requested ||
        native_roster_patch::Install(config.edf41_experimental_room_limit);
    const bool room_bots_ok = !config.coop8 || room_bots::Start();

    const bool steam_requested = config.steam || config.coop8;
    const bool winsock_requested = config.sniffer && config.winsock;
    const bool steam_ok =
        !steam_requested || sniffer::InstallSteamHooks();
    const bool winsock_ok =
        !winsock_requested || winsock_capture::Install();
    const bool usable = room_bots_ok && steam_ok && winsock_ok;

    EDF5_CAPTURE_EVENT(
        usable ? capture::Level::Info : capture::Level::Error,
        "edf41_sniffer", "startup_complete",
        capture::Fields().Bool("steam_requested", steam_requested)
            .Bool("steam_ok", steam_ok)
            .Bool("winsock_requested", winsock_requested)
            .Bool("winsock_ok", winsock_ok)
            .Bool("coop8_enabled", config.coop8)
            .Bool("room_bots_ready", room_bots_ok)
            .Bool("native_roster_patch_requested",
                  native_roster_patch_requested)
            .Bool("native_roster_patch_ok", native_roster_patch_ok)
            .Bool("game_memory_patches", native_roster_patch::Ready())
            .Bool("native_safe_limit_enforced",
                  config.coop8 && !native_roster_patch::Ready())
            .UInt("native_safe_limit",
                  config.edf41_native_safe_limit)
            .Bool("experimental_room_overfill",
                  config.edf41_experimental_room_overfill)
            .UInt("experimental_room_limit",
                  config.edf41_experimental_room_limit)
            .UInt("target_players", config.edf41_target_players)
            .Bool("usable", usable));
    EDF5_CAPTURE_FLUSH();
    if (!usable) {
        return Quarantine("EDF 4.1 network hooks unavailable");
    }
#else
    (void)diagnostics_ok;
    if (config.coop8) {
        OutputDebugStringW(
            L"EDF4.1 room bots are currently available only in the "
            L"Diagnostics development build.\r\n");
    }
#endif
    return true;
}

void RequestStop() {
#if EDF5_COMPILE_DIAGNOSTICS
    room_bots::RequestStop();
    native_roster_patch::Restore();
#endif
}

}  // namespace edf41
