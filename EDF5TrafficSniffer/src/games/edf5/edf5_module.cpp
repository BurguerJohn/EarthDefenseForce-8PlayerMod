#include "edf5_module.h"

#include "crash_handler.h"
#include "game_patches.h"
#include "hook_manager.h"
#include "logger.h"
#include "more_players.h"
#include "steam_interfaces.h"
#include "winsock_hooks.h"

namespace edf5 {
namespace {

bool NetworkHooksUsable(bool coop8_enabled, bool steam_requested,
                        bool steam_ok, bool winsock_requested,
                        bool winsock_ok) {
#if !EDF5_COMPILE_DIAGNOSTICS
    if (!coop8_enabled) return true;
#endif
    const bool steam_ready = steam_requested && steam_ok;
    const bool any_network_layer_ready = steam_ready ||
        (winsock_requested && winsock_ok);
    return any_network_layer_ready && (!coop8_enabled || steam_ready);
}

bool Quarantine(const char* reason) {
    hooks::ReportStartupFailure(reason);
    EDF5_CAPTURE_EVENT(capture::Level::Error, "sniffer", "startup_failed",
                       capture::Fields().String("reason", reason));
    RequestStop();
    hooks::Shutdown();
    const bool patches_restored = game_patches::RestoreInstalledPatches();
#if !EDF5_COMPILE_DIAGNOSTICS
    (void)patches_restored;
#endif
    EDF5_CAPTURE_EVENT(
        patches_restored ? capture::Level::Info : capture::Level::Error,
        "sniffer", "startup_quarantine_complete",
        capture::Fields().Bool("patches_restored", patches_restored));
#if EDF5_COMPILE_DIAGNOSTICS
    crash_capture::RequestStop();
#endif
    EDF5_CAPTURE_REQUEST_STOP();
    // EDFModLoader can still hold an outer loader lock here. Keep a failed
    // instance loaded but inert so diagnostic worker entry points are never
    // unloaded before their threads have had a chance to stop.
#if EDF5_COMPILE_DIAGNOSTICS
    OutputDebugStringW(
        patches_restored
            ? L"EDF5_MultiSlotMod: startup quarantined and patches restored; "
              L"see Mods\\TrafficSniffer\\startup-failures.log.\r\n"
            : L"EDF5_MultiSlotMod: startup quarantine could not restore every "
              L"patch; close the game and see "
              L"Mods\\TrafficSniffer\\startup-failures.log.\r\n");
#endif
    return true;
}

}  // namespace

bool SelfTestNetworkHookPolicy(std::string& report) {
#if EDF5_COMPILE_DIAGNOSTICS
    const bool ok =
        NetworkHooksUsable(true, true, true, true, false) &&
        NetworkHooksUsable(true, true, true, false, true) &&
        !NetworkHooksUsable(true, true, false, true, true) &&
        !NetworkHooksUsable(true, false, true, true, true) &&
        NetworkHooksUsable(false, true, false, true, true) &&
        !NetworkHooksUsable(false, true, false, true, false) &&
        !NetworkHooksUsable(false, false, true, false, true);
    report = ok
        ? "startup requires working Steam hooks when EDF5.Coop8 is enabled"
        : "network hook availability policy mismatch";
#else
    const bool ok =
        NetworkHooksUsable(true, true, true, false, false) &&
        !NetworkHooksUsable(true, true, false, false, false) &&
        !NetworkHooksUsable(true, false, true, false, false) &&
        NetworkHooksUsable(false, false, false, false, false);
    report = ok
        ? "Users requires only working Steam hooks when EDF5.Coop8 is enabled"
        : "Users flavor hook policy mismatch";
#endif
    return ok;
}

bool Load(HMODULE plugin_module) {
    const bool diagnostics_ok = capture::Initialize(plugin_module);
    const capture::Config& config = capture::GetConfig();
#if EDF5_COMPILE_DIAGNOSTICS
    if (!diagnostics_ok && !config.coop8) {
        return Quarantine("diagnostics initialization failed");
    }
    if (!diagnostics_ok) {
        OutputDebugStringW(
            L"EDF5_MultiSlotMod: diagnostics unavailable; continuing "
            L"with EDF5.Coop8.\r\n");
    }
    const bool crash_handler_ok = crash_capture::Initialize(plugin_module);
    if (!crash_handler_ok) {
        EDF5_CAPTURE_EVENT(
            capture::Level::Error, "diagnostics", "crash_handler_unavailable",
            capture::Fields().Bool("edf5_coop8_continues", true));
    }
#else
    (void)diagnostics_ok;
#endif

    if (!config.sniffer && !config.coop8) return true;

    if (config.coop8 &&
        !game_patches::InstallRosterCapacity(
            more_players::MaxPlayers(), config.preallocated_roster_slots)) {
        return Quarantine("EDF5 roster-capacity patch failed");
    }
    if (config.coop8 &&
        !game_patches::InstallExperimentalReserveCapacity(
            config.experimental_reserve_patches,
            config.preallocated_roster_slots)) {
        return Quarantine("EDF5 experimental reserve patch failed");
    }
    if (!hooks::Initialize()) {
        return Quarantine("MinHook initialization failed");
    }
    if (config.coop8 && !more_players::InstallGameHooks()) {
        return Quarantine("EDF5 Coop8 game hooks failed");
    }

    bool steam_ok = true;
    bool winsock_ok = true;
    const bool steam_required =
#if EDF5_COMPILE_DIAGNOSTICS
        config.steam ||
#endif
        config.coop8;
#if EDF5_COMPILE_DIAGNOSTICS
    const bool winsock_requested = config.winsock;
#else
    const bool winsock_requested = false;
#endif
    if (steam_required) steam_ok = steam_capture::Install();
#if EDF5_COMPILE_DIAGNOSTICS
    if (winsock_requested) winsock_ok = winsock_capture::Install();
#endif
    const bool usable = NetworkHooksUsable(
        config.coop8, steam_required, steam_ok,
        winsock_requested, winsock_ok);
    EDF5_CAPTURE_EVENT(
        "sniffer", "startup_complete",
        capture::Fields().String("game", game::Name(game::Id::Edf5))
            .Bool("sniffer_enabled", config.sniffer)
            .Bool("coop8_enabled", config.coop8)
            .Bool("steam_required", steam_required)
            .Bool("steam_ok", steam_ok)
            .Bool("winsock_requested", winsock_requested)
            .Bool("winsock_ok", winsock_ok)
            .Bool("usable", usable));
    EDF5_CAPTURE_FLUSH();
    if (!usable) {
        return Quarantine(
            config.coop8 && !steam_ok
                ? "required Steam hooks unavailable for EDF5.Coop8"
                : "EDF5 sniffer network hooks unavailable");
    }
    return true;
}

void RequestStop() {
    more_players::RequestStop();
}

}  // namespace edf5
