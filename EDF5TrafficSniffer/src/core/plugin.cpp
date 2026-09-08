#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <PluginAPI.h>

#include "crash_handler.h"
#include "edf5_module.h"
#include "game_patches.h"
#include "logger.h"
#include "mod_info.h"
#include "module_registry.h"
#include "more_players.h"
#include "steam_interfaces.h"

#if EDF5_COMPILE_DIAGNOSTICS
#include "native_roster_patch.h"
#include "room_bots.h"
#endif

#include <algorithm>
#include <cstring>
#include <string>

namespace {

HMODULE g_module = nullptr;

bool LoadForGame(game::Id game_id, PluginInfo* plugin_info) {
    if (!plugin_info) return false;
    plugin_info->infoVersion = PluginInfo::MaxInfoVer;
    plugin_info->name = mod_info::NameForGame(game_id);
    plugin_info->version =
        PLUG_VER(mod_info::kVersionMajor, mod_info::kVersionMinor,
                 mod_info::kVersionPatch, mod_info::kVersionRevision);
    return module_registry::Load(game_id, g_module);
}

}  // namespace

extern "C" __declspec(dllexport) bool __fastcall
EML4_Load(PluginInfo* plugin_info) {
    return LoadForGame(game::Id::Edf41, plugin_info);
}

extern "C" __declspec(dllexport) bool __fastcall
EML5_Load(PluginInfo* plugin_info) {
    return LoadForGame(game::Id::Edf5, plugin_info);
}

extern "C" __declspec(dllexport) bool __fastcall
EML6_Load(PluginInfo* plugin_info) {
    return LoadForGame(game::Id::Edf6, plugin_info);
}

extern "C" __declspec(dllexport) bool __fastcall
EDF5MP_SelfTest(char* report, uint32_t capacity) {
    std::string message;
    const bool protocol_result = more_players::SelfTest(message);
    std::string identity_message;
    const bool identity_result =
        steam_capture::SelfTestPrivateIdentityAudit(identity_message);
    if (!identity_message.empty()) message += "; " + identity_message;
    std::string patch_message;
    const bool patch_result = game_patches::SelfTest(patch_message);
    if (!patch_message.empty()) message += "; " + patch_message;
    std::string steam_policy_message;
    const bool steam_policy_result =
        steam_capture::SelfTestInstallPolicy(steam_policy_message);
    if (!steam_policy_message.empty()) message += "; " + steam_policy_message;
    std::string startup_policy_message;
    const bool startup_policy_result =
        edf5::SelfTestNetworkHookPolicy(startup_policy_message);
    if (!startup_policy_message.empty()) {
        message += "; " + startup_policy_message;
    }
#if EDF5_COMPILE_DIAGNOSTICS
    std::string edf41_patch_message;
    const bool edf41_patch_result =
        edf41::native_roster_patch::SelfTest(edf41_patch_message);
    if (!edf41_patch_message.empty()) {
        message += "; " + edf41_patch_message;
    }
#else
    const bool edf41_patch_result = true;
#endif
    const bool result = protocol_result && identity_result && patch_result &&
                        steam_policy_result && startup_policy_result &&
                        edf41_patch_result;
    if (report && capacity) {
        const size_t copied = std::min<size_t>(message.size(), capacity - 1);
        std::memcpy(report, message.data(), copied);
        report[copied] = '\0';
    }
    return result;
}

extern "C" __declspec(dllexport) const char* __fastcall EDF5MP_BuildId() {
    return mod_info::kBuildId;
}

extern "C" __declspec(dllexport) const char* __fastcall EDF5MP_BuildFlavor() {
    return mod_info::kBuildFlavor;
}

extern "C" __declspec(dllexport) bool __fastcall EDF5MP_ToggleBot() {
    return more_players::ToggleBotFromApi();
}

extern "C" __declspec(dllexport) bool __fastcall EDF5MP_AddBot() {
    return more_players::AddBotFromApi();
}

extern "C" __declspec(dllexport) bool __fastcall EDF5MP_RemoveBot() {
    return more_players::RemoveBotFromApi();
}

extern "C" __declspec(dllexport) bool __fastcall EDF5MP_ReadyBots() {
    return more_players::ReadyBotsFromApi();
}

extern "C" __declspec(dllexport) bool __fastcall EDF5MP_OpenInviteDialog() {
    return more_players::OpenInviteDialogFromApi();
}

#if EDF5_COMPILE_DIAGNOSTICS
extern "C" __declspec(dllexport) bool __fastcall EDF41MP_AddRoomBot() {
    return edf41::room_bots::RequestAddFromApi();
}

extern "C" __declspec(dllexport) bool __fastcall EDF41MP_RemoveRoomBot() {
    return edf41::room_bots::RequestRemoveFromApi();
}

extern "C" __declspec(dllexport) unsigned __fastcall EDF41MP_RoomBotCount() {
    return edf41::room_bots::Count();
}

extern "C" __declspec(dllexport) bool __fastcall
EDF5MP_RequestDiagnosticSnapshot() {
    return crash_capture::RequestSnapshot("export");
}

extern "C" __declspec(dllexport) bool __fastcall
EDF5MP_SetDeepCapture(bool enabled) {
    return crash_capture::SetDeepCapture(enabled, "export");
}
#endif

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_module = module;
        DisableThreadLibraryCalls(module);
    } else if (reason == DLL_PROCESS_DETACH) {
        module_registry::RequestStop();
#if EDF5_COMPILE_DIAGNOSTICS
        crash_capture::RequestStop();
#endif
        EDF5_CAPTURE_REQUEST_STOP();
    }
    return TRUE;
}
