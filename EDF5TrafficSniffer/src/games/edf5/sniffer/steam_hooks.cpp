#include "steam_interfaces.h"

#include "crash_handler.h"
#include "hook_manager.h"
#include "logger.h"
#include "more_players.h"

#include <atomic>
#include <algorithm>
#include <cstdint>
#include <vector>

namespace steam_capture {
namespace {

using SteamApiCall = uint64_t;
using ContextInitFn = void* (*)(void*);
using CreateInterfaceFn = void* (*)(const char*);
using InitFn = bool (*)();
using ShutdownFn = void (*)();
using RunCallbacksFn = void (*)();
using RegisterCallbackFn = void (*)(void*, int);
using UnregisterCallbackFn = void (*)(void*);
using RegisterCallResultFn = void (*)(void*, SteamApiCall);
using UnregisterCallResultFn = void (*)(void*, SteamApiCall);

ContextInitFn g_context_init = nullptr;
CreateInterfaceFn g_create_interface = nullptr;
InitFn g_init = nullptr;
ShutdownFn g_shutdown = nullptr;
RunCallbacksFn g_run_callbacks = nullptr;
RegisterCallbackFn g_register_callback = nullptr;
UnregisterCallbackFn g_unregister_callback = nullptr;
RegisterCallResultFn g_register_call_result = nullptr;
UnregisterCallResultFn g_unregister_call_result = nullptr;
std::atomic<void*> g_last_context{nullptr};
std::atomic<void*> g_lobby_chat_update_callback{nullptr};
SRWLOCK g_auth_callbacks_lock = SRWLOCK_INIT;
std::vector<void*> g_auth_callbacks;

struct RequiredHookState {
    bool context_init = false;
    bool shutdown = false;
    bool run_callbacks = false;
    bool register_callback = false;
    bool unregister_callback = false;
};

bool RequiredHooksReady(bool more_players_enabled,
                        const RequiredHookState& state) {
    if (!state.context_init) return false;
    return !more_players_enabled ||
        (state.shutdown && state.run_callbacks &&
         state.register_callback && state.unregister_callback);
}

#pragma pack(push, 8)
struct LobbyChatUpdate {
    uint64_t lobby;
    uint64_t user_changed;
    uint64_t making_change;
    uint32_t state_change;
};
#pragma pack(pop)
static_assert(sizeof(LobbyChatUpdate) == 32, "Steam callback packing mismatch");

struct ValidateAuthTicketResponse {
    uint64_t user;
    int32_t auth_session_response;
    uint32_t padding;
    uint64_t owner;
};
static_assert(sizeof(ValidateAuthTicketResponse) == 24,
              "Steam auth callback packing mismatch");

using CallbackRunFn = void (*)(void*, void*);

[[maybe_unused]] const char* CallbackName(int id) {
    switch (id) {
    case 101: return "SteamServersConnected_t";
    case 102: return "SteamServerConnectFailure_t";
    case 103: return "SteamServersDisconnected_t";
    case 117: return "IPCFailure_t";
    case 143: return "ValidateAuthTicketResponse_t";
    case 331: return "GameOverlayActivated_t";
    case 332: return "GameServerChangeRequested_t";
    case 333: return "GameLobbyJoinRequested_t";
    case 502: return "FavoritesListChanged_t";
    case 503: return "LobbyInvite_t";
    case 504: return "LobbyEnter_t";
    case 505: return "LobbyDataUpdate_t";
    case 506: return "LobbyChatUpdate_t";
    case 507: return "LobbyChatMsg_t";
    case 509: return "LobbyGameCreated_t";
    case 510: return "LobbyMatchList_t";
    case 512: return "LobbyKicked_t";
    case 513: return "LobbyCreated_t";
    case 516: return "FavoritesListAccountsUpdated_t";
    case 703: return "SteamAPICallCompleted_t";
    case 704: return "SteamShutdown_t";
    case 1101: return "UserStatsReceived_t";
    case 1102: return "UserStatsStored_t";
    case 1103: return "UserAchievementStored_t";
    case 1201: return "SocketStatusCallback_t";
    case 1202: return "P2PSessionRequest_t";
    case 1203: return "P2PSessionConnectFail_t";
    case 2101: return "HTTPRequestCompleted_t";
    case 2102: return "HTTPRequestHeadersReceived_t";
    case 2103: return "HTTPRequestDataReceived_t";
    default: return "unknown";
    }
}

int CallbackIdFromObject(void* object) {
    if (!object) return 0;
    // MSVC x64 CCallbackBase: vptr, uint8 flags, 3 bytes padding, int callback id.
    return *reinterpret_cast<int*>(static_cast<uint8_t*>(object) + 12);
}

void LogCallbackMetadata(const char* event, void* object, int callback_id,
                         SteamApiCall api_call, bool call_result) {
    // Keep callback capture metadata-only. Detouring CCallbackBase::Run changes
    // the ABI-sensitive Steam dispatch path used by EDF5's lobby search.
    if (!capture::GetConfig().steam_callbacks) return;
    EDF5_CAPTURE_EVENT("steam_callback", event,
                   capture::Fields().Int("callback_id", callback_id)
                       .String("callback_name", CallbackName(callback_id))
                       .Bool("call_result", call_result)
                       .UInt("api_call", api_call)
                       .String("object", capture::HexPointer(object)));
}

void DispatchSyntheticMembershipChange() {
    void* callback = g_lobby_chat_update_callback.load(std::memory_order_acquire);
    if (!callback) return;
    uint64_t lobby = 0;
    uint64_t user = 0;
    uint32_t state_change = 0;
    if (!more_players::ConsumeMembershipChange(lobby, user, state_change)) return;
    void** vtable = *reinterpret_cast<void***>(callback);
    if (!vtable || !vtable[0]) return;
    LobbyChatUpdate update{lobby, user, user, state_change};
    reinterpret_cast<CallbackRunFn>(vtable[0])(callback, &update);
    more_players::MembershipChangeDelivered(lobby, user, state_change);
    EDF5_CAPTURE_EVENT("more_players", "lobby_chat_update_dispatched",
                   capture::Fields().UInt("lobby_steam_id", lobby)
                       .UInt("user_steam_id", user).UInt("state_change", state_change)
                       .String("callback", capture::HexPointer(callback)));
}

void DispatchSyntheticAuthValidation() {
    uint64_t user = 0;
    if (!more_players::ConsumeSyntheticAuthValidation(user)) return;
    std::vector<void*> callbacks;
    AcquireSRWLockShared(&g_auth_callbacks_lock);
    callbacks = g_auth_callbacks;
    ReleaseSRWLockShared(&g_auth_callbacks_lock);
    if (callbacks.empty()) return;
    ValidateAuthTicketResponse update{user, 0, 0, user};
    unsigned dispatched = 0;
    for (void* callback : callbacks) {
        if (!callback) continue;
        void** vtable = *reinterpret_cast<void***>(callback);
        if (!vtable || !vtable[0]) continue;
        reinterpret_cast<CallbackRunFn>(vtable[0])(callback, &update);
        ++dispatched;
    }
    if (!dispatched) return;
    more_players::SyntheticAuthValidationDelivered(user);
    EDF5_CAPTURE_EVENT("more_players", "auth_validation_dispatched",
                   capture::Fields().UInt("user_steam_id", user)
                       .UInt("callbacks", dispatched).Int("response", 0));
}

void* HookedContextInit(void* init_data) {
    void* context = g_context_init(init_data);
    if (context) {
        auto** interfaces = reinterpret_cast<void**>(context);
        // CSteamAPIContext layout from the Steamworks SDK v1.42 used by EDF5.
        HookUserAuth(interfaces[1], "SteamUser019");
        HookFriends(interfaces[2]);
        HookMatchmaking(interfaces[4]);
        HookNetworking(interfaces[8]);
        HookHttp(interfaces[11]);
        more_players::Start();
        if (g_last_context.exchange(context, std::memory_order_acq_rel) != context) {
            EDF5_CAPTURE_EVENT("steam", "context_init",
                           capture::Fields().String("context", capture::HexPointer(context))
                               .String("client", capture::HexPointer(interfaces[0]))
                               .String("user", capture::HexPointer(interfaces[1]))
                               .String("friends", capture::HexPointer(interfaces[2]))
                               .String("matchmaking", capture::HexPointer(interfaces[4]))
                               .String("networking", capture::HexPointer(interfaces[8]))
                               .String("http", capture::HexPointer(interfaces[11])));
        }
    }
    return context;
}

void* HookedCreateInterface(const char* version) {
    void* result = g_create_interface(version);
    EDF5_CAPTURE_EVENT("steam", "create_interface",
                   capture::Fields().String("version", version)
                       .String("result", capture::HexPointer(result)));
    return result;
}

bool HookedInit() {
    const bool result = g_init();
    EDF5_CAPTURE_EVENT("steam", "api_init", capture::Fields().Bool("result", result));
    return result;
}

void HookedShutdown() {
    EDF5_CAPTURE_EVENT("steam", "api_shutdown_begin");
    more_players::Stop();
    g_shutdown();
    EDF5_CAPTURE_EVENT("steam", "api_shutdown_end");
    EDF5_CRASH_STOP();
    EDF5_CAPTURE_STOP_AND_FLUSH();
}

void HookedRunCallbacks() {
    g_run_callbacks();
    DispatchSyntheticMembershipChange();
    DispatchSyntheticAuthValidation();
}

void HookedRegisterCallback(void* callback, int callback_id) {
    g_register_callback(callback, callback_id);
    if (callback_id == 506) {
        g_lobby_chat_update_callback.store(callback, std::memory_order_release);
    } else if (callback_id == 143) {
        AcquireSRWLockExclusive(&g_auth_callbacks_lock);
        if (std::find(g_auth_callbacks.begin(), g_auth_callbacks.end(), callback) ==
            g_auth_callbacks.end()) {
            g_auth_callbacks.push_back(callback);
        }
        ReleaseSRWLockExclusive(&g_auth_callbacks_lock);
    }
    LogCallbackMetadata("register", callback, callback_id, 0, false);
}

void HookedUnregisterCallback(void* callback) {
    const int callback_id = CallbackIdFromObject(callback);
    if (callback_id == 506) {
        void* expected = callback;
        g_lobby_chat_update_callback.compare_exchange_strong(expected, nullptr,
                                                             std::memory_order_acq_rel);
    } else if (callback_id == 143) {
        AcquireSRWLockExclusive(&g_auth_callbacks_lock);
        g_auth_callbacks.erase(
            std::remove(g_auth_callbacks.begin(), g_auth_callbacks.end(), callback),
            g_auth_callbacks.end());
        ReleaseSRWLockExclusive(&g_auth_callbacks_lock);
    }
    g_unregister_callback(callback);
    LogCallbackMetadata("unregister", callback, callback_id, 0, false);
}

void HookedRegisterCallResult(void* callback, SteamApiCall api_call) {
    g_register_call_result(callback, api_call);
    LogCallbackMetadata("register_call_result", callback, CallbackIdFromObject(callback),
                        api_call, true);
}

void HookedUnregisterCallResult(void* callback, SteamApiCall api_call) {
    const int callback_id = CallbackIdFromObject(callback);
    g_unregister_call_result(callback, api_call);
    LogCallbackMetadata("unregister_call_result", callback, callback_id, api_call, true);
}

}  // namespace

bool Install() {
    const bool more_players_enabled = more_players::Enabled();
    RequiredHookState required{};
    required.context_init = hooks::Export(
        L"steam_api64.dll", "SteamInternal_ContextInit",
        reinterpret_cast<void*>(&HookedContextInit),
        reinterpret_cast<void**>(&g_context_init), true);
    hooks::Export(L"steam_api64.dll", "SteamInternal_CreateInterface",
                  reinterpret_cast<void*>(&HookedCreateInterface),
                  reinterpret_cast<void**>(&g_create_interface));
    hooks::Export(L"steam_api64.dll", "SteamAPI_Init", reinterpret_cast<void*>(&HookedInit),
                  reinterpret_cast<void**>(&g_init));
    required.shutdown = hooks::Export(
        L"steam_api64.dll", "SteamAPI_Shutdown",
        reinterpret_cast<void*>(&HookedShutdown),
        reinterpret_cast<void**>(&g_shutdown), more_players_enabled);
    if (more_players_enabled) {
        required.run_callbacks = hooks::Export(
            L"steam_api64.dll", "SteamAPI_RunCallbacks",
            reinterpret_cast<void*>(&HookedRunCallbacks),
            reinterpret_cast<void**>(&g_run_callbacks), true);
    }
    if (capture::GetConfig().steam_callbacks || more_players_enabled) {
        required.register_callback = hooks::Export(
            L"steam_api64.dll", "SteamAPI_RegisterCallback",
            reinterpret_cast<void*>(&HookedRegisterCallback),
            reinterpret_cast<void**>(&g_register_callback),
            more_players_enabled);
        required.unregister_callback = hooks::Export(
            L"steam_api64.dll", "SteamAPI_UnregisterCallback",
            reinterpret_cast<void*>(&HookedUnregisterCallback),
            reinterpret_cast<void**>(&g_unregister_callback),
            more_players_enabled);
        hooks::Export(L"steam_api64.dll", "SteamAPI_RegisterCallResult",
                      reinterpret_cast<void*>(&HookedRegisterCallResult),
                      reinterpret_cast<void**>(&g_register_call_result));
        hooks::Export(L"steam_api64.dll", "SteamAPI_UnregisterCallResult",
                      reinterpret_cast<void*>(&HookedUnregisterCallResult),
                      reinterpret_cast<void**>(&g_unregister_call_result));
    }
    return RequiredHooksReady(more_players_enabled, required);
}

bool SelfTestInstallPolicy(std::string& report) {
    const RequiredHookState complete{true, true, true, true, true};
    RequiredHookState missing = complete;
    bool ok = RequiredHooksReady(false, complete) &&
              RequiredHooksReady(true, complete);
    missing.context_init = false;
    ok = ok && !RequiredHooksReady(false, missing) &&
         !RequiredHooksReady(true, missing);
    missing = complete;
    missing.shutdown = false;
    ok = ok && RequiredHooksReady(false, missing) &&
         !RequiredHooksReady(true, missing);
    missing = complete;
    missing.run_callbacks = false;
    ok = ok && RequiredHooksReady(false, missing) &&
         !RequiredHooksReady(true, missing);
    missing = complete;
    missing.register_callback = false;
    ok = ok && RequiredHooksReady(false, missing) &&
         !RequiredHooksReady(true, missing);
    missing = complete;
    missing.unregister_callback = false;
    ok = ok && RequiredHooksReady(false, missing) &&
         !RequiredHooksReady(true, missing);
    report = ok
        ? "required Steam hooks fail closed in MorePlayers"
        : "required Steam hook policy mismatch";
    return ok;
}

}  // namespace steam_capture
