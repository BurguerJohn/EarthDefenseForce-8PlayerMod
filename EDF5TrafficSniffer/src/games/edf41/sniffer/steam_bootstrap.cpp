#include "steam_bootstrap.h"

#include "callback_dispatch.h"
#include "hook_manager.h"
#include "logger.h"
#include "room_bots.h"
#include "steam_legacy_interfaces.h"

#include <cstdint>

namespace edf41::sniffer {
namespace {

using AccessorFn = void* (*)();
using InitFn = bool (*)();
using ShutdownFn = void (*)();
using RunCallbacksFn = void (*)();
using SteamApiCall = uint64_t;
using RegisterCallbackFn = void (*)(void*, int);
using UnregisterCallbackFn = void (*)(void*);
using RegisterCallResultFn = void (*)(void*, SteamApiCall);
using UnregisterCallResultFn = void (*)(void*, SteamApiCall);

AccessorFn g_friends = nullptr;
AccessorFn g_matchmaking = nullptr;
AccessorFn g_networking = nullptr;
AccessorFn g_user = nullptr;
InitFn g_init = nullptr;
ShutdownFn g_shutdown = nullptr;
RunCallbacksFn g_run_callbacks = nullptr;
RegisterCallbackFn g_register_callback = nullptr;
UnregisterCallbackFn g_unregister_callback = nullptr;
RegisterCallResultFn g_register_call_result = nullptr;
UnregisterCallResultFn g_unregister_call_result = nullptr;

int CallbackIdFromObject(void* object) {
    if (!object) return 0;
    // MSVC x64 CCallbackBase used by this pinned build: vptr, uint8 flags,
    // three padding bytes, then the callback id at +12.
    return *reinterpret_cast<int*>(static_cast<uint8_t*>(object) + 12);
}

void LogCallback(const char* event, void* callback, int callback_id,
                 SteamApiCall api_call, bool call_result) {
    EDF5_CAPTURE_EVENT(
        capture::Level::Info, "edf41_steam_callback", event,
        capture::Fields().Int("callback_id", callback_id)
            .Bool("call_result", call_result)
            .UInt("api_call", api_call)
            .String("object", capture::HexPointer(callback)));
}

void AttachFriends(void* interface_pointer, const char* source) {
    if (interface_pointer) steam_capture::HookFriends(interface_pointer);
    EDF5_CAPTURE_EVENT(
        "edf41_steam", "interface_observed",
        capture::Fields().String("interface", "SteamFriends015")
            .String("source", source)
            .String("pointer", capture::HexPointer(interface_pointer))
            .Bool("available", interface_pointer != nullptr));
}

void AttachMatchmaking(void* interface_pointer, const char* source) {
    if (interface_pointer) steam_capture::HookMatchmaking(interface_pointer);
    EDF5_CAPTURE_EVENT(
        "edf41_steam", "interface_observed",
        capture::Fields().String("interface", "SteamMatchMaking009")
            .String("source", source)
            .String("pointer", capture::HexPointer(interface_pointer))
            .Bool("available", interface_pointer != nullptr));
}

void AttachNetworking(void* interface_pointer, const char* source) {
    if (interface_pointer) steam_capture::HookNetworking(interface_pointer);
    EDF5_CAPTURE_EVENT(
        "edf41_steam", "interface_observed",
        capture::Fields().String("interface", "SteamNetworking005")
            .String("source", source)
            .String("pointer", capture::HexPointer(interface_pointer))
            .Bool("available", interface_pointer != nullptr));
}

void AttachUser(void* interface_pointer, const char* source) {
    if (interface_pointer) {
        steam_capture::HookUserAuth(interface_pointer, "SteamUser018");
    }
    EDF5_CAPTURE_EVENT(
        "edf41_steam", "interface_observed",
        capture::Fields().String("interface", "SteamUser018")
            .String("source", source)
            .String("pointer", capture::HexPointer(interface_pointer))
            .Bool("available", interface_pointer != nullptr));
}

void AttachAvailableInterfaces(const char* source) {
    if (g_friends) AttachFriends(g_friends(), source);
    if (g_matchmaking) AttachMatchmaking(g_matchmaking(), source);
    if (g_networking) AttachNetworking(g_networking(), source);
    if (g_user) AttachUser(g_user(), source);
}

void* HookedFriends() {
    void* result = g_friends ? g_friends() : nullptr;
    AttachFriends(result, "SteamFriends accessor");
    return result;
}

void* HookedMatchmaking() {
    void* result = g_matchmaking ? g_matchmaking() : nullptr;
    AttachMatchmaking(result, "SteamMatchmaking accessor");
    return result;
}

void* HookedNetworking() {
    void* result = g_networking ? g_networking() : nullptr;
    AttachNetworking(result, "SteamNetworking accessor");
    return result;
}

void* HookedUser() {
    void* result = g_user ? g_user() : nullptr;
    AttachUser(result, "SteamUser accessor");
    return result;
}

bool HookedInit() {
    const bool result = g_init && g_init();
    EDF5_CAPTURE_EVENT("edf41_steam", "api_init",
                       capture::Fields().Bool("result", result));
    if (result) AttachAvailableInterfaces("SteamAPI_Init");
    return result;
}

void HookedShutdown() {
    EDF5_CAPTURE_EVENT("edf41_steam", "api_shutdown_begin");
    room_bots::RequestStop();
    if (g_shutdown) g_shutdown();
    EDF5_CAPTURE_EVENT("edf41_steam", "api_shutdown_end");
    EDF5_CAPTURE_FLUSH();
}

void HookedRunCallbacks() {
    if (g_run_callbacks) g_run_callbacks();
    room_bots::Pump();
}

void HookedRegisterCallback(void* callback, int callback_id) {
    if (g_register_callback) g_register_callback(callback, callback_id);
    callback_dispatch::ObserveRegistration(
        callback, callback_id, callback_dispatch::RegistrationKind::Callback);
    LogCallback("register", callback, callback_id, 0, false);
}

void HookedUnregisterCallback(void* callback) {
    const int callback_id = CallbackIdFromObject(callback);
    callback_dispatch::ForgetRegistration(
        callback, callback_dispatch::RegistrationKind::Callback);
    if (g_unregister_callback) g_unregister_callback(callback);
    LogCallback("unregister", callback, callback_id, 0, false);
}

void HookedRegisterCallResult(void* callback, SteamApiCall api_call) {
    const int callback_id = CallbackIdFromObject(callback);
    if (g_register_call_result) g_register_call_result(callback, api_call);
    callback_dispatch::ObserveRegistration(
        callback, callback_id,
        callback_dispatch::RegistrationKind::CallResult);
    LogCallback("register_call_result", callback, callback_id, api_call, true);
}

void HookedUnregisterCallResult(void* callback, SteamApiCall api_call) {
    const int callback_id = CallbackIdFromObject(callback);
    callback_dispatch::ForgetRegistration(
        callback, callback_dispatch::RegistrationKind::CallResult);
    if (g_unregister_call_result) {
        g_unregister_call_result(callback, api_call);
    }
    LogCallback("unregister_call_result", callback, callback_id, api_call,
                true);
}

}  // namespace

bool InstallSteamHooks() {
    const bool friends_ok = hooks::Export(
        L"steam_api64.dll", "SteamFriends",
        reinterpret_cast<void*>(&HookedFriends),
        reinterpret_cast<void**>(&g_friends), true);
    const bool matchmaking_ok = hooks::Export(
        L"steam_api64.dll", "SteamMatchmaking",
        reinterpret_cast<void*>(&HookedMatchmaking),
        reinterpret_cast<void**>(&g_matchmaking), true);
    const bool networking_ok = hooks::Export(
        L"steam_api64.dll", "SteamNetworking",
        reinterpret_cast<void*>(&HookedNetworking),
        reinterpret_cast<void**>(&g_networking), true);
    const bool user_ok = hooks::Export(
        L"steam_api64.dll", "SteamUser",
        reinterpret_cast<void*>(&HookedUser),
        reinterpret_cast<void**>(&g_user), true);

    const bool init_ok = hooks::Export(
        L"steam_api64.dll", "SteamAPI_Init",
        reinterpret_cast<void*>(&HookedInit),
        reinterpret_cast<void**>(&g_init));
    const bool shutdown_ok = hooks::Export(
        L"steam_api64.dll", "SteamAPI_Shutdown",
        reinterpret_cast<void*>(&HookedShutdown),
        reinterpret_cast<void**>(&g_shutdown));

    const bool callbacks_requested =
        capture::GetConfig().steam_callbacks || capture::GetConfig().coop8;
    bool callbacks_ready = true;
    bool run_callbacks_ok = true;
    if (callbacks_requested) {
        run_callbacks_ok = hooks::Export(
            L"steam_api64.dll", "SteamAPI_RunCallbacks",
            reinterpret_cast<void*>(&HookedRunCallbacks),
            reinterpret_cast<void**>(&g_run_callbacks), true);
        const bool register_callback_ok = hooks::Export(
            L"steam_api64.dll", "SteamAPI_RegisterCallback",
            reinterpret_cast<void*>(&HookedRegisterCallback),
            reinterpret_cast<void**>(&g_register_callback), true);
        const bool unregister_callback_ok = hooks::Export(
            L"steam_api64.dll", "SteamAPI_UnregisterCallback",
            reinterpret_cast<void*>(&HookedUnregisterCallback),
            reinterpret_cast<void**>(&g_unregister_callback), true);
        const bool register_call_result_ok = hooks::Export(
            L"steam_api64.dll", "SteamAPI_RegisterCallResult",
            reinterpret_cast<void*>(&HookedRegisterCallResult),
            reinterpret_cast<void**>(&g_register_call_result), true);
        const bool unregister_call_result_ok = hooks::Export(
            L"steam_api64.dll", "SteamAPI_UnregisterCallResult",
            reinterpret_cast<void*>(&HookedUnregisterCallResult),
            reinterpret_cast<void**>(&g_unregister_call_result), true);
        callbacks_ready = run_callbacks_ok && register_callback_ok &&
            unregister_callback_ok &&
            register_call_result_ok && unregister_call_result_ok;
    }

    const bool required_ready =
        friends_ok && matchmaking_ok && networking_ok && user_ok &&
        callbacks_ready;
    EDF5_CAPTURE_EVENT(
        required_ready ? capture::Level::Info : capture::Level::Error,
        "edf41_steam", "bootstrap_installed",
        capture::Fields().Bool("friends_accessor", friends_ok)
            .Bool("matchmaking_accessor", matchmaking_ok)
            .Bool("networking_accessor", networking_ok)
            .Bool("user_accessor", user_ok)
            .Bool("api_init", init_ok)
            .Bool("api_shutdown", shutdown_ok)
            .Bool("callbacks_requested", callbacks_requested)
            .Bool("run_callbacks", run_callbacks_ok)
            .Bool("callbacks_ready", callbacks_ready)
            .Bool("required_ready", required_ready)
            .Bool("uses_edf5_context_layout", false));

    // EDFModLoader normally loads before SteamAPI_Init. This probe also covers
    // late plugin loading: accessors return null harmlessly before Steam init
    // and return the already-created singleton afterwards.
    if (required_ready) AttachAvailableInterfaces("install probe");
    return required_ready;
}

}  // namespace edf41::sniffer
