#include "steam_legacy_interfaces.h"

#include "hook_manager.h"
#include "logger.h"
#include "steam_game_policy.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdint>
#include <cstring>
#include <string>

namespace steam_capture {
namespace {

using SteamId = uint64_t;
// ISteamUser018/019::GetSteamID returns CSteamID through the MSVC hidden return
// buffer. The plugin uses a MinGW target, so model RCX=this and RDX=result
// explicitly, just like the matchmaking CSteamID-returning methods.
using GetSteamIdFn = SteamId* (*)(void*, SteamId*);
using BeginAuthSessionFn = int (*)(void*, const void*, int, SteamId);
using EndAuthSessionFn = void (*)(void*, SteamId);
using GetAuthSessionTicketFn = uint32_t (*)(void*, void*, int, uint32_t*);
using CancelAuthTicketFn = void (*)(void*, uint32_t);

GetSteamIdFn o_get_steam_id = nullptr;
BeginAuthSessionFn o_begin_auth_session = nullptr;
EndAuthSessionFn o_end_auth_session = nullptr;
GetAuthSessionTicketFn o_get_auth_session_ticket = nullptr;
CancelAuthTicketFn o_cancel_auth_ticket = nullptr;
SRWLOCK g_user_lock = SRWLOCK_INIT;
void* g_user_interface = nullptr;

int BeginAuthSession(void* self, const void* ticket, int ticket_size, SteamId user) {
    const bool synthetic = steam_game_policy::IsSyntheticPeer(user);
    const int result = synthetic ? 0 : o_begin_auth_session(self, ticket, ticket_size, user);
    if (synthetic) steam_game_policy::QueueSyntheticAuthValidation(user);
    EDF5_CAPTURE_EVENT("steam_user", "begin_auth_session",
                   capture::Fields().UInt("user_steam_id", user)
                       .Int("ticket_bytes", ticket_size).Bool("synthetic", synthetic)
                       .Int("result", result),
                   ticket, ticket_size > 0 ? static_cast<size_t>(ticket_size) : 0);
    return result;
}

void EndAuthSession(void* self, SteamId user) {
    const bool synthetic = steam_game_policy::IsSyntheticIdentity(user);
    if (!synthetic) o_end_auth_session(self, user);
    EDF5_CAPTURE_EVENT("steam_user", "end_auth_session",
                   capture::Fields().UInt("user_steam_id", user)
                       .Bool("synthetic", synthetic));
}

uint32_t GetAuthSessionTicket(void* self, void* ticket, int capacity,
                              uint32_t* written) {
    const uint32_t handle = o_get_auth_session_ticket
        ? o_get_auth_session_ticket(self, ticket, capacity, written)
        : 0;
    EDF5_CAPTURE_EVENT(
        capture::Level::Info, "steam_user", "get_auth_session_ticket",
        capture::Fields().UInt("ticket_handle", handle)
            .Int("ticket_capacity", capacity)
            .UInt("ticket_bytes", written ? *written : 0)
            .Bool("ticket_payload_logged", false));
    return handle;
}

void CancelAuthTicket(void* self, uint32_t handle) {
    if (o_cancel_auth_ticket) o_cancel_auth_ticket(self, handle);
    EDF5_CAPTURE_EVENT(capture::Level::Info, "steam_user",
                       "cancel_auth_ticket",
                       capture::Fields().UInt("ticket_handle", handle));
}

}  // namespace

void HookUserAuth(void* interface_pointer, const char* interface_version) {
    if (!interface_pointer) return;
    AcquireSRWLockExclusive(&g_user_lock);
    if (g_user_interface) {
        ReleaseSRWLockExclusive(&g_user_lock);
        return;
    }
    void** vtable = *reinterpret_cast<void***>(interface_pointer);
    o_get_steam_id = reinterpret_cast<GetSteamIdFn>(vtable[2]);
    // BeginAuthSession=14 and EndAuthSession=15 were confirmed independently
    // at the EDF41.exe and EDF5.exe authentication call sites. Ticket slots
    // 13/16 are enabled below only for the separately proven User018 profile.
    const std::string begin_label =
        std::string(interface_version) + "::BeginAuthSession";
    const std::string end_label =
        std::string(interface_version) + "::EndAuthSession";
    o_begin_auth_session = reinterpret_cast<BeginAuthSessionFn>(
        hooks::SharedAddress(vtable[14], reinterpret_cast<void*>(&BeginAuthSession),
                             begin_label.c_str()));
    o_end_auth_session = reinterpret_cast<EndAuthSessionFn>(
        hooks::SharedAddress(vtable[15], reinterpret_cast<void*>(&EndAuthSession),
                             end_label.c_str()));
    const bool user018 = interface_version &&
        std::strcmp(interface_version, "SteamUser018") == 0;
    if (user018) {
        o_get_auth_session_ticket =
            reinterpret_cast<GetAuthSessionTicketFn>(hooks::SharedAddress(
                vtable[13], reinterpret_cast<void*>(&GetAuthSessionTicket),
                "SteamUser018::GetAuthSessionTicket"));
        o_cancel_auth_ticket =
            reinterpret_cast<CancelAuthTicketFn>(hooks::SharedAddress(
                vtable[16], reinterpret_cast<void*>(&CancelAuthTicket),
                "SteamUser018::CancelAuthTicket"));
    }
    if (o_get_steam_id && o_begin_auth_session && o_end_auth_session) {
        g_user_interface = interface_pointer;
    }
    ReleaseSRWLockExclusive(&g_user_lock);
    EDF5_CAPTURE_EVENT("steam", "user_interface_hooked",
                   capture::Fields().String("interface_version", interface_version)
                       .String("interface", capture::HexPointer(interface_pointer))
                       .Bool("get_steam_id_success", o_get_steam_id != nullptr)
                       .Bool("begin_auth_success", o_begin_auth_session != nullptr)
                       .Bool("end_auth_success", o_end_auth_session != nullptr)
                       .Bool("ticket_issue_requested", user018)
                       .Bool("ticket_issue_success",
                             o_get_auth_session_ticket != nullptr)
                       .Bool("ticket_cancel_success",
                             o_cancel_auth_ticket != nullptr));
}

uint64_t LocalUserSteamId() {
    GetSteamIdFn get_steam_id = nullptr;
    void* interface_pointer = nullptr;
    AcquireSRWLockShared(&g_user_lock);
    get_steam_id = o_get_steam_id;
    interface_pointer = g_user_interface;
    ReleaseSRWLockShared(&g_user_lock);
    if (!get_steam_id || !interface_pointer) return 0;
    SteamId result = 0;
    get_steam_id(interface_pointer, &result);
    return result;
}

}  // namespace steam_capture
