#include "steam_legacy_interfaces.h"

#include "hook_manager.h"
#include "logger.h"
#include "steam_game_policy.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <array>
#include <cstdint>
#include <string>

namespace steam_capture {
namespace {

using SteamId = uint64_t;
using GetFriendPersonaNameFn = const char* (*)(void*, SteamId);
using ActivateInviteDialogFn = void (*)(void*, SteamId);

constexpr size_t kActivateInviteDialogSlot = 33;

GetFriendPersonaNameFn o_get_friend_persona_name = nullptr;
ActivateInviteDialogFn o_activate_invite_dialog = nullptr;
SRWLOCK g_friends_lock = SRWLOCK_INIT;
SRWLOCK g_persona_audit_lock = SRWLOCK_INIT;
void* g_friends_interface = nullptr;

struct PersonaAuditEntry {
    SteamId user = 0;
    uint64_t name_fingerprint = 0;
    uint32_t name_length = 0;
    uint32_t user_token = 0;
    uint32_t name_token = 0;
    uint32_t last_reported_shared_users = 0;
    bool name_valid = false;
};

struct PersonaAuditObservation {
    uint32_t user_token = 0;
    uint32_t name_token = 0;
    uint32_t name_length = 0;
    uint32_t shared_name_users = 0;
    bool name_valid = false;
    bool mapping_changed = false;
    bool stored = false;
    bool should_log = false;
};

constexpr size_t kPersonaAuditCapacity = 32;
constexpr size_t kPersonaAuditMaximumLength = 128;
std::array<PersonaAuditEntry, kPersonaAuditCapacity> g_persona_audit{};
uint32_t g_next_persona_user_token = 1;
uint32_t g_next_persona_name_token = 1;

uint32_t NextNonzeroToken(uint32_t& next) {
    const uint32_t result = next++;
    if (!next) next = 1;
    return result ? result : next++;
}

PersonaAuditObservation ObservePersona(SteamId user, const char* name) {
    PersonaAuditObservation result;
    size_t length = 0;
    if (name) {
        while (length < kPersonaAuditMaximumLength && name[length]) ++length;
    }
    const bool name_valid = name && length > 0 &&
        length < kPersonaAuditMaximumLength;
    uint64_t fingerprint = 0;
    if (name_valid) {
        fingerprint = 1469598103934665603ULL;
        for (size_t index = 0; index < length; ++index) {
            fingerprint ^= static_cast<uint8_t>(name[index]);
            fingerprint *= 1099511628211ULL;
        }
        if (!fingerprint) fingerprint = 1;
    }

    AcquireSRWLockExclusive(&g_persona_audit_lock);
    PersonaAuditEntry* entry = nullptr;
    PersonaAuditEntry* empty = nullptr;
    for (auto& candidate : g_persona_audit) {
        if (!candidate.user && !empty) empty = &candidate;
        if (candidate.user == user && user) entry = &candidate;
    }
    const bool created = !entry && empty && user;
    if (created) {
        entry = empty;
        entry->user = user;
        entry->user_token = NextNonzeroToken(g_next_persona_user_token);
    }
    if (entry) {
        uint32_t name_token = 0;
        if (name_valid) {
            for (const auto& candidate : g_persona_audit) {
                if (candidate.user && candidate.name_valid &&
                    candidate.name_fingerprint == fingerprint &&
                    candidate.name_length == length) {
                    name_token = candidate.name_token;
                    break;
                }
            }
            if (!name_token) {
                name_token = NextNonzeroToken(g_next_persona_name_token);
            }
        }
        const bool mapping_changed = !created &&
            (entry->name_valid != name_valid ||
             entry->name_fingerprint != fingerprint ||
             entry->name_length != length ||
             entry->name_token != name_token);
        entry->name_valid = name_valid;
        entry->name_fingerprint = fingerprint;
        entry->name_length = static_cast<uint32_t>(length);
        entry->name_token = name_token;
        uint32_t shared_users = 0;
        if (name_token) {
            for (const auto& candidate : g_persona_audit) {
                if (candidate.user && candidate.name_valid &&
                    candidate.name_token == name_token) {
                    ++shared_users;
                }
            }
        }
        result.user_token = entry->user_token;
        result.name_token = name_token;
        result.name_length = static_cast<uint32_t>(length);
        result.shared_name_users = shared_users;
        result.name_valid = name_valid;
        result.mapping_changed = mapping_changed;
        result.stored = true;
        result.should_log = created || mapping_changed ||
            shared_users > entry->last_reported_shared_users;
        if (result.should_log) {
            entry->last_reported_shared_users = shared_users;
        }
    } else {
        result.name_length = static_cast<uint32_t>(length);
        result.name_valid = name_valid;
        result.should_log = true;
    }
    ReleaseSRWLockExclusive(&g_persona_audit_lock);
    return result;
}

const char* GetFriendPersonaName(void* self, SteamId user) {
    thread_local std::string synthetic_name;
    const bool synthetic =
        steam_game_policy::TryGetBotName(user, synthetic_name);
    const char* result = synthetic ? synthetic_name.c_str()
                                   : o_get_friend_persona_name(self, user);
    const PersonaAuditObservation audit = ObservePersona(user, result);
    if (audit.should_log) {
        EDF5_CAPTURE_EVENT(
            capture::Level::Info, "steam_friends",
            "persona_identity_observed",
            capture::Fields()
                .UInt("user_identity_token", audit.user_token)
                .UInt("persona_name_token", audit.name_token)
                .UInt("persona_name_length", audit.name_length)
                .UInt("shared_name_user_count", audit.shared_name_users)
                .Bool("persona_name_valid", audit.name_valid)
                .Bool("mapping_changed", audit.mapping_changed)
                .Bool("stored", audit.stored)
                .Bool("synthetic", synthetic)
                .Bool("steam_id_logged", false)
                .Bool("persona_name_text_logged", false));
    }
    return result;
}

void ActivateInviteDialog(void* self, SteamId lobby) {
    if (o_activate_invite_dialog) o_activate_invite_dialog(self, lobby);
    EDF5_CAPTURE_EVENT(
        capture::Level::Info, "steam_friends",
        "activate_lobby_invite_dialog",
        capture::Fields().UInt("lobby_steam_id", lobby)
            .UInt("vtable_slot", kActivateInviteDialogSlot));
}

}  // namespace

bool SelfTestPrivateIdentityAudit(std::string& report) {
    auto reset = [] {
        AcquireSRWLockExclusive(&g_persona_audit_lock);
        for (auto& entry : g_persona_audit) entry = {};
        g_next_persona_user_token = 1;
        g_next_persona_name_token = 1;
        ReleaseSRWLockExclusive(&g_persona_audit_lock);
    };
    reset();
    const PersonaAuditObservation host =
        ObservePersona(76561198000000001ULL, "Host");
    const PersonaAuditObservation wing =
        ObservePersona(76561198000000002ULL, "Wing");
    const PersonaAuditObservation duplicate =
        ObservePersona(76561198000000003ULL, "Host");
    const PersonaAuditObservation collision_refresh =
        ObservePersona(76561198000000001ULL, "Host");
    const PersonaAuditObservation repeated =
        ObservePersona(76561198000000001ULL, "Host");
    const PersonaAuditObservation renamed =
        ObservePersona(76561198000000002ULL, "Host");
    const bool passed = host.stored && wing.stored && duplicate.stored &&
        collision_refresh.stored && repeated.stored && renamed.stored &&
        host.user_token != wing.user_token &&
        wing.user_token != duplicate.user_token && host.name_token &&
        wing.name_token && host.name_token != wing.name_token &&
        duplicate.name_token == host.name_token &&
        duplicate.shared_name_users == 2 &&
        collision_refresh.should_log &&
        collision_refresh.shared_name_users == 2 &&
        !repeated.should_log && renamed.mapping_changed &&
        renamed.name_token == host.name_token &&
        renamed.shared_name_users == 3;
    reset();
    report = passed
        ? "private persona tokens distinguish names and detect duplicates"
        : "private persona token check failed";
    return passed;
}

bool OpenLobbyInviteDialog(uint64_t lobby) {
    if (!lobby) return false;
    void* interface_pointer = nullptr;
    ActivateInviteDialogFn activate = nullptr;
    AcquireSRWLockShared(&g_friends_lock);
    interface_pointer = g_friends_interface;
    if (interface_pointer) {
        void** vtable = *reinterpret_cast<void***>(interface_pointer);
        if (vtable) {
            activate = reinterpret_cast<ActivateInviteDialogFn>(
                vtable[kActivateInviteDialogSlot]);
        }
    }
    ReleaseSRWLockShared(&g_friends_lock);
    if (!interface_pointer || !activate) {
        EDF5_CAPTURE_EVENT(capture::Level::Warning, "steam_friends",
                       "open_lobby_invite_dialog_failed",
                       capture::Fields().UInt("lobby_steam_id", lobby)
                           .String("reason", "friends interface unavailable"));
        return false;
    }
    activate(interface_pointer, lobby);
    EDF5_CAPTURE_EVENT(capture::Level::Info, "steam_friends",
                   "open_lobby_invite_dialog",
                   capture::Fields().UInt("lobby_steam_id", lobby)
                       .UInt("vtable_slot", kActivateInviteDialogSlot)
                       .Bool("success", true));
    return true;
}

void HookFriends(void* interface_pointer) {
    if (!interface_pointer) return;
    AcquireSRWLockExclusive(&g_friends_lock);
    if (g_friends_interface) {
        ReleaseSRWLockExclusive(&g_friends_lock);
        return;
    }
    void** vtable = *reinterpret_cast<void***>(interface_pointer);
    // SteamFriends015 slot 7. It remains slot 7 in the SDK headers used for
    // the ABI audit. Hook the implementation directly so an unknown-length
    // interface vtable never has to be copied.
    o_get_friend_persona_name = reinterpret_cast<GetFriendPersonaNameFn>(
        hooks::SharedAddress(vtable[7], reinterpret_cast<void*>(&GetFriendPersonaName),
                             "SteamFriends015::GetFriendPersonaName"));
    o_activate_invite_dialog = reinterpret_cast<ActivateInviteDialogFn>(
        hooks::SharedAddress(vtable[kActivateInviteDialogSlot],
                             reinterpret_cast<void*>(&ActivateInviteDialog),
                             "SteamFriends015::ActivateGameOverlayInviteDialog"));
    if (o_get_friend_persona_name) g_friends_interface = interface_pointer;
    ReleaseSRWLockExclusive(&g_friends_lock);
    EDF5_CAPTURE_EVENT("steam", "friends_interface_hooked",
                   capture::Fields().String("interface_version", "SteamFriends015")
                       .String("interface", capture::HexPointer(interface_pointer))
                       .Bool("persona_name_success",
                             o_get_friend_persona_name != nullptr)
                       .Bool("invite_dialog_success",
                             o_activate_invite_dialog != nullptr));
}

}  // namespace steam_capture
