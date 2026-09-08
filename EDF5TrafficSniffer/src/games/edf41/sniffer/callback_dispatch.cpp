#include "callback_dispatch.h"

#include "logger.h"
#include "room_bots.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <unordered_map>
#include <vector>

namespace edf41::sniffer::callback_dispatch {
namespace {

using SteamApiCall = uint64_t;
using RunCallbackFn = void (*)(void*, void*);
using RunCallResultFn = void (*)(void*, void*, bool, SteamApiCall);
using GetCallbackSizeFn = int (*)(void*);

constexpr unsigned kMaximumCallbackBytes = 64u * 1024u;

struct CallbackRecord {
    void** original_vtable = nullptr;
    void* shadow_vtable[3]{};
    int callback_id = 0;
    unsigned callback_bytes = 0;
    bool callback_registered = false;
    bool call_result_registered = false;
};

SRWLOCK g_callback_lock = SRWLOCK_INIT;
std::unordered_map<void*, std::unique_ptr<CallbackRecord>> g_callbacks;

template <typename Value>
bool ReadField(const void* payload, unsigned payload_bytes, size_t offset,
               Value& value) {
    if (!payload || offset > payload_bytes ||
        sizeof(Value) > static_cast<size_t>(payload_bytes) - offset) {
        return false;
    }
    std::memcpy(&value, static_cast<const uint8_t*>(payload) + offset,
                sizeof(Value));
    return true;
}

const char* CallbackName(int callback_id) {
    switch (callback_id) {
    case 143: return "ValidateAuthTicketResponse";
    case 331: return "GameOverlayActivated";
    case 333: return "GameLobbyJoinRequested";
    case 503: return "LobbyInvite";
    case 504: return "LobbyEnter";
    case 505: return "LobbyDataUpdate";
    case 506: return "LobbyChatUpdate";
    case 507: return "LobbyChatMsg";
    case 509: return "LobbyGameCreated";
    case 510: return "LobbyMatchList";
    case 512: return "LobbyKicked";
    case 513: return "LobbyCreated";
    case 703: return "SteamAPICallCompleted";
    case 1101: return "UserStatsReceived";
    case 1103: return "UserAchievementStored";
    case 1202: return "P2PSessionRequest";
    case 1203: return "P2PSessionConnectFail";
    default: return "Unknown";
    }
}

void AddKnownFields(int callback_id, const void* payload,
                    unsigned payload_bytes, capture::Fields& fields) {
    uint64_t value64_a = 0;
    uint64_t value64_b = 0;
    uint64_t value64_c = 0;
    uint32_t value32_a = 0;
    uint32_t value32_b = 0;
    uint16_t value16 = 0;
    uint8_t value8 = 0;

    switch (callback_id) {
    case 143:
        // The SteamUser callback is packed to 4-byte alignment in this
        // steam_api64 build: CSteamID (8), EAuthSessionResponse (4), then the
        // owner CSteamID (8). Real EDF4.1 sessions report exactly 20 bytes.
        if (ReadField(payload, payload_bytes, 0, value64_a)) {
            fields.UInt("validated_steam_id", value64_a);
        }
        if (ReadField(payload, payload_bytes, 8, value32_a)) {
            fields.Int("auth_session_response",
                       static_cast<int32_t>(value32_a));
        }
        if (ReadField(payload, payload_bytes, 12, value64_b)) {
            fields.UInt("owner_steam_id", value64_b);
        }
        break;
    case 331:
        if (ReadField(payload, payload_bytes, 0, value8)) {
            fields.Bool("overlay_active", value8 != 0);
        }
        break;
    case 333:
        if (ReadField(payload, payload_bytes, 0, value64_a)) {
            fields.UInt("lobby_steam_id", value64_a);
        }
        if (ReadField(payload, payload_bytes, 8, value64_b)) {
            fields.UInt("friend_steam_id", value64_b);
        }
        break;
    case 503:
        if (ReadField(payload, payload_bytes, 0, value64_a)) {
            fields.UInt("inviter_steam_id", value64_a);
        }
        if (ReadField(payload, payload_bytes, 8, value64_b)) {
            fields.UInt("lobby_steam_id", value64_b);
        }
        if (ReadField(payload, payload_bytes, 16, value64_c)) {
            fields.UInt("game_id", value64_c);
        }
        break;
    case 504:
        if (ReadField(payload, payload_bytes, 0, value64_a)) {
            fields.UInt("lobby_steam_id", value64_a);
        }
        if (ReadField(payload, payload_bytes, 8, value32_a)) {
            fields.UInt("chat_permissions", value32_a);
        }
        if (ReadField(payload, payload_bytes, 12, value8)) {
            fields.Bool("locked", value8 != 0);
        }
        if (ReadField(payload, payload_bytes, 16, value32_b)) {
            fields.UInt("enter_response", value32_b);
        }
        break;
    case 505:
        if (ReadField(payload, payload_bytes, 0, value64_a)) {
            fields.UInt("lobby_steam_id", value64_a);
        }
        if (ReadField(payload, payload_bytes, 8, value64_b)) {
            fields.UInt("member_steam_id", value64_b);
        }
        if (ReadField(payload, payload_bytes, 16, value8)) {
            fields.Bool("success", value8 != 0);
        }
        break;
    case 506:
        if (ReadField(payload, payload_bytes, 0, value64_a)) {
            fields.UInt("lobby_steam_id", value64_a);
        }
        if (ReadField(payload, payload_bytes, 8, value64_b)) {
            fields.UInt("changed_user_steam_id", value64_b);
        }
        if (ReadField(payload, payload_bytes, 16, value64_c)) {
            fields.UInt("making_change_steam_id", value64_c);
        }
        if (ReadField(payload, payload_bytes, 24, value32_a)) {
            fields.UInt("member_state_change", value32_a);
        }
        break;
    case 507:
        if (ReadField(payload, payload_bytes, 0, value64_a)) {
            fields.UInt("lobby_steam_id", value64_a);
        }
        if (ReadField(payload, payload_bytes, 8, value64_b)) {
            fields.UInt("sender_steam_id", value64_b);
        }
        if (ReadField(payload, payload_bytes, 16, value8)) {
            fields.UInt("chat_entry_type", value8);
        }
        if (ReadField(payload, payload_bytes, 20, value32_a)) {
            fields.UInt("chat_id", value32_a);
        }
        break;
    case 509:
        if (ReadField(payload, payload_bytes, 0, value64_a)) {
            fields.UInt("lobby_steam_id", value64_a);
        }
        if (ReadField(payload, payload_bytes, 8, value64_b)) {
            fields.UInt("game_server_steam_id", value64_b);
        }
        if (ReadField(payload, payload_bytes, 16, value32_a)) {
            fields.UInt("server_ip_u32", value32_a);
        }
        if (ReadField(payload, payload_bytes, 20, value16)) {
            fields.UInt("server_port", value16);
        }
        break;
    case 510:
        if (ReadField(payload, payload_bytes, 0, value32_a)) {
            fields.UInt("matching_lobbies", value32_a);
        }
        break;
    case 512:
        if (ReadField(payload, payload_bytes, 0, value64_a)) {
            fields.UInt("lobby_steam_id", value64_a);
        }
        if (ReadField(payload, payload_bytes, 8, value64_b)) {
            fields.UInt("admin_steam_id", value64_b);
        }
        if (ReadField(payload, payload_bytes, 16, value8)) {
            fields.Bool("disconnect", value8 != 0);
        }
        break;
    case 513:
        if (ReadField(payload, payload_bytes, 0, value32_a)) {
            fields.Int("result", static_cast<int32_t>(value32_a));
        }
        if (ReadField(payload, payload_bytes, 8, value64_a)) {
            fields.UInt("lobby_steam_id", value64_a);
        }
        break;
    case 703:
        if (ReadField(payload, payload_bytes, 0, value64_a)) {
            fields.UInt("completed_api_call", value64_a);
        }
        if (ReadField(payload, payload_bytes, 8, value32_a)) {
            fields.Int("completed_callback_id",
                       static_cast<int32_t>(value32_a));
        }
        if (ReadField(payload, payload_bytes, 12, value32_b)) {
            fields.UInt("completed_parameter_bytes", value32_b);
        }
        break;
    case 1101:
        if (ReadField(payload, payload_bytes, 0, value64_a)) {
            fields.UInt("game_id", value64_a);
        }
        if (ReadField(payload, payload_bytes, 8, value32_a)) {
            fields.Int("result", static_cast<int32_t>(value32_a));
        }
        if (ReadField(payload, payload_bytes, 16, value64_b)) {
            fields.UInt("user_steam_id", value64_b);
        }
        break;
    case 1103:
        if (ReadField(payload, payload_bytes, 0, value64_a)) {
            fields.UInt("game_id", value64_a);
        }
        if (ReadField(payload, payload_bytes, 8, value8)) {
            fields.Bool("group_achievement", value8 != 0);
        }
        if (ReadField(payload, payload_bytes, 140, value32_a)) {
            fields.UInt("current_progress", value32_a);
        }
        if (ReadField(payload, payload_bytes, 144, value32_b)) {
            fields.UInt("maximum_progress", value32_b);
        }
        break;
    case 1202:
        if (ReadField(payload, payload_bytes, 0, value64_a)) {
            fields.UInt("remote_steam_id", value64_a);
        }
        break;
    case 1203:
        if (ReadField(payload, payload_bytes, 0, value64_a)) {
            fields.UInt("remote_steam_id", value64_a);
        }
        if (ReadField(payload, payload_bytes, 8, value8)) {
            fields.UInt("p2p_session_error", value8);
        }
        break;
    default:
        break;
    }
}

void LogDispatch(int callback_id, unsigned callback_bytes, void* callback,
                 const void* payload, bool call_result, bool io_failure,
                 SteamApiCall api_call, bool synthetic) {
    capture::Fields fields;
    fields.Int("callback_id", callback_id)
        .String("callback_name", CallbackName(callback_id))
        .String("invocation", call_result ? "call_result" : "callback")
        .UInt("callback_bytes", callback_bytes)
        .Bool("io_failure", io_failure)
        .UInt("api_call", api_call)
        .Bool("synthetic", synthetic)
        .String("object", capture::HexPointer(callback));
    AddKnownFields(callback_id, payload, callback_bytes, fields);
    EDF5_CAPTURE_EVENT(capture::Level::Info, "edf41_steam_callback",
                       "dispatch", fields, payload, callback_bytes);
}

void HookedRunCallback(void* callback, void* payload) {
    RunCallbackFn original = nullptr;
    int callback_id = 0;
    unsigned callback_bytes = 0;
    AcquireSRWLockShared(&g_callback_lock);
    const auto found = g_callbacks.find(callback);
    if (found != g_callbacks.end()) {
        CallbackRecord& record = *found->second;
        // CCallbackBase's two Run overloads are emitted in this order by the
        // Steamworks ABI used by EDF 4.1:
        //   [0] Run(payload, io_failure, api_call)
        //   [1] Run(payload)
        // Keep the shadow slot and the original slot paired exactly. Calling
        // slot 0 with slot 1's signature corrupts SteamAPICallCompleted and can
        // leave the lobby browser permanently refreshing.
        original = reinterpret_cast<RunCallbackFn>(record.original_vtable[1]);
        callback_id = record.callback_id;
        callback_bytes = record.callback_bytes;
    }
    ReleaseSRWLockShared(&g_callback_lock);

    room_bots::ObserveSteamCallback(callback_id, payload, callback_bytes,
                                    false, false);
    LogDispatch(callback_id, callback_bytes, callback, payload, false, false,
                0, false);
    if (original) original(callback, payload);
}

void HookedRunCallResult(void* callback, void* payload, bool io_failure,
                         SteamApiCall api_call) {
    RunCallResultFn original = nullptr;
    int callback_id = 0;
    unsigned callback_bytes = 0;
    AcquireSRWLockShared(&g_callback_lock);
    const auto found = g_callbacks.find(callback);
    if (found != g_callbacks.end()) {
        CallbackRecord& record = *found->second;
        original =
            reinterpret_cast<RunCallResultFn>(record.original_vtable[0]);
        callback_id = record.callback_id;
        callback_bytes = record.callback_bytes;
    }
    ReleaseSRWLockShared(&g_callback_lock);

    room_bots::ObserveSteamCallback(callback_id, payload, callback_bytes,
                                    true, io_failure);
    LogDispatch(callback_id, callback_bytes, callback, payload, true,
                io_failure, api_call, false);
    if (original) original(callback, payload, io_failure, api_call);
}

unsigned ReadCallbackSize(void* callback, void** vtable) {
    const auto get_size = reinterpret_cast<GetCallbackSizeFn>(vtable[2]);
    if (!get_size) return 0;
    const int bytes = get_size(callback);
    if (bytes <= 0 || static_cast<unsigned>(bytes) > kMaximumCallbackBytes) {
        return 0;
    }
    return static_cast<unsigned>(bytes);
}

}  // namespace

bool ObserveRegistration(void* callback, int callback_id,
                         RegistrationKind kind) {
    if (!callback) return false;

    bool installed = false;
    bool reused = false;
    unsigned callback_bytes = 0;
    AcquireSRWLockExclusive(&g_callback_lock);
    auto found = g_callbacks.find(callback);
    if (found != g_callbacks.end() &&
        *reinterpret_cast<void***>(callback) ==
            found->second->shadow_vtable) {
        CallbackRecord& record = *found->second;
        record.callback_id = callback_id;
        record.callback_registered = record.callback_registered ||
            kind == RegistrationKind::Callback;
        record.call_result_registered = record.call_result_registered ||
            kind == RegistrationKind::CallResult;
        callback_bytes = record.callback_bytes;
        installed = true;
        reused = true;
    } else {
        if (found != g_callbacks.end()) g_callbacks.erase(found);
        void** original_vtable = *reinterpret_cast<void***>(callback);
        if (original_vtable && original_vtable[0] && original_vtable[1] &&
            original_vtable[2]) {
            auto record = std::make_unique<CallbackRecord>();
            record->original_vtable = original_vtable;
            record->shadow_vtable[0] =
                reinterpret_cast<void*>(&HookedRunCallResult);
            record->shadow_vtable[1] =
                reinterpret_cast<void*>(&HookedRunCallback);
            record->shadow_vtable[2] = original_vtable[2];
            record->callback_id = callback_id;
            record->callback_bytes = ReadCallbackSize(callback, original_vtable);
            record->callback_registered =
                kind == RegistrationKind::Callback;
            record->call_result_registered =
                kind == RegistrationKind::CallResult;
            callback_bytes = record->callback_bytes;
            CallbackRecord* raw_record = record.get();
            g_callbacks.emplace(callback, std::move(record));
            void* const previous = InterlockedCompareExchangePointer(
                reinterpret_cast<PVOID volatile*>(callback),
                raw_record->shadow_vtable, original_vtable);
            installed = previous == original_vtable;
            if (!installed) g_callbacks.erase(callback);
        }
    }
    ReleaseSRWLockExclusive(&g_callback_lock);

    EDF5_CAPTURE_EVENT(
        installed ? capture::Level::Info : capture::Level::Warning,
        "edf41_steam_callback", "dispatch_hook",
        capture::Fields().Int("callback_id", callback_id)
            .String("callback_name", CallbackName(callback_id))
            .String("registration",
                    kind == RegistrationKind::CallResult ? "call_result"
                                                         : "callback")
            .UInt("callback_bytes", callback_bytes)
            .Bool("reused", reused)
            .Bool("installed", installed)
            .String("object", capture::HexPointer(callback)));
    return installed;
}

void ForgetRegistration(void* callback, RegistrationKind kind) {
    if (!callback) return;
    bool found_record = false;
    bool restored = false;
    bool retained = false;
    int callback_id = 0;

    AcquireSRWLockExclusive(&g_callback_lock);
    const auto found = g_callbacks.find(callback);
    if (found != g_callbacks.end()) {
        found_record = true;
        CallbackRecord& record = *found->second;
        callback_id = record.callback_id;
        if (kind == RegistrationKind::Callback) {
            record.callback_registered = false;
        } else {
            record.call_result_registered = false;
        }
        retained = record.callback_registered || record.call_result_registered;
        if (!retained) {
            void* const previous = InterlockedCompareExchangePointer(
                reinterpret_cast<PVOID volatile*>(callback),
                record.original_vtable, record.shadow_vtable);
            restored = previous == record.shadow_vtable;
            g_callbacks.erase(found);
        }
    }
    ReleaseSRWLockExclusive(&g_callback_lock);

    EDF5_CAPTURE_EVENT(
        capture::Level::Info, "edf41_steam_callback", "dispatch_unhook",
        capture::Fields().Int("callback_id", callback_id)
            .String("registration",
                    kind == RegistrationKind::CallResult ? "call_result"
                                                         : "callback")
            .Bool("record_found", found_record)
            .Bool("retained", retained)
            .Bool("restored", restored)
            .String("object", capture::HexPointer(callback)));
}

unsigned DispatchSyntheticCallback(int callback_id, const void* payload,
                                   unsigned payload_bytes) {
    if (!payload || !payload_bytes) return 0;
    std::vector<void*> callbacks;
    AcquireSRWLockShared(&g_callback_lock);
    for (const auto& item : g_callbacks) {
        const CallbackRecord& record = *item.second;
        if (record.callback_registered && record.callback_id == callback_id &&
            record.callback_bytes == payload_bytes) {
            callbacks.push_back(item.first);
        }
    }
    ReleaseSRWLockShared(&g_callback_lock);

    unsigned dispatched = 0;
    for (void* callback : callbacks) {
        RunCallbackFn original = nullptr;
        AcquireSRWLockShared(&g_callback_lock);
        const auto found = g_callbacks.find(callback);
        if (found != g_callbacks.end() &&
            found->second->callback_registered &&
            found->second->callback_id == callback_id &&
            found->second->callback_bytes == payload_bytes) {
            original = reinterpret_cast<RunCallbackFn>(
                found->second->original_vtable[1]);
        }
        ReleaseSRWLockShared(&g_callback_lock);
        if (!original) continue;
        LogDispatch(callback_id, payload_bytes, callback, payload, false,
                    false, 0, true);
        original(callback, const_cast<void*>(payload));
        ++dispatched;
    }
    return dispatched;
}

}  // namespace edf41::sniffer::callback_dispatch
