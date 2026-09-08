#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cstring>

union PluginVersion {
    struct { uint16_t build, patch, minor, major; } parts;
    uint64_t raw;
};

struct PluginInfo {
    uint32_t infoVersion;
    const char* name;
    PluginVersion version;
};

using LoadFn = bool (__fastcall*)(PluginInfo*);
using VoidFn = void (*)();
using BoolFn = bool (*)();
using UIntFn = unsigned (*)();
using AccessorFn = void* (*)();
using GetIntFn = int (*)();
using GetStringFn = const char* (*)();
using CreateLobbyFn = uint64_t (*)(void*, int, int);
using MemberCountFn = int (*)(void*, uint64_t);
using MemberByIndexFn = uint64_t* (*)(void*, uint64_t*, uint64_t, int);
using GetMemberDataFn = const char* (*)(void*, uint64_t, uint64_t,
                                        const char*);
using FriendNameFn = const char* (*)(void*, uint64_t);
using SendP2PFn = bool (*)(void*, uint64_t, const void*, uint32_t, int, int);
using IsP2PAvailableFn = bool (*)(void*, uint32_t*, int);
using ReadP2PFn = bool (*)(void*, void*, uint32_t, uint32_t*, uint64_t*, int);
using BeginAuthFn = int (*)(void*, const void*, int, uint64_t);
using EndAuthFn = void (*)(void*, uint64_t);
using GetAuthTicketFn = uint32_t (*)(void*, void*, int, uint32_t*);
using CancelAuthTicketFn = void (*)(void*, uint32_t);
using ActivateInviteDialogFn = void (*)(void*, uint64_t);
using RegisterCallbackFn = void (*)(void*, int);
using UnregisterCallbackFn = void (*)(void*);
using CallResultFn = void (*)(void*, uint64_t);
using RunCallbackFn = void (*)(void*, void*);
using RunCallResultFn = void (*)(void*, void*, bool, uint64_t);

struct CallbackProbe {
    void** vtable;
    uint8_t flags;
    uint8_t padding[3];
    int callback_id;
    int callback_bytes;
};

volatile long g_callback_run_count = 0;
volatile long g_call_result_run_count = 0;
volatile long g_call_result_io_failure = -1;
volatile uint64_t g_call_result_api_call = 0;
volatile uint64_t g_last_callback_lobby = 0;
volatile uint64_t g_last_callback_user = 0;
volatile uint32_t g_last_callback_state = 0;
volatile int32_t g_last_auth_response = -1;

__declspec(noinline) void CallbackRun(void* object, void* payload) {
    const auto* probe = static_cast<const CallbackProbe*>(object);
    if (probe && payload && probe->callback_id == 506) {
        std::memcpy(const_cast<uint64_t*>(&g_last_callback_lobby), payload, 8);
        std::memcpy(const_cast<uint64_t*>(&g_last_callback_user),
                    static_cast<const uint8_t*>(payload) + 8, 8);
        std::memcpy(const_cast<uint32_t*>(&g_last_callback_state),
                    static_cast<const uint8_t*>(payload) + 24, 4);
    } else if (probe && payload && probe->callback_id == 143) {
        std::memcpy(const_cast<uint64_t*>(&g_last_callback_user), payload, 8);
        std::memcpy(const_cast<int32_t*>(&g_last_auth_response),
                    static_cast<const uint8_t*>(payload) + 8, 4);
    }
    InterlockedIncrement(&g_callback_run_count);
}

__declspec(noinline) void CallbackRunCallResult(void*, void*, bool io_failure,
                                                uint64_t api_call) {
    g_call_result_io_failure = io_failure ? 1 : 0;
    g_call_result_api_call = api_call;
    InterlockedIncrement(&g_call_result_run_count);
}

__declspec(noinline) int CallbackSize(void* object) {
    return static_cast<CallbackProbe*>(object)->callback_bytes;
}

template <typename T>
T Export(HMODULE module, const char* name) {
    return reinterpret_cast<T>(GetProcAddress(module, name));
}

int Fail(const char* message) {
    std::fprintf(stderr, "edf41_integration_failure=%s\n", message);
    return 10;
}

int wmain(int argc, wchar_t** argv) {
    if (argc != 3) {
        std::fprintf(
            stderr,
            "usage: edf41_steam_harness.exe <plugin.dll> <steam_api64.dll>\n");
        return 2;
    }

    HMODULE fake = LoadLibraryW(argv[2]);
    if (!fake) return Fail("LoadLibrary fake steam_api64");
    HMODULE plugin = LoadLibraryW(argv[1]);
    if (!plugin) return Fail("LoadLibrary plugin");

    const auto load = Export<LoadFn>(plugin, "EML4_Load");
    const auto init = Export<BoolFn>(fake, "SteamAPI_Init");
    const auto shutdown = Export<VoidFn>(fake, "SteamAPI_Shutdown");
    const auto run_callbacks =
        Export<VoidFn>(fake, "SteamAPI_RunCallbacks");
    const auto friends_accessor = Export<AccessorFn>(fake, "SteamFriends");
    const auto matchmaking_accessor =
        Export<AccessorFn>(fake, "SteamMatchmaking");
    const auto networking_accessor =
        Export<AccessorFn>(fake, "SteamNetworking");
    const auto user_accessor = Export<AccessorFn>(fake, "SteamUser");
    const auto register_callback =
        Export<RegisterCallbackFn>(fake, "SteamAPI_RegisterCallback");
    const auto unregister_callback =
        Export<UnregisterCallbackFn>(fake, "SteamAPI_UnregisterCallback");
    const auto register_call_result =
        Export<CallResultFn>(fake, "SteamAPI_RegisterCallResult");
    const auto unregister_call_result =
        Export<CallResultFn>(fake, "SteamAPI_UnregisterCallResult");
    const auto get_create_limit =
        Export<GetIntFn>(fake, "FakeSteam_GetLastCreateLimit");
    const auto get_send_count =
        Export<GetIntFn>(fake, "FakeSteam_GetOriginalSendCount");
    const auto get_begin_auth_count =
        Export<GetIntFn>(fake, "FakeSteam_GetOriginalBeginAuthCount");
    const auto get_end_auth_count =
        Export<GetIntFn>(fake, "FakeSteam_GetOriginalEndAuthCount");
    const auto get_auth_ticket_count =
        Export<GetIntFn>(fake, "FakeSteam_GetOriginalGetAuthTicketCount");
    const auto get_cancel_auth_ticket_count =
        Export<GetIntFn>(fake, "FakeSteam_GetOriginalCancelAuthTicketCount");
    const auto get_invite_lobby =
        Export<uint64_t (*)()>(fake, "FakeSteam_GetLastInviteDialogLobby");
    const auto set_actual_members =
        Export<void (*)(int)>(fake, "FakeSteam_SetActualMembers");
    const auto set_local_member_data =
        Export<void (*)(const char*)>(fake,
                                     "FakeSteam_SetLocalMemberData");
    const auto add_room_bot = Export<BoolFn>(plugin, "EDF41MP_AddRoomBot");
    const auto remove_room_bot =
        Export<BoolFn>(plugin, "EDF41MP_RemoveRoomBot");
    const auto room_bot_count =
        Export<UIntFn>(plugin, "EDF41MP_RoomBotCount");
    if (!load || !init || !shutdown || !friends_accessor ||
        !matchmaking_accessor || !networking_accessor || !user_accessor ||
        !register_callback || !unregister_callback ||
        !register_call_result || !unregister_call_result ||
        !get_create_limit || !get_send_count || !get_begin_auth_count ||
        !get_end_auth_count || !get_auth_ticket_count ||
        !get_cancel_auth_ticket_count || !get_invite_lobby ||
        !run_callbacks || !set_actual_members || !set_local_member_data ||
        !add_room_bot ||
        !remove_room_bot || !room_bot_count) {
        return Fail("required exports");
    }

    PluginInfo info{};
    if (!load(&info)) return Fail("EML4_Load");
    if (!info.name || std::strstr(info.name, "EDF41") == nullptr) {
        return Fail("EDF 4.1 plugin identity");
    }
    if (!init()) return Fail("hooked SteamAPI_Init");

    void* callback_vtable[] = {
        reinterpret_cast<void*>(&CallbackRunCallResult),
        reinterpret_cast<void*>(&CallbackRun),
        reinterpret_cast<void*>(&CallbackSize),
    };
    CallbackProbe callback{
        callback_vtable, 0, {0, 0, 0}, 506, 32,
    };
    register_callback(&callback, callback.callback_id);
    uint8_t chat_update[32]{};
    const uint64_t callback_lobby = 109775241799999998ULL;
    const uint64_t callback_user = 76561198000000001ULL;
    const uint32_t entered = 1;
    std::memcpy(chat_update, &callback_lobby, sizeof(callback_lobby));
    std::memcpy(chat_update + 8, &callback_user, sizeof(callback_user));
    std::memcpy(chat_update + 16, &callback_user, sizeof(callback_user));
    std::memcpy(chat_update + 24, &entered, sizeof(entered));
    reinterpret_cast<RunCallbackFn>(callback.vtable[1])(
        &callback, chat_update);
    unregister_callback(&callback);
    if (callback.vtable != callback_vtable || g_callback_run_count != 1) {
        return Fail("persistent callback dispatch passthrough");
    }

    callback.callback_id = 143;
    callback.callback_bytes = 20;
    register_callback(&callback, callback.callback_id);
    uint8_t auth_validation[20]{};
    const uint64_t validated_user = 76561198000000002ULL;
    const int32_t auth_response_ok = 0;
    const uint64_t ticket_owner = 76561198000000003ULL;
    std::memcpy(auth_validation, &validated_user, sizeof(validated_user));
    std::memcpy(auth_validation + 8, &auth_response_ok,
                sizeof(auth_response_ok));
    std::memcpy(auth_validation + 12, &ticket_owner,
                sizeof(ticket_owner));
    reinterpret_cast<RunCallbackFn>(callback.vtable[1])(
        &callback, auth_validation);
    unregister_callback(&callback);
    if (callback.vtable != callback_vtable || g_callback_run_count != 2) {
        return Fail("auth-validation callback dispatch passthrough");
    }

    void* call_result_vtable[] = {
        reinterpret_cast<void*>(&CallbackRunCallResult),
        reinterpret_cast<void*>(&CallbackRun),
        reinterpret_cast<void*>(&CallbackSize),
    };
    CallbackProbe call_result{
        call_result_vtable, 0, {0, 0, 0}, 513, 16,
    };
    constexpr uint64_t kCallbackApiCall = 0x1122334455667788ULL;
    register_call_result(&call_result, kCallbackApiCall);
    uint8_t lobby_created[16]{};
    const int32_t create_result = 1;
    std::memcpy(lobby_created, &create_result, sizeof(create_result));
    std::memcpy(lobby_created + 8, &callback_lobby,
                sizeof(callback_lobby));
    reinterpret_cast<RunCallResultFn>(call_result.vtable[0])(
        &call_result, lobby_created, false, kCallbackApiCall);
    unregister_call_result(&call_result, kCallbackApiCall);
    if (call_result.vtable != call_result_vtable ||
        g_call_result_run_count != 1 || g_call_result_io_failure != 0 ||
        g_call_result_api_call != kCallbackApiCall) {
        return Fail("call-result dispatch passthrough");
    }

    void* friends = friends_accessor();
    void* matchmaking = matchmaking_accessor();
    void* networking = networking_accessor();
    void* user = user_accessor();
    if (!friends || !matchmaking || !networking || !user) {
        return Fail("legacy direct accessors");
    }

    auto friends_vtable = *reinterpret_cast<void***>(friends);
    auto matchmaking_vtable = *reinterpret_cast<void***>(matchmaking);
    auto networking_vtable = *reinterpret_cast<void***>(networking);
    auto user_vtable = *reinterpret_cast<void***>(user);
    const auto friend_name =
        reinterpret_cast<FriendNameFn>(friends_vtable[7]);
    const auto invite_dialog =
        reinterpret_cast<ActivateInviteDialogFn>(friends_vtable[33]);
    const auto create_lobby =
        reinterpret_cast<CreateLobbyFn>(matchmaking_vtable[13]);
    const auto member_count =
        reinterpret_cast<MemberCountFn>(matchmaking_vtable[17]);
    const auto member_by_index =
        reinterpret_cast<MemberByIndexFn>(matchmaking_vtable[18]);
    const auto get_member_data =
        reinterpret_cast<GetMemberDataFn>(matchmaking_vtable[24]);
    const auto send_p2p =
        reinterpret_cast<SendP2PFn>(networking_vtable[0]);
    const auto p2p_available =
        reinterpret_cast<IsP2PAvailableFn>(networking_vtable[1]);
    const auto read_p2p =
        reinterpret_cast<ReadP2PFn>(networking_vtable[2]);
    const auto begin_auth = reinterpret_cast<BeginAuthFn>(user_vtable[14]);
    const auto end_auth = reinterpret_cast<EndAuthFn>(user_vtable[15]);
    const auto get_auth_ticket =
        reinterpret_cast<GetAuthTicketFn>(user_vtable[13]);
    const auto cancel_auth_ticket =
        reinterpret_cast<CancelAuthTicketFn>(user_vtable[16]);

    constexpr uint64_t kRemote = 76561198000000002ULL;
    const char packet[] = "edf41-passive-probe";
    if (std::strcmp(friend_name(friends, kRemote), "fake-original-name") != 0) {
        return Fail("Friends015 passthrough");
    }
    invite_dialog(friends, callback_lobby);
    if (get_invite_lobby() != callback_lobby) {
        return Fail("Friends015 invite dialog passthrough");
    }
    if (!create_lobby(matchmaking, 2, 4) || get_create_limit() != 4) {
        return Fail("EDF 4.1 phase-one lobby limit changed");
    }

    // Complete the locally-created lobby after CreateLobby has armed the
    // room-bot policy. This must still leave Steam's native limit at four.
    CallbackProbe owned_lobby_result{
        call_result_vtable, 0, {0, 0, 0}, 513, 16,
    };
    register_call_result(&owned_lobby_result, kCallbackApiCall);
    reinterpret_cast<RunCallResultFn>(owned_lobby_result.vtable[0])(
        &owned_lobby_result, lobby_created, false, kCallbackApiCall);
    unregister_call_result(&owned_lobby_result, kCallbackApiCall);

    CallbackProbe room_callback{
        callback_vtable, 0, {0, 0, 0}, 506, 32,
    };
    CallbackProbe room_auth_callback{
        callback_vtable, 0, {0, 0, 0}, 143, 20,
    };
    register_callback(&room_callback, room_callback.callback_id);
    register_callback(&room_auth_callback, room_auth_callback.callback_id);
    set_actual_members(1);
    set_local_member_data("edf41-local-room-template");
    for (unsigned expected = 1; expected <= 7; ++expected) {
        if (!add_room_bot()) return Fail("queue room-list probe bot");
        run_callbacks();
        if (room_bot_count() != expected ||
            member_count(matchmaking, callback_lobby) !=
                static_cast<int>(expected + 1) ||
            g_last_callback_lobby != callback_lobby ||
            g_last_callback_state != 1) {
            return Fail("room-list probe bot entry");
        }
    }
    if (!add_room_bot()) return Fail("queue room-full rejection");
    run_callbacks();
    if (room_bot_count() != 7 ||
        member_count(matchmaking, callback_lobby) != 8) {
        return Fail("expanded room-list limit");
    }

    uint64_t first_bot = 0;
    if (member_by_index(matchmaking, &first_bot, callback_lobby, 1) !=
            &first_bot ||
        !first_bot ||
        std::strcmp(friend_name(friends, first_bot), "EDF41 Bot 1") != 0) {
        return Fail("synthetic room member identity");
    }
    char bot_member_key[64]{};
    std::snprintf(bot_member_key, sizeof(bot_member_key), "usr%llu",
                  static_cast<unsigned long long>(first_bot));
    const char* bot_member_data = get_member_data(
        matchmaking, callback_lobby, first_bot, bot_member_key);
    if (!bot_member_data ||
        std::strcmp(bot_member_data, "edf41-local-room-template") != 0) {
        return Fail("synthetic member data projection");
    }
    // EDF 4.1 exchanges auth tickets over channel 2. The phase-one bot echoes
    // that opaque ticket locally, bypasses Steam validation only for its
    // private identity, then dispatches the normal success callback.
    const char bot_ticket[] = "edf41-room-bot-ticket";
    const int sends_before_bot = get_send_count();
    if (!send_p2p(networking, first_bot, bot_ticket,
                  static_cast<uint32_t>(sizeof(bot_ticket)), 2, 2) ||
        get_send_count() != sends_before_bot) {
        return Fail("synthetic channel-2 send isolation");
    }
    uint32_t available_bytes = 0;
    if (!p2p_available(networking, &available_bytes, 2) ||
        available_bytes != sizeof(bot_ticket)) {
        return Fail("synthetic channel-2 availability");
    }
    char echoed_ticket[64]{};
    uint32_t echoed_bytes = 0;
    uint64_t echoed_peer = 0;
    if (!read_p2p(networking, echoed_ticket, sizeof(echoed_ticket),
                  &echoed_bytes, &echoed_peer, 2) ||
        echoed_peer != first_bot || echoed_bytes != sizeof(bot_ticket) ||
        std::memcmp(echoed_ticket, bot_ticket, sizeof(bot_ticket)) != 0) {
        return Fail("synthetic channel-2 ticket echo");
    }
    const int auth_before_bot = get_begin_auth_count();
    if (begin_auth(user, echoed_ticket, static_cast<int>(echoed_bytes),
                   first_bot) != 0 ||
        get_begin_auth_count() != auth_before_bot) {
        return Fail("synthetic auth isolation");
    }
    run_callbacks();
    if (g_last_callback_user != first_bot || g_last_auth_response != 0) {
        return Fail("synthetic auth callback");
    }

    // A real player always wins a room-list slot. Dropping from seven to six
    // fillers keeps the expanded roster total at eight.
    set_actual_members(2);
    if (member_count(matchmaking, callback_lobby) != 8) {
        return Fail("real member eviction count");
    }
    run_callbacks();
    if (room_bot_count() != 6 || g_last_callback_state != 2) {
        return Fail("real member evicted newest bot");
    }
    if (!remove_room_bot()) return Fail("queue room bot removal");
    run_callbacks();
    if (room_bot_count() != 5 ||
        member_count(matchmaking, callback_lobby) != 7 ||
        g_last_callback_state != 2) {
        return Fail("room bot removal");
    }
    unregister_callback(&room_auth_callback);
    unregister_callback(&room_callback);
    if (!send_p2p(networking, kRemote, packet,
                  static_cast<uint32_t>(sizeof(packet)), 2, 0) ||
        get_send_count() != 1) {
        return Fail("Networking005 passthrough");
    }
    if (begin_auth(user, packet, static_cast<int>(sizeof(packet)), kRemote) != 8 ||
        get_begin_auth_count() != 1) {
        return Fail("SteamUser018 BeginAuthSession passthrough");
    }
    char auth_ticket[64]{};
    uint32_t auth_ticket_bytes = 0;
    const uint32_t auth_ticket_handle = get_auth_ticket(
        user, auth_ticket, static_cast<int>(sizeof(auth_ticket)),
        &auth_ticket_bytes);
    if (auth_ticket_handle != 77 || !auth_ticket_bytes ||
        get_auth_ticket_count() != 1) {
        return Fail("SteamUser018 GetAuthSessionTicket passthrough");
    }
    cancel_auth_ticket(user, auth_ticket_handle);
    if (get_cancel_auth_ticket_count() != 1) {
        return Fail("SteamUser018 CancelAuthTicket passthrough");
    }
    end_auth(user, kRemote);
    if (get_end_auth_count() != 1) {
        return Fail("SteamUser018 EndAuthSession passthrough");
    }

    shutdown();
    std::printf(
        "edf41_steam_integration=pass accessors=4 create_limit=%d "
        "send_count=%d auth_begin=%d auth_end=%d auth_ticket=%d/%d "
        "callback_dispatch=%ld room_bots=pass final_count=%u "
        "native_safe_limit=4 room_limit=8 native_roster_expansion=pass\n",
        get_create_limit(), get_send_count(), get_begin_auth_count(),
        get_end_auth_count(), get_auth_ticket_count(),
        get_cancel_auth_ticket_count(),
        g_callback_run_count + g_call_result_run_count, room_bot_count());
    return 0;
}
