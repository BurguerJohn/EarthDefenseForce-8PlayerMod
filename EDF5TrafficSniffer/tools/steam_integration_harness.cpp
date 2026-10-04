#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <steam/steamclientpublic.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iterator>
#include <string>
#include <vector>

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
using BotActionFn = bool (__fastcall*)();
using ContextInitFn = void* (*)(void*);
using VoidFn = void (*)();
using RegisterFn = void (*)(void*, int);
using UnregisterFn = void (*)(void*);
using SetIntFn = void (*)(int);
using GetIntFn = int (*)();
using GetUInt64Fn = uint64_t (*)();
using GetStringFn = const char* (*)();
using SteamId = uint64_t;

#pragma pack(push, 8)
struct LobbyChatUpdate {
    uint64_t lobby;
    uint64_t user_changed;
    uint64_t making_change;
    uint32_t state_change;
};

struct ValidateAuthTicketResponse {
    uint64_t user;
    int32_t response;
    uint32_t padding;
    uint64_t owner;
};

struct P2PSessionState {
    uint8_t connection_active;
    uint8_t connecting;
    uint8_t session_error;
    uint8_t using_relay;
    int32_t bytes_queued_for_send;
    int32_t packets_queued_for_send;
    uint32_t remote_ip;
    uint16_t remote_port;
};
#pragma pack(pop)

struct CallbackProbe {
    void** vtable;
    uint8_t flags;
    uint8_t padding[3];
    int callback_id;
    int runs;
    uint32_t state_or_response;
    uint64_t lobby_or_user;
    uint64_t changed_user;
};
static_assert(offsetof(CallbackProbe, callback_id) == 12,
              "CCallbackBase layout mismatch");

void CallbackRun(void* object, void* parameter) {
    auto* probe = static_cast<CallbackProbe*>(object);
    ++probe->runs;
    if (probe->callback_id == 506) {
        const auto* update = static_cast<const LobbyChatUpdate*>(parameter);
        probe->state_or_response = update->state_change;
        probe->lobby_or_user = update->lobby;
        probe->changed_user = update->user_changed;
    } else if (probe->callback_id == 143) {
        const auto* update = static_cast<const ValidateAuthTicketResponse*>(parameter);
        probe->state_or_response = static_cast<uint32_t>(update->response);
        probe->lobby_or_user = update->user;
        probe->changed_user = update->owner;
    }
}

template <typename T>
T Export(HMODULE module, const char* name) {
    return reinterpret_cast<T>(GetProcAddress(module, name));
}

int Fail(const char* message) {
    std::fprintf(stderr, "integration_failure=%s\n", message);
    return 10;
}

int wmain(int argc, wchar_t** argv) {
    if (argc != 3) {
        std::fwprintf(stderr, L"usage: steam_integration_harness.exe <plugin.dll> <steam_api64.dll>\n");
        return 2;
    }
    HMODULE fake = LoadLibraryW(argv[2]);
    if (!fake) return Fail("LoadLibrary fake steam_api64");
    HMODULE plugin = LoadLibraryW(argv[1]);
    if (!plugin) return Fail("LoadLibrary plugin");
    const auto load = Export<LoadFn>(plugin, "EML5_Load");
    const auto add_bot = Export<BotActionFn>(plugin, "EDF5MP_AddBot");
    const auto remove_bot = Export<BotActionFn>(plugin, "EDF5MP_RemoveBot");
    const auto ready_bots = Export<BotActionFn>(plugin, "EDF5MP_ReadyBots");
    const auto open_invite = Export<BotActionFn>(
        plugin, "EDF5MP_OpenInviteDialog");
    if (!load || !add_bot || !remove_bot || !ready_bots || !open_invite) {
        return Fail("plugin exports");
    }
    PluginInfo info{};
    if (!load(&info)) return Fail("EML5_Load");

    const auto context_init = Export<ContextInitFn>(fake, "SteamInternal_ContextInit");
    const auto run_callbacks = Export<VoidFn>(fake, "SteamAPI_RunCallbacks");
    const auto shutdown = Export<VoidFn>(fake, "SteamAPI_Shutdown");
    const auto register_callback = Export<RegisterFn>(fake, "SteamAPI_RegisterCallback");
    const auto unregister_callback = Export<UnregisterFn>(fake, "SteamAPI_UnregisterCallback");
    const auto set_actual_members = Export<SetIntFn>(fake, "FakeSteam_SetActualMembers");
    const auto get_create_limit = Export<GetIntFn>(fake, "FakeSteam_GetLastCreateLimit");
    const auto get_member_limit = Export<GetIntFn>(fake, "FakeSteam_GetLastMemberLimit");
    const auto get_public_slot = Export<GetStringFn>(fake, "FakeSteam_GetPublicSlot");
    const auto get_open_public = Export<GetStringFn>(fake, "FakeSteam_GetOpenPublic");
    const auto get_private_slot =
        Export<GetStringFn>(fake, "FakeSteam_GetPrivateSlot");
    const auto get_send_count = Export<GetIntFn>(fake, "FakeSteam_GetOriginalSendCount");
    const auto get_auth_count = Export<GetIntFn>(fake, "FakeSteam_GetOriginalBeginAuthCount");
    const auto get_invite_lobby = Export<GetUInt64Fn>(
        fake, "FakeSteam_GetLastInviteDialogLobby");
    if (!context_init || !run_callbacks || !shutdown || !register_callback ||
        !unregister_callback || !set_actual_members || !get_create_limit ||
        !get_member_limit || !get_public_slot || !get_open_public ||
        !get_private_slot ||
        !get_send_count || !get_auth_count || !get_invite_lobby) {
        return Fail("fake steam exports");
    }

    auto** context = static_cast<void**>(context_init(nullptr));
    if (!context || !context[1] || !context[2] || !context[4] || !context[8]) {
        return Fail("hooked Steam context");
    }
    void* user = context[1];
    void* friends = context[2];
    void* matchmaking = context[4];
    void* networking = context[8];
    auto user_vtable = *reinterpret_cast<void***>(user);
    auto friends_vtable = *reinterpret_cast<void***>(friends);
    auto match_vtable = *reinterpret_cast<void***>(matchmaking);
    auto network_vtable = *reinterpret_cast<void***>(networking);

    using CreateLobbyFn = uint64_t (*)(void*, int, int);
    using SetDataFn = bool (*)(void*, SteamId, const char*, const char*);
    using SetMemberDataFn = void (*)(void*, SteamId, const char*, const char*);
    using MemberCountFn = int (*)(void*, SteamId);
    using IdResultFn = SteamId* (*)(void*, SteamId*, int);
    using MemberByIndexFn = SteamId* (*)(void*, SteamId*, SteamId, int);
    using GetOwnerFn = SteamId* (*)(void*, SteamId*, SteamId);
    using GetMemberDataFn = const char* (*)(void*, SteamId, SteamId, const char*);
    using SetLimitFn = bool (*)(void*, SteamId, int);
    using FriendNameFn = const char* (*)(void*, SteamId);
    using SendP2PFn = bool (*)(void*, SteamId, const void*, uint32_t, int, int);
    using AvailableFn = bool (*)(void*, uint32_t*, int);
    using ReadP2PFn = bool (*)(void*, void*, uint32_t, uint32_t*, SteamId*, int);
    using PeerFn = bool (*)(void*, SteamId);
    using SessionStateFn = bool (*)(void*, SteamId, P2PSessionState*);
    using BeginAuthFn = int (*)(void*, const void*, int, SteamId);

    const auto lobby_by_index = reinterpret_cast<IdResultFn>(match_vtable[12]);
    const auto create_lobby = reinterpret_cast<CreateLobbyFn>(match_vtable[13]);
    const auto set_data = reinterpret_cast<SetDataFn>(match_vtable[20]);
    const auto set_member_data = reinterpret_cast<SetMemberDataFn>(match_vtable[25]);
    const auto member_count = reinterpret_cast<MemberCountFn>(match_vtable[17]);
    const auto member_by_index = reinterpret_cast<MemberByIndexFn>(match_vtable[18]);
    const auto get_member_data = reinterpret_cast<GetMemberDataFn>(match_vtable[24]);
    const auto set_limit = reinterpret_cast<SetLimitFn>(match_vtable[31]);
    const auto get_owner = reinterpret_cast<GetOwnerFn>(match_vtable[35]);
    const auto friend_name = reinterpret_cast<FriendNameFn>(friends_vtable[7]);
    const auto send_p2p = reinterpret_cast<SendP2PFn>(network_vtable[0]);
    const auto available = reinterpret_cast<AvailableFn>(network_vtable[1]);
    const auto read_p2p = reinterpret_cast<ReadP2PFn>(network_vtable[2]);
    const auto accept_peer = reinterpret_cast<PeerFn>(network_vtable[3]);
    const auto session_state = reinterpret_cast<SessionStateFn>(network_vtable[6]);
    const auto begin_auth = reinterpret_cast<BeginAuthFn>(user_vtable[14]);

    constexpr SteamId lobby = 109775241799999998ULL;
    constexpr SteamId local = 76561198000000001ULL;
    constexpr int kExpectedMaxPlayers = 8;
    constexpr SteamId bots[] = {
        76561202255233023ULL,
        76561202255233022ULL,
        76561202255233021ULL,
        76561202255233020ULL,
        76561202255233019ULL,
        76561202255233018ULL,
        76561202255233017ULL,
    };
    set_actual_members(1);
    SteamId returned_lobby = 0;
    SteamId returned_owner = 0;
    SteamId returned_member = 0;
    if (lobby_by_index(matchmaking, &returned_lobby, 0) != &returned_lobby ||
        returned_lobby != lobby ||
        get_owner(matchmaking, &returned_owner, lobby) != &returned_owner ||
        returned_owner != local ||
        member_by_index(matchmaking, &returned_member, lobby, 0) != &returned_member ||
        returned_member != local) {
        return Fail("MSVC CSteamID return-buffer ABI");
    }
    const uint64_t created_lobby_call = create_lobby(matchmaking, 2, 4);
    const int observed_create_limit = get_create_limit();
    if (created_lobby_call == 0 ||
        observed_create_limit != kExpectedMaxPlayers) {
        std::fprintf(stderr,
                     "create_call=0x%016llx observed_create_limit=%d\n",
                     static_cast<unsigned long long>(created_lobby_call),
                     observed_create_limit);
        return Fail("CreateLobby limit hook");
    }
    // Public room (four native public seats incl. host): the extra seats are
    // public and free public seats grow to MaxPlayers - members.
    const std::string expected_public_slot =
        std::to_string(kExpectedMaxPlayers);
    const std::string expected_open_public =
        std::to_string(kExpectedMaxPlayers - 1);
    if (!set_data(matchmaking, lobby, "public_slot", "4") ||
        std::strcmp(get_public_slot(), expected_public_slot.c_str()) != 0 ||
        !set_data(matchmaking, lobby, "open_public", "3") ||
        std::strcmp(get_open_public(), expected_open_public.c_str()) != 0) {
        std::fprintf(stderr, "public_slot=%s open_public=%s\n",
                     get_public_slot(), get_open_public());
        return Fail("lobby metadata rewrite");
    }
    // Friends-only room (host-only public seat): never advertises a free
    // public seat, even when a fifth member underflows the native count,
    // and the extra seats become friend seats.
    const std::string expected_private_slot =
        std::to_string(kExpectedMaxPlayers - 1);
    if (!set_data(matchmaking, lobby, "public_slot", "1") ||
        std::strcmp(get_public_slot(), "1") != 0 ||
        !set_data(matchmaking, lobby, "private_slot", "3") ||
        std::strcmp(get_private_slot(), expected_private_slot.c_str()) != 0 ||
        !set_data(matchmaking, lobby, "open_public", "-1") ||
        std::strcmp(get_open_public(), "0") != 0) {
        return Fail("friends-only lobby stayed public");
    }
    if (!set_limit(matchmaking, lobby, 4) ||
        get_member_limit() != kExpectedMaxPlayers) {
        return Fail("member limit hook");
    }
    if (!open_invite() || get_invite_lobby() != lobby) {
        return Fail("Steam lobby invite dialog");
    }
    set_member_data(matchmaking, lobby, "usr76561198000000001", "integration-member-data");

    void* callback_vtable[] = {reinterpret_cast<void*>(&CallbackRun)};
    CallbackProbe lobby_callback{callback_vtable, 0, {0, 0, 0}, 506, 0, 0, 0, 0};
    CallbackProbe auth_callback{callback_vtable, 0, {0, 0, 0}, 143, 0, 0, 0, 0};
    register_callback(&lobby_callback, 506);
    register_callback(&auth_callback, 143);

    for (unsigned i = 0; i < std::size(bots); ++i) {
        if (!add_bot()) return Fail("programmatic F8 add");
        run_callbacks();
        if (lobby_callback.runs != static_cast<int>(i + 1) ||
            lobby_callback.state_or_response != 1 ||
            lobby_callback.lobby_or_user != lobby ||
            lobby_callback.changed_user != bots[i]) {
            return Fail("LobbyChatUpdate entered callback");
        }
    }
    if (add_bot()) return Fail("extra filler exceeded room capacity");
    if (member_count(matchmaking, lobby) != kExpectedMaxPlayers) {
        return Fail("synthetic dynamic member count");
    }
    for (unsigned i = 0; i < std::size(bots); ++i) {
        SteamId synthetic_member = 0;
        if (member_by_index(matchmaking, &synthetic_member, lobby,
                            static_cast<int>(i + 1)) != &synthetic_member ||
            synthetic_member != bots[i]) {
            return Fail("synthetic member index/ABI");
        }
        const char* data = get_member_data(
            matchmaking, lobby, bots[i], "usr-synthetic");
        if (!data || std::strcmp(data, "integration-member-data") != 0) {
            return Fail("synthetic member data");
        }
        const char* name = friend_name(friends, bots[i]);
        char expected_name[32]{};
        std::snprintf(expected_name, sizeof(expected_name), "EDF Bot %u", i + 1);
        if (!name || std::strcmp(name, expected_name) != 0) {
            return Fail("synthetic persona name");
        }
        P2PSessionState state{};
        if (!accept_peer(networking, bots[i]) ||
            !session_state(networking, bots[i], &state) ||
            state.connection_active != 1 || state.connecting != 0 ||
            state.session_error != 0) {
            return Fail("synthetic active P2P session");
        }
    }
    set_member_data(matchmaking, lobby, "usr76561198000000001", "ready-state-data");
    for (SteamId bot : bots) {
        const char* data = get_member_data(matchmaking, lobby, bot, "usr-synthetic");
        if (!data || std::strcmp(data, "ready-state-data") != 0) {
            return Fail("dynamic synthetic member data");
        }
    }

    std::vector<uint8_t> packet(246, 0xa5);
    const uint32_t type = 20;
    const uint32_t four = 4;
    std::memcpy(packet.data(), &type, sizeof(type));
    std::memcpy(packet.data() + 12, &local, sizeof(local));
    std::memcpy(packet.data() + 60, &four, sizeof(four));
    std::memcpy(packet.data() + 64, &local, sizeof(local));
    std::vector<uint8_t> reply(packet.size());
    const SteamId transport_bots[] = {bots[0], bots[std::size(bots) - 1]};
    for (unsigned i = 0; i < 2; ++i) {
        const SteamId bot = transport_bots[i];
        if (!send_p2p(networking, bot, packet.data(),
                      static_cast<uint32_t>(packet.size()), 2, 2) ||
            get_send_count() != 0) {
            return Fail("synthetic SendP2PPacket interception");
        }
        uint32_t packet_size = 0;
        if (!available(networking, &packet_size, 2) || packet_size != packet.size()) {
            return Fail("synthetic packet availability");
        }
        SteamId reply_peer = 0;
        if (!read_p2p(networking, reply.data(), static_cast<uint32_t>(reply.size()),
                      &packet_size, &reply_peer, 2) || reply_peer != bot) {
            return Fail("synthetic ReadP2PPacket");
        }
        SteamId patched_id = 0;
        uint32_t patched_limit = 0;
        std::memcpy(&patched_id, reply.data() + 12, sizeof(patched_id));
        std::memcpy(&patched_limit, reply.data() + 60, sizeof(patched_limit));
        if (patched_id != bot ||
            patched_limit != kExpectedMaxPlayers) {
            return Fail("synthetic packet contents");
        }
        if (begin_auth(user, reply.data(), static_cast<int>(reply.size()), bot) != 0 ||
            get_auth_count() != 0) {
            return Fail("synthetic BeginAuthSession bypass");
        }
        run_callbacks();
        if (auth_callback.runs != static_cast<int>(i + 1) ||
            auth_callback.state_or_response != 0 ||
            auth_callback.lobby_or_user != bot || auth_callback.changed_user != bot) {
            return Fail("ValidateAuthTicketResponse callback");
        }
    }
    for (SteamId bot : bots) {
        if (!send_p2p(networking, bot, packet.data(),
                      static_cast<uint32_t>(packet.size()), 0, 0) ||
            get_send_count() != 0) {
            return Fail("synthetic gameplay-channel send acceptance");
        }
    }
    uint32_t gameplay_packet_size = 0;
    if (available(networking, &gameplay_packet_size, 0)) {
        return Fail("synthetic gameplay command was fabricated");
    }
    if (begin_auth(user, reply.data(), static_cast<int>(reply.size()), local) != 8 ||
        get_auth_count() != 1) {
        return Fail("real BeginAuthSession passthrough");
    }
    if (send_p2p(networking, local, packet.data(),
                 static_cast<uint32_t>(packet.size()), 2, 2) ||
        get_send_count() != 1) {
        return Fail("real SendP2PPacket passthrough");
    }
    if (!send_p2p(networking, local, packet.data(),
                  static_cast<uint32_t>(packet.size()), 0, 0) ||
        get_send_count() != 2) {
        return Fail("real gameplay-channel observer passthrough");
    }

    if (!remove_bot()) return Fail("programmatic F7 remove");
    run_callbacks();
    if (lobby_callback.runs != static_cast<int>(std::size(bots) + 1) ||
        lobby_callback.state_or_response != 2 ||
        lobby_callback.changed_user != bots[std::size(bots) - 1] ||
        member_count(matchmaking, lobby) != kExpectedMaxPlayers - 1) {
        return Fail("LobbyChatUpdate left callback");
    }
    set_actual_members(3);
    if (member_count(matchmaking, lobby) != kExpectedMaxPlayers) {
        return Fail("real member collision count");
    }
    run_callbacks();
    if (lobby_callback.runs != static_cast<int>(std::size(bots) + 2) ||
        lobby_callback.state_or_response != 2 ||
        lobby_callback.changed_user != bots[std::size(bots) - 2]) {
        return Fail("real member evicted highest filler");
    }

    unregister_callback(&auth_callback);
    unregister_callback(&lobby_callback);
    shutdown();
    std::printf(
        "integration=true name=%s version=0x%016llx create_limit=%d public_slot=%s "
        "open_public=%s invite_lobby=0x%016llx callbacks=%d/%d\n",
        info.name ? info.name : "(null)",
        static_cast<unsigned long long>(info.version.raw), get_create_limit(),
        get_public_slot(), get_open_public(),
        static_cast<unsigned long long>(get_invite_lobby()),
        lobby_callback.runs, auth_callback.runs);
    return 0;
}
