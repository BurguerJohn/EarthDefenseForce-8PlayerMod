#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <steam/steamclientpublic.h>

#include <cstdint>
#include <cstdio>
#include <cstring>

#if defined(__GNUC__)
#define FAKE_NOINLINE __attribute__((noinline))
#else
#define FAKE_NOINLINE __declspec(noinline)
#endif

namespace {

using SteamId = uint64_t;
using ApiCall = uint64_t;

constexpr SteamId kLocalSteamId = 76561198000000001ULL;
constexpr SteamId kLobbySteamId = 109775241799999998ULL;

struct InterfaceObject {
    void** vtable;
};

void* g_user_vtable[25]{};
void* g_friends_vtable[64]{};
void* g_matchmaking_vtable[38]{};
void* g_networking_vtable[22]{};
InterfaceObject g_user{g_user_vtable};
InterfaceObject g_friends{g_friends_vtable};
InterfaceObject g_matchmaking{g_matchmaking_vtable};
InterfaceObject g_networking{g_networking_vtable};
void* g_context[12]{};
bool g_initialized = false;

volatile long g_effect = 0;
int g_actual_members = 1;
int g_last_create_limit = -1;
int g_last_member_limit = -1;
int g_original_send_count = 0;
int g_original_begin_auth_count = 0;
int g_original_end_auth_count = 0;
int g_original_get_auth_ticket_count = 0;
int g_original_cancel_auth_ticket_count = 0;
SteamId g_last_invite_dialog_lobby = 0;
char g_public_slot[32]{};
char g_open_public[32]{};
char g_private_slot[32]{};
char g_member_data[256]{};
char g_member_data_key[64]{};

FAKE_NOINLINE uint64_t Generic(void*) {
    InterlockedIncrement(&g_effect);
    return 0;
}

FAKE_NOINLINE SteamId* GetSteamId(void*, SteamId* result) {
    InterlockedIncrement(&g_effect);
    if (result) *result = kLocalSteamId;
    return result;
}

FAKE_NOINLINE ApiCall CreateLobby(void*, int, int max_members) {
    InterlockedIncrement(&g_effect);
    g_last_create_limit = max_members;
    return 0x1122334455667788ULL;
}

FAKE_NOINLINE int MemberCount(void*, SteamId) {
    InterlockedIncrement(&g_effect);
    return g_actual_members;
}

// Explicitly emulate the MSVC hidden-return-buffer convention used by the
// real Steam matchmaking vtable. The plugin itself is built for MinGW.
FAKE_NOINLINE SteamId* LobbyByIndex(void*, SteamId* result, int index) {
    InterlockedIncrement(&g_effect);
    if (result) *result = index == 0 ? kLobbySteamId : 0ULL;
    return result;
}

FAKE_NOINLINE SteamId* MemberByIndex(void*, SteamId* result, SteamId lobby,
                                     int index) {
    InterlockedIncrement(&g_effect);
    if (result) {
        *result = lobby == kLobbySteamId && index == 0 ? kLocalSteamId : 0ULL;
    }
    return result;
}

FAKE_NOINLINE SteamId* GetLobbyOwner(void*, SteamId* result, SteamId lobby) {
    InterlockedIncrement(&g_effect);
    if (result) *result = lobby == kLobbySteamId ? kLocalSteamId : 0ULL;
    return result;
}

FAKE_NOINLINE const char* GetLobbyData(void*, SteamId, const char* key) {
    InterlockedIncrement(&g_effect);
    if (key && std::strcmp(key, "public_slot") == 0) return g_public_slot;
    if (key && std::strcmp(key, "open_public") == 0) return g_open_public;
    if (key && std::strcmp(key, "private_slot") == 0) return g_private_slot;
    return "";
}

FAKE_NOINLINE bool SetLobbyData(void*, SteamId, const char* key, const char* value) {
    InterlockedIncrement(&g_effect);
    if (!key || !value) return false;
    char* destination = nullptr;
    size_t capacity = 0;
    if (std::strcmp(key, "public_slot") == 0) {
        destination = g_public_slot;
        capacity = sizeof(g_public_slot);
    } else if (std::strcmp(key, "open_public") == 0) {
        destination = g_open_public;
        capacity = sizeof(g_open_public);
    } else if (std::strcmp(key, "private_slot") == 0) {
        destination = g_private_slot;
        capacity = sizeof(g_private_slot);
    }
    if (destination) {
        std::snprintf(destination, capacity, "%s", value);
    }
    return true;
}

FAKE_NOINLINE const char* GetMemberData(void*, SteamId lobby, SteamId user,
                                         const char* key) {
    InterlockedIncrement(&g_effect);
    return lobby == kLobbySteamId && user == kLocalSteamId && key &&
            std::strcmp(key, g_member_data_key) == 0
        ? g_member_data : nullptr;
}

FAKE_NOINLINE void SetMemberData(void*, SteamId, const char* key,
                                 const char* value) {
    InterlockedIncrement(&g_effect);
    std::snprintf(g_member_data_key, sizeof(g_member_data_key), "%s",
                  key ? key : "");
    std::snprintf(g_member_data, sizeof(g_member_data), "%s", value ? value : "");
}

FAKE_NOINLINE bool SetMemberLimit(void*, SteamId, int limit) {
    InterlockedIncrement(&g_effect);
    g_last_member_limit = limit;
    return true;
}

FAKE_NOINLINE int GetMemberLimit(void*, SteamId) {
    InterlockedIncrement(&g_effect);
    return g_last_member_limit;
}

FAKE_NOINLINE const char* FriendPersonaName(void*, SteamId) {
    InterlockedIncrement(&g_effect);
    return "fake-original-name";
}

FAKE_NOINLINE void ActivateInviteDialog(void*, SteamId lobby) {
    InterlockedIncrement(&g_effect);
    g_last_invite_dialog_lobby = lobby;
}

FAKE_NOINLINE int BeginAuthSession(void*, const void*, int, SteamId) {
    InterlockedIncrement(&g_effect);
    ++g_original_begin_auth_count;
    return 8;
}

FAKE_NOINLINE uint32_t GetAuthSessionTicket(void*, void* ticket, int capacity,
                                             uint32_t* written) {
    InterlockedIncrement(&g_effect);
    ++g_original_get_auth_ticket_count;
    constexpr char kTicket[] = "fake-ticket";
    const uint32_t copied = capacity >= static_cast<int>(sizeof(kTicket))
        ? static_cast<uint32_t>(sizeof(kTicket))
        : 0;
    if (copied && ticket) std::memcpy(ticket, kTicket, copied);
    if (written) *written = copied;
    return 77;
}

FAKE_NOINLINE void CancelAuthTicket(void*, uint32_t) {
    InterlockedIncrement(&g_effect);
    ++g_original_cancel_auth_ticket_count;
}

FAKE_NOINLINE void EndAuthSession(void*, SteamId) {
    InterlockedIncrement(&g_effect);
    ++g_original_end_auth_count;
}

FAKE_NOINLINE bool SendP2P(void*, SteamId, const void*, uint32_t, int,
                           int channel) {
    InterlockedIncrement(&g_effect);
    ++g_original_send_count;
    return channel == 0;
}

FAKE_NOINLINE bool IsP2PAvailable(void*, uint32_t* size, int) {
    InterlockedIncrement(&g_effect);
    if (size) *size = 0;
    return false;
}

FAKE_NOINLINE bool ReadP2P(void*, void*, uint32_t, uint32_t* size, SteamId* peer, int) {
    InterlockedIncrement(&g_effect);
    if (size) *size = 0;
    if (peer) *peer = 0;
    return false;
}

void InitializeContext() {
    if (g_initialized) return;
    g_initialized = true;
    for (void*& slot : g_user_vtable) slot = reinterpret_cast<void*>(&Generic);
    for (void*& slot : g_friends_vtable) slot = reinterpret_cast<void*>(&Generic);
    for (void*& slot : g_matchmaking_vtable) slot = reinterpret_cast<void*>(&Generic);
    for (void*& slot : g_networking_vtable) slot = reinterpret_cast<void*>(&Generic);

    g_user_vtable[2] = reinterpret_cast<void*>(&GetSteamId);
    g_user_vtable[13] = reinterpret_cast<void*>(&GetAuthSessionTicket);
    g_user_vtable[14] = reinterpret_cast<void*>(&BeginAuthSession);
    g_user_vtable[15] = reinterpret_cast<void*>(&EndAuthSession);
    g_user_vtable[16] = reinterpret_cast<void*>(&CancelAuthTicket);
    g_friends_vtable[7] = reinterpret_cast<void*>(&FriendPersonaName);
    g_friends_vtable[33] = reinterpret_cast<void*>(&ActivateInviteDialog);
    g_matchmaking_vtable[12] = reinterpret_cast<void*>(&LobbyByIndex);
    g_matchmaking_vtable[13] = reinterpret_cast<void*>(&CreateLobby);
    g_matchmaking_vtable[17] = reinterpret_cast<void*>(&MemberCount);
    g_matchmaking_vtable[18] = reinterpret_cast<void*>(&MemberByIndex);
    g_matchmaking_vtable[19] = reinterpret_cast<void*>(&GetLobbyData);
    g_matchmaking_vtable[20] = reinterpret_cast<void*>(&SetLobbyData);
    g_matchmaking_vtable[24] = reinterpret_cast<void*>(&GetMemberData);
    g_matchmaking_vtable[25] = reinterpret_cast<void*>(&SetMemberData);
    g_matchmaking_vtable[31] = reinterpret_cast<void*>(&SetMemberLimit);
    g_matchmaking_vtable[32] = reinterpret_cast<void*>(&GetMemberLimit);
    g_matchmaking_vtable[35] = reinterpret_cast<void*>(&GetLobbyOwner);
    g_networking_vtable[0] = reinterpret_cast<void*>(&SendP2P);
    g_networking_vtable[1] = reinterpret_cast<void*>(&IsP2PAvailable);
    g_networking_vtable[2] = reinterpret_cast<void*>(&ReadP2P);

    g_context[1] = &g_user;
    g_context[2] = &g_friends;
    g_context[4] = &g_matchmaking;
    g_context[8] = &g_networking;
}

}  // namespace

extern "C" __declspec(dllexport) FAKE_NOINLINE void* SteamInternal_ContextInit(void*) {
    InterlockedIncrement(&g_effect);
    InitializeContext();
    return g_context;
}

extern "C" __declspec(dllexport) FAKE_NOINLINE void* SteamInternal_CreateInterface(const char*) {
    InterlockedIncrement(&g_effect);
    return nullptr;
}

extern "C" __declspec(dllexport) FAKE_NOINLINE bool SteamAPI_Init() {
    InterlockedIncrement(&g_effect);
    InitializeContext();
    return true;
}

// EDF 4.1 uses these pre-SteamInternal direct accessors. The interface
// versions represented by the fake vtables match the versions embedded in
// its pinned steam_api64.dll: Friends015, MatchMaking009 and Networking005.
extern "C" __declspec(dllexport) FAKE_NOINLINE void* SteamFriends() {
    InterlockedIncrement(&g_effect);
    InitializeContext();
    return &g_friends;
}

extern "C" __declspec(dllexport) FAKE_NOINLINE void* SteamMatchmaking() {
    InterlockedIncrement(&g_effect);
    InitializeContext();
    return &g_matchmaking;
}

extern "C" __declspec(dllexport) FAKE_NOINLINE void* SteamNetworking() {
    InterlockedIncrement(&g_effect);
    InitializeContext();
    return &g_networking;
}

extern "C" __declspec(dllexport) FAKE_NOINLINE void* SteamUser() {
    InterlockedIncrement(&g_effect);
    InitializeContext();
    return &g_user;
}

extern "C" __declspec(dllexport) FAKE_NOINLINE void SteamAPI_Shutdown() {
    InterlockedIncrement(&g_effect);
}

extern "C" __declspec(dllexport) FAKE_NOINLINE void SteamAPI_RunCallbacks() {
    InterlockedIncrement(&g_effect);
}

extern "C" __declspec(dllexport) FAKE_NOINLINE void SteamAPI_RegisterCallback(void*, int) {
    InterlockedIncrement(&g_effect);
}

extern "C" __declspec(dllexport) FAKE_NOINLINE void SteamAPI_UnregisterCallback(void*) {
    InterlockedIncrement(&g_effect);
}

extern "C" __declspec(dllexport) FAKE_NOINLINE void SteamAPI_RegisterCallResult(void*, uint64_t) {
    InterlockedIncrement(&g_effect);
}

extern "C" __declspec(dllexport) FAKE_NOINLINE void SteamAPI_UnregisterCallResult(void*, uint64_t) {
    InterlockedIncrement(&g_effect);
}

extern "C" __declspec(dllexport) void FakeSteam_SetActualMembers(int count) {
    g_actual_members = count;
}

extern "C" __declspec(dllexport) void FakeSteam_SetLocalMemberData(
    const char* value) {
    std::snprintf(g_member_data_key, sizeof(g_member_data_key),
                  "usr%llu",
                  static_cast<unsigned long long>(kLocalSteamId));
    std::snprintf(g_member_data, sizeof(g_member_data), "%s",
                  value ? value : "");
}

extern "C" __declspec(dllexport) int FakeSteam_GetLastCreateLimit() {
    return g_last_create_limit;
}

extern "C" __declspec(dllexport) int FakeSteam_GetLastMemberLimit() {
    return g_last_member_limit;
}

extern "C" __declspec(dllexport) uint64_t FakeSteam_GetLastInviteDialogLobby() {
    return g_last_invite_dialog_lobby;
}

extern "C" __declspec(dllexport) const char* FakeSteam_GetPublicSlot() {
    return g_public_slot;
}

extern "C" __declspec(dllexport) const char* FakeSteam_GetPrivateSlot() {
    return g_private_slot;
}

extern "C" __declspec(dllexport) const char* FakeSteam_GetOpenPublic() {
    return g_open_public;
}

extern "C" __declspec(dllexport) int FakeSteam_GetOriginalSendCount() {
    return g_original_send_count;
}

extern "C" __declspec(dllexport) int FakeSteam_GetOriginalBeginAuthCount() {
    return g_original_begin_auth_count;
}

extern "C" __declspec(dllexport) int FakeSteam_GetOriginalEndAuthCount() {
    return g_original_end_auth_count;
}

extern "C" __declspec(dllexport) int FakeSteam_GetOriginalGetAuthTicketCount() {
    return g_original_get_auth_ticket_count;
}

extern "C" __declspec(dllexport) int FakeSteam_GetOriginalCancelAuthTicketCount() {
    return g_original_cancel_auth_ticket_count;
}
