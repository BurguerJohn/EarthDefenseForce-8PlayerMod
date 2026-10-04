#include "steam_legacy_interfaces.h"

#include "logger.h"
#include "steam_game_policy.h"

#include <algorithm>
#include <cstdint>

namespace steam_capture {
namespace {

using SteamId = uint64_t;
using ApiCall = uint64_t;

using GetFavoriteCountFn = int (*)(void*);
using GetFavoriteFn = bool (*)(void*, int, uint32_t*, uint32_t*, uint16_t*, uint16_t*, uint32_t*, uint32_t*);
using AddFavoriteFn = int (*)(void*, uint32_t, uint32_t, uint16_t, uint16_t, uint32_t, uint32_t);
using RemoveFavoriteFn = bool (*)(void*, uint32_t, uint32_t, uint16_t, uint16_t, uint32_t);
using RequestListFn = ApiCall (*)(void*);
using StringFilterFn = void (*)(void*, const char*, const char*, int);
using NumericFilterFn = void (*)(void*, const char*, int, int);
using NearFilterFn = void (*)(void*, const char*, int);
using IntFilterFn = void (*)(void*, int);
using IdFilterFn = void (*)(void*, SteamId);
// EDF5 and steam_api64.dll use the MSVC ABI for CSteamID return values. Since
// this plugin is built with the MinGW target, model the hidden return buffer
// explicitly: RCX=this, RDX=result, followed by the declared arguments.
using LobbyByIndexFn = SteamId* (*)(void*, SteamId*, int);
using CreateLobbyFn = ApiCall (*)(void*, int, int);
using LobbyCallFn = ApiCall (*)(void*, SteamId);
using LobbyVoidFn = void (*)(void*, SteamId);
using TwoIdBoolFn = bool (*)(void*, SteamId, SteamId);
using LobbyIntFn = int (*)(void*, SteamId);
using MemberByIndexFn = SteamId* (*)(void*, SteamId*, SteamId, int);
using GetDataFn = const char* (*)(void*, SteamId, const char*);
using SetDataFn = bool (*)(void*, SteamId, const char*, const char*);
using DataByIndexFn = bool (*)(void*, SteamId, int, char*, int, char*, int);
using DeleteDataFn = bool (*)(void*, SteamId, const char*);
using GetMemberDataFn = const char* (*)(void*, SteamId, SteamId, const char*);
using SetMemberDataFn = void (*)(void*, SteamId, const char*, const char*);
using SendChatFn = bool (*)(void*, SteamId, const void*, int);
using GetChatFn = int (*)(void*, SteamId, int, SteamId*, void*, int, int*);
using LobbyBoolFn = bool (*)(void*, SteamId);
using SetGameServerFn = void (*)(void*, SteamId, uint32_t, uint16_t, SteamId);
using GetGameServerFn = bool (*)(void*, SteamId, uint32_t*, uint16_t*, SteamId*);
using SetLimitFn = bool (*)(void*, SteamId, int);
using SetTypeFn = bool (*)(void*, SteamId, int);
using SetJoinableFn = bool (*)(void*, SteamId, bool);
using GetOwnerFn = SteamId* (*)(void*, SteamId*, SteamId);

GetFavoriteCountFn o_get_favorite_count;
GetFavoriteFn o_get_favorite;
AddFavoriteFn o_add_favorite;
RemoveFavoriteFn o_remove_favorite;
RequestListFn o_request_list;
StringFilterFn o_string_filter;
NumericFilterFn o_numeric_filter;
NearFilterFn o_near_filter;
IntFilterFn o_slots_filter;
IntFilterFn o_distance_filter;
IntFilterFn o_result_count_filter;
IdFilterFn o_compatible_filter;
LobbyByIndexFn o_lobby_by_index;
CreateLobbyFn o_create_lobby;
LobbyCallFn o_join_lobby;
LobbyVoidFn o_leave_lobby;
TwoIdBoolFn o_invite_user;
LobbyIntFn o_member_count;
MemberByIndexFn o_member_by_index;
GetDataFn o_get_data;
SetDataFn o_set_data;
LobbyIntFn o_data_count;
DataByIndexFn o_data_by_index;
DeleteDataFn o_delete_data;
GetMemberDataFn o_get_member_data;
SetMemberDataFn o_set_member_data;
SendChatFn o_send_chat;
GetChatFn o_get_chat;
LobbyBoolFn o_request_data;
SetGameServerFn o_set_game_server;
GetGameServerFn o_get_game_server;
SetLimitFn o_set_member_limit;
LobbyIntFn o_get_member_limit;
SetTypeFn o_set_lobby_type;
SetJoinableFn o_set_joinable;
GetOwnerFn o_get_owner;
TwoIdBoolFn o_set_owner;
TwoIdBoolFn o_set_linked;

SRWLOCK g_match_lock = SRWLOCK_INIT;
void* g_match_interface = nullptr;
void* g_match_vtable[38]{};

int GetFavoriteCount(void* self) {
    const int result = o_get_favorite_count(self);
    EDF5_CAPTURE_EVENT("steam_matchmaking", "get_favorite_count", capture::Fields().Int("count", result));
    return result;
}

bool GetFavorite(void* self, int index, uint32_t* app, uint32_t* ip, uint16_t* connect_port,
                 uint16_t* query_port, uint32_t* flags, uint32_t* last_played) {
    const bool result = o_get_favorite(self, index, app, ip, connect_port, query_port, flags, last_played);
    EDF5_CAPTURE_EVENT("steam_matchmaking", "get_favorite",
                   capture::Fields().Int("index", index).Bool("result", result)
                       .UInt("app_id", result && app ? *app : 0)
                       .UInt("ip_u32", result && ip ? *ip : 0)
                       .String("ip_memory_order", result && ip ? capture::IpV4(*ip) : "")
                       .UInt("connect_port", result && connect_port ? *connect_port : 0)
                       .UInt("query_port", result && query_port ? *query_port : 0)
                       .UInt("flags", result && flags ? *flags : 0)
                       .UInt("last_played_unix", result && last_played ? *last_played : 0));
    return result;
}

int AddFavorite(void* self, uint32_t app, uint32_t ip, uint16_t connect_port,
                uint16_t query_port, uint32_t flags, uint32_t last_played) {
    const int result = o_add_favorite(self, app, ip, connect_port, query_port, flags, last_played);
    EDF5_CAPTURE_EVENT("steam_matchmaking", "add_favorite",
                   capture::Fields().UInt("app_id", app).UInt("ip_u32", ip)
                       .String("ip_memory_order", capture::IpV4(ip))
                       .UInt("connect_port", connect_port).UInt("query_port", query_port)
                       .UInt("flags", flags).UInt("last_played_unix", last_played)
                       .Int("result_index", result));
    return result;
}

bool RemoveFavorite(void* self, uint32_t app, uint32_t ip, uint16_t connect_port,
                    uint16_t query_port, uint32_t flags) {
    const bool result = o_remove_favorite(self, app, ip, connect_port, query_port, flags);
    EDF5_CAPTURE_EVENT("steam_matchmaking", "remove_favorite",
                   capture::Fields().UInt("app_id", app).UInt("ip_u32", ip)
                       .String("ip_memory_order", capture::IpV4(ip))
                       .UInt("connect_port", connect_port).UInt("query_port", query_port)
                       .UInt("flags", flags).Bool("result", result));
    return result;
}

ApiCall RequestList(void* self) {
    const ApiCall call = o_request_list(self);
    EDF5_CAPTURE_EVENT("steam_matchmaking", "request_lobby_list", capture::Fields().UInt("api_call", call));
    return call;
}

void StringFilter(void* self, const char* key, const char* value, int comparison) {
    o_string_filter(self, key, value, comparison);
    EDF5_CAPTURE_EVENT("steam_matchmaking", "lobby_list_string_filter",
                   capture::Fields().String("key", key).String("value", value)
                       .Int("comparison", comparison));
}

void NumericFilter(void* self, const char* key, int value, int comparison) {
    o_numeric_filter(self, key, value, comparison);
    EDF5_CAPTURE_EVENT("steam_matchmaking", "lobby_list_numeric_filter",
                   capture::Fields().String("key", key).Int("value", value)
                       .Int("comparison", comparison));
}

void NearFilter(void* self, const char* key, int value) {
    o_near_filter(self, key, value);
    EDF5_CAPTURE_EVENT("steam_matchmaking", "lobby_list_near_filter",
                   capture::Fields().String("key", key).Int("value", value));
}

void SlotsFilter(void* self, int slots) {
    o_slots_filter(self, slots);
    EDF5_CAPTURE_EVENT("steam_matchmaking", "lobby_list_slots_filter", capture::Fields().Int("slots", slots));
}

void DistanceFilter(void* self, int distance) {
    o_distance_filter(self, distance);
    EDF5_CAPTURE_EVENT("steam_matchmaking", "lobby_list_distance_filter",
                   capture::Fields().Int("distance", distance));
}

void ResultCountFilter(void* self, int count) {
    o_result_count_filter(self, count);
    EDF5_CAPTURE_EVENT("steam_matchmaking", "lobby_list_result_count_filter",
                   capture::Fields().Int("max_results", count));
}

void CompatibleFilter(void* self, SteamId lobby) {
    o_compatible_filter(self, lobby);
    EDF5_CAPTURE_EVENT("steam_matchmaking", "lobby_list_compatible_filter",
                   capture::Fields().UInt("lobby_steam_id", lobby));
}

SteamId* LobbyByIndex(void* self, SteamId* result, int index) {
    if (result) o_lobby_by_index(self, result, index);
    const SteamId lobby_value = result ? *result : 0;
    EDF5_CAPTURE_EVENT("steam_matchmaking", "get_lobby_by_index",
                   capture::Fields().Int("index", index).UInt("lobby_steam_id", lobby_value));
    return result;
}

ApiCall CreateLobby(void* self, int type, int max_members) {
    const int effective_max =
        steam_game_policy::EffectiveCreateLimit(max_members);
    steam_game_policy::NotifyCreateLobby(max_members, effective_max);
    const ApiCall call = o_create_lobby(self, type, effective_max);
    EDF5_CAPTURE_EVENT("steam_matchmaking", "create_lobby",
                   capture::Fields().Int("lobby_type", type)
                       .Int("requested_max_members", max_members)
                       .Int("max_members", effective_max)
                       .UInt("api_call", call));
    return call;
}

ApiCall JoinLobby(void* self, SteamId lobby) {
    const ApiCall call = o_join_lobby(self, lobby);
    if (call) steam_game_policy::NotifyJoinLobby(lobby);
    EDF5_CAPTURE_EVENT("steam_matchmaking", "join_lobby",
                   capture::Fields().UInt("lobby_steam_id", lobby).UInt("api_call", call));
    return call;
}

void LeaveLobby(void* self, SteamId lobby) {
    o_leave_lobby(self, lobby);
    steam_game_policy::ObserveLeaveLobby(lobby);
    EDF5_CAPTURE_EVENT("steam_matchmaking", "leave_lobby", capture::Fields().UInt("lobby_steam_id", lobby));
}

bool InviteUser(void* self, SteamId lobby, SteamId user) {
    const bool result = o_invite_user(self, lobby, user);
    EDF5_CAPTURE_EVENT("steam_matchmaking", "invite_user",
                   capture::Fields().UInt("lobby_steam_id", lobby).UInt("user_steam_id", user)
                       .Bool("result", result));
    return result;
}

int MemberCount(void* self, SteamId lobby) {
    const int actual_count = o_member_count(self, lobby);
    steam_game_policy::ObserveMemberCount(lobby, actual_count);
    const int count =
        steam_game_policy::AdjustMemberCount(lobby, actual_count);
    EDF5_CAPTURE_EVENT("steam_matchmaking", "get_member_count",
                   capture::Fields().UInt("lobby_steam_id", lobby)
                       .Int("actual_count", actual_count).Int("count", count)
                       .Bool("synthetic_member", count != actual_count));
    return count;
}

SteamId* MemberByIndex(void* self, SteamId* result, SteamId lobby, int index) {
    const int actual_count = o_member_count(self, lobby);
    uint64_t synthetic_user = 0;
    const bool synthetic = steam_game_policy::TryGetSyntheticMember(
        lobby, actual_count, index, synthetic_user);
    if (result) {
        if (synthetic) {
            *result = synthetic_user;
        } else {
            o_member_by_index(self, result, lobby, index);
        }
    }
    const SteamId user_value = result ? *result : 0;
    EDF5_CAPTURE_EVENT("steam_matchmaking", "get_member_by_index",
                   capture::Fields().UInt("lobby_steam_id", lobby).Int("index", index)
                       .UInt("user_steam_id", user_value).Bool("synthetic", synthetic));
    return result;
}

const char* GetData(void* self, SteamId lobby, const char* key) {
    const char* value = o_get_data(self, lobby, key);
    EDF5_CAPTURE_EVENT("steam_matchmaking", "get_lobby_data",
                   capture::Fields().UInt("lobby_steam_id", lobby).String("key", key)
                       .String("value", value));
    return value;
}

bool SetData(void* self, SteamId lobby, const char* key, const char* value) {
    steam_game_policy::ObserveLobbyDataWrite(lobby, key);
    std::string rewritten;
    const bool changed = steam_game_policy::RewriteLobbyData(
        lobby, key, value, rewritten);
    const char* effective_value = changed ? rewritten.c_str() : value;
    const bool result = o_set_data(self, lobby, key, effective_value);
    EDF5_CAPTURE_EVENT("steam_matchmaking", "set_lobby_data",
                   capture::Fields().UInt("lobby_steam_id", lobby).String("key", key)
                       .String("requested_value", value).String("value", effective_value)
                       .Bool("rewritten", changed).Bool("result", result));
    return result;
}

int DataCount(void* self, SteamId lobby) {
    const int count = o_data_count(self, lobby);
    EDF5_CAPTURE_EVENT("steam_matchmaking", "get_lobby_data_count",
                   capture::Fields().UInt("lobby_steam_id", lobby).Int("count", count));
    return count;
}

bool DataByIndex(void* self, SteamId lobby, int index, char* key, int key_capacity,
                 char* value, int value_capacity) {
    const bool result = o_data_by_index(self, lobby, index, key, key_capacity, value, value_capacity);
    EDF5_CAPTURE_EVENT("steam_matchmaking", "get_lobby_data_by_index",
                   capture::Fields().UInt("lobby_steam_id", lobby).Int("index", index)
                       .String("key", result ? key : nullptr).String("value", result ? value : nullptr)
                       .Int("key_capacity", key_capacity).Int("value_capacity", value_capacity)
                       .Bool("result", result));
    return result;
}

bool DeleteData(void* self, SteamId lobby, const char* key) {
    const bool result = o_delete_data(self, lobby, key);
    EDF5_CAPTURE_EVENT("steam_matchmaking", "delete_lobby_data",
                   capture::Fields().UInt("lobby_steam_id", lobby).String("key", key)
                       .Bool("result", result));
    return result;
}

const char* GetMemberData(void* self, SteamId lobby, SteamId user, const char* key) {
    thread_local std::string synthetic_value;
    const bool synthetic = steam_game_policy::TryGetMemberData(
        lobby, user, key, synthetic_value);
    const char* value = synthetic ? synthetic_value.c_str()
                                  : o_get_member_data(self, lobby, user, key);
    EDF5_CAPTURE_EVENT("steam_matchmaking", "get_member_data",
                   capture::Fields().UInt("lobby_steam_id", lobby).UInt("user_steam_id", user)
                       .String("key", key).String("value", value).Bool("synthetic", synthetic));
    return value;
}

void SetMemberData(void* self, SteamId lobby, const char* key, const char* value) {
    o_set_member_data(self, lobby, key, value);
    steam_game_policy::CaptureLocalMemberData(key, value);
    EDF5_CAPTURE_EVENT("steam_matchmaking", "set_member_data",
                   capture::Fields().UInt("lobby_steam_id", lobby).String("key", key)
                       .String("value", value));
}

bool SendChat(void* self, SteamId lobby, const void* data, int size) {
    const bool result = o_send_chat(self, lobby, data, size);
    EDF5_CAPTURE_EVENT("steam_matchmaking", "send_lobby_chat",
                   capture::Fields().String("direction", "out").UInt("lobby_steam_id", lobby)
                       .Int("requested_bytes", size).Bool("result", result),
                   data, size > 0 ? static_cast<size_t>(size) : 0);
    return result;
}

int GetChat(void* self, SteamId lobby, int chat_id, SteamId* user, void* data,
            int capacity, int* entry_type) {
    const int result = o_get_chat(self, lobby, chat_id, user, data, capacity, entry_type);
    const size_t captured = result > 0 ? static_cast<size_t>(std::min(result, capacity)) : 0;
    EDF5_CAPTURE_EVENT("steam_matchmaking", "get_lobby_chat_entry",
                   capture::Fields().String("direction", "in").UInt("lobby_steam_id", lobby)
                       .Int("chat_id", chat_id).UInt("user_steam_id", result > 0 && user ? *user : 0)
                       .Int("entry_type", result > 0 && entry_type ? *entry_type : 0)
                       .Int("buffer_capacity", capacity).Int("reported_bytes", result),
                   data, captured);
    return result;
}

bool RequestData(void* self, SteamId lobby) {
    const bool result = o_request_data(self, lobby);
    EDF5_CAPTURE_EVENT("steam_matchmaking", "request_lobby_data",
                   capture::Fields().UInt("lobby_steam_id", lobby).Bool("result", result));
    return result;
}

void SetGameServer(void* self, SteamId lobby, uint32_t ip, uint16_t port, SteamId server) {
    o_set_game_server(self, lobby, ip, port, server);
    EDF5_CAPTURE_EVENT("steam_matchmaking", "set_lobby_game_server",
                   capture::Fields().UInt("lobby_steam_id", lobby).UInt("ip_u32", ip)
                       .String("ip_memory_order", capture::IpV4(ip)).UInt("port", port)
                       .UInt("server_steam_id", server));
}

bool GetGameServer(void* self, SteamId lobby, uint32_t* ip, uint16_t* port, SteamId* server) {
    const bool result = o_get_game_server(self, lobby, ip, port, server);
    EDF5_CAPTURE_EVENT("steam_matchmaking", "get_lobby_game_server",
                   capture::Fields().UInt("lobby_steam_id", lobby).Bool("result", result)
                       .UInt("ip_u32", result && ip ? *ip : 0)
                       .String("ip_memory_order", result && ip ? capture::IpV4(*ip) : "")
                       .UInt("port", result && port ? *port : 0)
                       .UInt("server_steam_id", result && server ? *server : 0));
    return result;
}

bool SetMemberLimit(void* self, SteamId lobby, int limit) {
    const int effective_limit =
        steam_game_policy::EffectiveMemberLimit(lobby, limit);
    const bool result = o_set_member_limit(self, lobby, effective_limit);
    EDF5_CAPTURE_EVENT("steam_matchmaking", "set_member_limit",
                   capture::Fields().UInt("lobby_steam_id", lobby)
                       .Int("requested_limit", limit).Int("limit", effective_limit)
                       .Bool("result", result));
    return result;
}

int GetMemberLimit(void* self, SteamId lobby) {
    const int result = o_get_member_limit(self, lobby);
    EDF5_CAPTURE_EVENT("steam_matchmaking", "get_member_limit",
                   capture::Fields().UInt("lobby_steam_id", lobby).Int("limit", result));
    return result;
}

bool SetLobbyType(void* self, SteamId lobby, int type) {
    const int effective_type = steam_game_policy::AdjustLobbyType(lobby, type);
    const bool result = o_set_lobby_type(self, lobby, effective_type);
    EDF5_CAPTURE_EVENT("steam_matchmaking", "set_lobby_type",
                   capture::Fields().UInt("lobby_steam_id", lobby)
                       .Int("requested_lobby_type", type)
                       .Int("lobby_type", effective_type)
                       .Bool("result", result));
    return result;
}

bool SetJoinable(void* self, SteamId lobby, bool joinable) {
    const bool result = o_set_joinable(self, lobby, joinable);
    EDF5_CAPTURE_EVENT("steam_matchmaking", "set_lobby_joinable",
                   capture::Fields().UInt("lobby_steam_id", lobby).Bool("joinable", joinable)
                       .Bool("result", result));
    return result;
}

SteamId* GetOwner(void* self, SteamId* result, SteamId lobby) {
    if (result) o_get_owner(self, result, lobby);
    const SteamId owner_value = result ? *result : 0;
    EDF5_CAPTURE_EVENT("steam_matchmaking", "get_lobby_owner",
                   capture::Fields().UInt("lobby_steam_id", lobby)
                       .UInt("owner_steam_id", owner_value));
    return result;
}

bool SetOwner(void* self, SteamId lobby, SteamId owner) {
    const bool result = o_set_owner(self, lobby, owner);
    EDF5_CAPTURE_EVENT("steam_matchmaking", "set_lobby_owner",
                   capture::Fields().UInt("lobby_steam_id", lobby).UInt("owner_steam_id", owner)
                       .Bool("result", result));
    return result;
}

bool SetLinked(void* self, SteamId lobby, SteamId dependent) {
    const bool result = o_set_linked(self, lobby, dependent);
    EDF5_CAPTURE_EVENT("steam_matchmaking", "set_linked_lobby",
                   capture::Fields().UInt("lobby_steam_id", lobby)
                       .UInt("dependent_lobby_steam_id", dependent).Bool("result", result));
    return result;
}

#define INSTALL_SLOT(index, original, replacement, label) \
    original = reinterpret_cast<decltype(original)>(vtable[index]); \
    g_match_vtable[index] = reinterpret_cast<void*>(&replacement); \
    installed += original != nullptr

}  // namespace

void HookMatchmaking(void* interface_pointer) {
    if (!interface_pointer) return;
    AcquireSRWLockExclusive(&g_match_lock);
    if (g_match_interface) {
        ReleaseSRWLockExclusive(&g_match_lock);
        return;
    }
    void** vtable = *reinterpret_cast<void***>(interface_pointer);
    for (unsigned i = 0; i < 38; ++i) g_match_vtable[i] = vtable[i];
    unsigned installed = 0;
    INSTALL_SLOT(0, o_get_favorite_count, GetFavoriteCount, "ISteamMatchmaking009::GetFavoriteGameCount");
    INSTALL_SLOT(1, o_get_favorite, GetFavorite, "ISteamMatchmaking009::GetFavoriteGame");
    INSTALL_SLOT(2, o_add_favorite, AddFavorite, "ISteamMatchmaking009::AddFavoriteGame");
    INSTALL_SLOT(3, o_remove_favorite, RemoveFavorite, "ISteamMatchmaking009::RemoveFavoriteGame");
    INSTALL_SLOT(4, o_request_list, RequestList, "ISteamMatchmaking009::RequestLobbyList");
    INSTALL_SLOT(5, o_string_filter, StringFilter, "ISteamMatchmaking009::AddRequestLobbyListStringFilter");
    INSTALL_SLOT(6, o_numeric_filter, NumericFilter, "ISteamMatchmaking009::AddRequestLobbyListNumericalFilter");
    INSTALL_SLOT(7, o_near_filter, NearFilter, "ISteamMatchmaking009::AddRequestLobbyListNearValueFilter");
    INSTALL_SLOT(8, o_slots_filter, SlotsFilter, "ISteamMatchmaking009::AddRequestLobbyListFilterSlotsAvailable");
    INSTALL_SLOT(9, o_distance_filter, DistanceFilter, "ISteamMatchmaking009::AddRequestLobbyListDistanceFilter");
    INSTALL_SLOT(10, o_result_count_filter, ResultCountFilter, "ISteamMatchmaking009::AddRequestLobbyListResultCountFilter");
    INSTALL_SLOT(11, o_compatible_filter, CompatibleFilter, "ISteamMatchmaking009::AddRequestLobbyListCompatibleMembersFilter");
    INSTALL_SLOT(12, o_lobby_by_index, LobbyByIndex, "ISteamMatchmaking009::GetLobbyByIndex");
    INSTALL_SLOT(13, o_create_lobby, CreateLobby, "ISteamMatchmaking009::CreateLobby");
    INSTALL_SLOT(14, o_join_lobby, JoinLobby, "ISteamMatchmaking009::JoinLobby");
    INSTALL_SLOT(15, o_leave_lobby, LeaveLobby, "ISteamMatchmaking009::LeaveLobby");
    INSTALL_SLOT(16, o_invite_user, InviteUser, "ISteamMatchmaking009::InviteUserToLobby");
    INSTALL_SLOT(17, o_member_count, MemberCount, "ISteamMatchmaking009::GetNumLobbyMembers");
    INSTALL_SLOT(18, o_member_by_index, MemberByIndex, "ISteamMatchmaking009::GetLobbyMemberByIndex");
    INSTALL_SLOT(19, o_get_data, GetData, "ISteamMatchmaking009::GetLobbyData");
    INSTALL_SLOT(20, o_set_data, SetData, "ISteamMatchmaking009::SetLobbyData");
    INSTALL_SLOT(21, o_data_count, DataCount, "ISteamMatchmaking009::GetLobbyDataCount");
    INSTALL_SLOT(22, o_data_by_index, DataByIndex, "ISteamMatchmaking009::GetLobbyDataByIndex");
    INSTALL_SLOT(23, o_delete_data, DeleteData, "ISteamMatchmaking009::DeleteLobbyData");
    INSTALL_SLOT(24, o_get_member_data, GetMemberData, "ISteamMatchmaking009::GetLobbyMemberData");
    INSTALL_SLOT(25, o_set_member_data, SetMemberData, "ISteamMatchmaking009::SetLobbyMemberData");
    INSTALL_SLOT(26, o_send_chat, SendChat, "ISteamMatchmaking009::SendLobbyChatMsg");
    INSTALL_SLOT(27, o_get_chat, GetChat, "ISteamMatchmaking009::GetLobbyChatEntry");
    INSTALL_SLOT(28, o_request_data, RequestData, "ISteamMatchmaking009::RequestLobbyData");
    INSTALL_SLOT(29, o_set_game_server, SetGameServer, "ISteamMatchmaking009::SetLobbyGameServer");
    INSTALL_SLOT(30, o_get_game_server, GetGameServer, "ISteamMatchmaking009::GetLobbyGameServer");
    INSTALL_SLOT(31, o_set_member_limit, SetMemberLimit, "ISteamMatchmaking009::SetLobbyMemberLimit");
    INSTALL_SLOT(32, o_get_member_limit, GetMemberLimit, "ISteamMatchmaking009::GetLobbyMemberLimit");
    INSTALL_SLOT(33, o_set_lobby_type, SetLobbyType, "ISteamMatchmaking009::SetLobbyType");
    INSTALL_SLOT(34, o_set_joinable, SetJoinable, "ISteamMatchmaking009::SetLobbyJoinable");
    INSTALL_SLOT(35, o_get_owner, GetOwner, "ISteamMatchmaking009::GetLobbyOwner");
    INSTALL_SLOT(36, o_set_owner, SetOwner, "ISteamMatchmaking009::SetLobbyOwner");
    INSTALL_SLOT(37, o_set_linked, SetLinked, "ISteamMatchmaking009::SetLinkedLobby");
    InterlockedExchangePointer(reinterpret_cast<PVOID volatile*>(interface_pointer), g_match_vtable);
    g_match_interface = interface_pointer;
    ReleaseSRWLockExclusive(&g_match_lock);
    EDF5_CAPTURE_EVENT("steam", "matchmaking_interface_hooked",
                   capture::Fields().String("interface_version", "SteamMatchMaking009")
                       .String("interface", capture::HexPointer(interface_pointer))
                       .UInt("hooks_installed", installed).UInt("hooks_expected", 38));
}

int GetActualLobbyMemberCount(uint64_t lobby) {
    LobbyIntFn member_count = nullptr;
    void* interface_pointer = nullptr;
    AcquireSRWLockShared(&g_match_lock);
    member_count = o_member_count;
    interface_pointer = g_match_interface;
    ReleaseSRWLockShared(&g_match_lock);
    if (!member_count || !interface_pointer || !lobby) return -1;
    return member_count(interface_pointer, lobby);
}

bool CopyActualLobbyMemberData(uint64_t lobby, uint64_t user,
                               const char* key, std::string& value) {
    GetMemberDataFn get_member_data = nullptr;
    void* interface_pointer = nullptr;
    AcquireSRWLockShared(&g_match_lock);
    get_member_data = o_get_member_data;
    interface_pointer = g_match_interface;
    ReleaseSRWLockShared(&g_match_lock);
    if (!get_member_data || !interface_pointer || !lobby || !user || !key ||
        !*key) {
        return false;
    }
    const char* source = get_member_data(interface_pointer, lobby, user, key);
    if (!source || !*source) return false;
    value.assign(source);
    return true;
}

}  // namespace steam_capture
