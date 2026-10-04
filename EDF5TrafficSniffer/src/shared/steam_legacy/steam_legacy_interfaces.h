#pragma once

#include <cstdint>
#include <string>

// Steamworks interface ABIs shared by EDF 4.1 and EDF5. These functions hook
// exact, verified interface versions; discovery of the interface pointer stays
// inside each game's bootstrap.
namespace steam_capture {

void HookNetworking(void* interface_pointer);   // SteamNetworking005
void HookMatchmaking(void* interface_pointer);  // SteamMatchMaking009
void HookFriends(void* interface_pointer);      // SteamFriends015
// GetSteamID=2, BeginAuthSession=14 and EndAuthSession=15 are shared. The
// independently verified EDF 4.1 profile also observes ticket issue=13 and
// cancellation=16; EDF5 passes "SteamUser019" and keeps the narrow set.
void HookUserAuth(void* interface_pointer, const char* interface_version);

bool OpenLobbyInviteDialog(uint64_t lobby);
// Steam persona (UTF-8) of a user through the original, unhooked
// GetFriendPersonaName. Returns false when unavailable or empty. The text is
// for in-game display only and must never be logged.
bool CopyFriendPersonaName(uint64_t user, std::string& name);
uint64_t LocalUserSteamId();
// Bypasses the synthetic-member policy and queries the real Steam lobby. It is
// used on SteamAPI_RunCallbacks' game thread to enforce EDF 4.1's native-safe
// room limit before a filler is exposed.
int GetActualLobbyMemberCount(uint64_t lobby);
bool CopyActualLobbyMemberData(uint64_t lobby, uint64_t user,
                               const char* key, std::string& value);
bool SelfTestPrivateIdentityAudit(std::string& report);

}  // namespace steam_capture
