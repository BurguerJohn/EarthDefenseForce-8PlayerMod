#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

// Game-specific behavior behind the shared legacy Steam ABI hooks. The hook
// files know only Steam interface versions; this policy is the sole dispatch
// point for optional coop behavior.
namespace steam_game_policy {

bool TryGetBotName(uint64_t user, std::string& name);
int EffectiveCreateLimit(int requested);
int EffectiveMemberLimit(uint64_t lobby, int requested);
void NotifyCreateLobby(int requested, int effective);
void NotifyJoinLobby(uint64_t lobby);
void ObserveLobbyDataWrite(uint64_t lobby, const char* key);
void ObserveLeaveLobby(uint64_t lobby);
bool RewriteLobbyData(uint64_t lobby, const char* key, const char* value,
                      std::string& rewritten);
int AdjustMemberCount(uint64_t lobby, int actual_count);
void ObserveMemberCount(uint64_t lobby, int actual_count);
bool TryGetSyntheticMember(uint64_t lobby, int actual_count, int index,
                           uint64_t& user);
bool TryGetMemberData(uint64_t lobby, uint64_t user, const char* key,
                      std::string& value);
void CaptureLocalMemberData(const char* key, const char* value);

bool IsSyntheticPeer(uint64_t peer);
bool IsSyntheticIdentity(uint64_t peer);
void ObserveRealP2PSend(uint64_t peer, int channel, size_t bytes,
                        bool success);
bool HandleSyntheticSend(uint64_t peer, const void* data, uint32_t size,
                         int send_type, int channel);
bool PeekSyntheticPacket(int channel, uint32_t* size);
bool ReadSyntheticPacket(void* destination, uint32_t capacity,
                         uint32_t* message_size, uint64_t* peer, int channel);
void CloseSyntheticPeer(uint64_t peer);
void QueueSyntheticAuthValidation(uint64_t user);

}  // namespace steam_game_policy
