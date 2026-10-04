#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace more_players {

bool Start();
void RequestStop();
void Stop();
bool InstallGameHooks();
bool AddBotFromApi();
bool RemoveBotFromApi();
bool ReadyBotsFromApi();
bool OpenInviteDialogFromApi();
bool ToggleBotFromApi();

bool Enabled();
unsigned MaxPlayers();
uint64_t BotSteamId(unsigned index = 0);
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
// Keeps the Steam visibility of the owned room consistent with the room the
// host created (friends/private rooms never become Public; public rooms stay
// listed until MaxPlayers members).
int AdjustLobbyType(uint64_t lobby, int type);
void ObserveMemberCount(uint64_t lobby, int actual_count);
bool TryGetSyntheticMember(uint64_t lobby, int actual_count, int index,
                           uint64_t& user);
bool TryGetMemberData(uint64_t lobby, uint64_t user, const char* key,
                      std::string& value);
void CaptureLocalMemberData(const char* key, const char* value);

bool ConsumeMembershipChange(uint64_t& lobby, uint64_t& user, uint32_t& state_change);
void MembershipChangeDelivered(uint64_t lobby, uint64_t user, uint32_t state_change);

bool IsSyntheticPeer(uint64_t peer);
bool IsSyntheticIdentity(uint64_t peer);
void ObserveRealP2PSend(uint64_t peer, int channel, size_t bytes, bool success);
bool HandleSyntheticSend(uint64_t peer, const void* data, uint32_t size,
                         int send_type, int channel);
bool PeekSyntheticPacket(int channel, uint32_t* size);
bool ReadSyntheticPacket(void* destination, uint32_t capacity, uint32_t* message_size,
                         uint64_t* peer, int channel);
void CloseSyntheticPeer(uint64_t peer);

void QueueSyntheticAuthValidation(uint64_t user);
bool ConsumeSyntheticAuthValidation(uint64_t& user);
void SyntheticAuthValidationDelivered(uint64_t user);

// Pure protocol checks used by the standalone smoke harness. This does not
// initialize Steam or launch EDF5.
bool SelfTest(std::string& report);

}  // namespace more_players
