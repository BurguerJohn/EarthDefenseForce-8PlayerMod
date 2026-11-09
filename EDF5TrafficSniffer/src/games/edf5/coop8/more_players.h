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

// Combat statistics of the participants controlled on this machine, for the
// on-screen stats overlay. Only this machine applies their hits with a live
// attacker, so these numbers are complete.
struct CombatStatsPlayer {
    int32_t participant_index = -1;
    double damage = 0.0;
    // Damage of the last few seconds divided by that window.
    double recent_dps = 0.0;
    uint32_t kills = 0;
    double distance = 0.0;  // metres moved since the stage began
    // Friendly fire on the other players (allied NPCs excluded).
    double friendly_damage = 0.0;
    uint32_t friendly_kills = 0;
};

struct CombatStats {
    // A measurement is running and the mission script updated recently.
    bool in_mission = false;
    bool kills_supported = false;
    // Enemies alive right now (the game's own count), -1 when unknown.
    int32_t enemies_alive = -1;
    // Why in_mission is false (for the overlay's diagnostics).
    bool measurement_active = false;
    bool measurement_ended = false;
    uint64_t last_update_age_ms = 0;  // UINT64_MAX: no Mission() update yet
    // Time the mission script ran since the stage began (pauses excluded).
    uint64_t active_ms = 0;
    uint32_t count = 0;  // local participants (two in split screen)
    CombatStatsPlayer players[2];
};

bool GetCombatStats(CombatStats& stats);
// The EDF5 main window once found by the hotkey thread, or nullptr.
void* GameWindow();
// The title screen's update ran within the last half second.
bool TitleScreenActive();

// Pure protocol checks used by the standalone smoke harness. This does not
// initialize Steam or launch EDF5.
bool SelfTest(std::string& report);

}  // namespace more_players
