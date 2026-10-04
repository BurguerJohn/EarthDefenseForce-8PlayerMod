#include "steam_game_policy.h"

#include "game_id.h"
#include "more_players.h"
#include "runtime_config.h"

#if EDF5_COMPILE_DIAGNOSTICS
#include "room_bots.h"
#endif

namespace steam_game_policy {
namespace {

bool UsesEdf5CoopPolicy() {
    return runtime_config::SelectedGame() == game::Id::Edf5;
}

#if EDF5_COMPILE_DIAGNOSTICS
bool UsesEdf41CoopPolicy() {
    return runtime_config::SelectedGame() == game::Id::Edf41 &&
           capture::GetConfig().edf41.coop8;
}
#endif

}  // namespace

bool TryGetBotName(uint64_t user, std::string& name) {
#if EDF5_COMPILE_DIAGNOSTICS
    if (UsesEdf41CoopPolicy()) {
        return edf41::room_bots::TryGetBotName(user, name);
    }
#endif
    return UsesEdf5CoopPolicy() && more_players::TryGetBotName(user, name);
}

int EffectiveCreateLimit(int requested) {
#if EDF5_COMPILE_DIAGNOSTICS
    if (UsesEdf41CoopPolicy()) {
        return edf41::room_bots::EffectiveCreateLimit(requested);
    }
#endif
    return UsesEdf5CoopPolicy()
        ? more_players::EffectiveCreateLimit(requested) : requested;
}

int EffectiveMemberLimit(uint64_t lobby, int requested) {
#if EDF5_COMPILE_DIAGNOSTICS
    if (UsesEdf41CoopPolicy()) {
        return edf41::room_bots::EffectiveMemberLimit(lobby, requested);
    }
#endif
    return UsesEdf5CoopPolicy()
        ? more_players::EffectiveMemberLimit(lobby, requested) : requested;
}

void NotifyCreateLobby(int requested, int effective) {
#if EDF5_COMPILE_DIAGNOSTICS
    if (UsesEdf41CoopPolicy()) {
        edf41::room_bots::NotifyCreateLobby(requested, effective);
        return;
    }
#endif
    if (UsesEdf5CoopPolicy()) {
        more_players::NotifyCreateLobby(requested, effective);
    }
}

void NotifyJoinLobby(uint64_t lobby) {
#if EDF5_COMPILE_DIAGNOSTICS
    if (UsesEdf41CoopPolicy()) {
        edf41::room_bots::NotifyJoinLobby(lobby);
        return;
    }
#endif
    if (UsesEdf5CoopPolicy()) more_players::NotifyJoinLobby(lobby);
}

void ObserveLobbyDataWrite(uint64_t lobby, const char* key) {
#if EDF5_COMPILE_DIAGNOSTICS
    if (UsesEdf41CoopPolicy()) {
        edf41::room_bots::ObserveLobbyDataWrite(lobby, key);
        return;
    }
#endif
    if (UsesEdf5CoopPolicy()) more_players::ObserveLobbyDataWrite(lobby, key);
}

void ObserveLeaveLobby(uint64_t lobby) {
#if EDF5_COMPILE_DIAGNOSTICS
    if (UsesEdf41CoopPolicy()) {
        edf41::room_bots::ObserveLeaveLobby(lobby);
        return;
    }
#endif
    if (UsesEdf5CoopPolicy()) more_players::ObserveLeaveLobby(lobby);
}

bool RewriteLobbyData(uint64_t lobby, const char* key, const char* value,
                      std::string& rewritten) {
#if EDF5_COMPILE_DIAGNOSTICS
    if (UsesEdf41CoopPolicy()) {
        return edf41::room_bots::RewriteLobbyData(
            lobby, key, value, rewritten);
    }
#endif
    return UsesEdf5CoopPolicy() &&
        more_players::RewriteLobbyData(lobby, key, value, rewritten);
}

int AdjustMemberCount(uint64_t lobby, int actual_count) {
#if EDF5_COMPILE_DIAGNOSTICS
    if (UsesEdf41CoopPolicy()) {
        return edf41::room_bots::AdjustMemberCount(lobby, actual_count);
    }
#endif
    return UsesEdf5CoopPolicy()
        ? more_players::AdjustMemberCount(lobby, actual_count) : actual_count;
}

int AdjustLobbyType(uint64_t lobby, int type) {
#if EDF5_COMPILE_DIAGNOSTICS
    if (UsesEdf41CoopPolicy()) return type;
#endif
    return UsesEdf5CoopPolicy()
        ? more_players::AdjustLobbyType(lobby, type) : type;
}

void ObserveMemberCount(uint64_t lobby, int actual_count) {
#if EDF5_COMPILE_DIAGNOSTICS
    if (UsesEdf41CoopPolicy()) {
        edf41::room_bots::ObserveMemberCount(lobby, actual_count);
        return;
    }
#endif
    if (UsesEdf5CoopPolicy()) {
        more_players::ObserveMemberCount(lobby, actual_count);
    }
}

bool TryGetSyntheticMember(uint64_t lobby, int actual_count, int index,
                           uint64_t& user) {
#if EDF5_COMPILE_DIAGNOSTICS
    if (UsesEdf41CoopPolicy()) {
        return edf41::room_bots::TryGetSyntheticMember(
            lobby, actual_count, index, user);
    }
#endif
    return UsesEdf5CoopPolicy() &&
        more_players::TryGetSyntheticMember(lobby, actual_count, index, user);
}

bool TryGetMemberData(uint64_t lobby, uint64_t user, const char* key,
                      std::string& value) {
#if EDF5_COMPILE_DIAGNOSTICS
    if (UsesEdf41CoopPolicy()) {
        return edf41::room_bots::TryGetMemberData(
            lobby, user, key, value);
    }
#endif
    return UsesEdf5CoopPolicy() &&
        more_players::TryGetMemberData(lobby, user, key, value);
}

void CaptureLocalMemberData(const char* key, const char* value) {
#if EDF5_COMPILE_DIAGNOSTICS
    if (UsesEdf41CoopPolicy()) {
        edf41::room_bots::CaptureLocalMemberData(key, value);
        return;
    }
#endif
    if (UsesEdf5CoopPolicy()) {
        more_players::CaptureLocalMemberData(key, value);
    }
}

bool IsSyntheticPeer(uint64_t peer) {
#if EDF5_COMPILE_DIAGNOSTICS
    if (UsesEdf41CoopPolicy()) {
        return edf41::room_bots::IsSyntheticPeer(peer);
    }
#endif
    return UsesEdf5CoopPolicy() && more_players::IsSyntheticPeer(peer);
}

bool IsSyntheticIdentity(uint64_t peer) {
#if EDF5_COMPILE_DIAGNOSTICS
    if (UsesEdf41CoopPolicy()) {
        return edf41::room_bots::IsSyntheticIdentity(peer);
    }
#endif
    return UsesEdf5CoopPolicy() && more_players::IsSyntheticIdentity(peer);
}

void ObserveRealP2PSend(uint64_t peer, int channel, size_t bytes,
                        bool success) {
#if EDF5_COMPILE_DIAGNOSTICS
    if (UsesEdf41CoopPolicy()) {
        edf41::room_bots::ObserveRealP2PSend(
            peer, channel, bytes, success);
        return;
    }
#endif
    if (UsesEdf5CoopPolicy()) {
        more_players::ObserveRealP2PSend(peer, channel, bytes, success);
    }
}

bool HandleSyntheticSend(uint64_t peer, const void* data, uint32_t size,
                         int send_type, int channel) {
#if EDF5_COMPILE_DIAGNOSTICS
    if (UsesEdf41CoopPolicy()) {
        return edf41::room_bots::HandleSyntheticSend(
            peer, data, size, send_type, channel);
    }
#endif
    return UsesEdf5CoopPolicy() && more_players::HandleSyntheticSend(
        peer, data, size, send_type, channel);
}

bool PeekSyntheticPacket(int channel, uint32_t* size) {
#if EDF5_COMPILE_DIAGNOSTICS
    if (UsesEdf41CoopPolicy()) {
        return edf41::room_bots::PeekSyntheticPacket(channel, size);
    }
#endif
    return UsesEdf5CoopPolicy() &&
        more_players::PeekSyntheticPacket(channel, size);
}

bool ReadSyntheticPacket(void* destination, uint32_t capacity,
                         uint32_t* message_size, uint64_t* peer, int channel) {
#if EDF5_COMPILE_DIAGNOSTICS
    if (UsesEdf41CoopPolicy()) {
        return edf41::room_bots::ReadSyntheticPacket(
            destination, capacity, message_size, peer, channel);
    }
#endif
    return UsesEdf5CoopPolicy() && more_players::ReadSyntheticPacket(
        destination, capacity, message_size, peer, channel);
}

void CloseSyntheticPeer(uint64_t peer) {
#if EDF5_COMPILE_DIAGNOSTICS
    if (UsesEdf41CoopPolicy()) {
        edf41::room_bots::CloseSyntheticPeer(peer);
        return;
    }
#endif
    if (UsesEdf5CoopPolicy()) more_players::CloseSyntheticPeer(peer);
}

void QueueSyntheticAuthValidation(uint64_t user) {
#if EDF5_COMPILE_DIAGNOSTICS
    if (UsesEdf41CoopPolicy()) {
        edf41::room_bots::QueueSyntheticAuthValidation(user);
        return;
    }
#endif
    if (UsesEdf5CoopPolicy()) {
        more_players::QueueSyntheticAuthValidation(user);
    }
}

}  // namespace steam_game_policy
