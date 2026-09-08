#include "room_bots.h"

#include "callback_dispatch.h"
#include "logger.h"
#include "native_roster_patch.h"
#include "steam_legacy_interfaces.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <deque>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace edf41::room_bots {
namespace {

constexpr int kLobbyCreatedCallback = 513;
constexpr int kLobbyChatUpdateCallback = 506;
constexpr int kValidateAuthTicketResponseCallback = 143;
constexpr int32_t kSteamResultOk = 1;
constexpr uint32_t kMemberEntered = 1;
constexpr uint32_t kMemberLeft = 2;
constexpr uint32_t kMaximumSyntheticPacketBytes = 4096;
constexpr unsigned kNativeRoomLimit = 4;
constexpr unsigned kMaximumRoomLimit = 8;

struct LobbyChatUpdate {
    uint64_t lobby;
    uint64_t changed_user;
    uint64_t making_change_user;
    uint32_t state_change;
};

#pragma pack(push, 4)
struct ValidateAuthTicketResponse {
    uint64_t validated_user;
    int32_t response;
    uint64_t owner;
};
#pragma pack(pop)

static_assert(sizeof(LobbyChatUpdate) == 32,
              "Steam LobbyChatUpdate payload layout changed");
static_assert(sizeof(ValidateAuthTicketResponse) == 20,
              "Steam auth callback payload layout changed");

struct MembershipChange {
    uint64_t lobby = 0;
    uint64_t user = 0;
    uint32_t state = 0;
};

struct SyntheticPacket {
    uint64_t peer = 0;
    int channel = 0;
    std::vector<uint8_t> bytes;
};

SRWLOCK g_state_lock = SRWLOCK_INIT;
std::deque<MembershipChange> g_membership_changes;
std::deque<SyntheticPacket> g_packets;
std::deque<uint64_t> g_auth_validations;
std::unordered_map<std::string, std::string> g_local_member_data;

std::atomic<bool> g_running{false};
std::atomic<bool> g_create_pending{false};
std::atomic<uint64_t> g_owned_lobby{0};
std::atomic<int> g_actual_members{-1};
std::atomic<unsigned> g_bot_count{0};
std::atomic<unsigned> g_add_requests{0};
std::atomic<unsigned> g_remove_requests{0};
bool g_add_hotkey_down = false;
bool g_remove_hotkey_down = false;

unsigned RoomLimit() {
    const capture::Config& config = capture::GetConfig();
    if (!config.edf41_experimental_room_overfill) {
        return config.edf41_native_safe_limit;
    }
    const unsigned requested = std::min({
        config.edf41_experimental_room_limit,
        config.edf41_target_players,
        kMaximumRoomLimit,
    });
    if (!native_roster_patch::Ready()) {
        return std::min(requested, kNativeRoomLimit);
    }
    return requested;
}

bool RoomOverfillQuarantined() {
    return capture::GetConfig().edf41_experimental_room_overfill &&
           !native_roster_patch::Ready();
}

uint64_t BotSteamId(unsigned index) {
    const uint64_t base = capture::GetConfig().edf41_bot_steam_id;
    const uint64_t prefix = base & 0xffffffff00000000ULL;
    const uint32_t account = static_cast<uint32_t>(base);
    const uint32_t derived = account >= index ? account - index
                                               : account + index;
    return prefix | derived;
}

bool TryBotIndex(uint64_t user, unsigned& index) {
    for (unsigned current = 0; current < kMaximumRoomLimit - 1; ++current) {
        if (BotSteamId(current) == user) {
            index = current;
            return true;
        }
    }
    return false;
}

bool AppliesToLobby(uint64_t lobby) {
    return g_running.load(std::memory_order_acquire) && lobby != 0 &&
           lobby == g_owned_lobby.load(std::memory_order_acquire);
}

bool StartsWith(const char* value, const char* prefix) {
    if (!value || !prefix) return false;
    const size_t prefix_length = std::strlen(prefix);
    return std::strncmp(value, prefix, prefix_length) == 0;
}

bool ResolveLocalMemberTemplate(uint64_t lobby, std::string& value,
                                uint64_t& local_user) {
    local_user = steam_capture::LocalUserSteamId();
    if (!local_user) return false;
    const std::string source_key = "usr" + std::to_string(local_user);

    AcquireSRWLockShared(&g_state_lock);
    const auto cached = g_local_member_data.find(source_key);
    const bool cached_present = cached != g_local_member_data.end() &&
                                !cached->second.empty();
    if (cached_present) value = cached->second;
    ReleaseSRWLockShared(&g_state_lock);
    if (cached_present) return true;

    if (!steam_capture::CopyActualLobbyMemberData(
            lobby, local_user, source_key.c_str(), value) || value.empty()) {
        return false;
    }
    AcquireSRWLockExclusive(&g_state_lock);
    g_local_member_data[source_key] = value;
    ReleaseSRWLockExclusive(&g_state_lock);
    EDF5_CAPTURE_EVENT(
        capture::Level::Info, "edf41_room_bots",
        "member_template_resolved",
        capture::Fields().UInt("lobby_steam_id", lobby)
            .UInt("source_user_steam_id", local_user)
            .UInt("template_bytes", value.size())
            .Bool("template_payload_logged", false));
    return true;
}

bool GameOwnsForeground() {
    const HWND foreground = GetForegroundWindow();
    if (!foreground) return false;
    DWORD process_id = 0;
    GetWindowThreadProcessId(foreground, &process_id);
    return process_id == GetCurrentProcessId();
}

void ClearState(bool keep_create_pending) {
    AcquireSRWLockExclusive(&g_state_lock);
    g_membership_changes.clear();
    g_packets.clear();
    g_auth_validations.clear();
    g_local_member_data.clear();
    ReleaseSRWLockExclusive(&g_state_lock);
    g_bot_count.store(0, std::memory_order_release);
    g_actual_members.store(-1, std::memory_order_release);
    g_owned_lobby.store(0, std::memory_order_release);
    if (!keep_create_pending) {
        g_create_pending.store(false, std::memory_order_release);
    }
}

void QueueMembershipChange(uint64_t lobby, uint64_t user, uint32_t state) {
    AcquireSRWLockExclusive(&g_state_lock);
    g_membership_changes.push_back({lobby, user, state});
    ReleaseSRWLockExclusive(&g_state_lock);
}

void ClearPeerState(uint64_t peer) {
    AcquireSRWLockExclusive(&g_state_lock);
    g_packets.erase(
        std::remove_if(g_packets.begin(), g_packets.end(),
                       [peer](const SyntheticPacket& packet) {
                           return packet.peer == peer;
                       }),
        g_packets.end());
    g_auth_validations.erase(
        std::remove(g_auth_validations.begin(), g_auth_validations.end(), peer),
        g_auth_validations.end());
    ReleaseSRWLockExclusive(&g_state_lock);
}

void ObserveActualMembers(uint64_t lobby, int actual_count) {
    if (!AppliesToLobby(lobby) || actual_count < 0) return;
    g_actual_members.store(actual_count, std::memory_order_release);

    std::vector<uint64_t> evicted;
    AcquireSRWLockExclusive(&g_state_lock);
    unsigned count = g_bot_count.load(std::memory_order_relaxed);
    const unsigned allowed = actual_count >= static_cast<int>(RoomLimit())
        ? 0U : RoomLimit() - static_cast<unsigned>(actual_count);
    while (count > allowed) {
        --count;
        const uint64_t user = BotSteamId(count);
        g_packets.erase(
            std::remove_if(g_packets.begin(), g_packets.end(),
                           [user](const SyntheticPacket& packet) {
                               return packet.peer == user;
                           }),
            g_packets.end());
        g_auth_validations.erase(
            std::remove(g_auth_validations.begin(),
                        g_auth_validations.end(), user),
            g_auth_validations.end());
        evicted.push_back(user);
    }
    g_bot_count.store(count, std::memory_order_release);
    for (uint64_t user : evicted) {
        g_membership_changes.push_back({lobby, user, kMemberLeft});
    }
    ReleaseSRWLockExclusive(&g_state_lock);

    for (uint64_t user : evicted) {
        EDF5_CAPTURE_EVENT(
            capture::Level::Info, "edf41_room_bots",
            "bot_evicted_for_real_member",
            capture::Fields().UInt("lobby_steam_id", lobby)
                .UInt("bot_steam_id", user)
                .Int("actual_members", actual_count)
                .UInt("synthetic_members", count)
                .UInt("effective_room_limit", RoomLimit()));
    }
}

bool ApplyAddRequest() {
    const uint64_t lobby = g_owned_lobby.load(std::memory_order_acquire);
    if (!AppliesToLobby(lobby)) {
        EDF5_CAPTURE_EVENT(capture::Level::Warning, "edf41_room_bots",
                           "add_rejected",
                           capture::Fields().String(
                               "reason", "no locally-created lobby"));
        return false;
    }

    const int queried = steam_capture::GetActualLobbyMemberCount(lobby);
    if (queried >= 0) ObserveActualMembers(lobby, queried);
    const int actual = g_actual_members.load(std::memory_order_acquire);
    if (actual < 1 || actual > static_cast<int>(RoomLimit())) {
        EDF5_CAPTURE_EVENT(
            capture::Level::Warning, "edf41_room_bots", "add_rejected",
            capture::Fields().String("reason", "unsafe member count")
                .UInt("lobby_steam_id", lobby)
                .Int("actual_members", actual)
                .UInt("effective_room_limit", RoomLimit()));
        return false;
    }

    std::string member_template;
    uint64_t local_user = 0;
    if (!ResolveLocalMemberTemplate(lobby, member_template, local_user)) {
        EDF5_CAPTURE_EVENT(
            capture::Level::Warning, "edf41_room_bots", "add_rejected",
            capture::Fields().String(
                "reason", "local member data unavailable")
                .UInt("lobby_steam_id", lobby)
                .UInt("local_user_steam_id", local_user)
                .Bool("ghost_member_created", false));
        return false;
    }

    unsigned count = g_bot_count.load(std::memory_order_acquire);
    const unsigned allowed = RoomLimit() - static_cast<unsigned>(actual);
    if (count >= allowed) {
        EDF5_CAPTURE_EVENT(
            capture::Level::Warning, "edf41_room_bots", "add_rejected",
            capture::Fields().String(
                "reason", RoomOverfillQuarantined()
                    ? "native roster capacity not expanded"
                    : "configured room limit reached")
                .UInt("lobby_steam_id", lobby)
                .Int("actual_members", actual)
                .UInt("synthetic_members", count)
                .UInt("effective_room_limit", RoomLimit()));
        return false;
    }

    const uint64_t user = BotSteamId(count);
    ++count;
    g_bot_count.store(count, std::memory_order_release);
    QueueMembershipChange(lobby, user, kMemberEntered);
    EDF5_CAPTURE_EVENT(
        capture::Level::Info, "edf41_room_bots", "bot_added",
        capture::Fields().UInt("lobby_steam_id", lobby)
            .UInt("bot_steam_id", user)
            .UInt("bot_number", count)
            .Int("actual_members", actual)
            .UInt("synthetic_members", count)
            .UInt("reported_members",
                  static_cast<unsigned>(actual) + count)
            .UInt("native_safe_limit", kNativeRoomLimit)
            .UInt("effective_room_limit", RoomLimit())
            .UInt("target_players",
                  capture::GetConfig().edf41_target_players));
    return true;
}

bool ApplyRemoveRequest() {
    const uint64_t lobby = g_owned_lobby.load(std::memory_order_acquire);
    unsigned count = g_bot_count.load(std::memory_order_acquire);
    if (!AppliesToLobby(lobby) || count == 0) {
        EDF5_CAPTURE_EVENT(capture::Level::Warning, "edf41_room_bots",
                           "remove_rejected",
                           capture::Fields().String(
                               "reason", "no synthetic room member"));
        return false;
    }
    --count;
    const uint64_t user = BotSteamId(count);
    g_bot_count.store(count, std::memory_order_release);
    ClearPeerState(user);
    QueueMembershipChange(lobby, user, kMemberLeft);
    EDF5_CAPTURE_EVENT(
        capture::Level::Info, "edf41_room_bots", "bot_removed",
        capture::Fields().UInt("lobby_steam_id", lobby)
            .UInt("bot_steam_id", user)
            .UInt("synthetic_members", count));
    return true;
}

void DispatchMembershipChange() {
    MembershipChange change;
    AcquireSRWLockShared(&g_state_lock);
    const bool available = !g_membership_changes.empty();
    if (available) change = g_membership_changes.front();
    ReleaseSRWLockShared(&g_state_lock);
    if (!available) return;

    const LobbyChatUpdate update{
        change.lobby, change.user, change.user, change.state};
    const unsigned dispatched = sniffer::callback_dispatch::DispatchSyntheticCallback(
        kLobbyChatUpdateCallback, &update, sizeof(update));
    if (!dispatched) return;

    AcquireSRWLockExclusive(&g_state_lock);
    if (!g_membership_changes.empty()) {
        const MembershipChange& front = g_membership_changes.front();
        if (front.lobby == change.lobby && front.user == change.user &&
            front.state == change.state) {
            g_membership_changes.pop_front();
        }
    }
    ReleaseSRWLockExclusive(&g_state_lock);
    EDF5_CAPTURE_EVENT(
        capture::Level::Info, "edf41_room_bots",
        "lobby_chat_update_dispatched",
        capture::Fields().UInt("lobby_steam_id", change.lobby)
            .UInt("user_steam_id", change.user)
            .UInt("state_change", change.state)
            .UInt("callbacks", dispatched));
}

void DispatchAuthValidation() {
    uint64_t user = 0;
    AcquireSRWLockShared(&g_state_lock);
    const bool available = !g_auth_validations.empty();
    if (available) user = g_auth_validations.front();
    ReleaseSRWLockShared(&g_state_lock);
    if (!available) return;

    const ValidateAuthTicketResponse update{user, 0, user};
    const unsigned dispatched = sniffer::callback_dispatch::DispatchSyntheticCallback(
        kValidateAuthTicketResponseCallback, &update, sizeof(update));
    if (!dispatched) return;

    AcquireSRWLockExclusive(&g_state_lock);
    if (!g_auth_validations.empty() && g_auth_validations.front() == user) {
        g_auth_validations.pop_front();
    }
    ReleaseSRWLockExclusive(&g_state_lock);
    EDF5_CAPTURE_EVENT(
        capture::Level::Info, "edf41_room_bots",
        "auth_validation_dispatched",
        capture::Fields().UInt("user_steam_id", user)
            .Int("response", 0)
            .UInt("callbacks", dispatched));
}

void PollHotkeys() {
    if (!GameOwnsForeground()) {
        g_add_hotkey_down = false;
        g_remove_hotkey_down = false;
        return;
    }
    const bool add_down =
        (GetAsyncKeyState(static_cast<int>(
             capture::GetConfig().edf41_bot_hotkey_vk)) & 0x8000) != 0;
    const bool remove_down =
        (GetAsyncKeyState(static_cast<int>(
             capture::GetConfig().edf41_bot_remove_hotkey_vk)) & 0x8000) != 0;
    if (add_down && !g_add_hotkey_down) {
        g_add_requests.fetch_add(1, std::memory_order_acq_rel);
    }
    if (remove_down && !g_remove_hotkey_down) {
        g_remove_requests.fetch_add(1, std::memory_order_acq_rel);
    }
    g_add_hotkey_down = add_down;
    g_remove_hotkey_down = remove_down;
}

}  // namespace

bool Start() {
    ClearState(false);
    g_add_requests.store(0, std::memory_order_release);
    g_remove_requests.store(0, std::memory_order_release);
    g_running.store(capture::GetConfig().edf41.coop8,
                    std::memory_order_release);
    EDF5_CAPTURE_EVENT(
        capture::Level::Info, "edf41_room_bots", "started",
        capture::Fields().Bool("enabled", g_running.load())
            .UInt("target_players",
                  capture::GetConfig().edf41_target_players)
            .UInt("native_safe_limit", kNativeRoomLimit)
            .Bool("experimental_room_overfill",
                  capture::GetConfig().edf41_experimental_room_overfill)
            .Bool("native_roster_expansion_ready",
                  native_roster_patch::Ready())
            .Bool("room_overfill_quarantined",
                  RoomOverfillQuarantined())
            .UInt("effective_room_limit", RoomLimit())
            .UInt("add_hotkey_vk",
                  capture::GetConfig().edf41_bot_hotkey_vk)
            .UInt("remove_hotkey_vk",
                  capture::GetConfig().edf41_bot_remove_hotkey_vk)
            .Bool("game_memory_patches", native_roster_patch::Ready())
            .Bool("players_above_native_limit",
                  RoomLimit() > kNativeRoomLimit)
            .Bool("mission_launch_supported", false));
    return g_running.load(std::memory_order_acquire);
}

void RequestStop() {
    g_running.store(false, std::memory_order_release);
    ClearState(false);
}

void Pump() {
    if (!g_running.load(std::memory_order_acquire)) return;
    PollHotkeys();
    unsigned remove_requests =
        g_remove_requests.exchange(0, std::memory_order_acq_rel);
    unsigned add_requests =
        g_add_requests.exchange(0, std::memory_order_acq_rel);
    while (remove_requests-- > 0) ApplyRemoveRequest();
    while (add_requests-- > 0) ApplyAddRequest();
    DispatchMembershipChange();
    DispatchAuthValidation();
}

bool RequestAddFromApi() {
    if (!g_running.load(std::memory_order_acquire)) return false;
    g_add_requests.fetch_add(1, std::memory_order_acq_rel);
    return true;
}

bool RequestRemoveFromApi() {
    if (!g_running.load(std::memory_order_acquire)) return false;
    g_remove_requests.fetch_add(1, std::memory_order_acq_rel);
    return true;
}

unsigned Count() {
    return g_bot_count.load(std::memory_order_acquire);
}

void ObserveSteamCallback(int callback_id, const void* payload,
                          unsigned payload_bytes, bool call_result,
                          bool io_failure) {
    if (!g_running.load(std::memory_order_acquire) || !payload) return;
    if (callback_id != kLobbyCreatedCallback || !call_result || io_failure ||
        payload_bytes < 16 ||
        !g_create_pending.exchange(false, std::memory_order_acq_rel)) {
        return;
    }
    int32_t result = 0;
    uint64_t lobby = 0;
    std::memcpy(&result, payload, sizeof(result));
    std::memcpy(&lobby, static_cast<const uint8_t*>(payload) + 8,
                sizeof(lobby));
    if (result != kSteamResultOk || !lobby) {
        EDF5_CAPTURE_EVENT(
            capture::Level::Warning, "edf41_room_bots",
            "owned_lobby_not_created",
            capture::Fields().Int("result", result)
                .UInt("lobby_steam_id", lobby));
        return;
    }
    g_owned_lobby.store(lobby, std::memory_order_release);
    const int actual = steam_capture::GetActualLobbyMemberCount(lobby);
    if (actual >= 0) g_actual_members.store(actual, std::memory_order_release);
    EDF5_CAPTURE_EVENT(
        capture::Level::Info, "edf41_room_bots", "owned_lobby_detected",
        capture::Fields().UInt("lobby_steam_id", lobby)
            .Int("actual_members", actual)
            .UInt("native_safe_limit", kNativeRoomLimit)
            .UInt("effective_room_limit", RoomLimit())
            .UInt("target_players",
                  capture::GetConfig().edf41_target_players));
}

bool TryGetBotName(uint64_t user, std::string& name) {
    unsigned index = 0;
    if (!TryBotIndex(user, index) ||
        index >= g_bot_count.load(std::memory_order_acquire)) {
        return false;
    }
    name = "EDF41 Bot " + std::to_string(index + 1);
    return true;
}

int EffectiveCreateLimit(int requested) {
    // Phase one intentionally preserves EDF 4.1's native lobby boundary.
    return requested;
}

int EffectiveMemberLimit(uint64_t, int requested) {
    return requested;
}

void NotifyCreateLobby(int requested, int effective) {
    if (!g_running.load(std::memory_order_acquire)) return;
    ClearState(true);
    g_create_pending.store(true, std::memory_order_release);
    EDF5_CAPTURE_EVENT(
        capture::Level::Info, "edf41_room_bots", "create_lobby_armed",
        capture::Fields().Int("requested_limit", requested)
            .Int("effective_limit", effective)
            .UInt("native_safe_limit", kNativeRoomLimit)
            .UInt("effective_room_limit", RoomLimit())
            .UInt("target_players",
                  capture::GetConfig().edf41_target_players)
            .Bool("limit_expanded", effective != requested));
}

void NotifyJoinLobby(uint64_t lobby) {
    if (!g_running.load(std::memory_order_acquire)) return;
    ClearState(false);
    EDF5_CAPTURE_EVENT(
        capture::Level::Info, "edf41_room_bots", "remote_lobby_observed",
        capture::Fields().UInt("lobby_steam_id", lobby)
            .Bool("bots_allowed", false)
            .String("reason", "only locally-created lobbies are writable"));
}

void ObserveLobbyDataWrite(uint64_t, const char*) {}

void ObserveLeaveLobby(uint64_t lobby) {
    if (!AppliesToLobby(lobby)) return;
    EDF5_CAPTURE_EVENT(
        capture::Level::Info, "edf41_room_bots", "owned_lobby_left",
        capture::Fields().UInt("lobby_steam_id", lobby)
            .UInt("synthetic_members", Count()));
    ClearState(false);
}

bool RewriteLobbyData(uint64_t, const char*, const char*, std::string&) {
    return false;
}

int AdjustMemberCount(uint64_t lobby, int actual_count) {
    if (!AppliesToLobby(lobby) || actual_count < 0) return actual_count;
    const unsigned bots = g_bot_count.load(std::memory_order_acquire);
    return std::min<int>(static_cast<int>(RoomLimit()),
                         actual_count + static_cast<int>(bots));
}

void ObserveMemberCount(uint64_t lobby, int actual_count) {
    ObserveActualMembers(lobby, actual_count);
}

bool TryGetSyntheticMember(uint64_t lobby, int actual_count, int index,
                           uint64_t& user) {
    if (!AppliesToLobby(lobby) || actual_count < 0 || index < actual_count ||
        index >= static_cast<int>(RoomLimit())) {
        return false;
    }
    const unsigned synthetic_index =
        static_cast<unsigned>(index - actual_count);
    if (synthetic_index >= g_bot_count.load(std::memory_order_acquire)) {
        return false;
    }
    user = BotSteamId(synthetic_index);
    return true;
}

bool TryGetMemberData(uint64_t lobby, uint64_t user, const char* key,
                      std::string& value) {
    unsigned index = 0;
    if (!AppliesToLobby(lobby) || !key || !TryBotIndex(user, index) ||
        index >= g_bot_count.load(std::memory_order_acquire)) {
        return false;
    }
    if (!StartsWith(key, "usr")) return false;
    uint64_t local_user = 0;
    return ResolveLocalMemberTemplate(lobby, value, local_user);
}

void CaptureLocalMemberData(const char* key, const char* value) {
    if (!g_running.load(std::memory_order_acquire) || !key || !*key ||
        !value || std::strlen(key) > 128 || std::strlen(value) > 2048) {
        return;
    }
    AcquireSRWLockExclusive(&g_state_lock);
    if (g_local_member_data.size() < 64 ||
        g_local_member_data.find(key) != g_local_member_data.end()) {
        g_local_member_data[key] = value;
    }
    ReleaseSRWLockExclusive(&g_state_lock);
}

bool IsSyntheticPeer(uint64_t peer) {
    unsigned index = 0;
    return TryBotIndex(peer, index) &&
           index < g_bot_count.load(std::memory_order_acquire);
}

bool IsSyntheticIdentity(uint64_t peer) {
    unsigned index = 0;
    return TryBotIndex(peer, index);
}

void ObserveRealP2PSend(uint64_t, int, size_t, bool) {}

bool HandleSyntheticSend(uint64_t peer, const void* data, uint32_t size,
                         int send_type, int channel) {
    if (!IsSyntheticPeer(peer)) return false;
    bool reply_queued = false;
    if (channel == 2 && data && size > 0 &&
        size <= kMaximumSyntheticPacketBytes) {
        SyntheticPacket packet;
        packet.peer = peer;
        packet.channel = channel;
        const auto* begin = static_cast<const uint8_t*>(data);
        packet.bytes.assign(begin, begin + size);
        AcquireSRWLockExclusive(&g_state_lock);
        g_packets.push_back(std::move(packet));
        ReleaseSRWLockExclusive(&g_state_lock);
        reply_queued = true;
    }
    EDF5_CAPTURE_EVENT(
        capture::Level::Info, "edf41_room_bots", "synthetic_p2p_send",
        capture::Fields().UInt("peer_steam_id", peer)
            .Int("channel", channel)
            .Int("send_type", send_type)
            .UInt("bytes", size)
            .Bool("consumed", true)
            .Bool("auth_ticket_echo_queued", reply_queued));
    return true;
}

bool PeekSyntheticPacket(int channel, uint32_t* size) {
    AcquireSRWLockShared(&g_state_lock);
    const auto found = std::find_if(
        g_packets.begin(), g_packets.end(),
        [channel](const SyntheticPacket& packet) {
            return packet.channel == channel;
        });
    const bool present = found != g_packets.end();
    if (present && size) *size = static_cast<uint32_t>(found->bytes.size());
    ReleaseSRWLockShared(&g_state_lock);
    return present;
}

bool ReadSyntheticPacket(void* destination, uint32_t capacity,
                         uint32_t* message_size, uint64_t* peer,
                         int channel) {
    SyntheticPacket packet;
    bool available = false;
    AcquireSRWLockExclusive(&g_state_lock);
    const auto found = std::find_if(
        g_packets.begin(), g_packets.end(),
        [channel](const SyntheticPacket& item) {
            return item.channel == channel;
        });
    if (found != g_packets.end()) {
        if (message_size) {
            *message_size = static_cast<uint32_t>(found->bytes.size());
        }
        if (destination && capacity >= found->bytes.size()) {
            packet = std::move(*found);
            g_packets.erase(found);
            available = true;
        }
    }
    ReleaseSRWLockExclusive(&g_state_lock);
    if (!available) return false;
    std::memcpy(destination, packet.bytes.data(), packet.bytes.size());
    if (message_size) *message_size = static_cast<uint32_t>(packet.bytes.size());
    if (peer) *peer = packet.peer;
    EDF5_CAPTURE_EVENT(
        capture::Level::Info, "edf41_room_bots", "synthetic_p2p_read",
        capture::Fields().UInt("peer_steam_id", packet.peer)
            .Int("channel", channel)
            .UInt("bytes", packet.bytes.size()));
    return true;
}

void CloseSyntheticPeer(uint64_t peer) {
    if (IsSyntheticIdentity(peer)) ClearPeerState(peer);
}

void QueueSyntheticAuthValidation(uint64_t user) {
    if (!IsSyntheticPeer(user)) return;
    AcquireSRWLockExclusive(&g_state_lock);
    if (std::find(g_auth_validations.begin(), g_auth_validations.end(), user) ==
        g_auth_validations.end()) {
        g_auth_validations.push_back(user);
    }
    ReleaseSRWLockExclusive(&g_state_lock);
}

}  // namespace edf41::room_bots
