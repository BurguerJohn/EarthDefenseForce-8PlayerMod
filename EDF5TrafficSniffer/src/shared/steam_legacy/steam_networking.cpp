#include "steam_legacy_interfaces.h"

#include "logger.h"
#include "steam_game_policy.h"

#include <algorithm>
#include <cstdint>
#include <cstring>

namespace steam_capture {
namespace {

using SteamId = uint64_t;
using NetSocket = uint32_t;
using ListenSocket = uint32_t;

#pragma pack(push, 8)
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

using SendP2PFn = bool (*)(void*, SteamId, const void*, uint32_t, int, int);
using IsP2PAvailableFn = bool (*)(void*, uint32_t*, int);
using ReadP2PFn = bool (*)(void*, void*, uint32_t, uint32_t*, SteamId*, int);
using PeerFn = bool (*)(void*, SteamId);
using CloseChannelFn = bool (*)(void*, SteamId, int);
using SessionStateFn = bool (*)(void*, SteamId, P2PSessionState*);
using RelayFn = bool (*)(void*, bool);
using CreateListenFn = ListenSocket (*)(void*, int, uint32_t, uint16_t, bool);
using CreateP2PSocketFn = NetSocket (*)(void*, SteamId, int, int, bool);
using CreateSocketFn = NetSocket (*)(void*, uint32_t, uint16_t, int);
using DestroySocketFn = bool (*)(void*, NetSocket, bool);
using SendSocketFn = bool (*)(void*, NetSocket, void*, uint32_t, bool);
using IsSocketAvailableFn = bool (*)(void*, NetSocket, uint32_t*);
using RetrieveSocketFn = bool (*)(void*, NetSocket, void*, uint32_t, uint32_t*);
using IsListenAvailableFn = bool (*)(void*, ListenSocket, uint32_t*, NetSocket*);
using RetrieveListenFn = bool (*)(void*, ListenSocket, void*, uint32_t, uint32_t*, NetSocket*);
using SocketInfoFn = bool (*)(void*, NetSocket, SteamId*, int*, uint32_t*, uint16_t*);
using ListenInfoFn = bool (*)(void*, ListenSocket, uint32_t*, uint16_t*);
using SocketIntFn = int (*)(void*, NetSocket);

SendP2PFn o_send_p2p;
IsP2PAvailableFn o_is_p2p_available;
ReadP2PFn o_read_p2p;
PeerFn o_accept_peer;
PeerFn o_close_peer;
CloseChannelFn o_close_channel;
SessionStateFn o_session_state;
RelayFn o_allow_relay;
CreateListenFn o_create_listen;
CreateP2PSocketFn o_create_p2p_socket;
CreateSocketFn o_create_socket;
DestroySocketFn o_destroy_socket;
DestroySocketFn o_destroy_listen;
SendSocketFn o_send_socket;
IsSocketAvailableFn o_is_socket_available;
RetrieveSocketFn o_retrieve_socket;
IsListenAvailableFn o_is_listen_available;
RetrieveListenFn o_retrieve_listen;
SocketInfoFn o_socket_info;
ListenInfoFn o_listen_info;
SocketIntFn o_connection_type;
SocketIntFn o_max_packet;

SRWLOCK g_network_lock = SRWLOCK_INIT;
void* g_network_interface = nullptr;
void* g_network_vtable[22]{};

uint64_t ProcessImageRva(const void* address) {
    if (!address) return 0;
    const auto* base = reinterpret_cast<const uint8_t*>(
        GetModuleHandleW(nullptr));
    if (!base) return 0;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) return 0;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return 0;
    }
    const uintptr_t begin = reinterpret_cast<uintptr_t>(base);
    const uintptr_t current = reinterpret_cast<uintptr_t>(address);
    const uintptr_t end = begin + nt->OptionalHeader.SizeOfImage;
    return current >= begin && current < end ? current - begin : 0;
}

bool SendP2P(void* self, SteamId peer, const void* data, uint32_t size, int send_type, int channel) {
#if defined(__clang__) || defined(__GNUC__)
    const uint64_t caller_rva = ProcessImageRva(__builtin_return_address(0));
#else
    const uint64_t caller_rva = 0;
#endif
    const bool synthetic = steam_game_policy::IsSyntheticPeer(peer);
    const bool result = synthetic
        ? steam_game_policy::HandleSyntheticSend(
              peer, data, size, send_type, channel)
        : o_send_p2p(self, peer, data, size, send_type, channel);
    if (!synthetic) {
        steam_game_policy::ObserveRealP2PSend(peer, channel, size, result);
    }
    EDF5_CAPTURE_RECORD_P2P(true, peer, channel, size, result, synthetic,
                       caller_rva);
    EDF5_CAPTURE_EVENT("steam_p2p", "send",
                   capture::Fields().String("direction", "out")
                       .UInt("peer_steam_id", peer)
                       .Int("channel", channel)
                       .Int("send_type", send_type)
                       .UInt("caller_rva", caller_rva)
                       .Bool("caller_in_process_image", caller_rva != 0)
                       .UInt("requested_bytes", size)
                       .Bool("synthetic", synthetic)
                       .Bool("result", result),
                   data, size);
    return result;
}

bool IsP2PAvailable(void* self, uint32_t* size, int channel) {
    const bool synthetic =
        steam_game_policy::PeekSyntheticPacket(channel, size);
    const bool result = synthetic ? true : o_is_p2p_available(self, size, channel);
    if (result) {
        EDF5_CAPTURE_EVENT("steam_p2p", "packet_available",
                       capture::Fields().Int("channel", channel)
                           .UInt("packet_bytes", size ? *size : 0)
                           .Bool("synthetic", synthetic)
                           .Bool("result", result));
    }
    return result;
}

bool ReadP2P(void* self, void* destination, uint32_t capacity, uint32_t* message_size,
             SteamId* peer, int channel) {
#if defined(__clang__) || defined(__GNUC__)
    const uint64_t caller_rva = ProcessImageRva(__builtin_return_address(0));
#else
    const uint64_t caller_rva = 0;
#endif
    uint32_t synthetic_size = 0;
    const bool synthetic = steam_game_policy::PeekSyntheticPacket(
        channel, &synthetic_size);
    const bool result = synthetic
        ? steam_game_policy::ReadSyntheticPacket(
              destination, capacity, message_size, peer, channel)
        : o_read_p2p(self, destination, capacity, message_size, peer, channel);
    const uint32_t reported = message_size ? *message_size : 0;
    const uint32_t captured = result ? std::min(capacity, reported) : 0;
    EDF5_CAPTURE_RECORD_P2P(false, peer && result ? *peer : 0, channel, captured,
                       result, synthetic, caller_rva);
    EDF5_CAPTURE_EVENT("steam_p2p", "read",
                   capture::Fields().String("direction", "in")
                       .UInt("peer_steam_id", peer && result ? *peer : 0)
                       .Int("channel", channel)
                       .UInt("caller_rva", caller_rva)
                       .Bool("caller_in_process_image", caller_rva != 0)
                       .UInt("buffer_capacity", capacity)
                       .UInt("reported_bytes", reported)
                       .UInt("captured_bytes", captured)
                       .Bool("caller_buffer_truncated", reported > capacity)
                       .Bool("synthetic", synthetic)
                       .Bool("result", result),
                   destination, captured);
    return result;
}

bool AcceptPeer(void* self, SteamId peer) {
    const bool synthetic = steam_game_policy::IsSyntheticPeer(peer);
    const bool result = synthetic ? true : o_accept_peer(self, peer);
    EDF5_CAPTURE_EVENT("steam_p2p", "accept_session",
                   capture::Fields().UInt("peer_steam_id", peer)
                       .Bool("synthetic", synthetic).Bool("result", result));
    return result;
}

bool ClosePeer(void* self, SteamId peer) {
    const bool synthetic = steam_game_policy::IsSyntheticIdentity(peer);
    if (synthetic) steam_game_policy::CloseSyntheticPeer(peer);
    const bool result = synthetic ? true : o_close_peer(self, peer);
    EDF5_CAPTURE_EVENT("steam_p2p", "close_session",
                   capture::Fields().UInt("peer_steam_id", peer)
                       .Bool("synthetic", synthetic).Bool("result", result));
    return result;
}

bool CloseChannel(void* self, SteamId peer, int channel) {
    const bool synthetic = steam_game_policy::IsSyntheticIdentity(peer);
    if (synthetic) steam_game_policy::CloseSyntheticPeer(peer);
    const bool result = synthetic ? true : o_close_channel(self, peer, channel);
    EDF5_CAPTURE_EVENT("steam_p2p", "close_channel",
                   capture::Fields().UInt("peer_steam_id", peer)
                       .Int("channel", channel).Bool("synthetic", synthetic)
                       .Bool("result", result));
    return result;
}

bool GetSessionState(void* self, SteamId peer, P2PSessionState* state) {
    const bool synthetic = steam_game_policy::IsSyntheticPeer(peer);
    bool result = false;
    if (synthetic && state) {
        std::memset(state, 0, sizeof(*state));
        state->connection_active = 1;
        state->remote_ip = 0x0100007f;
        result = true;
    } else {
        result = o_session_state(self, peer, state);
    }
#if EDF5_COMPILE_DIAGNOSTICS
    capture::Fields fields;
    fields.UInt("peer_steam_id", peer).Bool("synthetic", synthetic).Bool("result", result);
    if (result && state) {
        fields.Bool("connection_active", state->connection_active != 0)
            .Bool("connecting", state->connecting != 0)
            .Int("session_error", state->session_error)
            .Bool("using_relay", state->using_relay != 0)
            .Int("bytes_queued_for_send", state->bytes_queued_for_send)
            .Int("packets_queued_for_send", state->packets_queued_for_send)
            .UInt("remote_ip_u32", state->remote_ip)
            .String("remote_ip_memory_order", capture::IpV4(state->remote_ip))
            .UInt("remote_port", state->remote_port);
    }
    EDF5_CAPTURE_EVENT("steam_p2p", "session_state", fields);
#endif
    return result;
}

bool AllowRelay(void* self, bool allow) {
    const bool result = o_allow_relay(self, allow);
    EDF5_CAPTURE_EVENT("steam_p2p", "allow_relay",
                   capture::Fields().Bool("allow", allow).Bool("result", result));
    return result;
}

ListenSocket CreateListen(void* self, int virtual_port, uint32_t ip, uint16_t port, bool relay) {
    const ListenSocket result = o_create_listen(self, virtual_port, ip, port, relay);
    EDF5_CAPTURE_EVENT("steam_socket", "create_listen",
                   capture::Fields().Int("virtual_port", virtual_port)
                       .UInt("ip_u32", ip).String("ip_memory_order", capture::IpV4(ip))
                       .UInt("port", port).Bool("allow_relay", relay)
                       .UInt("listen_socket", result));
    return result;
}

NetSocket CreateP2PSocket(void* self, SteamId peer, int virtual_port, int timeout, bool relay) {
    const NetSocket result = o_create_p2p_socket(self, peer, virtual_port, timeout, relay);
    EDF5_CAPTURE_EVENT("steam_socket", "create_p2p_connection",
                   capture::Fields().UInt("peer_steam_id", peer)
                       .Int("virtual_port", virtual_port).Int("timeout_seconds", timeout)
                       .Bool("allow_relay", relay).UInt("socket", result));
    return result;
}

NetSocket CreateSocket(void* self, uint32_t ip, uint16_t port, int timeout) {
    const NetSocket result = o_create_socket(self, ip, port, timeout);
    EDF5_CAPTURE_EVENT("steam_socket", "create_connection",
                   capture::Fields().UInt("ip_u32", ip)
                       .String("ip_memory_order", capture::IpV4(ip))
                       .UInt("port", port).Int("timeout_seconds", timeout)
                       .UInt("socket", result));
    return result;
}

bool DestroySocket(void* self, NetSocket socket, bool notify) {
    const bool result = o_destroy_socket(self, socket, notify);
    EDF5_CAPTURE_EVENT("steam_socket", "destroy",
                   capture::Fields().UInt("socket", socket)
                       .Bool("notify_remote", notify).Bool("result", result));
    return result;
}

bool DestroyListen(void* self, ListenSocket socket, bool notify) {
    const bool result = o_destroy_listen(self, socket, notify);
    EDF5_CAPTURE_EVENT("steam_socket", "destroy_listen",
                   capture::Fields().UInt("listen_socket", socket)
                       .Bool("notify_remote", notify).Bool("result", result));
    return result;
}

bool SendSocket(void* self, NetSocket socket, void* data, uint32_t size, bool reliable) {
    const bool result = o_send_socket(self, socket, data, size, reliable);
    EDF5_CAPTURE_EVENT("steam_socket", "send",
                   capture::Fields().String("direction", "out").UInt("socket", socket)
                       .UInt("requested_bytes", size).Bool("reliable", reliable)
                       .Bool("result", result), data, size);
    return result;
}

bool IsSocketAvailable(void* self, NetSocket socket, uint32_t* size) {
    const bool result = o_is_socket_available(self, socket, size);
    if (result) EDF5_CAPTURE_EVENT("steam_socket", "data_available",
                              capture::Fields().UInt("socket", socket)
                                  .UInt("packet_bytes", size ? *size : 0));
    return result;
}

bool RetrieveSocket(void* self, NetSocket socket, void* destination, uint32_t capacity,
                    uint32_t* message_size) {
    const bool result = o_retrieve_socket(self, socket, destination, capacity, message_size);
    const uint32_t reported = message_size ? *message_size : 0;
    const uint32_t captured = result ? std::min(capacity, reported) : 0;
    EDF5_CAPTURE_EVENT("steam_socket", "retrieve",
                   capture::Fields().String("direction", "in").UInt("socket", socket)
                       .UInt("buffer_capacity", capacity).UInt("reported_bytes", reported)
                       .UInt("captured_bytes", captured).Bool("result", result),
                   destination, captured);
    return result;
}

bool IsListenAvailable(void* self, ListenSocket listen, uint32_t* size, NetSocket* socket) {
    const bool result = o_is_listen_available(self, listen, size, socket);
    if (result) EDF5_CAPTURE_EVENT("steam_socket", "listen_data_available",
                              capture::Fields().UInt("listen_socket", listen)
                                  .UInt("socket", socket ? *socket : 0)
                                  .UInt("packet_bytes", size ? *size : 0));
    return result;
}

bool RetrieveListen(void* self, ListenSocket listen, void* destination, uint32_t capacity,
                    uint32_t* message_size, NetSocket* socket) {
    const bool result = o_retrieve_listen(self, listen, destination, capacity, message_size, socket);
    const uint32_t reported = message_size ? *message_size : 0;
    const uint32_t captured = result ? std::min(capacity, reported) : 0;
    EDF5_CAPTURE_EVENT("steam_socket", "retrieve_from_listen",
                   capture::Fields().String("direction", "in").UInt("listen_socket", listen)
                       .UInt("socket", socket && result ? *socket : 0)
                       .UInt("buffer_capacity", capacity).UInt("reported_bytes", reported)
                       .UInt("captured_bytes", captured).Bool("result", result),
                   destination, captured);
    return result;
}

bool GetSocketInfo(void* self, NetSocket socket, SteamId* peer, int* status,
                   uint32_t* ip, uint16_t* port) {
    const bool result = o_socket_info(self, socket, peer, status, ip, port);
    EDF5_CAPTURE_EVENT("steam_socket", "get_info",
                   capture::Fields().UInt("socket", socket).Bool("result", result)
                       .UInt("peer_steam_id", peer && result ? *peer : 0)
                       .Int("status", status && result ? *status : 0)
                       .UInt("ip_u32", ip && result ? *ip : 0)
                       .String("ip_memory_order", ip && result ? capture::IpV4(*ip) : "")
                       .UInt("port", port && result ? *port : 0));
    return result;
}

bool GetListenInfo(void* self, ListenSocket socket, uint32_t* ip, uint16_t* port) {
    const bool result = o_listen_info(self, socket, ip, port);
    EDF5_CAPTURE_EVENT("steam_socket", "get_listen_info",
                   capture::Fields().UInt("listen_socket", socket).Bool("result", result)
                       .UInt("ip_u32", ip && result ? *ip : 0)
                       .String("ip_memory_order", ip && result ? capture::IpV4(*ip) : "")
                       .UInt("port", port && result ? *port : 0));
    return result;
}

int GetConnectionType(void* self, NetSocket socket) {
    const int result = o_connection_type(self, socket);
    EDF5_CAPTURE_EVENT("steam_socket", "get_connection_type",
                   capture::Fields().UInt("socket", socket).Int("connection_type", result));
    return result;
}

int GetMaxPacket(void* self, NetSocket socket) {
    const int result = o_max_packet(self, socket);
    EDF5_CAPTURE_EVENT("steam_socket", "get_max_packet_size",
                   capture::Fields().UInt("socket", socket).Int("max_packet_bytes", result));
    return result;
}

#define INSTALL_SLOT(index, original, replacement, label) \
    original = reinterpret_cast<decltype(original)>(vtable[index]); \
    g_network_vtable[index] = reinterpret_cast<void*>(&replacement); \
    installed += original != nullptr

}  // namespace

void HookNetworking(void* interface_pointer) {
    if (!interface_pointer) return;
    AcquireSRWLockExclusive(&g_network_lock);
    if (g_network_interface) {
        ReleaseSRWLockExclusive(&g_network_lock);
        return;
    }
    void** vtable = *reinterpret_cast<void***>(interface_pointer);
    for (unsigned i = 0; i < 22; ++i) g_network_vtable[i] = vtable[i];
    unsigned installed = 0;
    INSTALL_SLOT(0, o_send_p2p, SendP2P, "ISteamNetworking005::SendP2PPacket");
    INSTALL_SLOT(1, o_is_p2p_available, IsP2PAvailable, "ISteamNetworking005::IsP2PPacketAvailable");
    INSTALL_SLOT(2, o_read_p2p, ReadP2P, "ISteamNetworking005::ReadP2PPacket");
    INSTALL_SLOT(3, o_accept_peer, AcceptPeer, "ISteamNetworking005::AcceptP2PSessionWithUser");
    INSTALL_SLOT(4, o_close_peer, ClosePeer, "ISteamNetworking005::CloseP2PSessionWithUser");
    INSTALL_SLOT(5, o_close_channel, CloseChannel, "ISteamNetworking005::CloseP2PChannelWithUser");
    INSTALL_SLOT(6, o_session_state, GetSessionState, "ISteamNetworking005::GetP2PSessionState");
    INSTALL_SLOT(7, o_allow_relay, AllowRelay, "ISteamNetworking005::AllowP2PPacketRelay");
    INSTALL_SLOT(8, o_create_listen, CreateListen, "ISteamNetworking005::CreateListenSocket");
    INSTALL_SLOT(9, o_create_p2p_socket, CreateP2PSocket, "ISteamNetworking005::CreateP2PConnectionSocket");
    INSTALL_SLOT(10, o_create_socket, CreateSocket, "ISteamNetworking005::CreateConnectionSocket");
    INSTALL_SLOT(11, o_destroy_socket, DestroySocket, "ISteamNetworking005::DestroySocket");
    INSTALL_SLOT(12, o_destroy_listen, DestroyListen, "ISteamNetworking005::DestroyListenSocket");
    INSTALL_SLOT(13, o_send_socket, SendSocket, "ISteamNetworking005::SendDataOnSocket");
    INSTALL_SLOT(14, o_is_socket_available, IsSocketAvailable, "ISteamNetworking005::IsDataAvailableOnSocket");
    INSTALL_SLOT(15, o_retrieve_socket, RetrieveSocket, "ISteamNetworking005::RetrieveDataFromSocket");
    INSTALL_SLOT(16, o_is_listen_available, IsListenAvailable, "ISteamNetworking005::IsDataAvailable");
    INSTALL_SLOT(17, o_retrieve_listen, RetrieveListen, "ISteamNetworking005::RetrieveData");
    INSTALL_SLOT(18, o_socket_info, GetSocketInfo, "ISteamNetworking005::GetSocketInfo");
    INSTALL_SLOT(19, o_listen_info, GetListenInfo, "ISteamNetworking005::GetListenSocketInfo");
    INSTALL_SLOT(20, o_connection_type, GetConnectionType, "ISteamNetworking005::GetSocketConnectionType");
    INSTALL_SLOT(21, o_max_packet, GetMaxPacket, "ISteamNetworking005::GetMaxPacketSize");
    InterlockedExchangePointer(reinterpret_cast<PVOID volatile*>(interface_pointer), g_network_vtable);
    g_network_interface = interface_pointer;
    ReleaseSRWLockExclusive(&g_network_lock);
    EDF5_CAPTURE_EVENT("steam", "networking_interface_hooked",
                   capture::Fields().String("interface_version", "SteamNetworking005")
                       .String("interface", capture::HexPointer(interface_pointer))
                       .UInt("hooks_installed", installed).UInt("hooks_expected", 22));
}

}  // namespace steam_capture
