#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include "winsock_hooks.h"

#include "hook_manager.h"
#include "logger.h"

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <string>
#include <unordered_map>
#include <vector>

namespace winsock_capture {
namespace {

using SocketFn = SOCKET (WSAAPI*)(int, int, int);
using WSASocketWFn = SOCKET (WSAAPI*)(int, int, int, LPWSAPROTOCOL_INFOW, GROUP, DWORD);
using ConnectFn = int (WSAAPI*)(SOCKET, const sockaddr*, int);
using WSAConnectFn = int (WSAAPI*)(SOCKET, const sockaddr*, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS);
using BindFn = int (WSAAPI*)(SOCKET, const sockaddr*, int);
using ListenFn = int (WSAAPI*)(SOCKET, int);
using AcceptFn = SOCKET (WSAAPI*)(SOCKET, sockaddr*, int*);
using GetNameFn = int (WSAAPI*)(SOCKET, sockaddr*, int*);
using ShutdownFn = int (WSAAPI*)(SOCKET, int);
using CloseFn = int (WSAAPI*)(SOCKET);
using SendFn = int (WSAAPI*)(SOCKET, const char*, int, int);
using SendToFn = int (WSAAPI*)(SOCKET, const char*, int, int, const sockaddr*, int);
using RecvFn = int (WSAAPI*)(SOCKET, char*, int, int);
using RecvFromFn = int (WSAAPI*)(SOCKET, char*, int, int, sockaddr*, int*);
using WSASendFn = int (WSAAPI*)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
using WSASendToFn = int (WSAAPI*)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, const sockaddr*, int, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
using WSARecvFn = int (WSAAPI*)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
using WSARecvFromFn = int (WSAAPI*)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, sockaddr*, LPINT, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
using WSAGetOverlappedResultFn = BOOL (WSAAPI*)(SOCKET, LPWSAOVERLAPPED, LPDWORD, BOOL, LPDWORD);
using GetAddrInfoAFn = int (WSAAPI*)(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*);
using GetAddrInfoWFn = int (WSAAPI*)(PCWSTR, PCWSTR, const ADDRINFOW*, PADDRINFOW*);
using GetQueuedCompletionStatusFn = BOOL (WINAPI*)(HANDLE, LPDWORD, PULONG_PTR, LPOVERLAPPED*, DWORD);
using GetQueuedCompletionStatusExFn = BOOL (WINAPI*)(HANDLE, LPOVERLAPPED_ENTRY, ULONG, PULONG, DWORD, BOOL);

SocketFn o_socket;
WSASocketWFn o_wsa_socket;
ConnectFn o_connect;
WSAConnectFn o_wsa_connect;
BindFn o_bind;
ListenFn o_listen;
AcceptFn o_accept;
GetNameFn o_getsockname;
GetNameFn o_getpeername;
ShutdownFn o_shutdown;
CloseFn o_close;
SendFn o_send;
SendToFn o_send_to;
RecvFn o_recv;
RecvFromFn o_recv_from;
WSASendFn o_wsa_send;
WSASendToFn o_wsa_send_to;
WSARecvFn o_wsa_recv;
WSARecvFromFn o_wsa_recv_from;
WSAGetOverlappedResultFn o_wsa_get_overlapped_result;
GetAddrInfoAFn o_getaddrinfo;
GetAddrInfoWFn o_getaddrinfo_w;
GetQueuedCompletionStatusFn o_gqcs;
GetQueuedCompletionStatusExFn o_gqcs_ex;

struct SocketState {
    int family = 0;
    int type = 0;
    int protocol = 0;
    std::string local;
    std::string remote;
};

struct PendingReceive {
    uint64_t operation_id = 0;
    SOCKET socket = INVALID_SOCKET;
    std::vector<WSABUF> buffers;
    sockaddr* from = nullptr;
    int* from_length = nullptr;
    LPWSAOVERLAPPED_COMPLETION_ROUTINE completion = nullptr;
};

SRWLOCK g_socket_lock = SRWLOCK_INIT;
std::unordered_map<uintptr_t, SocketState>& SocketMap() {
    static auto* map = new std::unordered_map<uintptr_t, SocketState>();
    return *map;
}
SRWLOCK g_pending_lock = SRWLOCK_INIT;
std::unordered_map<OVERLAPPED*, PendingReceive>& PendingMap() {
    static auto* map = new std::unordered_map<OVERLAPPED*, PendingReceive>();
    return *map;
}
std::atomic<uint64_t> g_operation_id{0};
thread_local unsigned g_hook_depth = 0;

uint64_t WsaErrorValue(int error) {
    return static_cast<uint64_t>(static_cast<uint32_t>(error));
}

struct RecursionGuard {
    bool nested;
    RecursionGuard() : nested(g_hook_depth++ != 0) {}
    ~RecursionGuard() { --g_hook_depth; }
};

uint16_t HostPort(uint16_t network_port) {
    return static_cast<uint16_t>((network_port >> 8) | (network_port << 8));
}

std::string Endpoint(const sockaddr* address, int length) {
    if (!address || length < static_cast<int>(sizeof(address->sa_family))) return "";
    char buffer[160]{};
    if (address->sa_family == AF_INET && length >= static_cast<int>(sizeof(sockaddr_in))) {
        const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(address);
        const auto* bytes = reinterpret_cast<const uint8_t*>(&ipv4->sin_addr.s_addr);
        std::snprintf(buffer, sizeof(buffer), "%u.%u.%u.%u:%u",
                      bytes[0], bytes[1], bytes[2], bytes[3], HostPort(ipv4->sin_port));
        return buffer;
    }
    if (address->sa_family == AF_INET6 && length >= static_cast<int>(sizeof(sockaddr_in6))) {
        const auto* ipv6 = reinterpret_cast<const sockaddr_in6*>(address);
        const auto* words = reinterpret_cast<const uint16_t*>(&ipv6->sin6_addr);
        std::snprintf(buffer, sizeof(buffer), "[%x:%x:%x:%x:%x:%x:%x:%x%%%lu]:%u",
                      HostPort(words[0]), HostPort(words[1]), HostPort(words[2]), HostPort(words[3]),
                      HostPort(words[4]), HostPort(words[5]), HostPort(words[6]), HostPort(words[7]),
                      static_cast<unsigned long>(ipv6->sin6_scope_id), HostPort(ipv6->sin6_port));
        return buffer;
    }
    std::snprintf(buffer, sizeof(buffer), "family:%d length:%d", address->sa_family, length);
    return buffer;
}

SocketState LookupSocketState(SOCKET socket) {
    SocketState state;
    AcquireSRWLockShared(&g_socket_lock);
    const auto found = SocketMap().find(static_cast<uintptr_t>(socket));
    if (found != SocketMap().end()) state = found->second;
    ReleaseSRWLockShared(&g_socket_lock);
    return state;
}

void SetSocketEndpoint(SOCKET socket, bool remote, const std::string& endpoint);

SocketState ResolveSocketState(SOCKET socket) {
    SocketState state = LookupSocketState(socket);
    sockaddr_storage address{};
    int length = sizeof(address);
    if (o_getsockname && o_getsockname(socket, reinterpret_cast<sockaddr*>(&address), &length) == 0) {
        state.local = Endpoint(reinterpret_cast<sockaddr*>(&address), length);
        SetSocketEndpoint(socket, false, state.local);
    }
    length = sizeof(address);
    if (o_getpeername && o_getpeername(socket, reinterpret_cast<sockaddr*>(&address), &length) == 0) {
        state.remote = Endpoint(reinterpret_cast<sockaddr*>(&address), length);
        SetSocketEndpoint(socket, true, state.remote);
    }
    return state;
}

SocketState GetSocketState(SOCKET socket) { return ResolveSocketState(socket); }

void AddSocket(SOCKET socket, int family, int type, int protocol) {
    if (socket == INVALID_SOCKET) return;
    AcquireSRWLockExclusive(&g_socket_lock);
    SocketMap()[static_cast<uintptr_t>(socket)] = SocketState{family, type, protocol, {}, {}};
    ReleaseSRWLockExclusive(&g_socket_lock);
}

void SetSocketEndpoint(SOCKET socket, bool remote, const std::string& endpoint) {
    AcquireSRWLockExclusive(&g_socket_lock);
    auto& state = SocketMap()[static_cast<uintptr_t>(socket)];
    (remote ? state.remote : state.local) = endpoint;
    ReleaseSRWLockExclusive(&g_socket_lock);
}

std::vector<uint8_t> GatherBuffers(LPWSABUF buffers, DWORD count, size_t byte_limit = SIZE_MAX) {
    std::vector<uint8_t> result;
    if (!buffers) return result;
    size_t total = 0;
    for (DWORD i = 0; i < count; ++i) total += buffers[i].len;
    total = std::min(total, byte_limit);
    result.reserve(total);
    size_t remaining = total;
    for (DWORD i = 0; i < count && remaining; ++i) {
        const size_t take = std::min<size_t>(buffers[i].len, remaining);
        if (buffers[i].buf && take) {
            const auto* first = reinterpret_cast<const uint8_t*>(buffers[i].buf);
            result.insert(result.end(), first, first + take);
        }
        remaining -= take;
    }
    return result;
}

uint64_t TotalBufferBytes(LPWSABUF buffers, DWORD count) {
    uint64_t total = 0;
    if (buffers) for (DWORD i = 0; i < count; ++i) total += buffers[i].len;
    return total;
}

void StorePending(LPWSAOVERLAPPED overlapped, SOCKET socket, LPWSABUF buffers, DWORD count,
                  sockaddr* from, int* from_length, LPWSAOVERLAPPED_COMPLETION_ROUTINE completion,
                  uint64_t operation_id) {
    if (!overlapped) return;
    PendingReceive pending;
    pending.operation_id = operation_id;
    pending.socket = socket;
    if (buffers) pending.buffers.assign(buffers, buffers + count);
    pending.from = from;
    pending.from_length = from_length;
    pending.completion = completion;
    AcquireSRWLockExclusive(&g_pending_lock);
    PendingMap()[overlapped] = std::move(pending);
    ReleaseSRWLockExclusive(&g_pending_lock);
}

bool TakePending(OVERLAPPED* overlapped, PendingReceive& result) {
    bool found = false;
    AcquireSRWLockExclusive(&g_pending_lock);
    const auto item = PendingMap().find(overlapped);
    if (item != PendingMap().end()) {
        result = std::move(item->second);
        PendingMap().erase(item);
        found = true;
    }
    ReleaseSRWLockExclusive(&g_pending_lock);
    return found;
}

void CompletePending(OVERLAPPED* overlapped, DWORD bytes, DWORD error, DWORD flags,
                     const char* completion_source, LPWSAOVERLAPPED_COMPLETION_ROUTINE* callback) {
    PendingReceive pending;
    if (!TakePending(overlapped, pending)) return;
    if (callback) *callback = pending.completion;
    auto payload = GatherBuffers(pending.buffers.data(), static_cast<DWORD>(pending.buffers.size()), bytes);
    const SocketState state = GetSocketState(pending.socket);
    const std::string source = pending.from && pending.from_length
        ? Endpoint(pending.from, *pending.from_length) : state.remote;
    EDF5_CAPTURE_EVENT("winsock", "overlapped_receive_complete",
                   capture::Fields().String("direction", "in")
                       .UInt("operation_id", pending.operation_id)
                       .UInt("socket", static_cast<uint64_t>(pending.socket))
                       .String("local_endpoint", state.local).String("remote_endpoint", source)
                       .UInt("transferred_bytes", bytes).UInt("flags", flags)
                       .UInt("error", error).String("completion_source", completion_source),
                   std::move(payload));
}

void CALLBACK CompletionRoutine(DWORD error, DWORD bytes, LPWSAOVERLAPPED overlapped, DWORD flags) {
    LPWSAOVERLAPPED_COMPLETION_ROUTINE callback = nullptr;
    CompletePending(overlapped, bytes, error, flags, "completion_routine", &callback);
    if (callback) callback(error, bytes, overlapped, flags);
}

SOCKET WSAAPI Socket(int family, int type, int protocol) {
    RecursionGuard guard;
    const SOCKET result = o_socket(family, type, protocol);
    const int error = WSAGetLastError();
    if (!guard.nested) {
        AddSocket(result, family, type, protocol);
        EDF5_CAPTURE_EVENT("winsock", "socket",
                       capture::Fields().UInt("socket", static_cast<uint64_t>(result))
                           .Int("family", family).Int("type", type).Int("protocol", protocol)
                           .UInt("error", result == INVALID_SOCKET
                                              ? WsaErrorValue(error)
                                              : uint64_t{0}));
    }
    WSASetLastError(error);
    return result;
}

SOCKET WSAAPI WSASocketW(int family, int type, int protocol, LPWSAPROTOCOL_INFOW info,
                         GROUP group, DWORD flags) {
    RecursionGuard guard;
    const SOCKET result = o_wsa_socket(family, type, protocol, info, group, flags);
    const int error = WSAGetLastError();
    if (!guard.nested) {
        AddSocket(result, family, type, protocol);
        EDF5_CAPTURE_EVENT("winsock", "wsa_socket",
                       capture::Fields().UInt("socket", static_cast<uint64_t>(result))
                           .Int("family", family).Int("type", type).Int("protocol", protocol)
                           .UInt("flags", flags)
                           .UInt("error", result == INVALID_SOCKET
                                              ? WsaErrorValue(error)
                                              : uint64_t{0}));
    }
    WSASetLastError(error);
    return result;
}

int WSAAPI Connect(SOCKET socket, const sockaddr* address, int length) {
    RecursionGuard guard;
    const std::string endpoint = Endpoint(address, length);
    const int result = o_connect(socket, address, length);
    const int error = WSAGetLastError();
    if (!guard.nested) {
        if (result == 0 || error == WSAEWOULDBLOCK || error == WSAEINPROGRESS) SetSocketEndpoint(socket, true, endpoint);
        const SocketState state = GetSocketState(socket);
        EDF5_CAPTURE_EVENT("winsock", "connect",
                       capture::Fields().UInt("socket", static_cast<uint64_t>(socket))
                           .String("local_endpoint", state.local).String("remote_endpoint", endpoint)
                           .Int("result", result)
                           .UInt("error", result == SOCKET_ERROR
                                              ? WsaErrorValue(error)
                                              : uint64_t{0}));
    }
    WSASetLastError(error);
    return result;
}

int WSAAPI WSAConnect(SOCKET socket, const sockaddr* address, int length, LPWSABUF caller,
                      LPWSABUF callee, LPQOS send_qos, LPQOS recv_qos) {
    RecursionGuard guard;
    const std::string endpoint = Endpoint(address, length);
    const int result = o_wsa_connect(socket, address, length, caller, callee, send_qos, recv_qos);
    const int error = WSAGetLastError();
    if (!guard.nested) {
        if (result == 0 || error == WSAEWOULDBLOCK || error == WSAEINPROGRESS) SetSocketEndpoint(socket, true, endpoint);
        const SocketState state = GetSocketState(socket);
        EDF5_CAPTURE_EVENT("winsock", "wsa_connect",
                       capture::Fields().UInt("socket", static_cast<uint64_t>(socket))
                           .String("local_endpoint", state.local).String("remote_endpoint", endpoint)
                           .Int("result", result)
                           .UInt("error", result == SOCKET_ERROR
                                              ? WsaErrorValue(error)
                                              : uint64_t{0}));
    }
    WSASetLastError(error);
    return result;
}

int WSAAPI Bind(SOCKET socket, const sockaddr* address, int length) {
    RecursionGuard guard;
    const std::string endpoint = Endpoint(address, length);
    const int result = o_bind(socket, address, length);
    const int error = WSAGetLastError();
    if (!guard.nested) {
        if (result == 0) SetSocketEndpoint(socket, false, endpoint);
        EDF5_CAPTURE_EVENT("winsock", "bind",
                       capture::Fields().UInt("socket", static_cast<uint64_t>(socket))
                           .String("local_endpoint", endpoint).Int("result", result)
                           .UInt("error", result == SOCKET_ERROR
                                              ? WsaErrorValue(error)
                                              : uint64_t{0}));
    }
    WSASetLastError(error);
    return result;
}

int WSAAPI Listen(SOCKET socket, int backlog) {
    RecursionGuard guard;
    const int result = o_listen(socket, backlog);
    const int error = WSAGetLastError();
    if (!guard.nested) {
        const SocketState state = GetSocketState(socket);
        EDF5_CAPTURE_EVENT("winsock", "listen",
                       capture::Fields().UInt("socket", static_cast<uint64_t>(socket))
                           .String("local_endpoint", state.local).Int("backlog", backlog)
                           .Int("result", result)
                           .UInt("error", result == SOCKET_ERROR
                                              ? WsaErrorValue(error)
                                              : uint64_t{0}));
    }
    WSASetLastError(error);
    return result;
}

SOCKET WSAAPI Accept(SOCKET listener, sockaddr* address, int* length) {
    RecursionGuard guard;
    const SOCKET result = o_accept(listener, address, length);
    const int error = WSAGetLastError();
    if (!guard.nested) {
        const SocketState listener_state = GetSocketState(listener);
        const std::string remote = result != INVALID_SOCKET && length ? Endpoint(address, *length) : "";
        if (result != INVALID_SOCKET) {
            AddSocket(result, listener_state.family, listener_state.type, listener_state.protocol);
            SetSocketEndpoint(result, false, listener_state.local);
            SetSocketEndpoint(result, true, remote);
        }
        EDF5_CAPTURE_EVENT("winsock", "accept",
                       capture::Fields().UInt("listen_socket", static_cast<uint64_t>(listener))
                           .UInt("accepted_socket", static_cast<uint64_t>(result))
                           .String("local_endpoint", listener_state.local).String("remote_endpoint", remote)
                           .UInt("error", result == INVALID_SOCKET
                                              ? WsaErrorValue(error)
                                              : uint64_t{0}));
    }
    WSASetLastError(error);
    return result;
}

int WSAAPI GetSockName(SOCKET socket, sockaddr* address, int* length) {
    RecursionGuard guard;
    const int result = o_getsockname(socket, address, length);
    const int error = WSAGetLastError();
    if (!guard.nested) {
        const std::string endpoint = result == 0 && length ? Endpoint(address, *length) : "";
        if (result == 0) SetSocketEndpoint(socket, false, endpoint);
        EDF5_CAPTURE_EVENT("winsock", "getsockname",
                       capture::Fields().UInt("socket", static_cast<uint64_t>(socket))
                           .String("local_endpoint", endpoint).Int("result", result)
                           .UInt("error", result == SOCKET_ERROR
                                              ? WsaErrorValue(error)
                                              : uint64_t{0}));
    }
    WSASetLastError(error);
    return result;
}

int WSAAPI GetPeerName(SOCKET socket, sockaddr* address, int* length) {
    RecursionGuard guard;
    const int result = o_getpeername(socket, address, length);
    const int error = WSAGetLastError();
    if (!guard.nested) {
        const std::string endpoint = result == 0 && length ? Endpoint(address, *length) : "";
        if (result == 0) SetSocketEndpoint(socket, true, endpoint);
        EDF5_CAPTURE_EVENT("winsock", "getpeername",
                       capture::Fields().UInt("socket", static_cast<uint64_t>(socket))
                           .String("remote_endpoint", endpoint).Int("result", result)
                           .UInt("error", result == SOCKET_ERROR
                                              ? WsaErrorValue(error)
                                              : uint64_t{0}));
    }
    WSASetLastError(error);
    return result;
}

int WSAAPI Shutdown(SOCKET socket, int how) {
    RecursionGuard guard;
    const int result = o_shutdown(socket, how);
    const int error = WSAGetLastError();
    if (!guard.nested) {
        const SocketState state = ResolveSocketState(socket);
        EDF5_CAPTURE_EVENT("winsock", "shutdown",
                       capture::Fields().UInt("socket", static_cast<uint64_t>(socket))
                           .String("local_endpoint", state.local).String("remote_endpoint", state.remote)
                           .Int("how", how).Int("result", result)
                           .UInt("error", result == SOCKET_ERROR
                                              ? WsaErrorValue(error)
                                              : uint64_t{0}));
    }
    WSASetLastError(error);
    return result;
}

int WSAAPI Close(SOCKET socket) {
    RecursionGuard guard;
    const SocketState state = GetSocketState(socket);
    const int result = o_close(socket);
    const int error = WSAGetLastError();
    if (!guard.nested) {
        EDF5_CAPTURE_EVENT("winsock", "close",
                       capture::Fields().UInt("socket", static_cast<uint64_t>(socket))
                           .String("local_endpoint", state.local).String("remote_endpoint", state.remote)
                           .Int("result", result)
                           .UInt("error", result == SOCKET_ERROR
                                              ? WsaErrorValue(error)
                                              : uint64_t{0}));
        AcquireSRWLockExclusive(&g_socket_lock);
        SocketMap().erase(static_cast<uintptr_t>(socket));
        ReleaseSRWLockExclusive(&g_socket_lock);
    }
    WSASetLastError(error);
    return result;
}

int WSAAPI Send(SOCKET socket, const char* buffer, int length, int flags) {
    RecursionGuard guard;
    const int result = o_send(socket, buffer, length, flags);
    const int error = WSAGetLastError();
    if (!guard.nested) {
        const SocketState state = ResolveSocketState(socket);
        EDF5_CAPTURE_EVENT("winsock", "send",
                       capture::Fields().String("direction", "out")
                           .UInt("socket", static_cast<uint64_t>(socket))
                           .String("local_endpoint", state.local).String("remote_endpoint", state.remote)
                           .Int("flags", flags).Int("requested_bytes", length).Int("transferred_bytes", result)
                           .UInt("error", result == SOCKET_ERROR
                                              ? WsaErrorValue(error)
                                              : uint64_t{0}),
                       buffer, length > 0 ? static_cast<size_t>(length) : 0);
    }
    WSASetLastError(error);
    return result;
}

int WSAAPI SendTo(SOCKET socket, const char* buffer, int length, int flags,
                  const sockaddr* address, int address_length) {
    RecursionGuard guard;
    const std::string remote = Endpoint(address, address_length);
    const int result = o_send_to(socket, buffer, length, flags, address, address_length);
    const int error = WSAGetLastError();
    if (!guard.nested) {
        const SocketState state = ResolveSocketState(socket);
        EDF5_CAPTURE_EVENT("winsock", "send_to",
                       capture::Fields().String("direction", "out")
                           .UInt("socket", static_cast<uint64_t>(socket))
                           .String("local_endpoint", state.local).String("remote_endpoint", remote)
                           .Int("flags", flags).Int("requested_bytes", length).Int("transferred_bytes", result)
                           .UInt("error", result == SOCKET_ERROR
                                              ? WsaErrorValue(error)
                                              : uint64_t{0}),
                       buffer, length > 0 ? static_cast<size_t>(length) : 0);
    }
    WSASetLastError(error);
    return result;
}

int WSAAPI Recv(SOCKET socket, char* buffer, int length, int flags) {
    RecursionGuard guard;
    const int result = o_recv(socket, buffer, length, flags);
    const int error = WSAGetLastError();
    if (!guard.nested && (result > 0 || (result == 0 && length != 0))) {
        const SocketState state = GetSocketState(socket);
        EDF5_CAPTURE_EVENT("winsock", "recv",
                       capture::Fields().String("direction", "in")
                           .UInt("socket", static_cast<uint64_t>(socket))
                           .String("local_endpoint", state.local).String("remote_endpoint", state.remote)
                           .Int("flags", flags).Int("buffer_capacity", length).Int("transferred_bytes", result)
                           .UInt("error", result == SOCKET_ERROR
                                              ? WsaErrorValue(error)
                                              : uint64_t{0}),
                       buffer, result > 0 ? static_cast<size_t>(result) : 0);
    }
    WSASetLastError(error);
    return result;
}

int WSAAPI RecvFrom(SOCKET socket, char* buffer, int length, int flags,
                    sockaddr* address, int* address_length) {
    RecursionGuard guard;
    const int result = o_recv_from(socket, buffer, length, flags, address, address_length);
    const int error = WSAGetLastError();
    if (!guard.nested && result >= 0) {
        const SocketState state = GetSocketState(socket);
        const std::string remote = address_length ? Endpoint(address, *address_length) : "";
        EDF5_CAPTURE_EVENT("winsock", "recv_from",
                       capture::Fields().String("direction", "in")
                           .UInt("socket", static_cast<uint64_t>(socket))
                           .String("local_endpoint", state.local).String("remote_endpoint", remote)
                           .Int("flags", flags).Int("buffer_capacity", length).Int("transferred_bytes", result)
                           .UInt("error", result == SOCKET_ERROR
                                              ? WsaErrorValue(error)
                                              : uint64_t{0}),
                       buffer, result > 0 ? static_cast<size_t>(result) : 0);
    }
    WSASetLastError(error);
    return result;
}

int WSAAPI WSASend(SOCKET socket, LPWSABUF buffers, DWORD count, LPDWORD bytes,
                   DWORD flags, LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completion) {
    RecursionGuard guard;
    auto payload = guard.nested ? std::vector<uint8_t>() : GatherBuffers(buffers, count);
    const int result = o_wsa_send(socket, buffers, count, bytes, flags, overlapped, completion);
    const int error = WSAGetLastError();
    if (!guard.nested) {
        const SocketState state = GetSocketState(socket);
        EDF5_CAPTURE_EVENT("winsock", "wsa_send",
                       capture::Fields().String("direction", "out").UInt("socket", static_cast<uint64_t>(socket))
                           .String("local_endpoint", state.local).String("remote_endpoint", state.remote)
                           .UInt("buffer_count", count).UInt("requested_bytes", payload.size())
                           .UInt("transferred_bytes", bytes ? *bytes : 0).UInt("flags", flags)
                           .Bool("overlapped", overlapped != nullptr)
                           .Bool("pending", result == SOCKET_ERROR && error == WSA_IO_PENDING)
                           .Int("result", result)
                           .UInt("error", result == SOCKET_ERROR
                                              ? WsaErrorValue(error)
                                              : uint64_t{0}),
                       std::move(payload));
    }
    WSASetLastError(error);
    return result;
}

int WSAAPI WSASendTo(SOCKET socket, LPWSABUF buffers, DWORD count, LPDWORD bytes,
                     DWORD flags, const sockaddr* address, int address_length,
                     LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completion) {
    RecursionGuard guard;
    auto payload = guard.nested ? std::vector<uint8_t>() : GatherBuffers(buffers, count);
    const std::string remote = Endpoint(address, address_length);
    const int result = o_wsa_send_to(socket, buffers, count, bytes, flags, address, address_length, overlapped, completion);
    const int error = WSAGetLastError();
    if (!guard.nested) {
        const SocketState state = GetSocketState(socket);
        EDF5_CAPTURE_EVENT("winsock", "wsa_send_to",
                       capture::Fields().String("direction", "out").UInt("socket", static_cast<uint64_t>(socket))
                           .String("local_endpoint", state.local).String("remote_endpoint", remote)
                           .UInt("buffer_count", count).UInt("requested_bytes", payload.size())
                           .UInt("transferred_bytes", bytes ? *bytes : 0).UInt("flags", flags)
                           .Bool("overlapped", overlapped != nullptr)
                           .Bool("pending", result == SOCKET_ERROR && error == WSA_IO_PENDING)
                           .Int("result", result)
                           .UInt("error", result == SOCKET_ERROR
                                              ? WsaErrorValue(error)
                                              : uint64_t{0}),
                       std::move(payload));
    }
    WSASetLastError(error);
    return result;
}

int WSAAPI WSARecv(SOCKET socket, LPWSABUF buffers, DWORD count, LPDWORD bytes,
                   LPDWORD flags, LPWSAOVERLAPPED overlapped,
                   LPWSAOVERLAPPED_COMPLETION_ROUTINE completion) {
    RecursionGuard guard;
    const uint64_t operation = g_operation_id.fetch_add(1) + 1;
    if (!guard.nested && overlapped) StorePending(overlapped, socket, buffers, count, nullptr, nullptr,
                                                  completion, operation);
    const int result = o_wsa_recv(socket, buffers, count, bytes, flags, overlapped,
                                  guard.nested ? completion : (completion ? &CompletionRoutine : nullptr));
    const int error = WSAGetLastError();
    if (!guard.nested) {
        if (!overlapped && result == 0) {
            auto payload = GatherBuffers(buffers, count, bytes ? *bytes : 0);
            const SocketState state = GetSocketState(socket);
            EDF5_CAPTURE_EVENT("winsock", "wsa_recv",
                           capture::Fields().String("direction", "in").UInt("operation_id", operation)
                               .UInt("socket", static_cast<uint64_t>(socket))
                               .String("local_endpoint", state.local).String("remote_endpoint", state.remote)
                               .UInt("buffer_count", count).UInt("buffer_capacity", TotalBufferBytes(buffers, count))
                               .UInt("transferred_bytes", bytes ? *bytes : 0)
                               .UInt("flags", flags ? *flags : 0).Int("result", result), std::move(payload));
        } else if (overlapped && result == 0 && !completion) {
            PendingReceive pending;
            if (TakePending(overlapped, pending)) {
                auto payload = GatherBuffers(pending.buffers.data(), static_cast<DWORD>(pending.buffers.size()), bytes ? *bytes : 0);
                const SocketState state = GetSocketState(socket);
                EDF5_CAPTURE_EVENT("winsock", "wsa_recv",
                               capture::Fields().String("direction", "in").UInt("operation_id", operation)
                                   .UInt("socket", static_cast<uint64_t>(socket))
                                   .String("local_endpoint", state.local).String("remote_endpoint", state.remote)
                                   .UInt("transferred_bytes", bytes ? *bytes : 0).UInt("flags", flags ? *flags : 0)
                                   .Bool("overlapped_immediate", true).Int("result", result), std::move(payload));
            }
        } else if (result == SOCKET_ERROR && error != WSA_IO_PENDING && overlapped) {
            PendingReceive ignored;
            TakePending(overlapped, ignored);
        }
        if (result == SOCKET_ERROR) {
            EDF5_CAPTURE_EVENT("winsock", "wsa_recv_status",
                           capture::Fields().UInt("operation_id", operation)
                               .UInt("socket", static_cast<uint64_t>(socket))
                               .Bool("pending", error == WSA_IO_PENDING)
                               .UInt("error", WsaErrorValue(error)));
        }
    }
    WSASetLastError(error);
    return result;
}

int WSAAPI WSARecvFrom(SOCKET socket, LPWSABUF buffers, DWORD count, LPDWORD bytes,
                       LPDWORD flags, sockaddr* address, LPINT address_length,
                       LPWSAOVERLAPPED overlapped,
                       LPWSAOVERLAPPED_COMPLETION_ROUTINE completion) {
    RecursionGuard guard;
    const uint64_t operation = g_operation_id.fetch_add(1) + 1;
    if (!guard.nested && overlapped) StorePending(overlapped, socket, buffers, count, address, address_length,
                                                  completion, operation);
    const int result = o_wsa_recv_from(socket, buffers, count, bytes, flags, address, address_length,
                                       overlapped, guard.nested ? completion : (completion ? &CompletionRoutine : nullptr));
    const int error = WSAGetLastError();
    if (!guard.nested) {
        if (!overlapped && result == 0) {
            auto payload = GatherBuffers(buffers, count, bytes ? *bytes : 0);
            const SocketState state = GetSocketState(socket);
            EDF5_CAPTURE_EVENT("winsock", "wsa_recv_from",
                           capture::Fields().String("direction", "in").UInt("operation_id", operation)
                               .UInt("socket", static_cast<uint64_t>(socket))
                               .String("local_endpoint", state.local)
                               .String("remote_endpoint", address_length ? Endpoint(address, *address_length) : "")
                               .UInt("buffer_count", count).UInt("buffer_capacity", TotalBufferBytes(buffers, count))
                               .UInt("transferred_bytes", bytes ? *bytes : 0)
                               .UInt("flags", flags ? *flags : 0).Int("result", result), std::move(payload));
        } else if (overlapped && result == 0 && !completion) {
            PendingReceive pending;
            if (TakePending(overlapped, pending)) {
                auto payload = GatherBuffers(pending.buffers.data(), static_cast<DWORD>(pending.buffers.size()), bytes ? *bytes : 0);
                const SocketState state = GetSocketState(socket);
                EDF5_CAPTURE_EVENT("winsock", "wsa_recv_from",
                               capture::Fields().String("direction", "in").UInt("operation_id", operation)
                                   .UInt("socket", static_cast<uint64_t>(socket)).String("local_endpoint", state.local)
                                   .String("remote_endpoint", address_length ? Endpoint(address, *address_length) : "")
                                   .UInt("transferred_bytes", bytes ? *bytes : 0).UInt("flags", flags ? *flags : 0)
                                   .Bool("overlapped_immediate", true).Int("result", result), std::move(payload));
            }
        } else if (result == SOCKET_ERROR && error != WSA_IO_PENDING && overlapped) {
            PendingReceive ignored;
            TakePending(overlapped, ignored);
        }
        if (result == SOCKET_ERROR) {
            EDF5_CAPTURE_EVENT("winsock", "wsa_recv_from_status",
                           capture::Fields().UInt("operation_id", operation)
                               .UInt("socket", static_cast<uint64_t>(socket))
                               .Bool("pending", error == WSA_IO_PENDING)
                               .UInt("error", WsaErrorValue(error)));
        }
    }
    WSASetLastError(error);
    return result;
}

BOOL WSAAPI WSAGetOverlappedResult(SOCKET socket, LPWSAOVERLAPPED overlapped, LPDWORD bytes,
                                   BOOL wait, LPDWORD flags) {
    RecursionGuard guard;
    const BOOL result = o_wsa_get_overlapped_result(socket, overlapped, bytes, wait, flags);
    const int error = WSAGetLastError();
    if (!guard.nested && result) CompletePending(overlapped, bytes ? *bytes : 0, 0,
                                                 flags ? *flags : 0, "WSAGetOverlappedResult", nullptr);
    WSASetLastError(error);
    return result;
}

BOOL WINAPI GetQueuedCompletionStatus(HANDLE port, LPDWORD bytes, PULONG_PTR key,
                                      LPOVERLAPPED* overlapped, DWORD milliseconds) {
    RecursionGuard guard;
    const BOOL result = o_gqcs(port, bytes, key, overlapped, milliseconds);
    const DWORD error = GetLastError();
    if (!guard.nested && overlapped && *overlapped) {
        CompletePending(*overlapped, bytes ? *bytes : 0, result ? 0 : error, 0,
                        "GetQueuedCompletionStatus", nullptr);
    }
    SetLastError(error);
    return result;
}

BOOL WINAPI GetQueuedCompletionStatusEx(HANDLE port, LPOVERLAPPED_ENTRY entries, ULONG count,
                                        PULONG removed, DWORD milliseconds, BOOL alertable) {
    RecursionGuard guard;
    const BOOL result = o_gqcs_ex(port, entries, count, removed, milliseconds, alertable);
    const DWORD error = GetLastError();
    if (!guard.nested && result && entries && removed) {
        for (ULONG i = 0; i < *removed; ++i) {
            CompletePending(entries[i].lpOverlapped, entries[i].dwNumberOfBytesTransferred,
                            0, 0, "GetQueuedCompletionStatusEx", nullptr);
        }
    }
    SetLastError(error);
    return result;
}

std::string AddrInfoJson(const ADDRINFOA* result) {
    std::string json = "[";
    bool first = true;
    for (const ADDRINFOA* item = result; item && json.size() < 128 * 1024; item = item->ai_next) {
        if (!first) json += ',';
        first = false;
        json += "{\"family\":" + std::to_string(item->ai_family)
            + ",\"socktype\":" + std::to_string(item->ai_socktype)
            + ",\"protocol\":" + std::to_string(item->ai_protocol)
            + ",\"endpoint\":\"" + capture::Escape(Endpoint(item->ai_addr, static_cast<int>(item->ai_addrlen))) + "\"}";
    }
    json += ']';
    return json;
}

int WSAAPI GetAddrInfoA(PCSTR node, PCSTR service, const ADDRINFOA* hints, PADDRINFOA* result) {
    RecursionGuard guard;
    const int status = o_getaddrinfo(node, service, hints, result);
    const int error = WSAGetLastError();
    if (!guard.nested) {
        EDF5_CAPTURE_EVENT("winsock_dns", "getaddrinfo",
                       capture::Fields().String("node", node).String("service", service)
                           .Int("hint_family", hints ? hints->ai_family : 0)
                           .Int("hint_socktype", hints ? hints->ai_socktype : 0)
                           .Int("hint_protocol", hints ? hints->ai_protocol : 0)
                           .Int("status", status)
                           .Raw("results", status == 0 && result ? AddrInfoJson(*result) : "[]"));
    }
    WSASetLastError(error);
    return status;
}

int WSAAPI GetAddrInfoW(PCWSTR node, PCWSTR service, const ADDRINFOW* hints, PADDRINFOW* result) {
    RecursionGuard guard;
    const int status = o_getaddrinfo_w(node, service, hints, result);
    const int error = WSAGetLastError();
    if (!guard.nested) {
        // ADDRINFOA/W have identical non-string address fields and linked-list layout on x64.
        EDF5_CAPTURE_EVENT("winsock_dns", "getaddrinfo_w",
                       capture::Fields().String("node", capture::WideToUtf8(node))
                           .String("service", capture::WideToUtf8(service))
                           .Int("hint_family", hints ? hints->ai_family : 0)
                           .Int("hint_socktype", hints ? hints->ai_socktype : 0)
                           .Int("hint_protocol", hints ? hints->ai_protocol : 0)
                           .Int("status", status)
                           .Raw("results", status == 0 && result
                               ? AddrInfoJson(reinterpret_cast<const ADDRINFOA*>(*result)) : "[]"));
    }
    WSASetLastError(error);
    return status;
}

}  // namespace

bool Install() {
    unsigned installed = 0;
#define HOOK(module, name, replacement, original) \
    installed += hooks::Export(module, name, reinterpret_cast<void*>(&replacement), \
                               reinterpret_cast<void**>(&original)) ? 1u : 0u
    HOOK(L"ws2_32.dll", "socket", Socket, o_socket);
    HOOK(L"ws2_32.dll", "WSASocketW", WSASocketW, o_wsa_socket);
    HOOK(L"ws2_32.dll", "connect", Connect, o_connect);
    HOOK(L"ws2_32.dll", "WSAConnect", WSAConnect, o_wsa_connect);
    HOOK(L"ws2_32.dll", "bind", Bind, o_bind);
    HOOK(L"ws2_32.dll", "listen", Listen, o_listen);
    HOOK(L"ws2_32.dll", "accept", Accept, o_accept);
    HOOK(L"ws2_32.dll", "getsockname", GetSockName, o_getsockname);
    HOOK(L"ws2_32.dll", "getpeername", GetPeerName, o_getpeername);
    HOOK(L"ws2_32.dll", "shutdown", Shutdown, o_shutdown);
    HOOK(L"ws2_32.dll", "closesocket", Close, o_close);
    HOOK(L"ws2_32.dll", "send", Send, o_send);
    HOOK(L"ws2_32.dll", "sendto", SendTo, o_send_to);
    HOOK(L"ws2_32.dll", "recv", Recv, o_recv);
    HOOK(L"ws2_32.dll", "recvfrom", RecvFrom, o_recv_from);
    HOOK(L"ws2_32.dll", "WSASend", WSASend, o_wsa_send);
    HOOK(L"ws2_32.dll", "WSASendTo", WSASendTo, o_wsa_send_to);
    HOOK(L"ws2_32.dll", "WSARecv", WSARecv, o_wsa_recv);
    HOOK(L"ws2_32.dll", "WSARecvFrom", WSARecvFrom, o_wsa_recv_from);
    HOOK(L"ws2_32.dll", "WSAGetOverlappedResult", WSAGetOverlappedResult, o_wsa_get_overlapped_result);
    HOOK(L"ws2_32.dll", "getaddrinfo", GetAddrInfoA, o_getaddrinfo);
    HOOK(L"ws2_32.dll", "GetAddrInfoW", GetAddrInfoW, o_getaddrinfo_w);
    HOOK(L"kernel32.dll", "GetQueuedCompletionStatus", GetQueuedCompletionStatus, o_gqcs);
    HOOK(L"kernel32.dll", "GetQueuedCompletionStatusEx", GetQueuedCompletionStatusEx, o_gqcs_ex);
#undef HOOK
    EDF5_CAPTURE_EVENT("sniffer", "winsock_hooks_installed",
                   capture::Fields().UInt("hooks_installed", installed).UInt("hooks_expected", 24));
    return installed >= 12 && o_send && o_recv && o_send_to && o_recv_from;
}

}  // namespace winsock_capture
