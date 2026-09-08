#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <cstdio>
#include <cstdint>
#include <cstring>

union PluginVersion {
    struct { uint16_t build, patch, minor, major; } parts;
    uint64_t raw;
};

struct PluginInfo {
    uint32_t infoVersion;
    const char* name;
    PluginVersion version;
};

using LoadFn = bool (__fastcall*)(PluginInfo*);
using SelfTestFn = bool (__fastcall*)(char*, uint32_t);

int wmain(int argc, wchar_t** argv) {
    if (argc != 2 && argc != 3) {
        fwprintf(stderr,
                 L"usage: smoke_harness.exe <plugin.dll> [EML4_Load|EML5_Load|EML6_Load]\n");
        return 2;
    }
    HMODULE module = LoadLibraryW(argv[1]);
    if (!module) {
        std::fprintf(stderr, "LoadLibraryW failed: %lu\n", GetLastError());
        return 3;
    }
    const char* entry_name = "EML5_Load";
    const char* expected_plugin_name = "EDF5_MultiSlotMod";
    if (argc == 3 && wcscmp(argv[2], L"EML4_Load") == 0) {
        entry_name = "EML4_Load";
        expected_plugin_name = "EDF41_MultiSlotMod";
    } else if (argc == 3 && wcscmp(argv[2], L"EML6_Load") == 0) {
        entry_name = "EML6_Load";
        expected_plugin_name = "EDF6_MultiSlotMod";
    } else if (argc == 3 && wcscmp(argv[2], L"EML5_Load") != 0) {
        std::fprintf(stderr, "unknown loader entry\n");
        return 4;
    }
    auto load = reinterpret_cast<LoadFn>(GetProcAddress(module, entry_name));
    const bool multi_game_exports =
        GetProcAddress(module, "EML4_Load") != nullptr &&
        GetProcAddress(module, "EML6_Load") != nullptr;
    if (!load || !multi_game_exports) {
        std::fprintf(stderr, "required EML4/EML5/EML6 export missing: %lu\n",
                     GetLastError());
        return 4;
    }
    PluginInfo info{};
    const bool result = load(&info);
    std::printf("entry=%s result=%s infoVersion=%lu name=%s version=0x%016llx\n",
                entry_name,
                result ? "true" : "false", static_cast<unsigned long>(info.infoVersion),
                info.name ? info.name : "(null)",
                static_cast<unsigned long long>(info.version.raw));

    auto self_test = reinterpret_cast<SelfTestFn>(GetProcAddress(module, "EDF5MP_SelfTest"));
    char self_test_report[4096]{};
    const bool edf5_entry = std::strcmp(entry_name, "EML5_Load") == 0;
    const bool self_test_result = !edf5_entry ||
        (self_test && self_test(
            self_test_report,
            static_cast<uint32_t>(sizeof(self_test_report))));
    std::printf("more_players_self_test=%s report=%s\n",
                edf5_entry ? (self_test_result ? "true" : "false") : "skipped",
                edf5_entry
                    ? (self_test ? self_test_report
                                 : "export EDF5MP_SelfTest ausente")
                    : "not applicable to this game profile");

    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) == 0) {
        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        addrinfo* addresses = nullptr;
        getaddrinfo("localhost", "80", &hints, &addresses);
        if (addresses) freeaddrinfo(addresses);

        SOCKET receiver = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        SOCKET sender = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        sockaddr_in endpoint{};
        endpoint.sin_family = AF_INET;
        endpoint.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        endpoint.sin_port = 0;
        if (receiver != INVALID_SOCKET && sender != INVALID_SOCKET &&
            bind(receiver, reinterpret_cast<sockaddr*>(&endpoint), sizeof(endpoint)) == 0) {
            int endpoint_size = sizeof(endpoint);
            getsockname(receiver, reinterpret_cast<sockaddr*>(&endpoint), &endpoint_size);
            const unsigned char smoke_payload[] = {
                'e','d','f','-','s','n','i','f','f','e','r','-','s','m','o','k','e',0,1,2,0xff
            };
            sendto(sender, reinterpret_cast<const char*>(smoke_payload), sizeof(smoke_payload), 0,
                   reinterpret_cast<sockaddr*>(&endpoint), sizeof(endpoint));
            char receive_buffer[64]{};
            sockaddr_in source{};
            int source_size = sizeof(source);
            recvfrom(receiver, receive_buffer, sizeof(receive_buffer), 0,
                     reinterpret_cast<sockaddr*>(&source), &source_size);
        }
        if (sender != INVALID_SOCKET) closesocket(sender);
        if (receiver != INVALID_SOCKET) closesocket(receiver);
        WSACleanup();
    }
    Sleep(250);
    return result && info.infoVersion == 1 && info.name &&
                   std::strcmp(info.name, expected_plugin_name) == 0 &&
                   self_test_result && multi_game_exports
               ? 0
               : 5;
}
