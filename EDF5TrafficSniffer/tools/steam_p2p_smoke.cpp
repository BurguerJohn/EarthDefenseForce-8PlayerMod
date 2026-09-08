#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "logger.h"
#include "steam_interfaces.h"

#include <cstdint>
#include <cstdio>
#include <cstring>

namespace {

struct FakeInterface { void** vtable; };

bool FakeUnused(void*) { return false; }

bool FakeSend(void*, uint64_t peer, const void* data, uint32_t size, int send_type, int channel) {
    static const uint8_t expected[] = {'s','t','e','a','m','-','p','2','p','-','o','u','t',0,0xff};
    return peer == 76561198000000001ull && send_type == 2 && channel == 7 &&
           size == sizeof(expected) && std::memcmp(data, expected, sizeof(expected)) == 0;
}

bool FakeRead(void*, void* destination, uint32_t capacity, uint32_t* size,
              uint64_t* peer, int channel) {
    static const uint8_t response[] = {'s','t','e','a','m','-','p','2','p','-','i','n',0,1,2,0xfe};
    if (channel != 7 || capacity < sizeof(response)) return false;
    std::memcpy(destination, response, sizeof(response));
    *size = sizeof(response);
    *peer = 76561198000000002ull;
    return true;
}

}  // namespace

int main() {
    if (!capture::Initialize(GetModuleHandleW(nullptr))) return 2;
    void* vtable[22];
    for (void*& slot : vtable) slot = reinterpret_cast<void*>(&FakeUnused);
    vtable[0] = reinterpret_cast<void*>(&FakeSend);
    vtable[2] = reinterpret_cast<void*>(&FakeRead);
    FakeInterface interface_object{vtable};
    steam_capture::HookNetworking(&interface_object);

    static const uint8_t outbound[] = {'s','t','e','a','m','-','p','2','p','-','o','u','t',0,0xff};
    using SendFn = bool (*)(void*, uint64_t, const void*, uint32_t, int, int);
    const bool sent = reinterpret_cast<SendFn>(interface_object.vtable[0])(
        &interface_object, 76561198000000001ull, outbound, sizeof(outbound), 2, 7);

    uint8_t inbound[64]{};
    uint32_t inbound_size = 0;
    uint64_t inbound_peer = 0;
    using ReadFn = bool (*)(void*, void*, uint32_t, uint32_t*, uint64_t*, int);
    const bool read = reinterpret_cast<ReadFn>(interface_object.vtable[2])(
        &interface_object, inbound, sizeof(inbound), &inbound_size, &inbound_peer, 7);

    capture::Flush();
    Sleep(250);
    std::printf("send=%s read=%s bytes=%u peer=%llu session=%s\n",
                sent ? "true" : "false", read ? "true" : "false", inbound_size,
                static_cast<unsigned long long>(inbound_peer),
                capture::WideToUtf8(capture::SessionDirectory().c_str()).c_str());
    return sent && read && inbound_size == 16 && inbound_peer == 76561198000000002ull ? 0 : 3;
}
