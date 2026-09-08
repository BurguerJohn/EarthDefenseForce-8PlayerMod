#pragma once

#include "build_config.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdint>

namespace crash_capture {

struct HookContext {
    char component[32]{};
    char operation[48]{};
    char phase[32]{};
    uint64_t value_a = 0;
    uint64_t value_b = 0;
};

#if EDF5_COMPILE_DIAGNOSTICS

class HookScope {
public:
    HookScope(const char* component, const char* operation,
              const char* phase = "enter", uint64_t value_a = 0,
              uint64_t value_b = 0);
    ~HookScope();
    void Phase(const char* phase, uint64_t value_a = 0,
               uint64_t value_b = 0);

    HookScope(const HookScope&) = delete;
    HookScope& operator=(const HookScope&) = delete;

private:
    HookContext previous_{};
};

bool Initialize(HMODULE plugin_module);
void RequestStop();
void Stop();
bool RequestSnapshot(const char* source = "api");
bool SetDeepCapture(bool enabled, const char* source = "api");
bool WaitForIdle(unsigned timeout_ms);
// Records a native fast-fail before the process executes int 29h. This is
// needed for /GS cookie failures, which bypass normal vectored/top-level
// exception handlers. detection_address should be the return address of the
// failing security-cookie check so the report identifies the corrupting
// function rather than the shared CRT fast-fail stub.
bool CaptureFastFail(uint32_t subcode, uintptr_t detection_address);

void Breadcrumb(const char* component, const char* operation,
                const char* phase, uint64_t value_a = 0,
                uint64_t value_b = 0);
HookContext CurrentHookContext();

#else

class HookScope {
public:
    HookScope() = default;
    void Phase() {}
};

template <typename... Values>
inline void Discard(Values&&...) {}

#endif

}  // namespace crash_capture

#if EDF5_COMPILE_DIAGNOSTICS
#define EDF5_DIAGNOSTIC_SCOPE(name, ...) \
    ::crash_capture::HookScope name(__VA_ARGS__)
#define EDF5_DIAGNOSTIC_PHASE(name, ...) name.Phase(__VA_ARGS__)
#define EDF5_CRASH_BREADCRUMB(...) ::crash_capture::Breadcrumb(__VA_ARGS__)
#define EDF5_CRASH_STOP() ::crash_capture::Stop()
#else
#define EDF5_DIAGNOSTIC_SCOPE(name, ...)                              \
    ::crash_capture::HookScope name;                                 \
    do {                                                             \
        (void)sizeof(name);                                          \
        if constexpr (false) ::crash_capture::Discard(__VA_ARGS__);  \
    } while (false)
#define EDF5_DIAGNOSTIC_PHASE(name, ...)                              \
    do {                                                             \
        (void)sizeof(name);                                          \
        if constexpr (false) ::crash_capture::Discard(__VA_ARGS__);  \
    } while (false)
#define EDF5_CRASH_BREADCRUMB(...)                                   \
    do {                                                             \
        if constexpr (false) ::crash_capture::Discard(__VA_ARGS__);  \
    } while (false)
#define EDF5_CRASH_STOP() ((void)0)
#endif
