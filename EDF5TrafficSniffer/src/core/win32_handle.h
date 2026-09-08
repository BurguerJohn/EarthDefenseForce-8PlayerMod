#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace win32_handle {

inline void CloseNullable(HANDLE& handle) {
    if (!handle) return;
    CloseHandle(handle);
    handle = nullptr;
}

inline void CloseFile(HANDLE& handle) {
    if (!handle || handle == INVALID_HANDLE_VALUE) {
        handle = INVALID_HANDLE_VALUE;
        return;
    }
    CloseHandle(handle);
    handle = INVALID_HANDLE_VALUE;
}

inline bool ThreadStopped(HANDLE thread, DWORD timeout_ms) {
    return !thread ||
           WaitForSingleObject(thread, timeout_ms) == WAIT_OBJECT_0;
}

}  // namespace win32_handle
