#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace hooks {

bool Initialize();
void Shutdown();
void ReportStartupFailure(const char* reason);
bool Export(const wchar_t* module, const char* name, void* detour, void** original,
            bool required = false);
bool Address(void* target, void* detour, void** original, const char* label,
             bool required = false);
void* SharedAddress(void* target, void* detour, const char* label);

}  // namespace hooks
