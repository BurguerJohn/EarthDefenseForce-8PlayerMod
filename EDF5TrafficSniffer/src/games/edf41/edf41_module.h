#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace edf41 {

bool Load(HMODULE plugin_module);
void RequestStop();

}  // namespace edf41
