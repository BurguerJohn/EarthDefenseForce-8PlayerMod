#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <string>

namespace edf5 {

bool Load(HMODULE plugin_module);
void RequestStop();
bool SelfTestNetworkHookPolicy(std::string& report);

}  // namespace edf5
