#pragma once

#include <cstdint>
#include <string>

#include "steam_legacy_interfaces.h"

namespace steam_capture {

bool Install();
bool SelfTestInstallPolicy(std::string& report);
void HookHttp(void* interface_pointer);

}  // namespace steam_capture
