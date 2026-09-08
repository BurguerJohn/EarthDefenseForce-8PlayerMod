#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "game_id.h"

namespace module_registry {

bool Load(game::Id game_id, HMODULE plugin_module);
void RequestStop();

}  // namespace module_registry
