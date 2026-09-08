#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "game_id.h"
#include "logger.h"

namespace runtime_config {

void SelectGame(game::Id game_id);
game::Id SelectedGame();
capture::Config Load(HMODULE plugin_module = nullptr);

}  // namespace runtime_config
