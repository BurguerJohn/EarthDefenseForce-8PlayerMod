#include "module_registry.h"

#include "edf41_module.h"
#include "edf5_module.h"
#include "edf6_module.h"
#include "runtime_config.h"

namespace module_registry {

bool Load(game::Id game_id, HMODULE plugin_module) {
    runtime_config::SelectGame(game_id);
    switch (game_id) {
    case game::Id::Edf41:
        return edf41::Load(plugin_module);
    case game::Id::Edf5:
        return edf5::Load(plugin_module);
    case game::Id::Edf6:
        return edf6::Load(plugin_module);
    case game::Id::Unknown:
        break;
    }
    return false;
}

void RequestStop() {
    switch (runtime_config::SelectedGame()) {
    case game::Id::Edf41:
        edf41::RequestStop();
        break;
    case game::Id::Edf5:
        edf5::RequestStop();
        break;
    case game::Id::Edf6:
        edf6::RequestStop();
        break;
    case game::Id::Unknown:
        break;
    }
}

}  // namespace module_registry
