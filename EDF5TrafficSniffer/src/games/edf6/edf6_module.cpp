#include "edf6_module.h"

#include "logger.h"

namespace edf6 {

bool Load(HMODULE plugin_module) {
    if (!capture::Initialize(plugin_module)) return false;
    const capture::Config& config = capture::GetConfig();
    EDF5_CAPTURE_EVENT(
        capture::Level::Warning, "modules", "game_profile_not_implemented",
        capture::Fields().String("game", "EDF6")
            .Bool("sniffer_requested", config.sniffer)
            .Bool("coop8_requested", config.coop8));
    EDF5_CAPTURE_FLUSH();
    return true;
}

void RequestStop() {}

}  // namespace edf6
