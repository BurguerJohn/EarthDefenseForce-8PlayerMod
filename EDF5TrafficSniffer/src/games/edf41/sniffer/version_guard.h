#pragma once

namespace edf41::sniffer {

// Accepts only the pinned EDF41.exe + steam_api64.dll pair documented under
// docs/technical-research/edf41. The dedicated integration harness is the
// only non-game process allowed through this guard.
bool ValidateSupportedBuild();

}  // namespace edf41::sniffer
