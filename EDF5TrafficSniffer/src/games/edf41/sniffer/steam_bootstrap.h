#pragma once

namespace edf41::sniffer {

// Hooks EDF 4.1's legacy SteamAPI accessors. No game-memory address or EDF5
// CSteamAPIContext layout is used here.
bool InstallSteamHooks();

}  // namespace edf41::sniffer
