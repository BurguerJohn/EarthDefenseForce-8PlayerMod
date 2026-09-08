#pragma once

#include <string>

namespace edf41::native_roster_patch {

// Expands the independent net::Users and net::SessionController room vectors
// from four initialized slots to the requested room capacity. The patch is
// accepted only for the pinned EDF41.exe byte signatures and is applied or
// restored as one eight-site transaction.
bool Install(unsigned capacity);
bool Restore();
bool Ready();

// Pure byte-transaction test used by the EDF4.1 integration harness. It does
// not inspect or modify the host executable.
bool SelfTest(std::string& report);

}  // namespace edf41::native_roster_patch
