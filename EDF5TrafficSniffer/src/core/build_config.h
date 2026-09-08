#pragma once

// build.ps1 defines this for every official build. Keeping a diagnostic
// default preserves compatibility with standalone harness builds.
#ifndef EDF5_COMPILE_DIAGNOSTICS
#define EDF5_COMPILE_DIAGNOSTICS 1
#endif

#if EDF5_COMPILE_DIAGNOSTICS != 0 && EDF5_COMPILE_DIAGNOSTICS != 1
#error "EDF5_COMPILE_DIAGNOSTICS must be 0 or 1"
#endif

namespace build_config {

inline constexpr bool kDiagnostics = EDF5_COMPILE_DIAGNOSTICS != 0;

}  // namespace build_config
