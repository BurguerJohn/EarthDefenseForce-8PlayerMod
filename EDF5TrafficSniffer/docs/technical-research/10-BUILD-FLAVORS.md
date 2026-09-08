# Build flavors: Users and Diagnostics

## Purpose

Since 0.6.54, diagnostics are optional at compile time. INI Enabled=false only
disables runtime behavior; it does not remove code. Users defines
EDF5_COMPILE_DIAGNOSTICS=0 so preprocessing and linking remove instrumentation
before distribution.

## Build contract

- build.ps1 -Flavor Diagnostics defines EDF5_COMPILE_DIAGNOSTICS=1 and writes
  build/EDF5_MultiSlotMod.dll. It is the historical suite's default.
- build.ps1 -Flavor Users defines EDF5_COMPILE_DIAGNOSTICS=0 and writes
  build/users/EDF5_MultiSlotMod.dll without replacing Diagnostics.
- build_config.h centralizes the flag and rejects values other than 0/1.
- Build IDs are edf5mp-0.6.64-diagnostics-win64 and edf5mp-0.6.64-users-win64.

## Excluded from Users

The build does not compile/link logger.cpp (queue, writer, JSONL, payloads,
rotation, retention, network aggregation, session metadata), crash_handler.cpp
(VEH, exception filter, dumps, snapshots, F9/F10, breadcrumbs, watchdog), or
winsock_hooks.cpp (process-wide socket/DNS detours).

EDF 4.1 sniffer and room-laboratory objects are also Diagnostics-only.

Conditional macros put event fields, breadcrumbs, diagnostic runtime state and
packet aggregation into if constexpr(false) branches in Users. The optimizer
does not emit them. The failure-only __report_gsfailure hook is neither validated
nor installed. EDF5MP_RequestDiagnosticSnapshot and EDF5MP_SetDeepCapture exports
exist only in Diagnostics.

## Preserved configuration

runtime_config.cpp separates INI reading from the former logger responsibility.
Both flavors read functional per-game Coop8 configuration; EDF5 settings use
[EDF5.Coop8.Settings] with legacy [MorePlayers] fallback. Only Diagnostics reads
diagnostic/capture settings. Users still installs Steam hooks required by Coop8,
but does not request Winsock or capture-only callbacks.

## Automated checks

tools/VerifyBuildFlavors.ps1 builds both flavors, loads Users through each game
entry point, runs the isolated EDF5 self-test, rejects diagnostic/EDF 4.1 objects
in Users, scans for session/snapshot/crash/payload markers, validates its build ID
and requires Users to be smaller than Diagnostics.

The initial 2026-08-31 build was approximately 711 KiB Users versus 1.37 MiB
Diagnostics. Its full offline Diagnostics suite at
test-output/diagnostics-20260831T210430Z had zero failed gates. These are historical
sizes/results; verify current binaries rather than reusing old hashes.
