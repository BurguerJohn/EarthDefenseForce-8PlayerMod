# Executable, ABI and plugin architecture

## Supported build identity

The plugin uses RVAs and exact signatures, not public function symbols.

| Item | Value |
| --- | --- |
| Game | EARTH DEFENSE FORCE 5, x64 `EDF5.exe` |
| SHA-256 | `3512D2A2E61D532C5D12DC0C5FD1AC61F6743E13349AE21301BB8449DD4BAE5F` |
| Steam API | `04.28.51.07` |
| Steam API SHA-256 | `B8246E1A629B945FE526B24C3E4F002C4F6EB86AA1B5ED9744399F22A0D2CA9F` |
| ModLoader | EDFModLoader 1.0.10, commit `c686e8fb48121e0a6b3f6b7f42d6df0d5249678b` |
| MinHook | 1.3.4, commit `c3fcafdc10146beb5919319d0683e44e3c30d537` |
| Steam headers | commit `df2baabf574a738ef1ea90a7e89339107fc0a279` |
| Compiler | Zig 0.14.1, C++17, `x86_64-windows-gnu` |

The executable must have valid DOS/PE64 headers and `SizeOfImage`. EDF5 game
hooks require the main process name `EDF5.exe`. Offline harnesses load the DLL
but deliberately skip live image patches.

## RVA, VA and ASLR

Persist module-relative RVAs, never absolute pointers from a particular execution:

```text
runtime_VA = GetModuleHandleW(nullptr) + RVA
RVA        = runtime_VA - module_base
```

Validators map RVAs to file offsets in the on-disk PE. Runtime checks first
confirm the interval lies within the image and has the expected protection.

## ABI boundary

The game and Steam DLL use MSVC x64 ABI. The plugin uses Clang/Zig with the
MinGW runtime, so these details are intentional:

- Explicit `__fastcall` signatures on native hooks.
- RCX, RDX, R8 and R9 remain the first four integer arguments.
- Stack patches must preserve shadow space, 16-byte alignment and native unwind data.
- Steam methods returning `CSteamID` by value use a hidden return buffer:
  `RCX=this`, `RDX=result`, then declared arguments.
- `PlayerInfoFromUser` must return the original destination in RAX even though
  it is also passed in RCX.
- `GeneratorPoll::Spawn` has an unknown source return type, but its caller
  consumes AL. The wrapper uses `uintptr_t` to preserve all of RAX.
- `ResultSync_Update` returns bool with caller-dependent meaning; observe it
  without assigning universal success semantics.
- Preserve `ResultSync_Finally` as void.
- Preserve Winsock/Win32 last-error values when observable in the native contract.
- `__report_gsfailure` ends in `int 29h`; its hook captures evidence before
  the original termination.

## Modules and ownership

| Module | Responsibility |
| --- | --- |
| `src/core/plugin.cpp` | Multi-game EDFModLoader exports |
| `src/games/edf5/edf5_module.cpp` | EDF5 startup and quarantine |
| `src/core/hook_manager.cpp` | MinHook, export/RVA hooks and early journal |
| `src/games/edf5/coop8/game_patches.cpp` | Transactional patches, relays and restoration |
| `src/games/edf5/coop8/more_players.cpp` | Participant state, game hooks, fillers and telemetry |
| `src/games/edf5/coop8/mission_spawn.cpp` | Pure enemy quantity/scale policy |
| `src/games/edf5/coop8/mission_result_recovery.cpp` | Pure Exec_Begin fallback policy |
| `src/games/edf5/sniffer/steam_hooks.cpp` | EDF5 ContextInit bootstrap |
| `src/shared/steam_legacy/steam_*.cpp` | Steam ABI wrappers shared with EDF 4.1 |
| `src/shared/sniffer/winsock_hooks.cpp` | Sockets, DNS and overlapped I/O |
| `src/shared/diagnostics/logger.cpp` | Bounded queue, rotation, status and diagnostic output |
| `src/shared/diagnostics/crash_handler.cpp` | Breadcrumbs, snapshots, exceptions and minidumps |

`more_players.cpp` keeps private detour state in one translation unit.
Splitting it without an ownership plan can introduce destruction-order problems,
races or ABI drift.

## Initialization

For Diagnostics, `EML5_Load` proceeds through these stages (Users excludes
diagnostic code at compile time):

1. Fill `PluginInfo` with name/version.
2. Load the sidecar configuration and initialize logging.
3. Initialize crash capture.
4. Install roster, UI, mission, result and scaling patches.
5. Optionally install experimental reserves.
6. Initialize MinHook.
7. Validate game signatures and install MorePlayers hooks.
8. Install required Steam hooks.
9. Install Winsock if requested.
10. After `SteamInternal_ContextInit`, capture Steam interfaces and start hotkeys.

Diagnostics may fail while MorePlayers continues only if MorePlayers is enabled
and its critical requirements remain safe. An unavailable crash handler records
an error but does not itself change game behavior.

## Required Steam hooks

MorePlayers requires:

- `SteamInternal_ContextInit`
- `SteamAPI_Shutdown`
- `SteamAPI_RunCallbacks`
- `SteamAPI_RegisterCallback`
- `SteamAPI_UnregisterCallback`

Working Winsock cannot compensate for incomplete Steam hooks. Without
MorePlayers, only ContextInit is required to consider Steam capture installed;
other hooks may be optional according to configuration.

## Fail-closed quarantine

A required failure calls `QuarantinePluginLoad`:

1. Record the synchronous cause in `Mods/TrafficSniffer/startup-failures.log`
   when diagnostics are compiled.
2. Emit `startup_failed`.
3. Request MorePlayers shutdown.
4. Disable all MinHook hooks.
5. Restore executable patches only if the current bytes match the complete
   replacement set, or the executable is already entirely original.
6. Emit `startup_quarantine_complete` with `patches_restored`.
7. Request crash-handler/logger shutdown.
8. Keep the DLL loaded but inert.

Loading may occur under the loader lock. Unloading before newly created threads
start could cause use-after-free at their entry point. Quarantine reports
success to the loader only to retain the inert module and failure journal.

## Transactional patches

For each group, validate every original signature before writing, make all
affected pages writable, write the complete group, flush the instruction cache,
reread and compare every replacement, and roll back on any failure. Restore
original page protections; failure to restore them also fails the transaction.

Quarantine does not repair mixed/unknown bytes. This prevents overwriting game
updates, other mods or corruption not produced by this plugin.

## Shutdown

`SteamAPI_Shutdown` stops MorePlayers before calling Steam, then stops crash
capture and flushes the logger. `DllMain(DLL_PROCESS_DETACH)` only requests
shutdown; it does not wait for threads under the loader lock. Timed-out threads
retain their handles/modules to avoid executing unloaded code.

## Configuration boundaries

- `MaxPlayers`: 5..8.
- `PreallocatedRosterSlots`: at least MaxPlayers; 8 is the baseline.
- `ExperimentalReservePatches`: only the 24 unidentified-owner reserve groups.
- `ExperimentalEnemySpawnMultiplier`: separate opt-in from scale compatibility repair.
- `EnemySpawnMultiplier`: 1..8, saturated at 400.
- `LocalMissionHarnessEnabled`: host-only, no real peer.
- `DebugStageWinEnabled`: manual debug action, not natural mission flow.

## Canonical sources

[Identity](../../src/core/mod_info.h),
[entry points](../../src/core/plugin.cpp),
[EDF5 startup](../../src/games/edf5/edf5_module.cpp),
[hook manager](../../src/core/hook_manager.cpp) and
[build script](../../build.ps1).
Local `BUILDINFO.json` is generated metadata, excluded from the public tree.
