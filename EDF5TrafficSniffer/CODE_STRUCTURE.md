# Code structure

This map records the boundaries that must survive future changes. The plugin
hooks native functions, so even a mechanical refactor can change the ABI,
registers or initialization order.

The consolidated memory map, negative evidence and RVA reference are in the
[reverse-engineering notebook](docs/technical-research/README.md).

## Module tree

```text
src/
|-- core/                         Entry points, configuration and infrastructure
|-- shared/
|   |-- diagnostics/              Logger, snapshots and crash handler
|   |-- sniffer/                  Game-independent Winsock capture
|   `-- steam_legacy/             Legacy Steam ABIs and per-game policy
`-- games/
    |-- edf41/
    |   |-- sniffer/              Steam bootstrap and EDF 4.1 build guard
    |   `-- coop8/                EDF 4.1 room laboratory and native roster patch
    |-- edf5/
    |   |-- sniffer/              EDF5 ContextInit bootstrap and HTTP
    |   `-- coop8/                Multiplayer, patches, spawn and results
    `-- edf6/
        |-- sniffer/              Reserved for implementation
        `-- coop8/                Reserved for implementation
```

One DLL exports `EML4_Load`, `EML5_Load` and `EML6_Load`. Each export selects
exactly one game profile; another game's code must never be installed in the
current process.

### Core

- `src/core/plugin.cpp`: EDFModLoader exports and public EDF5 API.
- `src/core/module_registry.cpp`: selects the profile from the invoked export.
- `src/core/runtime_config.cpp`: loads the sidecar INI, falling back to the
  historical `Mods/TrafficSniffer/config.ini` path.
- `src/core/hook_manager.cpp`: shared MinHook lifecycle.
- `src/core/mod_info.h`: name, version, banner and build ID.
- `src/core/win32_handle.h`: Win32 handles with idempotent close.

### EDF5 Coop8

- `src/games/edf5/edf5_module.cpp`: composition and fail-closed startup.
- `src/games/edf5/coop8/game_patches.cpp`: transactional capacity patches and
  participant relays.
- `src/games/edf5/coop8/mission_spawn.cpp`: testable spawn policy.
- `src/games/edf5/coop8/mission_result_recovery.cpp`: controlled recovery of
  `MissionResult::Exec_Begin`.
- `src/games/edf5/coop8/more_players.cpp`: participant state, native hooks,
  identity, replication, results and experimental tools.

### Shared Steam and sniffer code

- `src/shared/steam_legacy/steam_*.cpp`: wrappers for `Friends015`,
  `MatchMaking009`, `Networking005` and the individually verified
  `SteamUser018/019` methods. Do not infer compatibility from a slot number.
- `src/shared/steam_legacy/steam_game_policy.cpp`: single behavior dispatcher.
  EDF5 delegates to Coop8; EDF 4.1 preserves real traffic and isolates the
  Diagnostics-only synthetic room laboratory.
- `src/shared/sniffer/winsock_hooks.cpp`: game-independent capture, compiled
  only into Diagnostics.
- `src/shared/diagnostics/logger.cpp` and `crash_handler.cpp`: common diagnostics.

### EDF 4.1

- `src/games/edf41/edf41_module.cpp`: profile composition and quarantine.
- `src/games/edf41/sniffer/version_guard.cpp`: pinned PE pair and dedicated fixture.
- `src/games/edf41/sniffer/steam_bootstrap.cpp`: four direct Steam accessors
  and C callback exports; does not use EDF5's Steam context.
- `src/games/edf41/coop8/room_bots.cpp`: isolated room fillers.
- `src/games/edf41/coop8/native_roster_patch.cpp`: transactional expansion of
  the two pinned native room-list vectors.
- `docs/technical-research/edf41/`: fingerprints, evidence, callsites and roadmap.

### EDF5 sniffer/hooks

- `src/games/edf5/sniffer/steam_hooks.cpp`: `SteamInternal_ContextInit`
  bootstrap, synthetic callbacks and vtable composition.
- `src/games/edf5/sniffer/steam_http.cpp`: HTTP wrapper for EDF5's Steam context.
- Coop8 reuses shared vtables to intercept lobby/P2P calls even with telemetry off.

ABI-sensitive hooks should remain minimal wrappers around testable dispatchers,
for example `EnemySpawnHook -> DispatchEnemySpawn`.

### Tools

- `tools/player_flow_scanner.cpp`: participant consumers, route lifecycle,
  route/parser constructors and `parser -> route -> control -> UserImpl`.
- `tools/result_pipeline_scanner.cpp`: fail-closed inventory of small constants
  and capacity masks in the 12 verified result-pipeline bodies, including exact
  `Exec_Begin`, `Update` and `Finally` callers. New, missing or changed
  candidates/callers/wrappers fail the suite.
- `tools/validate_spawn_result_layout.py`: 24 boundary callers, 56 profile
  reads and the GeneratorPoll update/base/gate/vtable/method/return chain,
  including signed cooldown `0x1CC`. ABI changes prevent telemetry installation.
- `tools/steam_accessor_scanner.cpp`: EDF 4.1 direct Steam accessors and nearby
  virtual calls without assigning semantics from slot numbers alone.
- `tools/edf41_steam_harness.cpp`: four legacy interfaces, callbacks,
  passthrough and isolation from EDF5 policy.
- `tools/AuditEdf41.ps1`: hashes, interfaces, IAT/xrefs, strong callsites and
  the negative baseline that prohibits porting EDF5 scanners by RVA.
- `COOP_REVERSE_ROADMAP.md`: verified boundaries, expected next-test signals
  and criteria for promoting an observation to a patch.

## Initialization order

1. `EML4/5/6_Load` selects the game profile.
2. The INI resolves only that profile's Sniffer and Coop8 switches.
3. The logger starts only in Diagnostics when the selected sniffer is active.
4. EDF 4.1 validates pinned PE headers before installing hooks.
5. EDF5 validates and applies capacity patches when Coop8 is enabled.
6. MinHook and required Steam/Winsock hooks are installed.
7. EDF5's hotkey thread starts after the Steam context exists.

EDF 4.1 capture and its room laboratory exist only in Diagnostics. A mismatched
executable or Steam DLL leaves the profile inert. EDF6 modules are disabled
scaffolds. Never reuse EDF5 RVAs, layouts or signatures in those profiles.

## INI switches

The checked-in development configuration enables `EDF41.Sniffer`,
`EDF41.Coop8`, `EDF5.Sniffer` and `EDF5.Coop8`. Both EDF6 modules are disabled.
EDF 4.1 Coop8 is a room-only laboratory, not supported expanded missions.

EDF5 parameters live in `[EDF5.Coop8.Settings]`; legacy `[MorePlayers]` remains
a fallback. Disabling `EDF5.Sniffer` disables logging, crash handling and
capture, while Steam hooks required by Coop8 remain active without logs.
Users builds do not contain the sniffer, regardless of INI values.

A required failure quarantines the plugin, keeping its DLL loaded but inert.
Quarantine disables MinHook and restores capacity, UI, result, mission-relay and
experimental patches only when the complete signatures still match the plugin's
writes. Partially created resources must be undone before returning failure.
Threads that exceed the shutdown timeout retain their handles and modules to
avoid use-after-free.

## Multiplayer invariants

- `MaxPlayers` is 5..8. Native tables that need sidecars or circular mapping
  still physically contain four entries.
- Logical P4-P7 indices must never persist as P0-P3. A circular physical index
  may exist only during the native call that needs it.
- Validate every signature in a patch group before the first write.
- MorePlayers requires `SteamInternal_ContextInit`, `SteamAPI_Shutdown`,
  `SteamAPI_RunCallbacks`, `SteamAPI_RegisterCallback` and
  `SteamAPI_UnregisterCallback`; Winsock cannot replace this dependency.
- Rollback never overwrites unknown bytes: accept only the full replacement set
  or an executable that is already fully original.
- The 56 verified reads indexing native profiles by `participant_count-1`
  see at most 4. The getter and stored field retain the true logical count 5..8.
- Enemy quantities may change only at 24 confirmed callers and never exceed the
  native 400-live-actor cap.
- `Exec_Begin` recovery waits for the native path and is cancelled if it arrives.
  It never runs in the Local Mission Harness or missions with at most four players.
- Recovery pending/tick/generation fields form one transition under
  `g_mission_result_exec_recovery_lock`; hooks cannot publish/consume them separately.
- Preserve native return values, calling conventions and promised Win32/Winsock
  last-error behavior.
- Diagnostics may observe topology, masks and RVAs. Shared reports must exclude
  payloads, endpoints, SteamIDs, names, chat and absolute addresses.
- The Local Mission Harness is host-only and must not change rooms with real peers.

## Validation before distribution

1. Build Release with `build.ps1` and audit both flavors.
2. Run `smoke_harness.exe` against the new DLL.
3. Run `tools/RunDiagnosticsTests.ps1` in a fresh output directory; EDF 4.1 and
   EDF5 Steam integrations run in separate processes.
4. Check the result scanner, spawn/result layout validator, other executable
   audits and privacy tests.
5. Verify four EDF 4.1 accessors, callbacks, real lobby limit 4 and P2P auth;
   verify EDF5 still expands the lobby to 8 through its own policy.
6. Install/copy a DLL only while the target game is closed.
7. Compare SHA-256 of built, installed and packaged DLLs.

The game is never part of automated validation. In-game testing is a separate
manual stage with host and clients using exactly the same package.
