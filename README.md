# EDF5 MultiSlot Mod

Source and development tools for **EDF5_MultiSlotMod**, an experimental x64
EDFModLoader plugin that expands EARTH DEFENSE FORCE 5 lobbies to five through
eight players. It includes participant, loadout, spawn and result compatibility
patches, offline regression tests and optional diagnostics.

F4 opens Steam's invite dialog for a locally created room, including after the
game's usual four-player UI limit. The mouse wheel scrolls the participant list.
Synthetic fillers and a host-only mission harness are available for development;
fillers have no combat AI and are not real Steam lobby members.

Five-player EDF5 testing is recorded in the research documentation. Eight is the
configured target, not a claim that every eight-player mission has been validated.
All participants should use the same mod version and configuration. Required
executable signatures are checked before patches are installed.

The DLL exports EDF 4.1 and EDF6 entry points too. EDF 4.1 has a passive sniffer
and a Diagnostics-only local room laboratory; missions above four players are
unsupported. EDF6 modules are disabled scaffolds.

## Repository layout

```text
EDF5TrafficSniffer/
  src/               Core, shared code and per-game modules
  tools/             Offline harnesses, scanners, validators and report tools
  tools/fixtures/    Regression test data
  docs/              Reverse-engineering documentation
  release-assets/    Packaged-build instructions
  build.ps1          Windows x64 build
  config.ini         Development INI copied beside the built DLL
```

## Requirements and dependency setup

Use Windows x64, PowerShell and Zig **0.14.1**. Python 3 is required for Python
validators; disassembly helpers additionally require Capstone. Install the
following dependencies relative to this README:

```text
EDFModLoader/EDFModLoader/PluginAPI.h
SteamworksSDK-Headers/public/steam/steam_api.h
EDF5TrafficSniffer/third_party/minhook/include/MinHook.h
EDF5TrafficSniffer/tools/zig/zig.exe
```

Obtain the pinned EDFModLoader 1.0.10 and MinHook 1.3.4 sources with:

```powershell
git clone https://github.com/BlueAmulet/EDFModLoader.git EDFModLoader
git -C EDFModLoader checkout c686e8fb48121e0a6b3f6b7f42d6df0d5249678b
git clone --branch v1.3.4 --depth 1 https://github.com/TsudaKageyu/minhook.git EDF5TrafficSniffer/third_party/minhook
```

Extract Zig 0.14.1 at the path above. Obtain compatible Steamworks SDK headers
separately under their own terms and place their `public` directory under
`SteamworksSDK-Headers`. See [third-party dependencies](THIRD_PARTY.md).

## Build

From the repository root, build the DLL intended for ordinary users:

```powershell
& .\EDF5TrafficSniffer\build.ps1 -Configuration Release -Flavor Users
```

Output: `EDF5TrafficSniffer/build/users/EDF5_MultiSlotMod.dll` and its sidecar
`EDF5_MultiSlotMod.ini`. Users builds exclude logging, payload capture, crash
handling and the EDF 4.1 laboratory at compile time. INI switches cannot
reactivate excluded code.

For development, build Diagnostics (the default flavor):

```powershell
& .\EDF5TrafficSniffer\build.ps1 -Configuration Release -Flavor Diagnostics
```

Diagnostics outputs go to `EDF5TrafficSniffer/build/`. Pass
`-Zig 'C:\path\to\zig.exe'` to use another compiler location. Building does not
install the plugin or start the game.

## Installation and configuration

Install EDFModLoader in your own game installation. Close the game, then copy
the selected DLL and its sidecar INI together to `Mods/Plugins/`.

Review the INI before packaging: the checked-in configuration is for development
and enables experimental reserve patches, debug hotkeys and the EDF 4.1 room
laboratory. `MaxPlayers` accepts 5 through 8; `PreallocatedRosterSlots` must be at
least `MaxPlayers`. The Users DLL ignores all diagnostic and sniffer switches.

When enabled, F8 adds a filler, F7 removes the latest, F6 reapplies EDF5 filler
Ready state, F3 cycles the host-only mission harness, and F5 requests mission
completion. These are development controls; ordinary multiplayer uses real peers.

## Validation

With Zig at the default path, build and audit both flavors:

```powershell
& .\EDF5TrafficSniffer\tools\VerifyBuildFlavors.ps1
```

Run the standalone smoke test after building Diagnostics:

```powershell
& .\EDF5TrafficSniffer\build\smoke_harness.exe .\EDF5TrafficSniffer\build\EDF5_MultiSlotMod.dll
```

The full offline suite is:

```powershell
& .\EDF5TrafficSniffer\tools\RunDiagnosticsTests.ps1
```

The full suite includes static audits of locally installed game executables and
assumes the original `<EDF5 game>/_dev/EDF5TrafficSniffer` layout. Game files are
not distributed here. Automated tests do not launch the game and do not replace
manual host/client validation.

## Documentation and reports

See the [project documentation](EDF5TrafficSniffer/README.md),
[code structure](EDF5TrafficSniffer/CODE_STRUCTURE.md) and
[research index](EDF5TrafficSniffer/docs/technical-research/README.md).

Raw logs and dumps can contain identities, endpoints, tickets and process memory.
Use `EDF5TrafficSniffer/tools/CreateDebugReport.ps1` to prepare a sanitized report,
review it before sharing, and keep raw captures and dumps out of Git.

Hook changes must preserve ABI, native return values and transactional rollback.
Record the executable signatures and evidence behind each patch. Keep game
addresses isolated and distinguish offline validation from in-game observations.

## Credits

Thanks to **[mi9202](https://github.com/mi9202)** for
[pull request #1](https://github.com/BurguerJohn/EarthDefenseForce-8PlayerMod/pull/1),
researched and tested in six-player sessions:

- **Vehicle rear seats:** players 5-8 can ride in a rear seat of the Caliban
  and of cars with more than four seats. Previously they could only drive, and
  the native seat pickers wrote past the end of their seat list. Ported in
  0.6.78 together with the PR's execution self-tests.
- **Enemy HP with 5-8 players:** enemy health keeps scaling past the
  four-player value. On Inferno that is 1.25/1.30/1.35/1.40 for 5/6/7/8
  players. It can be configured with `ExtendedEnemyHealthScaling` and
  `EnemyHealth5Players`..`EnemyHealth8Players`. Ported in 0.6.78.
- **Six-player crash fixes:** the PR independently fixed the player 5-8 loadout
  blocks, the mission-start message reserve, the spawn transform loop and
  script records 4-7. It reached the same diagnosis as this mod's 0.6.66 and
  0.6.77 fixes, and gave them independent confirmation. Those existing
  implementations were kept.

## Publishing and licensing

Initialize Git in this directory. Before committing, inspect `git status --short`
and `git diff --cached --stat`. Only source, documentation, configuration, tools
and fixtures should be staged. Distribute binaries through GitHub Releases.

No first-party license has been selected. Public visibility alone does not grant
reuse or redistribution rights; the maintainer should select a license before
advertising the project as open source. Dependencies retain their own terms.
