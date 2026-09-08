# EDF 4.1 sniffer

Passive implementation based on legacy Steamworks accessors. This directory
contains the build-specific bootstrap and guard; exact vtables are in
`src/shared/steam_legacy`, with Winsock in `src/shared/sniffer`.

The profile does not import EDF5 RVAs, layouts or validators. Its guard recognizes
the pinned `EDF41.exe`/`steam_api64.dll` pair. The offline
`tools/edf41_steam_harness.cpp` covers four interfaces and callbacks.

See the [research index](../../../../docs/technical-research/edf41/README.md).
