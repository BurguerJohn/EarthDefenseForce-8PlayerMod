# Reverse-engineering notebook

This directory consolidates technical knowledge accumulated while developing
`EDF5_MultiSlotMod`. It does not replace the source: byte signatures, ABI types
and runtime lists remain canonical in `src/` and `tools/`. This notebook
preserves reasoning, memory layouts, evidence, past mistakes and boundaries that
cannot yet be changed safely.

## Pinned scope

- Documented mod: `EDF5_MultiSlotMod 0.6.64`.
- Build IDs: `edf5mp-0.6.64-diagnostics-win64` and `edf5mp-0.6.64-users-win64`.
- Supported executable: x64 `EDF5.exe`.
- Executable SHA-256: `3512D2A2E61D532C5D12DC0C5FD1AC61F6743E13349AE21301BB8449DD4BAE5F`.
- Observed Steam API: `steam_api64.dll` version `04.28.51.07`, SHA-256
  `B8246E1A629B945FE526B24C3E4F002C4F6EB86AA1B5ED9744399F22A0D2CA9F`.
- ABI: Windows x64/MSVC in the game; C++17 plugin built with Zig 0.14.1 for
  `x86_64-windows-gnu`.

Addresses are main-module RVAs unless explicitly described as object offsets:

```text
runtime_virtual_address = EDF5.exe_base + RVA
```

ASLR makes absolute virtual addresses unsuitable for reuse across executions.

## Evidence levels

- **STATICALLY-PROVEN:** bytes, flow, callers and layout checked in the pinned
  executable and protected by a scanner/signature.
- **OFFLINE-PROVEN:** also covered by a self-test, fixture or deterministic microtest.
- **OBSERVED-IN-GAME:** appeared in a real session's reports or dumps.
- **INFERRED:** explains current evidence but lacks a decisive observation.
- **EXPERIMENTAL:** deliberate opt-in behavior without enough validation to call safe.
- **PENDING:** an open question; numerical resemblance is not grounds for a patch.

When historical notes disagree with current implementation, use `src/`, the
validators and the 0.6.64 notebook. Old hypotheses explain why approaches were removed.

## Index

1. [Executable and architecture](01-EXECUTABLE-AND-ARCHITECTURE.md):
   fingerprints, ABI, modules, startup and fail-closed policy.
2. [Memory map](02-MEMORY-MAP.md): objects, vectors, offsets and player-index domains.
3. [Patches, relays and hooks](03-PATCHES-RELAYS-AND-HOOKS.md):
   proven patches, rollback, required hooks and the failures they prevent.
4. [Steam lobby networking and replication](04-STEAM-LOBBY-NETWORKING-AND-REPLICATION.md):
   Steamworks, fillers, handshake, P2P and receive-parser ownership.
5. [Mission, loadout, spawn and results](05-MISSION-LOADOUT-SPAWN-AND-RESULTS.md):
   entry, controls, equipment, enemies, sync, rewards and room return.
6. [Diagnostics, testing and privacy](06-DIAGNOSTICS-TESTING-AND-PRIVACY.md):
   sessions, events, dumps, fixtures and offline gates.
7. [Evidence, failures and open questions](07-EVIDENCE-FAILURES-AND-OPEN-QUESTIONS.md):
   crash timeline, negative conclusions and next manual tests.
8. [RVA reference](08-RVA-REFERENCE.md): offsets, spawn callers and scaling reads.
9. [Five-player live test, 2026-08-31](09-FIVE-PLAYER-LIVE-TEST-2026-08-31.md):
   cross-report audit, functional evidence, warning reclassification and unproven limits.
10. [Build flavors](10-BUILD-FLAVORS.md): compile-time boundary,
    configuration and checks for diagnostic code leaking into Users.
11. [EDF 4.1 research](edf41/README.md): independent baseline, passive sniffer,
    proven Steam ABI and future Coop8 gates.

## Central findings

1. The four-player limit is not one constant. Dynamic collections, physical
   four-entry tables, stack arrays, difficulty profiles 1..4 and overlapping
   result buffers each require different treatment.
2. `UserImpl+0xF8` is the logical/loadout index; `+0xC8` is transport route;
   `+0x190` is local control; visual slot is transient `logical_index % 4`.
   Confusing these domains caused crashes and P4/P0 aliases.
3. The receive vector does not store `UserImpl` directly. Ownership is
   `parser+0x498 -> route+0x58 -> control+0x08 -> UserImpl`.
   The former `parser-0x88` hypothesis was wrong.
4. The hypothetical fifth loadout block starts at `mission_state+0x24570`,
   overlapping Items at `+0x2457C`, local-profile count at `+0x2459C` and
   participant count at `+0x245A0`. P4-P7 need sidecars and bytewise rollback.
5. Exactly 56 proven participant-count reads index native 1..4 profiles. Only
   those reads clamp to 4; stored count and the getter still return 5..8.
6. Exactly 24 direct callers reach the common enemy-creation boundary.
   Multiplication/scale repair is restricted to them and the 400-live-actor cap.
7. Results mix dynamic handles with four fixed Item accumulators. Dynamic
   filters accept P4-P7 and atomically fold them into `index % 4` before rewards.
8. Startup requires all MorePlayers Steam hooks. Quarantine restores only bytes
   matching the complete plugin replacement set; it never overwrites unknown bytes.
9. The 0.6.52 five-player live test completed gameplay, spawn, results, rewards,
   room return and a second mission on every machine. Version 0.6.53 corrected
   diagnostic semantics and associations exposed by that test.

## Related records

- [Participant flow audit](../../PLAYER_FLOW_AUDIT.md)
- [Experimental slot inventory](../../EXPERIMENTAL_SLOT_PATCHES.md)
- [Cooperative roadmap](../../COOP_REVERSE_ROADMAP.md)
- [Code structure](../../CODE_STRUCTURE.md)

`BUILDINFO.json` is local generated validation/build metadata and is excluded
from the public repository. Release hashes must describe the actual packaged
binaries, not an earlier local build.

## Maintenance rule

A changed RVA, signature, layout, caller or ABI must update the consuming code,
corresponding scanner, applicable self-test/fixture and notebook in the same
commit. Refresh local build metadata after final validation.

Never promote a constant 4 to a player limit without proving its owner,
associated allocation, all callers and lifecycle.
