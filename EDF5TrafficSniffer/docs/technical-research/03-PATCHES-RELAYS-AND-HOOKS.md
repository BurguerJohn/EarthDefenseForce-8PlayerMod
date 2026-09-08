# Patches, relays and hooks

## Safety rule

All RVAs here belong exclusively to the EDF5.exe with SHA-256
`3512D2A2E61D532C5D12DC0C5FD1AC61F6743E13349AE21301BB8449DD4BAE5F`.
Runtime resolves RVAs from the loaded module base and validates signatures before writing.

Transactions validate all required bytes/targets, prepare relay pages and hooks,
and install only a consistent complete set. Failure must not leave partial
installation. Removal restores only exact known replacement bytes; unknown bytes
are never overwritten.

## Proven roster limits

The baseline contains 22 operands verified to control participant vectors/lists.

| Structure | Construction/growth | Capacity operands |
| --- | --- | --- |
| Primary roster | Constructor `0x448840`, region `0x44894B` | `0x44894B`, `0x448961` |
| Secondary roster | Constructor `0x4328C0`, grow `0x436990`, former fault `0x7D9B0` | `0x432AF9`, `0x432B14`, `0x432B2C`, `0x436996`, `0x4369B2`, `0x4369DB`, `0x436AAC` |
| Tertiary roster | Constructor `0x419550`, grow `0x41BB30`, former fault `0x25A5C` | `0x419789`, `0x4197A4`, `0x4197BC`, `0x41BB36`, `0x41BB52`, `0x41BB76`, `0x41BC0D` |
| Room boxes | Constructor `0x5A5910`, resize `0x5A7180`, grow `0x5A7240`, update `0x5A5BD0`, fault caller `0x5A5EB6` | `0x5A59FC`, `0x5A5A14`, `0x5A7261`, `0x5A726D`, `0x5A7281`, `0x5A72DC` |

The primary roster operands share a 41-byte region. Original values are four;
replacements use the validated configured preallocation capacity.

## Experimental reserves

There are 24 coherent `capacity < 4` / `reserve(4)` pairs, totaling 48
operands. `ExperimentalReservePatches=true` enables this group; each owner
has not yet been semantically identified.

| Anchor | Reserve operand | Anchor | Reserve operand |
| --- | --- | --- | --- |
| `0x014958D` | `0x0149594` | `0x01CDCF2` | `0x01CDCF9` |
| `0x01CE773` | `0x01CE77A` | `0x01D8176` | `0x01D817D` |
| `0x01D95AD` | `0x01D95B4` | `0x01F7D70` | `0x01F7D77` |
| `0x01FBF2A` | `0x01FBF31` | `0x01FC508` | `0x01FC50F` |
| `0x025D408` | `0x025D40F` | `0x0263925` | `0x026392C` |
| `0x02769A2` | `0x02769A9` | `0x0282612` | `0x0282619` |
| `0x029CBA2` | `0x029CBA9` | `0x02A27A5` | `0x02A27AC` |
| `0x02A6F6F` | `0x02A6F76` | `0x02B0242` | `0x02B0249` |
| `0x02B837D` | `0x02B8384` | `0x02BB10D` | `0x02BB114` |
| `0x02C4B67` | `0x02C4B6E` | `0x02D17F3` | `0x02D17FA` |
| `0x034EAA0` | `0x034EAA7` | `0x035037A` | `0x0350381` |
| `0x047A4CF` | `0x047A4D6` | `0x04AECFE` | `0x04AED05` |

Eleven comparisons remain HOLD without patches: `0x005B6C1`, `0x00D2238`,
`0x00D25B6`, `0x02BD3CF`, `0x0971940`, `0x09722C7`, `0x0C3B97C`,
`0x0C3B9FA`, `0x0C3BA2D`, `0x0C3BC1A` and `0x0C3BC76`.
They resemble state/type/dispatch comparisons, not reserves. See the
[individual rationale](../../EXPERIMENTAL_SLOT_PATCHES.md).

## Room member buttons

Loop `0x565A9D` assumed four stack pointers and could fault at `0x4E4773`.
Sites `0x565AA9`, `0x565AB0`, `0x565ABD` and `0x565AC4` use a safe mapping:
index zero selects the master resource at `0xED7FE8`; all others select the
member resource at `0xED7FC8`. Replacement storage is zeroed before population.

## Participant helper and sidecars

Native helper `0x126C90` receives an external eight-int buffer. The producer is
`0x11D5E0`, relevant write `0x11D7A9`, and cookie-protected return `0x126D57`.
Callsites `0x126CE0` and `0x126D24` connect producer and lookup `0x7E240`.

Creator `0x11D860` calls builder `0x11CE60`, which uses shared copy
`0x6E010`. The classic `0x6E022` failure demonstrated that the fifth control
integer could not safely occupy adjacent native memory.

Native records are `0x18` bytes starting at `+0x138`. The theoretical first
extra address is `+0x198`; it is redirected to one of four sidecars rather
than used as native storage.

- Primary redirect: `0x11DB90`, return `0x11DB98`, loop `0x11DD68`.
- Copy: `0x11DF95`, return `0x11DF9B`.
- Append redirect: `0x11E2A0`, return `0x11E2A7`, backedge `0x11E2FE`.
- Motivating faults: `0x11DC95` and `0x11E2DC`.
- Existing-record flow: `0x11E1A0`, native source `0x11E1AE`,
  extra return `0x11E1CC`.

Result participant filters are `0x42DB4C` and `0x430F23`. They follow
MaxPlayers while physical Item capacity remains four; extras are folded,
never written past the array.

## Mission relay page

A nearby executable page contains stubs and auxiliary data. See the
[memory map](02-MEMORY-MAP.md). Relative jumps require an in-range target
and matching signature. Stubs preserve the original register/flag contract.
Counters/masks are outside code ranges. Prepare the page before patching and
restore call/jump sites before releasing supporting storage.

### Native scaling clamp

There are 56 verified reads of `owner+0x245A0`. Relays limit only those
consumers' observed value to four; the real count remains available to expanded
flows. Destination registers may be EAX, R8D, R9D or R10D; other registers and
flags are preserved.

Leaf sites `0x0008ADCF` and `0x002D0913` have no unwind entry. Getter
`0x11E48E` stays unchanged. See the [full RVA list](08-RVA-REFERENCE.md).

## Hook installation criteria

Require an exact supported signature, a known callsite ABI (volatile registers,
stack and return value included), and a testable shutdown/restoration path.

Observational hooks must not alter state. Corrective hooks are narrow and
require valid extra-player mission, generation, index, pointers and ranges.
Unreadable or contradictory inputs fall back to native flow.

## Canonical sources

[Patch implementation](../../src/games/edf5/coop8/game_patches.cpp),
[participant hooks](../../src/games/edf5/coop8/more_players.cpp),
[spawn policy](../../src/games/edf5/coop8/mission_spawn.cpp),
[result recovery](../../src/games/edf5/coop8/mission_result_recovery.cpp),
[lifecycle](../../src/games/edf5/edf5_module.cpp),
[slot scanner](../../tools/slot_capacity_scanner.cpp),
[player-flow scanner](../../tools/player_flow_scanner.cpp),
[multiplayer validator](../../tools/validate_more_players.py) and
[spawn/result validator](../../tools/validate_spawn_result_layout.py).
