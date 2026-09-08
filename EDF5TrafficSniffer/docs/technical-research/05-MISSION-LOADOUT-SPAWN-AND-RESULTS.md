# Mission, loadout, spawn and results

## Capacity model

Expanded support distinguishes logical participants (up to MaxPlayers, maximum
eight), physical native blocks/slots (some remain four), and consumers extended
through sidecars, folding or temporary remapping. Confusing these quantities
caused the most serious historical failures.

## Mission state

Main mission update: `0x3E1890`. UserImpl holds logical/loadout index at +0xF8,
voice state at +0x100, l1/l2 mission groups, private descending sort key at +0x184,
and local-control index at +0x190. Never log the sort key or treat local control
as a global identity.

## Loadout layout

Parser `0x42F480` uses the state pointer at global slot `0x125AB30`.
Loadout blocks have stride 0x3E90; selection starts at +0x14B30, records at
+0x14B38 with stride 0x18. The observed selection bound is 16 slots across the
native records, not sixteen participants. Classes are 0..3, with six equipment
IDs and armor at block+0xF8.

The hypothetical fifth block at state+0x24570 overlaps:

- Four eight-byte Items at +0x2457C.
- Local reward-profile count at +0x2459C.
- Participant count at +0x245A0.

No independent fifth native block exists. Preserve extra logical identity in
sidecars and expose only a temporary bounded view to the exact native consumer.

## Lookup, copy and creation

| Boundary | RVA / call / return |
| --- | --- |
| Source lookup | `0x7E240`, call `0x11CF08`, return `0x11CF0D` |
| Transfer | `0x11DFCE`, return `0x11DFD3` |
| Append | `0x11E057`, return `0x11E05C` |
| Class consumer | `0x3123A0` |
| Identity reads | `0x11D0DD`, `0x11E05D` |
| Shared copy | `0x6E010` |
| Collection copy | `0x12B200`, calls `0x11D6AA`, `0x11D6CF` |
| Player creation | `0x11CE60`, calls `0x11DC34`, `0x11ECE9` |

Native physical loadout resources have four slots. P4-P7 fallback to 0..3 may
exist only during the factory requiring a native block. Restore UserImpl+0xF8
before name, route and replication consumers. Permanently reusing P0 for P4
duplicates identity and breaks control.

## Class and visuals

Class resolver: `0x4B6710`.

| Visual/parser boundary | RVA |
| --- | --- |
| Visual table | `0x4BB5E1` |
| Render submit | `0x4BBC37` |
| Native class read | `0x4B6886` |
| Text table / selection | `0x4BB5CE / 0x4BC266` |
| Historical invalid string read | `0x5E741C` |
| Shared render copy / reference read | `0xB1CF0 / 0xB1D60` |
| Consumer block / record | `0x31240C / 0x31242E` |
| Parser stride / record / count write | `0x42F7C9 / 0x42F881 / 0x42FA69` |

Transient extra-player visual index is logical % 4; final class is 0..3.
Neither changes network identity. The 0.6.26 P4/class-1 overlap uses weapon mask
0x2F and native fallback bit 0x10. These belong to this exact layout, not future
executable versions generally.

## Result Items and folding

Filter `0x430F23` accepts MaxPlayers, but physical Items[4] ends before the
counters. Sink `0x132BB0` atomically folds extra participants into
`destination = logical_index % 4`. Preserve reward totals without out-of-range
writes. Initialization at `0x430EF6` must remain four; expansion would overwrite
+0x2459C/+0x245A0.

## Completion pipeline

| Stage | Implementation | Callers and returns |
| --- | --- | --- |
| Exec_Begin | `0x42FD20` | Native argument setup `0x1153E9`, call `0x1153EE`, return `0x1153F3`; script wrapper `0x42AC40`, call `0x42AC48`, return `0x42AC4D` |
| Update | `0x430C20` | Script wrapper `0x42AC60`, call `0x42AC9F`, return `0x42ACA4`; native body `0x12AA30`, call `0x12AA8D`, return `0x12AA92` |
| Finally | `0x42F090` | Script wrapper `0x42AC20`, call `0x42AC28`, return `0x42AC2D`; native call `0x12AAA9`, return `0x12AAAE` |

Named sync uses begin `0x41F820` and poll `0x41F920`; script calls
`0x3E2DD8/0x3E2DE4`, network calls `0x42C134/0x42C13B`.

Rewards pass through ResolveResult `0x3E3150` and ApplyResult `0x3E3160`.
Count read: `0x3E3190`; profile base: `0x3E31A4`; stride: `0x3E32AE`;
local count setter: `0x55830`.

ApplyResult's bool does not mean reward success. Worker `0x199D50` is called at
`0x3E3175` independently; the return byte starts at zero and marks an auxiliary
transition. Live clear calls returned false despite complete Items, sync,
profiles, observed rewards and room returns. Gates require call completion,
not native_result=true.

Script-message dispatch is `0x114D50`. Clear application returns at
`0x114FEF`; natural clear calls `0x3D8153` from setup `0x3D814B`.
Manager load: `0x3E197D`; UI reads: `0x3E1A10/0x3E1A40`; preservation point:
`0x114C51`; global manager slot: `0x125AB40`.

## Result UI

Native setter: `0x111080`; publish point: `0x111098`; UI application:
`0x114BB0`; event publisher: `0x61E950`, global slot `0x125AB70`;
UI dispatch: `0x4A1B70`.

Expected event is type 1/payload 2. Manager UI/result are +0x28/+0x34;
UI state/result are +0xF8/+0xFC. Observed states are 1, 2 and 3; clear result is 1.
UI object flags/ID are +0x18/+0x78, with closing bit 1.

## Narrow result recovery

The separate Exec_Begin recovery targets the observed P4+ victory stall with
script sync 0/0 and no native Exec_Begin. Eligibility requires:

- Participant count 5..8.
- Script argument -20000.
- Script-wrapper origin, not an unrelated/native sync caller.
- Expired 1000 ms grace.
- Readable zero sync state/result.
- No Local Mission Harness.
- Available native function.
- No observed native Exec_Begin call.
- A nonzero current mission generation.

A native call or generation change cancels pending recovery.
The [pure policy](../../src/games/edf5/coop8/mission_result_recovery.cpp) is
testable without game memory.

Other observation timings are distinct: fresh update 750 ms, warmup 750 ms,
generation interval 2500 ms, request lifetime 2000 ms, and UI/result-state
recovery grace 250 ms.

## Enemy spawn and scaling

Common creation boundary: `0x1C1650`; count/cap: `0x1C16C6`; scale layout:
`0x1C16EF`. Owner numerator/denominator/source are +0x290/+0x294/+0x2B0.

Native live-actor capacity is 400. The optional multiplier accepts 1..8 and
saturates at 400. Only the 24 proven callers are eligible, and only with explicit
opt-in. Other callers retain native quantity.

### Temporary zero-scale repair

Require extra participants, positive requested count, readable owner/fields,
a valid source, zero numerator and denominator within 1..1,000,000.
Use the denominator as the temporary numerator for 1:1 scale, call the original,
then compare/exchange back to zero only if the temporary value is still present.
The denominator remains unchanged; concurrent game mutations are preserved.

### GeneratorPoll

Update `0x1F8B40`, Spawn `0x1F90A0`, vtable `0xEA0E38`, observed entries
`0xEA0ED8/0xEA0F40`. Update calls base `0x2DA720` at `0x1F8B5B`; its
tail path includes `0x2DA9DD/0x2DA9F4` and gate `0x2DC7C0`.
The virtual-call sequence begins at `0x2DC821`; manager gate is
`0x1F90E8`; common spawn call `0x1F9120`; return `0x1F9480`.

Manager is +0x788; Update/Spawn vtable offsets +0xA0/+0x108; embedded gate state
+0x400; remaining/cooldown/last time +0/+4/+8; period/current time +0x1F8/+0x1FC.
Signed cooldown threshold is 0x1CC (460), not an object offset.

GeneratorPoll hooks observe rather than force the gate and preserve RAX/AL.
An isolated update can legitimately skip spawn for cooldown/quota. Live testing
saw one such initial update per process followed by thousands of spawn calls.
Only persistent absence in summaries constitutes a spawn failure.

## Future-change invariants

Never create the fifth 0x3E90 block in place, expand Items[4], or leave +0xF8
remapped after the factory. Keep visual index, class, local control, transport
route and logical identity separate. Unclassified callers or invalid inputs
cancel corrective paths. Native completion always takes priority over recovery.

## Canonical sources

[Mission hooks](../../src/games/edf5/coop8/more_players.cpp),
[patches](../../src/games/edf5/coop8/game_patches.cpp),
[spawn](../../src/games/edf5/coop8/mission_spawn.cpp),
[result policy](../../src/games/edf5/coop8/mission_result_recovery.cpp) and
[extended audit](../../PLAYER_FLOW_AUDIT.md).
