# Evidence, failures and open questions

## Reading historical evidence

Failures explain which fields looked equivalent but were not. They do not
necessarily describe the current build. Each row preserves the observation
and its still-valid conclusion.

## Live-test timeline

| Build | Scenario/result | Retained technical conclusion |
| --- | --- | --- |
| 0.4.9 | Solo mission loaded and exited cleanly | The 22-operand roster baseline did not break solo flow; experimental reserves were not validated |
| 0.5.3 | Five real players entered with severe lag/desync and wrong controls | Logical P4 was recycled to source P0; persistent modulo mapping is not identity |
| 0.5.4 | Two players completed with clean transport | Two distinct full-collection UserImpl objects, one local object; +0x190 is local, not global |
| 0.5.6 | Host and three clients crashed at 0x6E022 | Fifth control integer overlapped transforms; direct slot 4 contained a distinct user, but the consumer returned null |
| 0.5.7 | Same crash during P3 | Pre-sort remapping was wrong: source 3 was sent to final slot 4 |
| 0.5.9 startup | Steam launch stable for 30 seconds | 0x6E010 signature needed prefix 0x40; safe install/rollback followed |
| 0.5.9 gameplay | Five correct controls; duplicate names and post-victory Connecting stall; separate host teardown AV | Post-sort identity fixed control, but P4 still used invalid class 4/P0 UserImpl; results and teardown are separate |
| 0.6.0 | Five controls; host movement absent on clients, P4 inherited host class, stalled rewards | P4 retained +0xF8=0; host P2P arrived; UI applied 3/1 without native setter |
| 0.6.23 | Mission-entry crash at 0xB1D60/0xB1D6B | 0x4BB5E1 used +0xF8=4 on a four-entry visual table with stride 0x40 |
| 0.6.24 | Visual remap ran, then class-text crash at 0x5E741C/0x4BC33A | Fifth 0x3E90 block invaded result state and produced class 256/257 |
| 0.6.52 | Five players completed two missions with controls, enemies, rewards and returns on every machine | The tested five-player core worked; 65 warnings reflected normal checkpoints or diagnostic misinterpretations |
| Unknown (third-party report) | Six players crashed; no logs or dumps were available | Reporters' version/flavor unknown; a Users DLL compiles out diagnostics and a /GS fast-fail leaves no plugin evidence |
| 0.6.65 static audit | Root-cause search for the six-player report | Static audit of 0x11D860 found the first spawn loop writing spawn[5] over the /GS cookie at rbp+0x230; P4 only reached padding. 0.6.65 relays the backedge at 0x11DB21 (not yet validated live) |

Original reports remain local and must not enter the repository. The
[experimental inventory](../../EXPERIMENTAL_SLOT_PATCHES.md) retains the
longer build-by-build record.

## Derived corrections

Identity/control: preserve native P0-P3, distinct extra UserImpl/logical identity,
final post-sort order and separate +0x190/+0xC8/+0xF8 domains. Restore temporary
factory/visual mappings before replication.

Loadout/class: no fifth physical 0x3E90 block. Use sidecars and minimal temporary
native views, class 0..3 and visual %4. Accept valid 0x42FA69 count with clean
failure output even when bool is false. P4/class 1 uses valid mask 0x2F and
fallback 0x10 for the weapon/count overlap.

Results: keep four physical Items, extend only logical filters and fold extras.
Observe Exec_Begin/Update/Finally, setter, UI and rewards separately.
Recovery targets only a recognized stall and yields to native execution.

Runtime: validate before hooks, restore only known replacements and quarantine
incomplete startup. Do not assume a teardown AV continues a result bug;
UserImpl/route destruction needs separate evidence.

## Refuted hypotheses

Do not reintroduce these interpretations:

- +0x190 is a global participant index: disproved by two-player testing.
- P4 may permanently reuse P0: disproved by control, replication, names and class.
- Pre-sort order equals final indices: disproved by 0.5.7's P3 crash.
- Targets are 16-byte SharedProperty entries: route descriptors have stride eight.
- Parser owner is parser-0x88: construction proves the +0x498 ownership chain.
- A fifth native loadout block is free: +0x24570 overlaps Items/counters.
- Expanding Items[4] to eight is safe: it overwrites counters.
- False parser return always invalidates count: 0x42FA69 may have written valid data.
- Winsock compensates for missing Steam hooks: lifecycle requires quarantine.
- An offline harness proves real multiplayer: it proves only local instrumented invariants.

## Historical 0.6.53 evidence status

Offline/static evidence covers fingerprints, signatures, transactional patches,
22 baseline operands, 24 experimental pairs/11 holds, UserImpl/route/parser
ownership, 24 spawn callers, 56 scaling reads, Item folding, result policy,
Steam wrappers, synthetic callbacks and the recorded zero-failure suite.

The 0.6.52 live five-player scenario confirmed:

- Five distinct identities/actors and exactly one local owner for each P0-P4
  across all five processes.
- Correct controls and gameplay without reported desynchronization.
- P4 loadout sidecar, corrected class and visual remap without identity loss.
- Four unique remote fan-out routes per process.
- Thousands of spawns across two missions without missing sources/unsafe repair.
- Complete result/reward mask 0x1F, including P4 fold.
- Native Exec_Begin preserved; queued fallback cancelled without duplication.
- Victory, rewards, room return, another mission and another return.
- Clean session endings without drops, write errors or crashes.

See the [per-machine audit](09-FIVE-PLAYER-LIVE-TEST-2026-08-31.md).

Still unproven: six/seven/eight real players; per-message incoming P0-P7
attribution; P4-P7 mission PlayerInfo nickname/chat source; long-session memory;
leave/disconnect at different gameplay stages; experimental enemy multiplication.
Do not generalize the tested five-player result to those scenarios.

## Six-player preparation (0.6.65)

- Deterministic cause found statically: `0x11D860` spawn transform loop
  overwrote its /GS cookie at the sixth participant. Fixed by relay; the
  micro-harness replays the exact native bytes unpatched and patched.
- The F3 Local Mission Harness now continues to host+5, host+6 and host+7,
  so P5-P7 mission creation, loadout, HUD, spawn and result can be exercised
  on one PC before a coordinated test.
- Crash JSON now carries registers and an unwound `stack_frames` list of
  module+RVA pairs that survive report sanitization. A /GS failure at this
  site would appear as `EDF5.exe` RVA `0x11E423`.
- `tools/EnableCrashDumps.ps1` configures Windows LocalDumps for EDF5.exe and
  lists Application Error events, which also cover Users DLL testers.
- Secondary script creation `0x11E7A0` keeps four control ints directly
  below its cookie (still unpatched; unused in five-player reports).

## Six-player host crash, 2026-10-03 (0.6.66)

A six-player test on the old Users 0.6.55 DLL crashed only the host, right
after everyone readied and the stage began loading, with
`STATUS_HEAP_CORRUPTION` (`0xC0000374`). The WER dump's stack candidates run
through the stage-load code around `0x3D87A0`/`0x3E1890` into the heap free.

- Mission-start message `0x1100` (builder `0x433000`): `0x2E8`-byte buffer,
  unchecked `memcpy` of the payload behind a 12-byte header at `0x433107`;
  the `0x578` packet limit is compared only afterwards. Five-player reports
  peaked at 724 bytes; six players need about 857. Only the sending host
  overflows. 0.6.66 raises the reservation to `0x800` (also for the
  `0x3300/0x3400` builder `0x432D20`, same pattern, 491 bytes observed).
  An external analysis of the same crash reached the same 744/857 figures.
- Parser `0x42F480` writes P4+ outside the `0x24600`-byte state. 0.6.66
  relays both `imul ...,0x3E90` sites so indices 4..7 write plugin-owned
  blocks (and indices above 7 a discard block); the ~63 KiB foreign-memory
  snapshot/restore is no longer used when the relays are installed.
- 0.6.67 live, 2026-10-03: six players (host P3) completed seven-plus
  missions with rewards and room returns and zero warnings; the spawn clamp
  and parser redirect fired once per mission. Players reported that the
  Fencer on P4 had a weaker second weapon (fewer rounds, slower fire and
  reload). Cause: the parser bounds its 0x3E60-byte loadout image copy with
  `cmp ecx,4` (`0x42F7E5`), so P4+ kept only class/weapons/armor, and the
  extra character was created on a borrowed P0-P3 block whose remaining
  fields (per-weapon data; `0x8AE00` reads `block+4`, nearby code indexes
  `0x3E60`-stride records) belonged to that player. 0.6.68 raises the bound
  to eight together with the relays (the copy then lands in the plugin
  block) and installs the extra player's full image on the borrowed block
  for the factory call, restoring it byte for byte afterwards.
- Reward report, 2026-10-03 (P3 client): every completed mission reached
  ResolveResult with all Items present; one complaint matched a two-part
  mission (`result 3` = script transition, players re-created) that the
  player left before the end. 0.6.69 logged the numbers for the first time:
  Items `[[10,15],[0,0],[0,0],[0,0]]`, resolver sum `[10,15]` = caps.
  Online ResolveResult (`0x199282`) credits every player the sum of all four
  Items. Native sink `0x132BB0` *assigns* its slot, while the mod added
  P4-P7 on top, so a native delivery after an extra erased the extra's
  pickups and a re-sent extra counted twice. 0.6.70 stores each delivery and
  rewrites the slot as native + extra, resetting at Exec_Begin.
- 0.6.71 profile diff, same client (native P3, five players): Items
  `[[9,31],0,0,0]`; only `profile+0xF8/+0xFC/+0x100` changed (+9/+6/+1,
  Fencer `+0x104` +0). Reverse of ResolveResult: field0 = weapon boxes,
  field1 = armor boxes. Each box goes to one class drawn with weight 600
  (weapons) / 250 (armor) for the class at `profile+0` (`0x1994AB`) and 100
  for the others; armor becomes resolver records `{0, class, count}`
  (list `resolver+0xA98`) credited by `0x199D7F` to
  `profile+0xF8+4*class`, capped by the save total `state+0x6D24+4*class`
  and skipped while `state+0x6D00+10*profile+class` is set. Only 16 of 31
  boxes landed, so the cap or the draw decided the rest; 0.6.73 logs
  `armor_context` (profile class, P0-P3 block classes, totals before/after,
  blocking bytes, armor records) to tell a wrong weighted class from the
  native cap. The client then hit the known `0x991C08` teardown AV on
  `leave_lobby` (recorded since 0.5.3).
- Resolution (native, not a mod defect): the player uses Fencer. The block
  byte `state+0x6D00+10*profile+class` is the soldier menu's armor
  adjustment: `PressButtonMin` (`0x509A60`) and `PressButtonValue`
  (`0x509B40`) set it and lower the current armor; `PressButtonMax`
  (`0x5099F0`) clears it and restores the hidden total that the menu
  (`0x5091C0`) reads from `state+0x6D24+4*class`. While set, `0x199D7F`
  still raises the total but skips the visible armor. The split confirms
  the weighted class was Fencer: 31 boxes - 16 credited to the other three
  = 15 for Fencer (expected ~14 at weight 250), all skipped. Pressing Max
  on the Fencer restores everything collected.
- The same external analysis reports two mission script commands reading
  per-player records that exist only for four players. Identified after a
  live 0.6.76 crash in a stage trigger (five players, host): AV reading
  `0x16` at `0x6D757` (weak_ptr lock of control block `0xE`) under the
  mod's MissionScriptMessageDispatchHook. `0x121BE0` (script dispatcher
  `0x116418`) and `0x127260` (from `0x115833`) loop `i < 0x11E460()` (the
  real participant count) over `mission+0x140+i*0x18`, the weak_ptr of the
  four native records at `+0x138`; they are the only two callers of the
  count that index those records. 0.6.77 relays both address computations
  (`0x121C43`, `0x127393`): 0..3 native, 4..7 the relay-page sidecars,
  >= 8 an empty record (lock yields null, slot skipped).

## Research priorities

1. Find a safe boundary carrying parser ownership through dispatch and prove
   per-participant incoming 0x3300/0x3400.
2. Prove runtime nickname/PlayerInfo sources for P4-P7.
3. Compare long-session memory against a matched baseline before attributing
   the single RADAR_PRE_LEAK_64 event to the mod.
4. Test six real players before seven/eight.
5. Map leave, peer loss, route removal and UserImpl destruction.
6. Inventory remaining participant-indexed physical tables beyond visual 0x40,
   loadout 0x3E90, Items and persistent records.
7. Identify the owners of all 24 experimental reserves before treating the
   group as established supported behavior.

## Minimum live-test matrix

| Stage | Players | Required evidence |
| --- | --- | --- |
| Native baseline | 2 and 4 | No regression in mission, victory and return |
| First extra | 5 | P4 identity/control, visible host, class/loadout, spawn, results, teardown |
| Expansion | 6 | Two distinct extra routes, fan-out, accumulated folding |
| Intermediate stress | 7 | Ordering, UI/scroll, generations, repeated returns |
| Maximum | 8 | All slots, lobby cap, scaling, rewards, second mission |

At each stage, collect host and client evidence around full lobby, Ready,
loading, first P2P, first spawn, victory, rewards, UI close and room return.
Stop at the first broken invariant rather than increasing count to mask it.

## Completion criteria

A tested capacity requires unique identities/routes, correct local and remote
actors, bounded physical accesses, mission start/scaling/completion/rewards/UI
closure, clean returns/teardown, a second mission without restart, and sanitized
reports confirming those invariants.
