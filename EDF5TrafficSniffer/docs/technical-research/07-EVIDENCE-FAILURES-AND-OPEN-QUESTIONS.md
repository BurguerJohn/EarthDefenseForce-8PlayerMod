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
