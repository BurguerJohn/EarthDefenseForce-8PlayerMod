# Inventory of experimental slot patches

Updated: 2026-08-27

Supported executable: `EDF5.exe` SHA-256
`3512D2A2E61D532C5D12DC0C5FD1AC61F6743E13349AE21301BB8449DD4BAE5F`

Test build: `0.6.13` / `edf5mp-0.6.13-result-item-fold-win64`

This file separates proven limits from comparisons that merely look like
capacity. An RVA in this list does not automatically mean "players".

## States

- `PROVEN`: related to the roster by dumps/call flow and kept active.
- `EXP-ENABLED`: coherent group `capacity < 4` + `reserve(4)`, changed
  together to 8, but the owning system has not been identified yet.
- `HOLD`: not changed; type/state comparison or ambiguous flow.
- `MANUAL-PASS` / `MANUAL-FAIL`: fill in only after testing in the game.

The experimental batch can be turned off without removing the proven patches:

```ini
[MorePlayers]
ExperimentalReservePatches=false
```

## Proven baseline: 22 operands

| Group | RVAs | State |
|---|---|---|
| primary roster | `0x44894B`, `0x448961` | PROVEN |
| secondary roster | `0x432AF9`, `0x432B14`, `0x432B2C`, `0x436996`, `0x4369B2`, `0x4369DB`, `0x436AAC` | PROVEN |
| tertiary roster | `0x419789`, `0x4197A4`, `0x4197BC`, `0x41BB36`, `0x41BB52`, `0x41BB76`, `0x41BC0D` | PROVEN |
| room boxes | `0x5A59FC`, `0x5A5A14`, `0x5A7261`, `0x5A726D`, `0x5A7281`, `0x5A72DC` | PROVEN |

## The 35 previously unclassified anchors

Twenty-four form coherent reserve groups. Each `EXP-ENABLED` row has two
operands: the comparison anchor and the argument of `reserve(4)`. This adds
up to 48 experimental modifications. The other eleven remain intact.

| # | Anchor | Second operand | Classification | Manual test | Notes |
|---:|---:|---:|---|---|---|
| 1 | `0x005B6C1` | - | HOLD | not tested | field/state comparisons; not a reserve pattern |
| 2 | `0x00D2238` | - | HOLD | not tested | selects SIMD constants according to state 4 |
| 3 | `0x00D25B6` | - | HOLD | not tested | selects SIMD constants according to state 4 |
| 4 | `0x014958D` | `0x0149594` | EXP-ENABLED | not tested | comparison + `reserve(4)` |
| 5 | `0x01CDCF2` | `0x01CDCF9` | EXP-ENABLED | not tested | comparison + `reserve(4)` |
| 6 | `0x01CE773` | `0x01CE77A` | EXP-ENABLED | not tested | comparison + `reserve(4)` |
| 7 | `0x01D8176` | `0x01D817D` | EXP-ENABLED | not tested | comparison + `reserve(4)` |
| 8 | `0x01D95AD` | `0x01D95B4` | EXP-ENABLED | not tested | comparison + `reserve(4)` |
| 9 | `0x01F7D70` | `0x01F7D77` | EXP-ENABLED | not tested | comparison + `reserve(4)` |
| 10 | `0x01FBF2A` | `0x01FBF31` | EXP-ENABLED | not tested | comparison + `reserve(4)` |
| 11 | `0x01FC508` | `0x01FC50F` | EXP-ENABLED | not tested | comparison + `reserve(4)` |
| 12 | `0x025D408` | `0x025D40F` | EXP-ENABLED | not tested | comparison + `reserve(4)` |
| 13 | `0x0263925` | `0x026392C` | EXP-ENABLED | not tested | comparison + `reserve(4)` |
| 14 | `0x02769A2` | `0x02769A9` | EXP-ENABLED | not tested | comparison + `reserve(4)` |
| 15 | `0x0282612` | `0x0282619` | EXP-ENABLED | not tested | comparison + `reserve(4)` |
| 16 | `0x029CBA2` | `0x029CBA9` | EXP-ENABLED | not tested | comparison + `reserve(4)` |
| 17 | `0x02A27A5` | `0x02A27AC` | EXP-ENABLED | not tested | comparison + `reserve(4)` |
| 18 | `0x02A6F6F` | `0x02A6F76` | EXP-ENABLED | not tested | comparison + `reserve(4)` |
| 19 | `0x02B0242` | `0x02B0249` | EXP-ENABLED | not tested | comparison + `reserve(4)` |
| 20 | `0x02B837D` | `0x02B8384` | EXP-ENABLED | not tested | comparison + `reserve(4)` |
| 21 | `0x02BB10D` | `0x02BB114` | EXP-ENABLED | not tested | comparison + `reserve(4)` |
| 22 | `0x02BD3CF` | - | HOLD | not tested | checks capacity and size in an existing flow; does not reserve |
| 23 | `0x02C4B67` | `0x02C4B6E` | EXP-ENABLED | not tested | comparison + `reserve(4)` |
| 24 | `0x02D17F3` | `0x02D17FA` | EXP-ENABLED | not tested | comparison + `reserve(4)` |
| 25 | `0x034EAA0` | `0x034EAA7` | EXP-ENABLED | not tested | comparison + `reserve(4)` |
| 26 | `0x035037A` | `0x0350381` | EXP-ENABLED | not tested | comparison + `reserve(4)` |
| 27 | `0x047A4CF` | `0x047A4D6` | EXP-ENABLED | not tested | comparison + `reserve(4)` |
| 28 | `0x04AECFE` | `0x04AED05` | EXP-ENABLED | not tested | comparison + `reserve(4)` |
| 29 | `0x0971940` | - | HOLD | not tested | dispatch on object/type equal to 4 |
| 30 | `0x09722C7` | - | HOLD | not tested | filter on object/type equal to 4 |
| 31 | `0x0C3B97C` | - | HOLD | not tested | type switch; writes id `0x8A` |
| 32 | `0x0C3B9FA` | - | HOLD | not tested | type switch alongside ids `0x45`/`0x31` |
| 33 | `0x0C3BA2D` | - | HOLD | not tested | type switch alongside ids `0x31`/`0x43` |
| 34 | `0x0C3BC1A` | - | HOLD | not tested | type switch; writes id `0xB9` |
| 35 | `0x0C3BC76` | - | HOLD | not tested | type switch; writes id `0xBA` |

## Test log

| Date | Build | Configuration | Result | Reports | Notes |
|---|---|---|---|---|---|
| 2026-08-26 | 0.4.9 | `PreallocatedRosterSlots=8`; experimental batch absent | solo match opened, entered a mission and ended cleanly | `Reports/single.zip` | validates only the 22-operand baseline; did not test these 35 modifications |
| pending | 0.5.0 | `ExperimentalReservePatches=true` | not tested | - | first test of the 24/48 batch |
| pending | 0.5.1 | `MaxPlayers=8`; `PreallocatedRosterSlots=8`; experimental batch active | not tested | - | first test of the dynamic mission paths for players 5-8 and of the 24/48 batch |
| pending | 0.6.9 | `MaxPlayers=5`; `PreallocatedRosterSlots=8`; experimental batch active | not tested | - | new proven filter `MissionSync_Res` 4->MaxPlayers; separate from the 35 experimental anchors |
| pending | 0.6.10 | same capacity; rollback of the extra parser, class sidecar and effective victory return | not tested | - | P4 starts at `state+0x24570` and overlaps `+0x2459C/+0x245A0`; restores the entire extra range and preserves only the legitimate result count |
| pending | 0.6.11 | same capacity; P0-P7 replication matrix and unique-identity audit | not tested | - | no limit of four found in `0x45EAD0/0x432D20/0x435670`; detects duplicate UserImpl and missing host on each client without capturing IDs/payload |
| pending | 0.6.12 | same capacity; audit of the real receive table `+0xD0/+0xE0` | not tested | - | callback `0x451B90 -> 0x4336F0` uses a dynamic count and stride `0x10`; detects missing P0 route or duplicate P0/P4 before the parser without capturing IDs/payload |
| pending | 0.6.13 | same capacity; dynamic filter and safe fold of extra result Items | not tested | - | `0x430F23` now follows MaxPlayers; hook at `0x132BB0` sums P4-P7 into the four accumulators that end before rewards at `+0x2459C` |
| pending | 0.6.14 | same capacity; nick origin and Items checkpoint before the rewards | not tested | - | cross-references participant/UserImpl/PlayerInfo/chat by private tokens; signatures prove ResolveResult with four aggregated totals and ApplyResult with a dynamic vector |
| pending | 0.6.15 | same capacity; identity of the transport route `UserImpl+0xC8` | not tested | - | audits dynamic allocator, registration/removal and exact route -> participant mapping; detects missing host route, P0/P4 collision and index outside the slot without collecting endpoints |
| superseded before testing | 0.6.16 | first audit of the serializer fan-out | not tested | - | hypothesis of a 16-byte `SharedProperty` element was wrong; reverse of `0x45ED80/0x432E00` proved a route descriptor with stride 8 |
| pending | 0.6.17 | same capacity; exact fan-out by route descriptor | not tested | - | cross-references `UserImpl+0xC4/+0xC8 -> descriptor+4 -> manager+0xD0` and requires the exact mask of the remotes without collecting raw route, IDs, endpoints or payloads |
| pending | 0.6.18 | same capacity; full matrix of result Items | not tested | - | records only P0-P7 presence at checkpoints/ResolveResult/ApplyResult, separate from the P4-P7 fold; does not collect weapon values, rewards or payloads |
| pending | 0.6.19 | same capacity; defensive restoration of the local rewards counter | not tested | - | uses the real local collection 1..2 to repair `state+0x2459C` only if invalid before ApplyResult on a P4+ victory; does not read weapon/reward contents |
| 2026-08-31 | 0.6.52 | five real players; `MaxPlayers=8`, enemy multiplier off | two levels with controls, spawns, rewards and returns complete on all five machines | `Reports/server.zip`; `Reports/client 01.zip`; `Reports/client 2.zip`; `Reports/client 3.zip`; `Reports/client 4.zip` | jointly validates P4 rollback/sidecar, class, visual, four-remote fan-out, Items `0x1f`, completed ApplyResult and native cancellation; per-participant incoming and mission nickname remain pending |
| pending | 0.5.2 | same capacity; index/P2P audit active | not tested | - | records callers and extra indexes without widening ambiguous candidates |
| 2026-08-27 | 0.5.3 | five real players; same capacity | entered gameplay without a crash, but with severe lag/desync and incorrect control | server and three client reports in `Reports` | player with index 4 was recycled to source 0 in all four reports |
| pending | 0.5.4 | same capacity; audit of UserImpl collections and logical messages | not tested | - | uses source 4 only when it exists and keeps modulo four as fallback |
| 2026-08-27 | 0.5.4 | two real players; same capacity | level completed, clean transport | `Reports/Server 2 players.zip`; `Reports/Client 2 players.zip` | complete collection with 2 distinct UserImpl; local subset with 1; revealed that +0x190 is not a global position |
| pending | 0.5.5 | same capacity; UserImpl order and source resolution active | not tested | - | does not change multiplayer; prepares conclusive diagnosis of the fifth control |
| pending | 0.5.6 | same capacity; observational hook at `0x11CE60` | not tested | - | records participant -> local control before/after the builder; does not change arguments |
| 2026-08-27 | 0.5.6 | five real players; same capacity | identical crash on server and three clients | `Reports/Server.zip`; `Reports/Client 1.zip`; `Reports/Client 2.zip`; `Reports/Client 3.zip` | fifth control integer overlapped by the transforms; direct entry 4 contained another `UserImpl`; consumer returned null and crashed at `0x6E022` |
| 2026-08-27 | 0.5.7 | same capacity; source and control routing by pre-sort order | identical crash on server and three clients | `Reports/Server.zip`; `Reports/client 01.zip`; `Reports/client 02.zip`; `Reports/client 03.zip` | all failed at `0x6E022` during P3: the mod remapped source 3 to final entry 4; the reports proved that the pre-sort order does not represent the final indexes |
| pending | 0.5.8 | same capacity; post-sort identity, consumer/loadout audit and null-return guard | not tested | - | preserves P0-P3; rebuilds only the extras' control; audits class/loadout/resource and tries a safe native source before aborting only the null player_create |
| 2026-08-27 | 0.5.9 | same capacity; signature and safe rollback of the hooks at startup | opened through Steam and stayed stable for 30 seconds | `Reports/crash.zip`; local session `pid18340` | fixed missing byte `40` in the signature of `0x6E010`; process was closed in a controlled way after the test window, with no new WER or dump |
| 2026-08-27 | 0.5.9 | five real players; post-sort identity/control | complete gameplay with five correct controls; duplicate nicks and stall at "Connecting" after victory | `Reports/Server.zip`; `Reports/client 1.zip`; `Reports/client 2.zip`; `Reports/client 3.zip` | P4 had invalid class 4 and reused P0's UserImpl on all four PCs; fight and victory worked; manual close produced a separate teardown AV on the host |
| pending | 0.6.0 | same capacity; preservation of the extra identity and result audit | not tested in game | - | repairs only `UserImpl+0xF8`, preserves P4; observes setter/apply and 1/5/15/30 s stall |
| 2026-08-28 | 0.6.0 | five real players; identity and result | gameplay with five controls, but host movement missing on the clients, P4 with the host's class and stall/rewards missing | server and three client reports in `Reports` | P4 stayed with `UserImpl+0xF8=0`; all received the host's P2P flow; all applied UI 3/1 without a native setter |
| pending | 0.6.1 | temporary/restored loadout index and host-only setter recovery | superseded before testing | - | restores identity 4 and prefers a native source of the same class; still depended on a duplicate class among P0-P3 |
| pending | 0.6.2 | temporary native block synthesized from the real PlayerInfo and same result recovery | not tested in game | - | exact class, six equipment items and armor of P4+; block restored byte by byte and index 4+ preserved for name/replication |
| 2026-08-28 | 0.6.23 | five real players; mission entry | crash on the host and on at least two clients at `EDF5.exe+0xB1D60/0xB1D6B` | `Reports/server.zip`; `Reports/client 1.zip`; `Reports/client 2.zip`; `Reports/client 3.zip`; local dump `EDF5.exe.22376.dmp` | host stack `0xB1D60 <- 0x9DD90 <- 0x4BBC3C`; `0x4BB5E1` used `UserImpl+0xF8=4` to access the nonexistent fifth entry of a visual table `stride 0x40` |
| 2026-08-28 | 0.6.24 | P4+ identity preserved; the resolver's visual output uses `index % 4`; enlarged emergency stack | visual remap ran, but host and two clients crashed while building the text for P4's class | `Reports/Server.zip`; `Reports/Client 1.zip`; `Reports/Client 2.zip`; `Reports/client 3.zip` | resolver read class 256/257 from the fifth `0x3E90` block; AV at `0x5E741C` on host/client 3 and `0x4BC33A` on client 1; client 2 exited cleanly after losing the room |
| superseded before testing | 0.6.25 | pre-rollback class/loadout sidecar and final HUD class limited to `0..3` | not tested in game | - | later reverse showed that `parser_result=false` still delivers a valid count and that P4/class 1 has one weapon overlapped by the count |
| pending | 0.6.26 | count preservation independent of the boolean return and sidecar with a per-weapon mask | not tested in game | - | validates `0x42FA69`; accepts sanitized count with clean out-failure; P4/class 1 uses mask `0x2F` and native fallback `0x10` |
| pending | 0.6.27 | Local Mission Harness F3 host+3/host+4/off over distinct synthetic UserImpl | offline self-test passed; game not opened | - | native baseline and P4 probe; automatic Ready/loadout and l1/l2; remote/inert dummies; Sync_MissionResult completed only in a valid host-only session |

## Policy for new candidates

1. Record RVA, original bytes, approximate function and reason for the
   classification.
2. Do not change a capacity comparison without the operand that controls the
   corresponding reservation/allocation.
3. Validate all signatures before the first write and apply the batch as a
   transaction; on failure, keep the original bytes.
4. Opening the game is a separate step from the room, mission entry and a match
   with five real players.
5. After each test, update the table above to `MANUAL-PASS` or
   `MANUAL-FAIL` and attach the exact report name.
