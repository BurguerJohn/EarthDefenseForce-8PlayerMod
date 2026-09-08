# EDF 4.1 initial Coop8 map

## Current boundary

Steam observation infrastructure is reusable; game internals are not.
Progression is sniffer -> four-player capture -> EDF 4.1 structure map ->
dedicated transactional patch -> five-player test -> gradual expansion.

Since 0.6.59, EDF41.Coop8 enables fillers. Version 0.6.61 exposed P5 and the
first four-pointer consumer; 0.6.62 quarantined it. Version 0.6.63 linked that
vector to net::Users RTTI, construction and dynamic teardown, then expanded it.
The live test passed this boundary but crashed at net::SessionController+0xD0
through 0xCB070. The original 0.6.64 transaction covered eight roster operands.

Current source adds two room-UI protection sites. Overflow members are headless
because only four native member windows exist; the ten-site transaction does
not implement an eight-row UI or expanded missions.

## Available Steam evidence

Shared wrappers cover CreateLobby 13, member count 17, indexed member 18,
lobby data 19..25, Set/GetLobbyMemberLimit 31/32, Friends invite 33,
Networking005 and verified User018 auth 14/15 plus C callbacks.

Since 0.6.56, the sniffer observes actual LobbyCreated, LobbyEnter, LobbyDataUpdate,
LobbyChatUpdate, LobbyChatMsg, invites, search results and P2P callbacks.
Registration alone is not proof that a payload reached the game.

steam_game_policy.cpp selects edf41::room_bots only for active EDF 4.1 Coop8.
Wrappers are shared; synthetic state, limits and protocol remain separate.

## Negative EDF5 scanner results

These tests prove what cannot be copied:

- Slot scanner: 17,072 immediate fours and 98 generic comparisons, but
  known_capacity_anchors=0. EDF5's printed experimental/deferred totals are
  hard-coded lists, not EDF 4.1 discoveries.
- Player-flow scanner: indexed_lookup_callers=0,
  confirmed_mission_lookup_callers=0 and all route/parser signatures false.
  Its nine seed names refer only to unrelated same-number RVAs in another binary.
- Result scanner: 15 expected elements and six EDF5 callers missing; 28
  unclassified candidates, seven callers and ten decode errors. EDF5 result
  ranges are invalid for EDF 4.1.

The single generic allocation_count_lea lacked an associated capacity comparison
and is not a patch candidate.

## Steam callsite scanner

tools/steam_accessor_scanner.cpp accepts an IAT RVA and enumerates nearby virtual
calls. A slot number alone does not establish semantics.

| Flow | Accessor | Vcall | Slot |
| --- | --- | --- | --- |
| CreateLobby | 0x3BBB59 | 0x3BBB6B | 13 |
| Friend persona | 0x3B5F1E | 0x3B5F31 | 7 |
| Invite dialog | 0x4E1585 | 0x4E159D | 33 |
| GetAuthSessionTicket | 0x381FA5 | 0x381FC5 | 13 |
| BeginAuthSession | 0x3817C0 | 0x3817DD | 14 |
| EndAuthSession | 0x381F15 | 0x381F24 | 15 |
| CancelAuthTicket | 0x381EE9 | 0x381EFB | 16 |

Two accessors within the 0x40-byte search window can yield multiple candidates;
inspect disassembly/arguments before naming them.

## Room-member ingestion

Function 0x3B92F0..0x3BA4DD reads GetNumLobbyMembers at 0x3B960E and
GetLobbyMemberByIndex at 0x3B965B. Index increment 0x3B9ECD, count comparison
0x3B9ED5 and branch 0x3B9EDE -> 0x3B9640 form a dynamic loop without a four clamp.

The 0.6.61 capture exposed the next boundary: 0x3BDF60..0x3BE475 with RDI=4
reads owner+0xD0, computes the fifth slot at 0x3BE2F0..0x3BE2F7 and faults
decrementing an out-of-allocation reference at 0x3BE316. owner+0xE0 bounds search;
+0xE8 increments after insertion. Direct callers: 0x3B6114 and 0x3B9BC6.

Increasing only GetNumLobbyMembers is insufficient. AuditEdf41.ps1 pins vcalls,
net::Users RTTI, constructor operands, allocation/initialization helpers and
dynamic teardown against the known hash.

The 0.6.63 capture proved the first vector grew, then exposed 0x3960D0 reading
index [entry+4], calculating SessionController+0xD0 + index*16 and calling
shared-pointer helper 0xCB060. At index 4, net::SessionControllerImpl still had
capacity/size 4 at +0xD8/+0xE0, causing 0xCB070. Base constructor 0x394940 and
helper 0x398F20 reserved four 16-byte records. Six lifecycle operands expand
together with the two net::Users operands.

The current UI guard separately protects UiOnlineRoom's four member-window
references. Network/roster expansion is not evidence of extra visible rows.

## Reusable architecture, not addresses

Reuse transaction design, sidecars, separation of lobby/roster/mission/spawn/
result capacities, five-player-first tests, fail-closed scanners, negative
fixtures and private-token correlation. EDF 4.1 must not call EDF5 game_patches,
more_players, mission_spawn or mission_result_recovery.

## Progress gates

1. Complete: clean four-player capture with callbacks, auth and channels.
2. Partial: ingestion and first two consumers mapped, constructors/allocators/
   teardown identified; Ready remains unmapped.
3. Complete for known roster boundaries: signatures and coherent eight-operand
   expansion, with dynamic teardown. Current UI protection adds two sites.
4. Pending: logical identity, Steam identity, loadout, Ready and P2P sender mapping.
5. Pending: mission entry/exit, spawn table and result pipeline.
6. Complete for the implemented boundary: dedicated pinned static audit and
   transactional fixture.
7. Experimental: up-to-eight synthetic room members, fallback four on any
   required mismatch, with overflow headless.
8. Pending: five real participants from lobby through mission return before six-eight.

P5-P8 remain a room-data probe. Expanded Ready, mission entry, spawn, gameplay
replication and results are unsupported. No EDF5 offset may be adapted merely
because it looks similar.
