# Player index and P2P audit

Updated: 2026-08-28

Supported executable: `EDF5.exe` SHA-256
`3512D2A2E61D532C5D12DC0C5FD1AC61F6743E13349AE21301BB8449DD4BAE5F`

This audit looks for structural limits in the room -> mission entry ->
gameplay path without blindly replacing `4` constants. The scanner and the
telemetry never launch the game.

## Static result v1

Command:

```powershell
_dev\EDF5TrafficSniffer\build\player_flow_scanner.exe EDF5.exe
```

After a test, the observed P2P callers can also be supplied as additional
roots (one or more RVAs):

```powershell
_dev\EDF5TrafficSniffer\build\player_flow_scanner.exe EDF5.exe 0x<caller_rva>
```

The scanner walked nine proven flow roots and 3,552,870 instructions and
found:

- 28 callers of the generic indexed-handle getter at `0x7e240`;
- three exact callers inside the mission pipeline;
- four immediate comparisons with `4` in the nine root functions;
- no `& 3`, `& 0x0f`, bit-test or variable-shift mask in those roots;
- 74 scaled-index accesses, 15 of which are close to the native bound in
  consumer `0x3123a0`.

Expected summary:

```text
summary seed_functions=9 indexed_lookup_callers=28 confirmed_mission_lookup_callers=3 compare_four=4 and_mask_3=0 and_mask_f=0 bit_index=0 variable_shift=0 scaled_index=74 indexed_near_four=15 direct_calls=326
```

## Classified mission callers

| Call RVA | Context | Table | Action |
|---:|---|---|---|
| `0x11CF08` | player creation | vector of `net::UserImpl` copied from the session | locates the `UserImpl` expected by the session's saved identity; if it is absent, uses `index % 4` as crash protection |
| `0x11DFCE` | record transfer | local vector whose size depends on the flow | preserve index; audit before the getter |
| `0x11E057` | record attachment | same flow-dependent local vector | preserve index; audit before the getter |
| `0x126D24` | consumption of the temporary participant vector | vector produced in the flow itself | preserve index; external temporary storage holds eight |

The first three callsites have exact signatures verified before the hook is
installed. The two local vectors are not reduced modulo four without dump
evidence: that could swap the real data of players 5-8 with that of players
1-4.

## Origin of the control source

The static reverse of function `0x11D5E0` showed two virtual calls on the
session object: slot `+0x20` produces the primary collection and slot `+0x28`
produces the subset of local controls. Both are copied by `0x12B200` as
vectors of 16-byte shared handles. Recognized objects use the `net::UserImpl`
vtable at `0xEC2730`. The 0.5.4 two-player baseline showed that the first
collection holds both users and the second is an exact subset of one object.
The reverse of the loop calls virtual slot `+0x60` only for objects of that
subset; `object+0x190` is zero in both processes. Therefore 0.5.5 classifies
that field as the local control index, not as the participant's global
position.

The builder at `0x11CE60` receives the primary collection and hands each
object to consumer `0x3123A0`. The dword `UserImpl+0xF8` read by that consumer
is the class selector: the `< 4` bound at `0x312403` corresponds exactly to
Ranger, Wing Diver, Air Raider and Fencer. It is not a participant limit and
must stay at four. The `UserImpl` source, on the other hand, is neither a
spawn point nor a neutral slot: recycling player 5 into entry 0 may duplicate
identity/control. 0.5.5 intercepts only the two proven copies, compares the
collections without logging pointers and automatically uses a fifth native
entry when it reaches the builder. No artificial entry is created without
evidence about ownership and lifetime.

The same reverse confirmed the contract of `0x11CE60`: the fourth argument is
the participant's global index and the fifth is the local control index
produced by `0x11D5E0`. At `0x11D277`, a negative value follows the remote
path; a non-negative value is passed to `0x2DBBC0`, which associates the
character with the local control. There are only two direct calls, `0x11DC34`
and `0x11ECE9`. 0.5.6 validates them by signature and audits this limit
without changing any argument.

The four reports from the 0.5.6 five-player test closed the immediate
failure. The server and three clients suffered the same invalid read at
`0x6E022`, still inside the builder for participant 4. The call before
`0x3123A0` returned a null character; then the native code formed `rcx=0x10`
and tried to read `[rcx+8]`. Final entry 4 existed, but the consumer could not
build a character from it. The difference between its registration ordinal
and the participant index did not yet prove an identity swap: that conclusion
depended on knowing the producer's later ordering.

The reverse of `0x11D5E0` also found the reason every process classified
participant 4 as local. The caller reserves the control integers at
`[rbp+0x1D0]`; five values occupy up to `[rbp+0x1E0]`. Right after that, the
caller itself writes 64 bytes of transforms starting at `[rbp+0x1E0]`,
overwriting exactly the fifth integer with zero before the creation loop. That
false zero was passed to the local binder on the server and the clients.

0.5.7 tried to fix the two arguments using the identity observed in the
copies. The next test showed why that was wrong: on the server and three
clients, the mod remapped participant 3 from final source 3 to final source 4
and all of them failed again at `0x6E022`, before reaching participant 4.

The complete reverse of `0x11D5E0` located two calls to `0x131F10`
immediately after the copy hooks (`0x11D6FE` and `0x11D723`). That routine
sorts the two vectors. For five entries it falls into the insertion sort at
`0x132CC0`; the comparator calls virtual slot `+0x50`, which in `UserImpl` is
`0x452E70` and returns the qword at `UserImpl+0x184` (SteamID). The move at
`0x132DAF` produces descending order. Only after that does `0x11D750` compare
the full collection with the local subset, write the controls, and `0x11D7D3`
hands the final table to the builder. Thus participant N is entry N of the
final table; the order of the pre-sort copies serves only for membership
tests. The logs never record the key/SteamID value.

0.5.8 fully preserves the source and control of P0-P3. For P4-P7, the local
control is rebuilt using entry N of the final table and per-object membership
in the local subset; remote becomes `-1`, and local uses `UserImpl+0x190`. The
second caller `0x11ECE9` also receives that same final table produced by
`0x11D5E0`, so it uses the same rule.

The complete reverse of `0x3123A0` also mapped the resource selection. The
class at `UserImpl+0xF8` chooses a block of `0x3E90` bytes in the global state
pointed to by `EDF5.exe+0x125AB30`. The active loadout is at `+0x14B30`; each
record is `0x18` bytes long and the resource selector starts at `+0x14B38`. A
class outside 0..3, a negative resource or a failure of the `0x6138E0` factory
leads to a null return. For extras, 0.5.8 prefers one of the four usable
native sources of the same class, tries the others if the consumer still
fails, and logs all the results. If none produces a character, the hook
restricted to helper `0x6E010` recognizes only `source=0x10` during
`mission_player_create`, returns an empty handle and lets the native path
abort that builder without processing the fatal read at `0x6E022`.

## Five-player test of 0.5.9

The four available reports (the local reports of host, P2, P4 and P3)
confirmed all five `mission_player_create_result` events, five distinct
objects/controls and exactly one local owner per computer. This closes the
control association failure. In all processes, however, P4 had
`class_selector=4`. Since 0.5.8 treated that class as an invalid source,
`MissionSourceLookupHook` returned the whole P0 entry. The character remained
playable, but the identity used for name/chat/result was no longer P4's.

0.6.0 keeps the P4 entry of the final table and changes only `UserImpl+0xF8`
when it is outside 0..3, copying a valid class from the native source modulo
four. The event `mission_source_identity_repaired` logs the previous/new class
and the ordinal of the class source, without recording SteamID or pointer. If
the field remains invalid, the old full fallback stays in place as the last
crash protection.

The test also won the stage, but the host stayed indefinitely on "Connecting"
before leaving the mission. The manual close happened before an observable
mission->result transition and later produced a teardown AV at
`EDF5.exe+0x92C643`; that AV is a consequence of the forced shutdown, not the
original point of the stall. 0.6.0 instruments the two native result stages:
setter `0x111080` and apply `0x114BB0`. The natural clear calls the setter at
`0x3D8153` with result 1. The setter writes `manager+0x34`; the apply takes
the UI at `+0xF8` to state 3 and keeps the result at `+0xFC`. The
`mission_result_progress` checkpoints at 1/5/15/30 s show which of these
milestones occurred and whether the transition is still pending.

## Revised comparisons with four

### Review after the 0.6.0 test

The field `UserImpl+0xF8` was reclassified as the index of the native loadout
block, not a class. `0x3123A0` limits the index to four, multiplies it by
`0x3E90` and accesses the selected loadout at `+0x14B30`. The real class is
observed when converting the `UserImpl` to `PlayerInfo` at `0x422F00`,
destination `+0x28`. Therefore P4 must temporarily use a compatible native
block to build the character and go back to 4 before normal replication.

The most recent reports also proved that the clients were receiving the
host's heavy P2P flow; the loss of movement occurred after the transport. The
persistent collision `[0,1,2,3,0]` is the concrete cause that 0.6.1 removes.
On leaving the stage, the 3/1 apply without a setter came from return
`0x114FEF`; the recovery is host-only, requires more than four members and
reuses setter `0x111080` on the `Mission()` thread after 250 ms.

### Revision 0.6.2: loadout block contents

The `0x3E90` stride does not need to be merely recycled per class. The parser
at `0x42F7C9..0x42F945` and the consumer at `0x31240C..0x3124D2` prove the
same active layout: class selector at the start of the block, a six-dword
record at `+8+class*0x18` and integer armor at `+0xF8`. The
`UserImpl -> PlayerInfo` conversion provides exactly the class, six equipment
items and armor without confusing any of them with `UserImpl+0xF8`.

0.6.2 takes a full snapshot/restore of a native block during the creation of
P4+, injects these `PlayerInfo` fields into it and afterwards restores the
exclusive index 4+. This eliminates both the Air Raider class inherited from
the host and the provisional dependency on there being a 0..3 source of the
same class. The events `mission_source_loadout_fallback_installed` and
`mission_player_create_result` record whether the block was synthesized and
restored, without name, SteamID, payload or pointer.

| RVA | Classification | Decision |
|---:|---|---|
| `0x11DF8F` | construction/copy of the native local table of four records | keep 4; extras live in the sidecars |
| `0x312403` | limit of the four native blocks selected by `UserImpl+0xF8` | keep 4; temporarily synthesize/restore the block contents for P4+ |
| `0x561E75` | index of a room structure with stride `0xDD0` | keep; `index >= 4` already selects the fallback at `object+0x3748` |
| `0x561E9E` | second read of the same structure | keep, for the same safe fallback |

## Deferred generic callers

The 24 callsites below use the same getter `0x7e240`, but there is still no
evidence that their indices represent players. They remain unchanged:

```text
0x3EE667
0x40C550 0x40CCDC 0x40CCF9 0x40CE00
0x418A7A 0x418FCF 0x4190B6
0x422AEB 0x424F1D
0x42E519 0x42E5B9 0x42E5C9 0x42E5DF 0x42E6BA 0x42EA23 0x42EAB1
0x43843F 0x438526 0x438D06
0x4498B6
0x45293F 0x452A0E
0x5A4384
```

## Telemetry prepared for the next test

- `mission_source_index_audit`: logs each extra index only once per context,
  its effective index, presence/type of the requested and effective entries,
  order in the `UserImpl` registration, class/loadout/resource, usable-source
  and local-control masks, and whether the final table is correctly sorted
  without logging the SteamID key. The breadcrumb is written
  before the getter, so it appears in the crash context even if the following
  access fails.
- `mission_source_resolution_audit`: after the getter, confirms whether the
  returned object is the effective entry, source zero or another registered
  item, without serializing pointers.
- `mission_source_collection_audit`: logs `session_all_users` and
  `session_local_controls` separately, including count, unique
  objects/controls, local control indices and the ordinal vector
  `source_to_registered_order`.
- `mission_source_collection_compare`: shows the delta, the mask of local
  entries in the full collection and ordinal maps by object and by control
  block between the collections, without serializing pointers.
- `mission_player_control_assignment`: before creation, logs for each
  process and participant the original and effective control indices, whether
  there was an identity-based correction and the index in the local subset;
  `-1` means remote and `0+` means locally controlled. The breadcrumb precedes
  the original function.
- `mission_player_create_result`: confirms that the builder returned and that
  the character handle was filled. The absence of this event after an
  assignment locates a crash inside `0x11CE60`.
- `mission_source_consumer_result`: logs the direct result, loadout/resource
  masks, native sources tried, which retry built the character and the exact
  stage of the null (`source`, `class`, `loadout`, `resource` or factory
  `0x6138E0`). The factory classification is marked as a static inference.
- `mission_null_character_guarded`: proves that all sources failed and that the
  null return was converted into an empty handle in helper `0x6E010`; includes
  the participant and the effective source, never pointers or SteamIDs.
- `player_info_class_observed`: internally associates each `UserImpl` with the
  real class of the `PlayerInfo`; the event logs only the ordinal and
  selectors.
- `mission_source_loadout_fallback_installed`: logs the original index,
  temporary fallback, real requested class/fallback class and object
  preservation.
- `mission_player_create_result`: besides the handle, confirms that index 4+
  was restored after the character was built.
- `mission_result_setter` and `mission_result_apply`: log the result, caller
  RVA, before/after state and counts; the natural clear caller is classified
  without exposing absolute addresses.
- `mission_result_progress`: at 1/5/15/30 s summarizes the result, UI state,
  setter/apply counts, `Exec_Begin`, sync and rewards, age of the last update
  and diagnostic phase. The event `mission_result_transition_completed`
  confirms the normal exit from the lobby.
- `mission_result_exec_begin`: observes the RTTI-confirmed entry
  `net::MissionResult::Exec_Begin(int)` at `0x42FD20` and its boolean return.
- `mission_result_sync_begin`/`mission_result_sync_poll`: classify only
  the four exact callers of `Sync_MissionResult` in the shared helpers
  `0x41F820/0x41F920`; they log the script/network origin and the two state
  integers, without the sync name, pointer or payload.
- `mission_reward_resolve`/`mission_reward_apply`: delimit the
  `ResolveResult()` and `ApplyResult(bool)` wrappers, their return and the 1..2
  count of local profiles. Weapon IDs/contents and save data are never written.
- `chat_name_association`: historical analyzer fixture. 0.6.48 no longer emits
  this event at runtime, since the argument previously treated as a name is the
  message text. `chat_identity_context` replaces it with boolean-only
  room/sender comparisons, without SteamID, lobby ID, nick or text.
- `network_summary/p2p_callsite`: aggregates direction, channel, caller RVA,
  count, minimum/maximum bytes and failures. It does not include SteamID, IP,
  payload or absolute address.
- `network_summary/game_packet_route`: aggregates the sending producer routine
  or the receiving consumer callback, channel, quantity and minimum/maximum
  sizes. The inventory has 128 fixed slots, does not allocate on the network
  path and does not record recipient, SteamID, IP or payload.
- `network_summary/game_message_route`: aggregates outgoing and incoming
  logical messages by
  code/family/flags, producer RVA, presence of the context handle, count and
  size. Distinguishes an unexpected header mismatch from a known `0x1100`
  multipart container. Reads only the four-byte header and never stores
  payload or endpoint identity.
- The detailed P2P events of the `Maximum` profile also receive `caller_rva`,
  making it possible to link a packet format to an exact routine of
  `EDF5.exe`.

## Baseline with two real players

The host and client reports with one complete stage confirmed the normal
transport path without failure:

| Observed RVA | Direction/channel | Classification |
|---:|---|---|
| `0x41AC53` | send / channel 0 | return of the normal `SendP2PPacket` |
| `0x41AE85` | send / channel 2 | Steam authentication ticket; not gameplay |
| `0x41A460` | receive / channels 0-2 | return of the central P2P reader |

The logical producer above Steam is at `0x453890`; its only direct transport
calls `0x41ABE0` at `0x4538EF`. The central receive distributor is at
`0x41A770`, called by `0x41A5DB`; it walks the protected list at
`object+0x88` and invokes the second method of each callback. 0.5.3 validates
the prologues, the loop body and the two call targets before installing these
hooks.

The client in this test ended with `0xC0000005` at `EDF5.exe+0x991C08` right
after `end_auth_session` and `leave_lobby`, when the Steam interfaces had
already been zeroed. This points to teardown/stale pointer, not to the mission
capacity path, but it is still an inference: registers and return address were
missing because the final crash filter was not called. 0.5.3 writes
`crashes/first-chance-emergency.json` directly in the VEH to preserve that
context even when another component replaces the top-level filter.

The reverse of the producer `0x432D20` and of its only direct caller
`0x45EAD0` also classified the frequent families `0x3300` and `0x3400`. The
code is assembled as `((object+0x40 << 4) | subtype) << 8` and then
encapsulated in the message header; therefore `0x33`/`0x34` are dynamic
subtypes of a replication layer, not the indices of players 3 and 4. The final
producer continues to be observed at `0x432EDA`, with no capture of payload or
endpoint identity.

0.6.4 closes the per-participant association that was missing at this point.
The `SharedProperty` at `0x45EAD0+self+8` provides the source `UserImpl` before
serialization. On the receive path, `0x4339DC` is the only direct call to
`0x435670` and passes `UserImpl+0x88`; the parser walks the messages and calls
the handlers synchronously. A thread-local scope therefore links the
`MissionScript` dispatcher to the same `UserImpl` without reading or logging
the payload. Counters for the `0x3300/0x3400` families are emitted per P0-P7,
and any context that is not in the final mission map explicitly falls into the
unresolved bucket.

The later offline review of 0.6.10 walked the three complete segments:
producer `0x45EAD0`, serializer `0x432D20` and remote parser `0x435670`. There
is no comparison, mask or four-participant array in those paths. The immediate
`4` at `0x432DC9` is the size of the message header; the `& 0xF` at
`0x45EB5B/0x45EB77` combine the subtype into the `0x33xx/0x34xx` code.
Therefore no speculative network capacity patch was applied.

The analyzer now offers `--require-replication-matrix`. In each capture it
requires `0x3300/0x3400` output associated with the locally controlled
participant and input associated with each remote participant. Thus a client
that receives P2, P3 and P4 but does not receive host P0 no longer passes just
because there was "some" incoming traffic. The negative fixture reproduces
exactly that case and must be rejected.

The first test with five real players reached gameplay without a crash, but
had severe lag/desynchronization and characters that did not move or seemed to
share control. In the four available reports, the player with index 4
was recycled to `source_index=0`. This motivated the audit of the two
collections and of the messages in 0.5.4. In the next test, the new events
should say whether the fifth `UserImpl` is lost in the full collection, in the
getter resolution or in the local control association, and whether the message
flow diverges between PCs.

The later 0.5.4 test with two players completed the stage on both sides and
confirmed `session_all_users=2`, `session_local_controls=1`, two distinct
objects and P2P transport without failures. 0.5.5 adds the ordinal permutation
and the final resolution needed to decide whether each PC associates the fifth
participant with the same `UserImpl`; the fact that the earlier five-person
test created five characters focuses the investigation on identity/control and
synchronization after the spawn.

## Result, sync and reward in 0.6.5

The reports from the host and three clients of the five-person test were
generated by 0.6.0. They confirm five characters and distinct local ownership
for P0/P2/P3/P4, but show the permanent temporary fallback `P4: 4->0` using
P0. This explains the Air Raider class and the nick repetition observed. 0.6.4
already replaces that path with a temporary native block that receives the
class, six equipment items and armor from P4's `PlayerInfo`, and restores both
the block and the exclusive index 4 before returning to the game.

On victory, all four reports registered UI 3/result 1 via apply,
but no native setter. The host only registered a result 2 setter about
210 seconds later, at the manual abort. The host-only recovery of 0.6.4 calls
the clear setter once after 250 ms when that exact pattern occurs.

The additional reverse mapped the continuation of the flow: RTTI/vtable
identifies `0x42FD20` as `net::MissionResult::Exec_Begin`; the xrefs of the
`Sync_MissionResult` string reach two pairs of calls at `0x3E2DD8/0x3E2DE4` and
`0x42C134/0x42C13B`; the registered script wrappers are at `0x3E3150`
(`ResolveResult`) and `0x3E3160` (`ApplyResult`). The block `0x42C0D6` is not a
hook target: it shares frame/epilogue with a larger function and has no safe
entry. The hooks use only real prologues and exact signatures.

`ApplyResult` reads the count from global state `+0x2459C`, starts local
profiles at `+0x6D4C` and advances `0x3E60` bytes. The only setter (`0x55830`)
accepts only 1 or 2; thus this limit belongs to the local saves, not to the
online roster, and must not be converted to 5/8/`MaxPlayers`.

The utilities `tools/disassemble_rva.py` and `tools/inspect_vtable.py` make it
possible to repeat the analysis by RVA and RTTI/vtable without launching the
game.

## Chat, replication parser and result dispatch in 0.6.6

The vtables of `net::Chat_Room` led to the publisher `0x3F0B70`. Its three
direct callers (`0x3F1635`, `0x3F1863`, `0x3F1F81`) converge two identities,
text and message state at this single entry. The 0.6.6 interpretation that the
text was the displayed name was invalidated by `Reports\msg_bug.zip`; for that
reason 0.6.48 does not use that argument to associate a nick with a
participant.

The only caller of the gameplay parser `0x435670` is at `0x4339DC` and passes
`UserImpl+0x88`. The parser iterates over vectors whose begin/end are read at
runtime and calls the handlers on the same thread. No comparison, mask or
four-participant array was found in that consumer. This reinforces that any
future divergence should be sought in the `UserImpl -> character` association,
not in a new indiscriminate capacity patch in that parser.

The result setter `0x111080` calls the UI apply and then builds a local event
of type 1/payload 2. Both internal paths call `0x61E950`, a synchronous fanout
over dynamic lists of listeners. The host-only recovery is not cosmetic because
it reproduces the complete original setter; however, the 0.6.8 reverse proves
that this event closes a local UI object and does not by itself start the
sync/reward stage. The two chains are audited separately.

## Pre-map restore and result event in 0.6.7

The character consumer `0x3123A0` needs a native index 0..3 only during
construction. The continuation of `MissionPlayerCreate`, however, reads
`UserImpl+0xF8` again at `0x11D0EC` and `0x11E061`; the second read feeds a
runtime tree/map. Leaving P4 with the `0` fallback until the whole function
returns creates a concrete collision with P0. The restore now happens on the
immediate return of the consumer and logs the phase, the index observed
before/after and whether it occurred before the map consumers. The validator
rejects the fixture that restores only at `player_create_return_fallback`.

The typed publisher `0x61E950` was instrumented with a thread-local scope only
during `MissionResultSetterHook`. Thus the report distinguishes: victory UI,
setter, expected publication `type=1/payload=2`, `Exec_Begin`, sync, resolve
and apply. Outside the setter, the hook is a pass-through without per-event
telemetry. The `Exec_Begin` argument was renamed to opaque value; the two
proven callers pass `-20000` and a received parameter respectively, therefore
it does not directly represent the clear result `1`.

## UI target of the event and sync separation in 0.6.8

The global used by the setter points to the secondary interface of
`xgs::ui::System`; subtracting `0x88` recovers the bus that owns the lists at
`+0x18` and `+0x28`. The fanout `0x61E950` calls the virtual callback `+0x18`
of each listener. The generic callback of `xgs::ui::Object` is at `0x4A1B70`:
event type `1` compares the payload with `Object+0x78`, and the `2 == 2` match
sets bit 0 in `Object+0x18` before invoking the virtual close transition.

That callback does not call `0x42FD20`, `0x41F820` or `0x41F920`. Therefore the
report now logs `mission_result_ui_close_dispatch` separately from
`mission_result_exec_begin`, `mission_result_sync_begin/poll` and rewards. The
event contains only integers/booleans: listener ID, target match, close flag
before/after and return; no absolute address or payload is persisted. A
positive fixture requires the closing of object 2 and a negative one with
listener 5 proves that the analyzer detects the missing target.

## MissionSync_Res participant filter in 0.6.9

The RTTI vtable of `MissionSync_Res` points to the main entry `0x42D8A0`. It
walks the live collection of `UserImpl`, validates `+0xC1/+0xC0` and, at
`0x42DB3E`, reads the exclusive index `UserImpl+0xF8`. The `cmp eax,4` test at
`0x42DB4C` eliminated P4-P7 before attaching their shared handle. This is a
limit on online participants, not on classes.

The destination started with `reserve(4)`, but the path `0x42DBDC` doubles the
capacity and each handle takes 16 bytes. The consumer at `0x42DE34` iterates
over the dynamic quantity and writes the aggregate to `state+0x245A0`; it does
not use the player index to address a four-position table. For that reason
0.6.9 binds only the operand of `0x42DB4C` to `MaxPlayers` and keeps all the
four-class loops and the 1..2 count of local profiles in `ApplyResult`
unchanged.

Exact signatures cover the filter, the dynamic grow, the loop by size and the
commit. The patch is part of the same protection, write and verification
transaction as the roster; any byte divergence leaves the plugin in quarantine
before the hooks.

## Loadout parser rollback and effective return in 0.6.10

The reverse of the full parser at `0x42F480` revealed an overlap that does not
appear in the isolated creation consumer. The parser keeps the participant's
real logical index and computes `state+0x14B30+index*0x3E90`. Therefore P4's
block starts at `state+0x24570`; inside that same fifth block lie the local
reward profile counter at `+0x2459C` and the result participant aggregate at
`+0x245A0`. The parser writes the selector, equipment, armor and other regions
of the block, so merely fixing the class would not prevent the corruption of
the stage completion.

0.6.10 wraps the whole parser: it snapshots the four extra blocks P4-P7
(`4 * 0x3E90`), calls the original with the true registers and indices,
restores byte by byte the region outside the four native blocks and, only when
the parse finishes successfully, preserves the legitimate final counter at
`+0x245A0`. The local counter at `+0x2459C` and everything else go back to the
previous values. No synthetic index is serialized, so name, chat, replication
and ownership remain associated with the real `UserImpl`.

Another consumer at `0x4B6710` also multiplied `UserImpl+0xF8` by `0x3E90`
with no bound. The sidecar hook of 0.6.10 leaves the logical index 4+ intact,
but replaces the output class with the class observed in the `PlayerInfo` of
that same participant. This covers the creation callers that do not go through
`0x3123A0`.

Finally, `MissionUpdateHook` now returns `clear=1` when the host-only setter
recovery occurred on the same tick and the native return captured before it
was still zero. Previously, the setter could publish the result, but the
script received the stale zero and failed to start sync/reward. The signatures
of the parser prologue, of the class resolver and the overlapping offsets are
part of the fail-closed; the self-test overwrites the whole extra range and
proves the exact restoration, with the intentional exception of the
participant counter.

## Receive callback and dynamic vector in 0.6.12

The only direct caller of `0x435670` is still at `0x4339DC`, but now the
previous level has also been reversed. Entry `0x4336F0` is reached through a
virtual callback whose thunk at `0x451B90` recovers the owner at
`callback+0x18`. The pump reads the qword count at `owner+0xE0`, the base at
`owner+0xD0` and computes each shared handle with `index << 4`. The backedge
`0x433B6C` compares the index with the count read at runtime; there is no
`cmp 4`, two-bit mask or local four-entry table on this path.

Each shared handle holds a `UserImpl`, and the pump passes `UserImpl+0x88` to
the parser. The observational hook of 0.6.12 uses the same lock at
`owner+0x80`, without waiting if it is busy, and compares the table with the
private participant map. The resulting event reports only count, P0-P7 masks,
readability and completeness. Isolated fixtures prove three cases: five
complete unique routes, missing P0, and duplicated P0/P4.

## NetGameStatus and result accumulators in 0.6.13

The shared decoder `0x430C20..0x4312FE` receives a function with signature
`void(int, NetGameStatus::Item const&)`. The number of Items comes from a
variable-size integer and the parse loop walks all the received records.
However, `0x430F23` compared the logical index with four and skipped the
callback for P4-P7. This left `MissionSync_Res` with five handles since 0.6.9,
but the result state still had data from only four participants.

The function's exact thunk is at `0x132BB0`: it loads the index and writes the
qword to `state+0x2457C+index*8`. The initialization at `0x430EF6` clears four
qwords and must stay that way, since the fourth ends exactly before the local
profile counter at `+0x2459C`. There is no contiguous space to turn that table
into eight entries.

0.6.13 binds only the application filter `0x430F23` to `MaxPlayers` and
intercepts the thunk. Indices 0..3 remain unchanged; each extra Item is summed
into the two dwords of slot `index % 4`. The native consumers `0x12AA30`,
`0x60E80`, `0x60F40` and `0x1991D0` reduce the four slots, so they preserve the
total of five to eight participants without indexing outside the block. Exact
signatures, an isolated self-test and an analyzer fixture cover the filter, the
thunk, the P4 sum and the intentional absence of reward/payload content in the
logs.

## Nickname origin and reward consumers in 0.6.14

The exact constructor `PlayerInfoFromUser` at `0x422F00` receives the
destination in RCX and the source `SharedProperty` in RDX. After keeping the
source `UserImpl`, it calls the virtual getter `+0x10` or `+0x08` of the same
object and copies the resulting string to `PlayerInfo+0x08`. There is no
parallel table of four names in that stretch. Therefore a P0/P4 swap is born
earlier, from the `UserImpl`/index collision, or later, when the chat
associates sender and name; it must not be fixed by blindly replacing text.

0.6.14 logs, without text or external identity, the logical index of the
`UserImpl` that originated each `PlayerInfo`, how many objects share the
private name token and whether the index still matches the participant during
character creation. The additional association through the common chat
publisher was tried in that version, but disabled in 0.6.48 after the fourth
argument was reclassified as a message. The origin of the names continues to be
audited in the `PlayerInfo` path itself, without persisting nickname, SteamID,
pointer, message or endpoint.

The reverse also walked the final consumers. `0x12AABE..0x12AAFB` and
`ResolveResult 0x199275..0x1992A9` reduce exactly the four contiguous Items at
`+0x2457C`; they produce totals and do not index players. Next, `0x199492`
distributes these totals over the dynamic count of local profiles at
`+0x2459C`, with stride `0x3E60`. The real `ApplyResult` at
`0x199D50..0x199EC7` walks a dynamic vector of 20-byte records and iterates the
local profiles separately. There is no other online limit of four in these
functions.

These bodies now have exact signatures in the validator. Before
`ResolveResult` and after `ApplyResult`, the telemetry compares the participant
count with the mask of extra Items already aggregated. It reports only count,
mask and completeness; no weapon/reward value or payload is written. 0.6.14
does not invent rewards or change the native algorithm: it makes it conclusive
whether P4-P7 reached the point where rewards are resolved.

## Independent transport route in 0.6.15

The participant/loadout index at `UserImpl+0xF8` does not by itself select the
route that receives messages. The dynamic allocator at `0x45C8E3` finds a slot
in the vector `manager+0xD0`, whose count is read from `manager+0xE0`. The
index goes on to the constructor at `0x45C948` and is persisted in
`UserImpl+0xC8` by `0x4525FB`. The registrar `0x433BD0` reads `+0xC8` at
`0x433C78`; the destructor uses the same field at `0x433E3C` to remove the
route.

These loops and vectors are dynamic, so they do not justify a capacity patch.
The relevant risk is a collision or an out-of-position index: for example, P0
and P4 with `+0xC8=0` leave the host route missing or replaced on a client. The
telemetry now provides ordinal arrays of route, participant and stored index,
plus masks of missing, duplicated and divergent entries. The analyzer
cross-checks these values with character creation and with the `0x3300/0x3400`
replication families. All data remain private and sanitized; there are no IDs,
names, endpoints or payloads.

## Fan-out by route descriptor in 0.6.17

The producer `0x45EAD0` calls `0x432D20` at `0x45EB9B`, passing a dynamic
vector of route descriptors. The builder `0x45ED80` walks a live collection of
users, copies the qword `UserImpl+0xC4` and appends it with stride 8. The
second dword, at `descriptor+4`, is read by `0x433F40` and used as the index of
the dynamic table `manager+0xD0`. This proves that the element is not a 16-byte
`SharedProperty`; the 0.6.16 instrumentation based on that hypothesis was
replaced before the test.

The 0.6.17 audit keeps in TLS only the local `UserImpl` during the call and
measures the vector immediately before handing it back to the game. For each
`0x3300/0x3400` family and local participant, the first event reports the
number of valid/unique routes, observed P0-P7 mask, missing/unexpected remotes,
duplicates, unresolved ones and the serializer result.

This makes it possible to distinguish a healthy local producer with four
destinations from a publication failure prior to P2P. The event does not
serialize descriptors, route indices/keys, pointers, IDs, names, endpoints or
message contents. The positive fixture
requires a single unique remote destination in a two-player session; the
negative one simulates zero destinations and must fail with
`--require-replication-send-fanout`.

## Complete matrix of result Items in 0.6.18

The sink `0x132BB0` receives all indices that went through the `NetGameStatus`
decoder, but 0.6.17 logged only the extra indices that require folding. 0.6.18
marks the readable presence of P0-P7 in a mask independent of the values and
keeps the extra mask separate to prove the aggregation.

The time checkpoints and the `ResolveResult`/`ApplyResult` hooks publish
participant count, expected mask, observed mask and completeness. This locates
the wait in a single report even if rewards are never called. No Item, weapon,
reward or payload content is logged. The complete audit of
`0x45EAD0/0x432D20/0x4336F0/0x435670`, `0x42FD20`, `0x41F820/0x41F920`,
`0x1991D0` and `0x199D50` found no other online limit of four; the proven
filters remain `MissionSync_Res 0x42DB4C` and `NetGameStatus 0x430F23`, both
already fixed.

## Recovery of the local reward counter in 0.6.19

The `ApplyResult` wrapper at `0x3E3160` reads the local profiles dword at
`state+0x2459C`; zero directly skips the entire loop that applies weapons to
the saves. That field is inside the range that the fifth `0x3E90` block used to
overwrite. The parser rollback remains the primary fix.

As a last defense, the `session_local_controls` collection, copied before the
characters are created, provides an independent, validated count of 1..2
profiles. On victory with P4+, `MissionRewardApplyHook` swaps an invalid native
counter for that count immediately before the original wrapper. No weapon,
reward, name, ID, pointer or payload value is read by the diagnostic. The
analyzer shows `profiles=before->effective->after`, the expected value and
whether the restore occurred.

## PlayerInfo return contract in 0.6.20

`Reports\Crash.zip` recorded a `c0000005` write at `0x55D64D`, returning to
`0x560537`, during the first room update and without fillers. The source value
preserved in R9 was `UserImpl vtable 0xEC2730`; when copying the supposed
object, the game loaded `0x452F70` from that table, the `UserImpl` destructor,
and tried to increment `+4` as if it were a reference counter. This proves that
the vector received the vtable as a `PlayerInfo` pointer, not that the
eight-slot reservation failed.

The callers `0x422087` and `0x422277` call `PlayerInfoFromUser 0x422F00` and
pass RAX directly to the handle constructor at `0x425760`. The converter's
epilogue executes `mov rax,r14` at `0x423962`, where R14 holds the destination.
The audit hook introduced for names/classes returned `void`, so the
observation routine overwrote that register after the original returned. The
signature is now `uint8_t*`, the original value is kept until the hook returns,
and `0x42395A..0x423964` is part of the offline validation. The sanitized event
`player_info_return_contract` records only match and divergence count;
destination/return addresses are not persisted.

When new reports exist, the control assignment can be compared directly between
sanitized ZIPs, without extracting them:

```powershell
python tools/analyze_player_controls.py Reports\*.zip --expected-players 5 --require-exact-loadout --require-pre-map-loadout-restore --require-loadout-parser-rollback --require-class-sidecar --require-name-identity --require-chat-name-association --require-replication-association --require-replication-matrix --require-replication-send-fanout --require-receive-route-matrix --require-transport-route-identity --require-extra-result-items --require-result-item-matrix --require-result-event-publish --require-effective-result-recovery --require-result-ui-close-dispatch --require-result-reward-chain --require-result-room-return --strict
```

Each process must list all participants, normally mark only one as local and
complete `mission_player_create_result` for all. Duplicate local owners across
computers, a null consumer or an extra-source fallback are highlighted.

## Local identification in the room chat in 0.6.21

`net::Chat_Room` uses the vtable `0xEBEDA8` and publishes the visual lines
through the common routine at `0x3F0B70`. The native local-message path
initializes a neutral `0x50`-byte state at `0x3F17F7`, writes `-1` into dword
`+0x08` and calls that publisher at `0x3F1863` with type 2 and subtype 0. The
send to Steam happens in another part of the native routine, so it is neither
necessary nor desirable to use it to identify the mod.

0.6.21 schedules `EDF5_MultiSlotMod v0.6.21` when a locally created room is
confirmed or when the positive count confirms entry into the requested lobby.
The first valid visual event of `Chat_Room` consumes the pending item and
directly calls the common publisher's trampoline. This avoids recursion in the
hook and does not execute `SendLobbyChatMsg`; the line exists only in the local
interface and cannot be attributed to another participant.

When leaving the room, the join target, the pending item and the lobby identity
are all cleared. The self-test covers asynchronous join, creation, exact
neutral state, exact text/version, single success, absence of duplication and
cleanup on exit. The logs keep only name, version, entry path and the result of
the attempt; no user message, nickname, SteamID, endpoint or payload is
persisted.

## Direct Chat_Room instance in 0.6.22

`Reports\no_name.zip`, generated by 0.6.21, ended cleanly and without any
crash. It recorded `chat_mod_banner_armed` for the created room, but did not
record `chat_mod_banner_publish` nor a single pass through the publisher hook.
This proves that waiting for a later visual entry is not a valid trigger.

The only direct caller of the `Chat_Room 0x3F0680` constructor is at
`0x412AFA`. It allocates `0xC0` bytes, builds the object and stores it in the
room shared handle. The vtable assignment occurs at `0x3F06B8` and points to
`0xEBEDA8`. 0.6.22 hooks only the constructor, validates these two signatures
and keeps the instance in an atomic without logging its address.

During `HUiRoom::Update`, publishing is attempted only when:

1. there is a pending banner;
2. the instance still has the exact `Chat_Room` vtable;
3. `ISteamUser019::GetSteamID` returns a valid local identity;
4. that identity matches a registered `UserImpl`.

The `CSteamID` return of `GetSteamID` uses the MSVC ABI hidden buffer, modeled
explicitly as in the lobby getters. A zero qword is passed as the recipient to
choose the public line, while the sender is always the local user. The call
goes straight to the trampoline of `0x3F0B70`, so it does not enter method
`0x3F16C0` or its Steam send `0x44D940`.

The self-test does not fabricate a native message: it confirms the wait before
the local registration, the single direct publication on create and join, the
neutral `0x50`-byte state and the absence of duplication. If any prerequisite
is missing at runtime, `chat_mod_banner_waiting` logs only the sanitized
reason, once.

## Chat_Room text state in 0.6.23

`Reports\no name v2.zip`, produced by 0.6.22, recorded the valid capture of the
`Chat_Room` and 755 consecutive false returns from the publisher. When the user
sent their first message, the native event occurred and attempt 756 was
accepted. There was no crash, loss of events or write error.

The guard of `0x3F0B70` at `0x3F0C04` rejects a message outside the active
editor when `state+0x20 == 0`, `state+0x00 == 0` and the pointer at
`state+0x10` is also null. The local message assembled at `0x3F17F7` does leave
`+0x10` zeroed, since its caller is in the editor context. The remote decoder,
on the other hand, copies the text pointer into that field at `0x3F1E72` before
publishing at `0x3F1F81`.

0.6.23 keeps the `0x50`-byte state, the `-1` selection, type 2 and subtype 0,
but writes the static address of `EDF5_MultiSlotMod v0.6.23` to `+0x10`. The
publisher continues to be called directly: there is no passage through the
send method `0x3F16C0`, the transport `0x44D940` or Steam. The self-test's fake
publisher now requires this association between field `+0x10` and the text
argument. Real rejections are attempted at most every 250 ms; only the first
sanitized failure and the eventual success are written.

## Native four-player visual table in 0.6.24

The reports `server.zip`, `client 2.zip` and `client 3.zip` recorded the same
access violation during mission opening: `EDF5.exe+0xB1D60` on the host and
client 3, and `EDF5.exe+0xB1D6B` on client 2. The raw host dump preserved by
Windows showed the stack `0xB1D60 <- 0x9DD90 <- 0x4BBC3C`. The routine
`0xB1CF0` copies a `0x30`-byte graphics descriptor and tried to increment a
reference whose invalid control block was `0x200000000`.

The caller `0x4BB010` resolves the `UserImpl`, receives in its first output the
logical index from `UserImpl+0xF8` and, at `0x4BB5E1`, computes
`render_base + index * 0x40`. The visual table has only four entries.
P4 selected the fifth, unbuilt entry; the crash occurred later, when submitting
that descriptor at `0x4BBC37`. This is a visual resource limit, not one of
identity, control, loadout or transport.

0.6.24 keeps `UserImpl+0xF8=4..7` and changes only the temporary output of
resolver `0x4B6710` to `index % 4`. Thus P4-P7 reuse visual resources 0-3
without colliding in the logical map. The sanitized event
`mission_participant_visual_slot_remapped` logs logical index, visual slot,
caller RVA and preservation booleans, without names, IDs, pointers or payloads.
Exact signatures cover the `*0x40` computation and the crash instruction.

The emergency logger also started scanning `0x800` bytes of the thread stack
and keeping up to eight executable candidates as `stack_offset/module_rva`
pairs. These RVAs remain in the sanitized ZIP, while absolute addresses and
dumps remain removed. The analyzer accepts `--stack-hex` for local inspection
of the dump and `--require-visual-slot-remap` for the next coordinated test.

## Native class and fixed text table in 0.6.25

The reports `Reports\Server.zip`, `Reports\Client 1.zip`,
`Reports\Client 2.zip` and `Reports\client 3.zip`, all from 0.6.24, prove that
`mission_participant_visual_slot_remapped` executed for P4 before the new
failure. Host and client 3 ended with a read AV at `0x5E741C`; client 1
at `0x4BC33A`. Client 2 recorded a clean exit after losing the room and staying
on loading, consistent with the host's drop.

The host's local dump (`pid 21544`, kept only locally) fixes the stack
`0x5E741C <- 0x4BC2CF`. At `0x5E741C`, `cmp bx,[r8]` received `r8=1`. The
caller chooses a native string at `0x4BC266` and obtains it from a record
computed at `0x4BB5CE` as `class * 0x30 + [rdi+0xB8]`. The events before the
crash logged native class 257 on the host and 256 on client 3.

The origin is `0x4B6886..0x4B689A`: the resolver multiplies the logical index
by `0x3E90` and reads the class at `state+0x14B30`. P4 therefore consults the
fifth block, which does not exist and overlaps the result state. The parser
rollback was correct, but it also erased the useful data that the parser had
just produced.

0.6.25 keeps, before the rollback, only the proven fields of the extra block:
class selector, active six-dword record and armor. The sidecar is indexed by
P4-P7, protected by a lock and cleared when creating/joining/leaving the
session. It serves both to synthesize the temporary block during the character
factory and to correct the HUD class when `PlayerInfo` was not observed. As a
last barrier, any native class outside `0..3` is replaced by the visual slot
modulo four.

The self-test covers the two values from the reports: native class 257 and
absence of `PlayerInfo`, first with a valid sidecar and then without a sidecar,
guaranteeing output 0 in both. The offline validation covers exactly
`0x4B6886`, `0x4BB5CE`, `0x4BC266` and `0x5E741C`. No game was launched during
implementation.

## Final parser contract and partial sidecar in 0.6.26

The complete flow of `0x42F480` fixes the order of the writes. For P4+, the
parser does not execute the large copy reserved for indices 0..3, but still
writes the selector, six weapons, armor and the final 0x30 bytes. After the
loop, `0x42FA69` executes `mov [state+0x245A0],r12d` without consulting the
boolean return value. This explains the real telemetry `after_parser=5`,
`parser_result=false`: it was a valid read, not a failure.

There is only one direct `call` to the parser, at `0x42ABDE`. The caller
prepares an error byte at `[rsp+0x38]`, passes its address and tests it at
`0x42AC05` to decide whether to return `-1`. `0x42F4D2` merely zeroes that byte
and no path makes it true. Separately, the return in `AL` only marks a state of
the object; in the decoding path, `0x42F73D` zeroes `r13b` before the writes.
Thus, preserving the count only when `AL=true` inverted the real contract.

P4 with class 1 has an active record at `0x24590..0x245A7`. Weapon 3 overlaps
the local counter at `0x2459C`, but still contains the real weapon at the time
of capture; weapon 4 at `0x245A0` has already been replaced by the final count.
The resulting validity mask is `0x2F`, with native fallback only at `0x10`. For
PlayerInfo the mask remains `0x3F`. The self-test reproduces return `false`,
count 5, class 1 and the overlap, requires the preservation of 5 and verifies
that the scratch receives `{1040,1041,1042,1043,native,1045}` before being
restored.

The events now expose only masks and state: `complete_sidecar_weapon_mask`,
`partial_sidecar_weapon_mask`, `participant_count_output_valid`,
`participant_count_source`, `weapon_valid_mask` and `fallback_weapon_mask`.
The masks add no equipment content to the report; only the first numeric ID
that the loadout telemetry already logged remains.

## Complete census of class/visual index consumers

The offline reverse found exactly three direct calls to the resolver
`0x4B6710`: `0x4B8039`, `0x4BB1FB` and `0x4CEEFC`. None of them uses the first
output as a persistent identity. It feeds only transient visual indices:

- `0x4B855E` computes `index*0x30` for a table of UI descriptors;
- `0x4BB5E1` computes `index*0x40` for the four status/HUD descriptors,
  while `0x4BB5CE` computes `class*0x30` for the texts of the four classes;
- `0x4CF21F` computes `index*0x10` over a local array that `0x4CEDE5`
  initializes with exactly four consecutive entries. The same caller selects
  only classes 0..3 at `0x4CEF24`.

Therefore, folding only the two transient outputs into 0..3 protects all known
consumers without changing `UserImpl+0xF8`, which remains unique for control,
names and replication. The validator now enumerates all `E8 rel32`
instructions in the `.text` section, requires exactly these three callers and
checks the three consumption layouts. A new caller or a layout change makes the
build fail instead of leaving a visual path unaudited.

## Sidecar concurrency and lifecycle

In the four 0.6.24 reports, each process used a single stage thread for all
parser calls and, afterwards, for the P0-P4 creation and the loadout
scratch/restore: host `22360`, clients `9632`, `7636` and
`12408`. There was no concurrent parser nor thread switch during the rollback.
The initial calls returned `true`, did not change the extra blocks and kept the
count at 1; only the last call returned `false`, wrote the P4 block and
produced `participant_count_after_parser=5`.

The visual panel ran later on a distinct UI thread and that thread was the one
that suffered the exception: client 1 `19340`, client 3 `6716` and host
`31564`. The event `mission_participant_visual_slot_remapped` appears on the
same thread as the respective exception and after the entire P0-P4 creation.
The native scratch was already restored; the class crosses from the stage to
the UI through the sidecar protected by `SRWLOCK`. This separation confirms the
parser -> sidecar -> HUD chaining and not a concurrent restoration of the
block.

Between the parser's last write and P4 there were about 32 seconds on the host
and clients; between P4 and the HUD, only 0.17 to 0.90 seconds. For that reason
the sidecar does not use an arbitrary TTL: expiring at 30 seconds would discard
valid data from these very reports. Validity is bounded by the session and the
logical index, and a new parser output atomically replaces the corresponding
slot.

The parser protection and the scratch are `thread_local` to prevent reentry on
the stage thread; the shared sidecar uses `SRWLOCK` on publication/read from
the UI thread. It is cleared when creating
or joining a room and at mod shutdown. The recovered class necessarily stays
within `0..3`, so an old sidecar can at worst cause an incorrect visual/loadout
fallback, but cannot reopen the out-of-range indexing across the four classes
that caused these crashes. No additional synchronization change was justified
by the reports.

## Local Mission Harness 0.6.27

The harness deliberately reuses the synthetic lobby route because it makes EDF5
build an independent `net::UserImpl` for each dummy. Duplicating the host's
object inside the final vector was discarded: that would repeat identity,
control, name and replication state, exactly the class of error already
observed in the first five-player test.

F3 cycles between target 3, target 4 and zero. Activation requires a room
created by the process, `actual_members == 1`, a recent room roster and no
manual filler. Each dummy receives Ready `+0xC0`, `cm=c1`, `ds=ds` and the
host's PlayerInfo clone. The `l1/l2` reconciliation stays pending from
activation, without waiting for the first channel 0 send. No gameplay response
is queued, so the resulting characters remain remote and inert.

When copying the mission collections, the gate waits for `target+1` unique
objects and controls in the full collection and exactly one in the local
collection. This proves that host+3 went through the native form and that
host+4 really delivered P4 to the builder, with no alias to P0. On the result,
the local write `{phase=1,result=0}` is limited to the proven callers of
`Sync_MissionResult` and again requires target 3/4, one real member and the
exact synthetic count. It creates no packet, ack or peer.

The isolated self-test validates the three F3 edges, absence of repetition when
the key is held, Ready of P1-P4, name `Harness Dummy 4`, early arming of l1/l2,
local completion of the sync and complete removal on shutdown. EDF5.exe was not
launched.

## Enemy spawn and result with five players (0.6.32)

The static census found exactly 24 direct calls to the common instantiation
routine at `0x1C1650`. RTTI associates the owners with AlienTrailer, Deiroi,
GeneratorPoll, InsectBase, Monster, Nephila, AntHill and UFOs. The routine
limits the live quantity to 400 and then applies `owner+0x290 / owner+0x294`; a
null source at `owner+0x2B0` also prevents creation. The GeneratorPoll
constructor at `0x1F872C` uses `participant_count-1` to index a native table of
four entries, but the result feeds the owner's timers `+0x1F8/+0x1FC`. That
table does not write the scale `+0x290/+0x294` of the spawn subobject and
therefore does not prove the origin of a zero scale.

The new hook is fail-closed: installation requires the signature of `0x1C1650`
and that the 24 `E8 rel32` still point to it. The multiplier and the temporary
repair are valid only for these confirmed returns. The repair requires
5..MaxPlayers, zero numerator, denominator between 1 and 1,000,000, source
present and writable memory; the restore uses compare/exchange so as not to
overwrite a concurrent change.

In the five-player reports, the script's `Sync_MissionResult` started at
`0/0`, but `Exec_Begin` never occurred. The wrapper registered at `0x42AC40`
calls `0x42FD20`, and the direct native caller at `0x1153EE` supplies the
proven argument `-20000`. The 0.6.32 recovery waits 1000 ms, cancels if the
native path appears and, if the stall persists, calls `Exec_Begin` exactly once
on the `Mission()` thread on real hosts and clients. The F3 harness is
explicitly excluded.

### Concurrency audit 0.6.33

The initial queue used three independent atomics. Although the observed flow is
normally single-threaded, a second `Sync_MissionResult` could overwrite the
tick/generation before the CAS of `pending` failed, and a simultaneous native
`Exec_Begin` could cancel a partially published set. 0.6.33 serializes
publish, cancel and claim with an SRW lock and increments the native-entry
counter before waiting for that lock. The recovery path never holds the lock
while calling EDF5 code.

A second check on the executable confirmed the 24 `E8 rel32`, `R8D` as the
quantity, the `0x190` clamp, the source at `+0x2B0`, the division
`(+0x290 * quantity) / +0x294` and `mov ecx, 0xFFFFB1E0` immediately before the
call to `MissionResult::Exec_Begin` at `0x1153EE`.

### Layout guard 0.6.34

Startup now also validates the semantic blocks at `0x1C16C6` and
`0x1C16EF`, not just the prologue: preservation of the request in `R8D`, clamp
400, source `+0x2B0`, denominator `+0x294`, numerator `+0x290` and the two
divisions. The caller `0x1153E9` must remain exactly
`mov ecx,-20000; call 0x42FD20`.

The independent offline verifier censuses any extra or missing caller and
confirms the stretch `0x1F910C`: the GeneratorPoll computes/sums the request
and calls the common routine before consulting the timer derived from the
participant table. This eliminates the hypothesis that the repair depends on a
later branch that would never reach the hook at P5.

### Closing observability 0.6.40

`EmitEnemySpawnSummary` no longer omits the event when the counter is zero. An
`enemy_spawn_summary` with `calls=0`, `common_spawn_reached=false` and
`confirmed_enemy_path_reached=false` proves that the closing was observed,
but no caller reached the common boundary. The fixture
`player-spawn-zero-calls-v0639` requires that the analyzer preserve this
evidence and still fail `--require-enemy-spawn`.

The old `mission_result_transition_completed` depended on leaving the Steam
lobby, which does not prove the return to the room screen when the lobby stays
alive. 0.6.40 ends the checkpoint at the first `HUiRoom::Update` observed after
`MissionResultApply` armed the result tick, logs
`completion_signal=room_ui_update` and changes the phase to `room`. The gate
does not require the textual phase to already be `result`: the real reports
show clients stuck in `mission` after apply 1 and before the sync. The path
changes neither the UI nor the native state; it only consumes the result tick
once. `leave_lobby` remains as a separate fallback signal.

The completion event includes counts of Exec_Begin, completed sync,
ResolveResult, successful ApplyResult and the sanitized mask of Items. The
analyzer accepts `--require-result-room-return` only for a clear result
with the explicit UI signal and rejects legacy conclusions or ones with only
`leave_lobby`. If `reward_apply` and `room_return` are present, the order
is also validated and the room cannot precede the application of the rewards.

### Upstream clamp of the native tables 0.6.41

The earlier census based on `.pdata` found 54 decoded reads of
`mission_state+0x245A0`. A second full sweep of `.text`, without relying on
unwind metadata, also found two leaf functions at `0x8ADCF` and
`0x2D0913`. Both execute `mov count; dec; count*3` and use the result to select
a three-dword record. The scaling inventory goes to 56 sites. The other leaf
function at `0x11E48E` merely returns the real count and stays outside the
patch.

The `GeneratorPoll` case pins down the most direct upstream cause observed:

- `0x1F872C` reads the real count and selects the profile `count-1`;
- the computed multipliers write `owner+0x1F8/+0x1FC`;
- `0x2DC7C0` compares those timers and only `0x2DC82C` calls the spawn virtual;
- `GeneratorPoll::spawn`, at `0x1F90A0`, calls the common boundary at `0x1F9120`.

Therefore, garbage/NaN in the P5 profile can prevent the common hook from being
reached. The 56 relays preserve the original instructions and flags, limit only
the loaded value to 4 and leave `state+0x245A0` intact at 5..8. An aggregate
counter and a 56-bit mask show which sites were actually used, without pointer,
payload, identity or endpoint. The analyzer requires this proof with
`--require-native-participant-scaling-clamp`.

The clamp chooses the last difficulty profile that exists in the game; it does
not increase the number of enemies. The optional multiplier remains in another
module, under `ExperimentalEnemySpawnMultiplier=false`, with inactive
intensity 1.

### Micro-execution of the 56 relays 0.6.42

The self-test no longer checks only the emitted layout. An isolated executable
page receives the same 56 stubs and a Win64 thunk loads/captures `RAX`,
`R8..R11`, `RBX`, `RDI` and `RFLAGS`. Each site is called with count 3, 5 and 8.
The test requires 3 with no clamp/telemetry and 5/8 reduced to 4 with exactly
one hit and the corresponding bit in the 56-site mask.

All non-destination registers, the arithmetic flag bits and the original dword
at `state+0x245A0` are also compared. Thus, the four destination variants and
all the base variants used by the executable go through the CPU, not just
through a byte inspection. The thunk and the pages exist only during
`EDF5MP_SelfTest`; no micro-test runs at normal EDF5 startup and no runtime
policy was changed.

### Separation between fixed storage and dynamic result collections

The complete body of `net::MissionResult::Exec_Begin` was reviewed again
after the clamp. At `0x42FD93..0x42FDCD`, it zeroes exactly four qwords at
`state+0x2457C`, `+0x24584`, `+0x2458C` and `+0x24594`. This is not a new
rejection of P4: they are the four native `Item` accumulators, whose range ends
before the local profile counter at `+0x2459C`. The proven fold of P4-P7
depends on keeping this storage at four entries.

Afterwards, the blocks at `0x430259` and `0x430356` walk two collections of
handles with a limit computed as `begin + count * 0x10`. Both compare the
cursor with that dynamic end and not with the immediate 4. Therefore,
`Exec_Begin` combines a fixed aggregate array and dynamic collections without
this imposing four online participants. `validate_spawn_result_layout.py` now
pins the three signatures and fails closed if any of these layouts changes.

### Decoded census of limits in the result pipeline

The new `result_pipeline_scanner.exe` decodes 2,882 instructions in the 12
proven bodies of `Exec_Begin`, named sync begin/poll, wrappers and
implementations of `ResolveResult`/`ApplyResult`, `MissionSync_Res`,
`NetGameStatus` and the two sync callers. Instead of searching loose bytes, it
inventories every instruction with immediate 3, 4 or 15 and requires the 15
known RVAs and exact encodings.

The eleven uses of the value 4 split into six dynamic 16-byte strides, one
state bit, an initial vector reserve that grows, a fixed limit of the
four `Item` accumulators and the two online filters already bound to
`MaxPlayers`. The value 3 is a division shift of the aggregate and the three 15
values are constants of the named sync. There is no `and 3`, `and 15` or other
unclassified limit in those bodies. The suite fails if any candidate appears,
disappears or changes.

The additional body confirmed in 0.6.43 is `0x42AC40..0x42AC55`. The
registration table names it `int ResultSync_Begin(int)`; it preserves `ECX`,
calls `Exec_Begin` at `0x42AC48` and returns the argument. The only other
direct call is `0x1153EE`, in the dispatch that supplies `-20000`. The scanner
and the startup validation now require exactly these two callers. The
`Exec_Begin` telemetry distinguishes `mission_script_dispatch`,
`result_sync_begin_wrapper` and `mod_recovery` by sanitized RVA, without
pointer or payload.

### Local context of the chat banner 0.6.47

The local `Chat_Room` route at `0x3F16C0` preserves its two identities in
`RSI` and `R12` and forwards them to the common publisher at call `0x3F1863`.
Inside `0x3F0B70`, the first resolution occurs at `0x3F0C94..0x3F0CA3` and the
second at `0x3F0CB3..0x3F0CC2`; they supply room and sender context. The old
hypothesis that the second identity being zero selected the public room was
wrong and explains why the pending banner was only accepted after a native
message.

The report `Reports\msg_bug.zip` invalidated the 0.6.47 hypothesis. There were
29 rejected `room_update_local_self` attempts; attempt 30 was only accepted by
`native_chat_fallback` after the user typed. In that natural caller, the first
identity did not match any registered `UserImpl`. This reclassifies the
arguments: the first is the room identity and the second is the sender.

### Room/sender pair of the chat banner 0.6.48

0.6.48 passes the active lobby as the first identity and the local SteamID as
the second. The local `UserImpl` is still checked before the call. The
SelfTest rejects the old local/local pair and requires two valid, distinct
qwords, equal respectively to the expected lobby and sender. The path goes
directly to the publisher: it does not go through `0x3F16C0` or `0x44D940` and
creates no Steam traffic.

The same report showed that the fourth argument of `0x3F0B70` is the text of
the message, not the nickname. The old runtime audit was disabled so as not to
fingerprint what the user typed. The new `chat_identity_context` compares
the two identities in memory only and persists boolean flags, ordinals and
participant index; SteamID, raw lobby ID, nickname and message are never
written.

### Local system-message publisher 0.6.49

`Reports\no_msg_2.zip` also invalidated the room/sender pair of 0.6.48: the
`room_update_lobby_local` attempt was rejected immediately, before any text was
typed. This result confirms that `0x3F0B70` must not be used to fabricate an
automatic player message, even with the two natural identities.

The caller at `0x41029C` supplies `Chat_Room` and text directly to `0x3F09D0`.
That body internally creates a type 1 record and inserts it into the local
list; it does not converge on `0x3F16C0`, `0x3F0B70` or `0x44D940`. The
validated signature is
`48 89 54 24 10 55 53 56 57 41 56 48 8B EC 48 83 EC 70 48 C7 45 C0 FE FF FF FF`.

0.6.49 uses this route only after validating the instance captured by the
vtable `0xEBEDA8`. The SelfTest requires exactly one call with the same
instance and the static banner on join and on create, no call while the
instance is absent and no duplication. Publication no longer depends on
SteamID, `UserImpl`, editor state or a previous message. The event logs only
the RVA, type 1, counters and flags; text, identities and pointers remain out
of the logs.

### Visual format of the banner 0.6.50

The static banner now uses `***` before and after the name and version. These
characters are plain ASCII and remain within the same `wstring` delivered to
`0x3F09D0`; no field, type, identity or publication path changed.

### Real ownership of the receive parser 0.6.51

The hypothesis that `manager+0xD0` held `SharedProperty<UserImpl>` was refuted
by the disassembly of the registrar `0x433BD0`. It allocates `0xA8` bytes and
calls `0x435DA0`; the property of that new object is what goes into slot
`route_index*0x10`. The constructor copies the control block of the original
handle to `route+0x58` at `0x435E37`. Since the control block layout keeps the
object at `+0x08`, the user can be recovered without storing identity or
address.

The parser used by the pump is also a separate object. `0x4351F0` receives the
route object in RDX and stores it at `parser+0x498` at `0x4352F0`; the pump
loads the parser from `route+0x88` before the call `0x4339DC`. The proven chain
is:

`parser+0x498 -> route+0x58 -> control+0x08 -> UserImpl`.

The old `receive_state-0x88` computation was removed. The receive matrix,
lifecycle and incoming scope now use the real chain. The SelfTest builds
artificial route and parser objects with the same offsets and requires
resolution of P4, besides detecting a missing route and a duplicate identity.
The independent scanner confirms the constructors, ownership stores, parser
call and exactly one direct caller for each constructor.

The loop at `0x45C8E3` examines eight-byte elements while the receive vector
uses `0x10` slots. This does not yet prove a bug: the owner passed to the
`UserImpl` constructor may be another class with coinciding offsets. 0.6.51
temporarily keeps that owner per user and, in the lifecycle, logs only the
boolean `allocator_owner_matches_receive_manager`. No stride was changed before
this real comparison.

### Result Update and Finally 0.6.51

The call census found only two direct callers of `0x430C20`:
`0x42AC9F`, in the script wrapper, and `0x12AA8D`, in the native consumer. The
return in AL is consumed differently in these paths, so the hook preserves
the `bool` and logs the result without assigning global semantics.

`0x42F090` is `void` and also has only two callers: `0x42AC28` and
`0x12AAA9`. The hook preserves the ABI and measures the origin. The
`result_pipeline_scanner` now fails if any caller appears, disappears or if
the wrappers change. These points make it possible to separate a block before
`Update`, inside it, before `Finally`, in the named sync, in the rewards or
in the UI return.

### Update, gate reasons and spawn method of the GeneratorPoll 0.6.46

The vptr of the `GeneratorPoll` object uses vtable `0xEA0E38`. Entry
`0xEA0ED8`, exactly `+0xA0`, points to `0x1F8B40`; that update calls the base
body `0x2DA720` at `0x1F8B5B` before any specific work. The base body ends at
`0x2DA9F4` with a tail-jump to `0x2DC7C0`, after setting up
`RCX=owner+0x400` and `RDX=owner`. Entry `0xEA0F40`, `+0x108`, points to
`0x1F90A0`; the gate's indirect call at `0x2DC82C` enters that method and the
following `test al,al` consumes its return. The method preserves `RCX` as self,
`RDX` as descriptor, queries `self+0x788` and calls the common boundary at
`0x1F9120` when that dependency exists.

`GeneratorPollUpdateHook` forwards both arguments without inspecting the frame
context and correlates how many updates reached the spawn method.
`GeneratorPollGateHook` preserves the ABI `void(owner+0x400, owner)`, filters
the concrete vtable and classifies the exact branch: cooldown still `>=0x1CC`
after the decrement, quota `+0x00<=0` within the window, method returning zero
AL or spawn accepted. The sampled event `generator_poll_gate_path` logs only
counters, pre/post scalars and bit-patterns of the floats `+0x08`, `+0x1F8` and
`+0x1FC`; no address is persisted.

The event `generator_poll_update_path`, the summary and the breadcrumbs before
the originals distinguish a missing update, a crash inside the update and each
gate reason. `GeneratorPollSpawnHook` keeps the native `RAX` whole and only
aggregates: calls, readability/presence of `+0x788`, methods that reached the
boundary, number of common calls and true/false AL return. The sampled event
`generator_poll_spawn_path` and the `enemy_spawn_summary` explicitly declare
that no pointer, descriptor or payload was stored. The offline validator pins
the two vtable slots, the three prologues, base call, tail-jump, gate,
boundary and return before the hooks are installed.

### Origin of the scale 0.6.38

The disassembly of the common configurator `0x3AC5F0` separated the two
mechanisms. At `0x3AD3DE` the spawn subobject receives the fail-closed default
`0/1`. Only if the fourth nested configuration record exists, the block
`0x3AD3EF..0x3AD52F` copies the record's integers to
`owner+0x290/+0x294`. The source at `+0x2B0` is built from the same
configuration, but through an independent field.

Therefore, zero is a possible native value before configuration and must not be
automatically attributed to the fifth player's index. The current repair
remains experimental and strictly temporary: it can only act at the common
boundary, with a confirmed caller, positive request, present source, plausible
denominator and 5..MaxPlayers; the original value is logged and restored after
the call. The next real report will say whether the boundary was even reached
and, if so, which scale pair arrived at it. The multiplier remains only
optional infrastructure. `ExperimentalEnemySpawnMultiplier=false` is a second
gate besides the value `EnemySpawnMultiplier=1`; thus, changing only the
intensity does not alter the MultiSlot under development.

The offline validator now pins the three configuration blocks, the separate
timer table and the 24 callers. `tools/find_member_accesses.py` also makes it
possible to enumerate decoded accesses to member offsets without loading the
executable.

The 24 callers form three ABI families, all with `RCX=owner`,
`RDX=descriptor` and `R8D=requested_count` at the common boundary:

- eleven simulation paths query the descriptor with `0x3BCB00` and deliver
  one or two integer parts of the request;
- eleven mirrored/serialized paths validate the read with `0x3BE480` and,
  when necessary, materialize the descriptor with `0x405A40` before the call;
- the two special paths `0x243CAD` and `0x245F8F` sum three parts and
  first apply a local limit of 50; the common limit of 400 is still
  applied afterwards.

On the mirrored paths, a helper failure skips the spawn. On the special ones, a
zero request also skips the call. The rest reach the boundary, which still
rejects a null source and a zero scaled result. No participant indexing
appeared in the assembly of `R8D`; the only proven `participant_count-1`
indexing in `GeneratorPoll` occurs after the call in the update flow and feeds
the timer.

### Reset by generation 0.6.37

The replay of the real 0.6.31 reports places the block after
`mission_result_apply(1)` and at the first `Sync_MissionResult(script, 0/0)`,
with `Exec_Begin=0` on host and clients. The current hook arms the recovery
inside that begin, before the repeated poll observed for up to 30 seconds.

A new phase in the same room now calls
`ResetMissionResultExecRecoveryState` under the exclusive lock. The operation
discards the previous queue, tick and generation and zeroes call/attempt/cancel
as a single generation state. The SelfTest injects a queue from generation 4,
forces the normal phase gap and requires generation 5 with all fields zeroed.
The analyzer accepts the new sanitized event
`mission_result_exec_recovery_generation_reset` only when
`stale_pending_discarded` and `queue_cleared` are true.

### Sequential native cancellation 0.6.36

The logical state of the recovery queue (`pending`, tick and generation) is now
cleared by a single routine called only under
`g_mission_result_exec_recovery_lock`. The runtime SelfTest enqueues the
recovery, calls the native wrapper before the grace period and requires a
single cancellation, one accepted original call, zero fallback attempts and the
three fields zeroed. It then confirms that the same sync cannot re-enqueue and
that a later poll does not duplicate `Exec_Begin`.

`analyze_player_controls.py` now models `Exec_Begin` and the recovery with named
records that preserve order and generation. The positive fixture requires
`queued -> cancelled -> Exec_Begin` with the argument preserved and no fallback;
the negative one contains a cancellation followed by two calls and `applied`,
and only passes in the suite when the analyzer rejects both duplications.

### Runtime SelfTest 0.6.35

The ABI wrapper now only resolves the return address and delegates to the same
`DispatchEnemySpawn` used by the SelfTest. With participant 5, confirmed
caller, request 10, multiplier 2, scale `0/4` and valid source, the fake
original function must receive 20 while observing numerator 4. On return, the
owner must contain zero again and the aggregates must record one call, one
repair and no failure.

`RestoreEnemySpawnScale` is tested separately with concurrent value 7. The CAS
expects 4, fails without writing and preserves 7, covering the rule that
prevents the mod from erasing native changes or those of another hook.

## Real five-player audit and telemetry 0.6.53

The five reports from 0.6.52 completed two stages without a crash and closed
the local ownership P0-P4 exactly once across the server and four clients. The
fan-out of each process contained four unique routes and the total destination
mask was always `0x1f` minus the local bit. 0.6.53 uses this local ownership as
a fallback only when there is a single bit; a missing owner no longer turns a
correct fan-out into a warning without accepting ambiguous cases.

The real receive vector is remote and preallocated: empty slots and the absence
of the local participant are normal. The audit now compares with
`participant_mask & ~local_mask`, separates empty from unresolved and does not
require `runtime_user_count == route_count`. The parser chain remains valid,
but its lifetime did not reach the dispatcher; per-participant incoming
attribution remains an open gate.

`ApplyResult 0x3E3160` calls `0x199D50` before deciding its auxiliary return.
In the ten real events the return was false, although Items `0x1f`, sync,
reward and return were complete. The counter and the analyzer now measure
`call_completed`; the native value is preserved only as semantic data. The
warnings of the first GeneratorPoll update and of result checkpoints that later
concluded were also reclassified.

Full evidence:
[`docs/technical-research/09-FIVE-PLAYER-LIVE-TEST-2026-08-31.md`](docs/technical-research/09-FIVE-PLAYER-LIVE-TEST-2026-08-31.md).
