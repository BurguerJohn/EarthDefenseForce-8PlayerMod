# EDF5_MultiSlotMod

Experimental x64 EDFModLoader plugin for expanded EARTH DEFENSE FORCE 5
multiplayer. The public [repository README](../README.md) covers dependency
setup, compilation, installation and publishing.

EDF5 Coop8 and its diagnostics are the main implementation. EDF 4.1 has a
build-guarded passive sniffer and a Diagnostics-only room laboratory. Its
experimental transaction expands the local `net::Users` and
`net::SessionController` room lists, but Ready, missions, spawn and results
above four remain unsupported. EDF6 entry points are disabled scaffolds.

## Documentation

- [Code structure and invariants](CODE_STRUCTURE.md)
- [Reverse-engineering notebook](docs/technical-research/README.md)
- [EDF 4.1 research](docs/technical-research/edf41/README.md)
- [Participant flow audit](PLAYER_FLOW_AUDIT.md)
- [Experimental reserve inventory](EXPERIMENTAL_SLOT_PATCHES.md)
- [Cooperative research roadmap](COOP_REVERSE_ROADMAP.md)
- [Manual testing instructions](TESTING.txt)

Historical notes record the build under test, including failed hypotheses.
Later evidence supersedes earlier interpretations. In particular,
`UserImpl+0xF8` is a logical participant/loadout index, not the chosen class;
receive ownership is `parser -> route -> control -> UserImpl`, not
`parser-0x88`; and the chat publisher's fourth argument is message text,
not a nickname.

## Build flavors

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\build.ps1 -Configuration Release -Flavor Users
powershell -NoProfile -ExecutionPolicy Bypass -File .\build.ps1 -Configuration Release -Flavor Diagnostics
```

Users output is `build/users/EDF5_MultiSlotMod.dll`; Diagnostics (the default)
outputs `build/EDF5_MultiSlotMod.dll`. Both receive a sidecar
`EDF5_MultiSlotMod.ini`.

Users excludes the logger, event files, payload capture, crash handler,
snapshots, flow watchdog, /GS hook and Winsock capture at compile time.
No INI switch can add those features back. Diagnostics includes research
instrumentation and offline harnesses.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\VerifyBuildFlavors.ps1
```

This builds and audits both flavors without starting the game.

## EDF5 behavior

### Lobby and native storage

`CreateLobby` and `SetLobbyMemberLimit` use `MaxPlayers`, default 8 and
limited to 5..8. Public slot announcements preserve the chosen public/private
split. The three proven roster containers and room information boxes reserve
`PreallocatedRosterSlots` entries; all 22 operands are validated together.

The native four-entry UI key array is replaced by direct `Button_Master`
selection for index zero and `Button_Member` for every other index. Room
information boxes are `0x50`-byte constructed records, with pointer,
capacity and size at `object+0x150/+0x158/+0x160`; all three remain consistent.

An independent `ExperimentalReservePatches` switch controls 24 unidentified
but coherent `capacity < 4` / `reserve(4)` groups (48 operands). These are
not proven player rosters. The [inventory](EXPERIMENTAL_SLOT_PATCHES.md) explains
why eleven ambiguous anchors and six non-roster anchors remain unchanged.

### Participant creation and identity

The temporary pre-mission participant vector uses external storage for eight
`int32` entries at two exact calls, preserving stack layout and unwind data.
P4-P7 reuse the four native spawn points by modulo four.

Persistent mission records retain the original four `0x18`-byte entries and
use four zeroed sidecars for P4-P7. Primary creation, existing-record transfer
and append loops all redirect the final out-of-range addresses. The stack-local
vector still constructs and destroys four entries. Relay counters are atomic;
logging is deferred outside the critical assembly path.

The final post-sort `UserImpl` table determines participant identity. P0-P3
remain untouched; extra local-control ownership is reconstructed from the
local-user subset. The pre-sort collection order is not a valid replacement
for the final table.

Four native loadout blocks have stride `0x3E90`. For an extra player, a
temporary native block receives the actual class, six equipment IDs and armor
from `PlayerInfo` or a parser sidecar. Its bytes and the participant's unique
index are restored immediately after the class consumer, before runtime-map
consumers execute. P4 must never persist as P0.

The parser can write P4 into `state+0x24570`, overlapping reward/result state.
Extra blocks are snapshotted and restored; valid participant count at
`+0x245A0` is retained independently of the parser's boolean return. A
separate failure output and bounded count determine validity. P4/class 1 has
one overlapping weapon field: valid mask `0x2F` preserves five weapons and
fallback mask `0x10` retains the safe borrowed value for the sixth.

Only transient visual outputs reuse `index % 4`; logical identity remains
P4-P7. HUD class selection is bounded to 0..3, preferring actual `PlayerInfo`,
then the parser sidecar, valid native class and finally a visual fallback.

### Results and rewards

`MissionSync_Res` and the result decoder's online-player filter follow
`MaxPlayers`. The native four result Item accumulators do not expand:
P4-P7 fold field-by-field into `index % 4`, ending before the independent
local reward-profile count at `state+0x2459C`.

That reward count represents 1..2 local save profiles, not online players.
Before rewards, a defensive repair can restore an invalid count from the
verified local-user collection. Logs record counts and success, not rewards.

The pipeline has independent `Exec_Begin`, sync, `ResolveResult`,
`ApplyResult`, `Update`, `Finally` and room-return checkpoints.
An auxiliary false return from `ApplyResult` does not mean reward failure.
A room return requires a native room UI update after result application.

If a real session above four players reaches script sync `0/0` without
`Exec_Begin`, recovery waits 1000 ms for the native path. It then schedules
one verified `Exec_Begin(-20000)` on the Mission thread. A native call during
the wait cancels recovery. Pending/tick/generation move atomically under one
SRW lock, and a new mission discards stale state. This recovery is disabled
inside the Local Mission Harness.

### Native scaling and optional spawn experiments

Exactly 56 proven native profile reads clamp participant counts above four to
the existing four-player profile while preserving the stored logical count.
The getter, roster, network and results still see 5..8. The self-test executes
all 56 generated relays at counts 3, 5 and 8 and checks registers, arithmetic
flags, masks and storage preservation.

The common enemy boundary has 24 verified callers and a native limit of 400
live actors. A bounded temporary zero-scale repair is restored with compare/
exchange so a concurrent mutation is not overwritten. The GeneratorPoll
participant timer and spawn scale have separate sources; telemetry must not
conflate them.

Artificial multiplication remains disabled by
`ExperimentalEnemySpawnMultiplier=false` and `EnemySpawnMultiplier=1`.
The explicit opt-in is required even if the numeric multiplier changes.

## Room controls

The local room chat displays this once after create/join:

```text
*** EDF5_MultiSlotMod v0.6.66 ***
If you have 4 players in the room,
press F4 to invite more.
```

Each line is at most 34 characters. The native local system-message publisher
does not send the banner through Steam chat or require a player identity.

| Control | Action |
| --- | --- |
| F4 | Open Steam's invite dialog for the locally created room |
| Mouse wheel | Scroll the room list anywhere in the room window; the game still receives the wheel for its own menus |
| F8 | Add one synthetic filler up to the effective room limit |
| F7 | Remove the newest filler |
| F6 | Reapply EDF5 filler Ready properties |
| F3 | Cycle host-only mission harness: host+3, host+4 ... host+7, Off |
| F5 | Request mission-clear result during an active stage, when debug mode is enabled |
| (automatic) | Measures damage per player per mission in the diagnostic log (`DamageMeterEnabled`); room chat summary only with `DamageMeterChat=true` (under validation) |
| (automatic) | With 5-8 players enemy HP keeps scaling past the four-player table (`ExtendedEnemyHealthScaling`, `EnemyHealth5Players`..`EnemyHealth8Players`) |
| F9 | Diagnostics live snapshot/minidump |
| F10 | Toggle bounded deep capture in Diagnostics |

Hotkeys trigger on press edges; holding them does not repeat the action.
F3/F8/F7/F6/F4 require a locally created room. F3 additionally requires the room
screen, exactly one real player and no F8 fillers.

### Synthetic fillers

Fillers have private synthetic IDs, distinct names, membership data, callbacks,
P2P queues and synthetic authentication. Real tickets, identities and traffic
continue through Steam without synthetic acceptance. A real player needing a
slot evicts the newest filler.

Filler transport state is updated at `UserImpl+0xC0` under the native lock;
Ready uses `cm="c1"` and `ds="ds"` in the native property map at `+0xF0`.
`+0x100` controls the voice indicator and must not be used for Ready.
The host's actual `l1/l2` mission list is mirrored without fabricating gameplay
packets. With one real equipped player, fillers copy class, equipment and armor
while retaining their own name, voice and state.

Fillers are visible only in the host's virtualized local view; they are not
members registered in Steam's lobby backend and have no AI or combat commands.

### Local Mission Harness

Start with host+3 as the native four-player baseline, then return to the room
and select host+4 to probe P4. Each further F3 adds one dummy (host+5, host+6,
host+7) to probe P5-P7, i.e. six to eight mission participants; the cycle
returns to Off after host+7 or as soon as the next roster would exceed
`MaxPlayers`. Each dummy has a distinct native `UserImpl`, a `Harness Dummy N`
name and copied host loadout.

The host-only gate requires exact target counts, complete Ready/l1/l2/contact
masks, zero real gameplay peers and the pinned global object. Native state 0
initializes normally. Only states 1..5 temporarily change
`controller+0x1AC` from 0 to 1 during the controller call, then restore it.
The final 4->5 transition is allowed only after all prerequisites are met.
Only verified local `Sync_MissionResult` callers receive completed `{1,0}`.

A real player joining disables the harness and frees its slots. It tests local
creation, loadout, HUD, spawn and shutdown, not remote P2P, motion, cross-machine
names/chat or desynchronization.

### F5 debug completion

F5 queues the native clear result 1 and consumes the request inside the game's
`Mission()` callback. It does not call `Request_MissionExit()` or grant
rewards manually. Normal resolve/apply/ResultSync code remains responsible.
The action is rejected outside an active stage, during its initial interval,
after an already consumed request or on a signature mismatch. Use the host for
multiplayer debug tests; synchronized behavior still needs separate validation.

## Diagnostics and privacy

Diagnostics are independent of raw capture. Balanced records room/mission
transitions, members, Ready, composition, patch failures, first gameplay contact,
hook state, P2P summaries and verified participant/result/scaling boundaries.
Repeated low-level activity is aggregated.

Each session under `Mods/TrafficSniffer/logs` contains:

- `session.json`: version, effective configuration and module hashes.
- `events.jsonl`: schema-2 events with sequence, UTC and monotonic time.
- `health.json`: queue peak, drops, write errors and flow.
- `status.json`: running, clean or crashed.
- `crashes/`: exception context, breadcrumbs and available minidumps.
  `first-chance-emergency.json` preserves the last serious VEH context even
  when the top-level filter does not run.
- `snapshots/`: state and optional minidumps requested with F9.

Event/payload files rotate at `RotateMiB`. Bounded queues drop noncritical
events first, account for losses and reserve warning/error capacity. Automatic
retention deletes only clean sessions.

Essential retains warnings/errors; Balanced is the default; Maximum includes
trace. F10 deep payload capture stops permanently for the session at
`DeepSessionMiB`, with each payload limited by `MaxPayloadBytes`.
Dump mode is Off, Mini (default) or Full.

Crash handling attempts to save evidence, then chains to prior handlers and
normal termination. The verified `__report_gsfailure` failure path preserves
evidence before the original fast-fail; successful /GS checks have no extra work.
Forced termination or other fast-fails can still prevent dumps. Reports may
include sanitized Windows crash events when available.

Raw captures and minidumps can contain SteamIDs, endpoints, names, URLs, tickets,
absolute addresses and process memory. A packaged Diagnostics build provides:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File Mods\TrafficSniffer\CreateDebugReport.ps1 -Session Mods\TrafficSniffer\logs\<session>
```

The report generator replaces identities/topology with stable aliases, removes
absolute addresses and excludes dumps and payload binaries. Module-relative
RVAs remain useful for research. Review the ZIP before sharing. The local dump
analyzer's `--safe` mode emits exception code and module/RVA without registers,
memory or paths.

## Offline validation and manual evidence

Standalone validation covers synthetic room capacity, unique identities,
callbacks, P2P/auth passthrough, hotkey edges, Ready/loadout, mouse scrolling,
the MSVC hidden return-buffer ABI, mission sidecars, generated relays, native
return values, transactional rollback and diagnostic privacy/retention.

From this project directory:

```powershell
& .\build\smoke_harness.exe .\build\EDF5_MultiSlotMod.dll
& .\build\mission_record_harness.exe .\tools\fixtures\mission-record-v046-append.json
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\RunDiagnosticsTests.ps1
```

Static tools read a local supported executable without running it:

```powershell
python tools\validate_roster_capacity_patch.py <EDF5.exe> --capacity 8 --preallocated-roster-slots 8
python tools\validate_spawn_result_layout.py <EDF5.exe>
build\slot_capacity_scanner.exe <EDF5.exe>
build\player_flow_scanner.exe <EDF5.exe> 0x<caller_rva>
python tools\disassemble_rva.py <EDF5.exe> --calls-to 0x<target_rva>
```

The slot scanner classifies 49 structural anchors: eight proven, 24 experimental
reserves, eleven deferred and six non-roster. Its historical fixture remains
`tools/fixtures/slot-capacity-scan-v049.json`.

The coordinated 0.6.52 five-player test completed two missions on all five
machines with distinct controls, four-remote fan-out, enemies, full result mask
`0x1F`, rewards and room returns. Sessions ended cleanly. Version 0.6.53 corrects
diagnostic semantics around auxiliary ApplyResult returns, empty preallocated
route slots and later-completed checkpoints. Per-message incoming attribution
and mission nickname/chat association remain research gates; six through eight
players require equivalent coordinated validation.

Use natural victories without F5 and identical packages on host and clients.
The detailed [research notebook](docs/technical-research/README.md) retains the
failure chains, exact signatures and remaining questions.
