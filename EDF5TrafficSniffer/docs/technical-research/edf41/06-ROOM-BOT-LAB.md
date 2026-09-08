# EDF 4.1 room-bot laboratory

## Scope and current state

Version 0.6.59 introduced local Coop8 fillers. Enumeration/callbacks alone did
not create visible rows: EDF 4.1 also requires each member's usr<SteamID> blob.
Version 0.6.60 projected the real host's data as a template. Version 0.6.61
exposed a fifth local member and crashed at a subordinate four-pointer table.
Version 0.6.62 quarantined overfill; 0.6.63 mapped and expanded net::Users, then
hit a second four-record vector in net::SessionController. The original 0.6.64
transaction expanded both through eight roster operands.

The current source additionally protects two UiOnlineRoom sites. Total
patched_sites is 10, room_ui_member_windows is 4, and room_ui_overflow_mode is
headless. Extra roster members do not gain visible member windows. The current
offline integration verifies all these fields. This is not full eight-player support.

Diagnostics configuration ExperimentalRoomOverfill=true requests eight.
A mismatched required signature rejects installation and retains the four-member
fallback. Real Steam lobby capacity remains four; expanded missions are unsupported.

## Controls and invariants

F8 queues one filler in a locally created room; F7 removes the latest.
SteamAPI_RunCallbacks consumes actions on the game's callback thread; the hotkey
thread does not modify native game state. Other hosts' rooms are observation-only.

NativeSafeLimit is parser-clamped to at most four. ExperimentalRoomLimit is 5..8
but exceeds four only after the full native transaction validates.
Read real membership directly from original Steam methods before adding.
Real+synthetic never exceeds the effective limit; newest fillers yield to real
players; synthetic enumeration follows real members.

Eight coherent roster operands cover two net::Users counts and six
SessionController reserve/allocation/copy/capacity/size values. Two additional
UI sites protect the four native member-window references. Validate complete
instructions and apply/restore all required sites transactionally.
Synthetic identities remain private laboratory identities.
mission_launch_supported=false explicitly excludes expanded missions.

## Implemented flow

Successful LobbyCreated marks the room owned. F8 first reads the host's
usr<host SteamID> blob from the original API. Without it, reject the request
without a ghost member. With it, add EDF41 Bot N, increase only the local
GetNumLobbyMembers view, enumerate its identity and answer the exact
GetLobbyMemberData(bot, usr<bot SteamID>) query with a template copy.

Synthetic LobbyChatUpdate uses the verified 32-byte layout and original simple
Run(payload) slot, delivered only to persistent callbacks with the exact size.

Channel-2 ticket sends to an active filler are consumed locally, echoed without
Steam transport, accepted by synthetic BeginAuthSession and followed by a
20-byte ValidateAuthTicketResponse with response zero.
Channel-0 gameplay sends to fillers are consumed without replies. Fillers do not
produce Ready, AI or mission actors.

## Offline coverage

The fixture verifies CreateLobby(4) reaches original Steam unchanged; host plus
seven fillers reaches eight and the ninth is rejected; names, enumeration,
strict usr<SteamID> projection and entry callbacks work; ticket bytes never
reach real Steam; auth/validation is limited to active fillers; a second real
member evicts the newest filler before exceeding eight; and F7 delivers exit.

The native transaction fixture also checks allocation, restoration, corrupted
signatures and the current two UI protections. Offline success does not prove
live room behavior or mission capacity.

## Live 0.6.59: invisible members

Session 20260903T203126.385Z_pid21632 processed F7/F8, created/removed fillers
and delivered LobbyChatUpdate without a crash. Keyboard, focus, queue and
callback ABI were therefore not the cause.

EDF 4.1 made 855 null GetLobbyMemberData requests for usr<bot SteamID>, with no
visible row. That isolated the missing template dependency addressed in 0.6.60.
member_template_resolved logs only blob size, not its private contents.

## Live 0.6.60: native four-member display

Session 20260903T204606.634Z_pid540 visibly showed host and three fillers.
Repeated add/remove/recreate cycles delivered callbacks without hook failure or
crash. Requests above four were deliberately rejected by the configured limit,
not lost by a new visual bug.

## Live 0.6.61: first P5 crash

Session 20260903T210540.837Z_pid13420 preserved the crash at
crashes/crash-20260903T210610.601.json and a minidump. bot_added number 4 reported
one real plus four synthetic members, total five, then delivered LobbyChatUpdate.
Materialization raised read AV 0xC0000005 at EDF41.exe+0x3BE316.

Function 0x3BDF60..0x3BE475 received RDI=4:

- 0x3BE129 compares the free index with owner+0xE0 capacity.
- 0x3BE140 reads the pointer table at owner+0xD0.
- 0x3BE2F0..0x3BE2F7 computes table + index*8.
- 0x3BE301 reads the old slot pointer.
- 0x3BE316 performs lock xadd dword ptr [rcx+4], -1 on an invalid pointer.
- 0x3BE347 increments owner+0xE8 after replacement.

Direct callers are 0x3B6114 (callback path) and 0x3B9BC6 (full ingestion).
The Steam loop is dynamic, but this consumer searches four slots and indexes 4
without growing storage. The apparent freeze preceded the invalid atomic access.

## 0.6.62 quarantine

While kNativeRosterExpansionReady=false, effective capacity stayed four and
ExperimentalRoomOverfill defaulted false. Even manual opt-in rejected the fourth
filler with reason="native roster capacity not expanded", without a P5 callback.

The next requirement was to map construction/destruction, allocate/zero with
the proper allocator and restore during teardown. Version 0.6.63 addressed that
list boundary; Ready and missions remained separate.

## 0.6.63 net::Users mapping

The dump's owner vtable 0xAA50E0 resolves through MSVC RTTI to .?AVUsers@net@@.
Constructor 0x3AA4E0..0x3AA62C:

- 0x3AA5AA selects the embedded container at net::Users+0xC8.
- 0x3AA5C2 loads capacity 4; 0x3AA5CD calls eight-byte allocation grow 0x1206A0.
- 0x3AA5D6 loads size 4; 0x3AA5E1 calls null initialization 0x120AE0.
- Destructor call 0x3AA6EA -> 0x1207C0 traverses dynamic size, releases references/
  allocation and zeros all three metadata fields. Teardown has no extra four clamp.

Version 0.6.63 changed the two lea edx,[rsi+4] operands to eight after checking
two 16-byte signature regions, including subsequent calls. Writable protection,
cache flush, post-write checks and rollback covered both sites. Unload restored
only known replacements. This was Diagnostics-only on the pinned executable.
Its harness simulated expansion/restoration, rejected corruption and enumerated eight.

## Live 0.6.63: second fixed vector

Session 20260904T023856.559Z_pid4268 confirmed signature_matched=true and
patched_sites=2, with stable host+three fillers. Adding the fourth produced five,
delivered the callback and passed 0x3BE316, then read-access-violated at
EDF41.exe+0xCB070/address 0x5.

Shared-pointer copy helper 0xCB060 was called at 0x39611E inside 0x3960D0,
which reads [entry+4], multiplies by 16 and adds SessionController+0xD0.
P5 index 4 selected a slot beginning with 0x1; mov eax,[rcx+4] then faulted.
Preserved chain: 0x395C12 -> 0x3960D0 -> 0xCB060.

Owner vtable 0xAA5448 resolves to net::SessionControllerImpl. Allocation,
capacity and logical size were at +0xD0/+0xD8/+0xE0 with both counts four
and 16-byte records, matching 0x396104.

## Original 0.6.64 combined roster patch

SessionControllerImpl factory calls base constructor 0x394940 at 0x3BA138;
base vtable 0xAA4720 resolves to net::SessionController. Its +0xC8 container uses:

| Site | Native behavior |
| --- | --- |
| 0x394B58 | Compare capacity with four |
| 0x394B70 | Pass logical size four to 0x3995B0 |
| 0x398F26 | Specialized reserve capacity comparison |
| 0x398F42 | Allocate 16 + 0x30 = 64 bytes |
| 0x398F5C | Bound old-record copy to four |
| 0x398FEA | Store capacity four |

Teardown call 0x394C8E -> 0x399010 follows dynamic metadata.
At capacity eight, allocation becomes 16 + 0x70 = 128 bytes.
These six sites and the two net::Users sites formed the original eight-site
transaction: all original instructions must match before writing; every
replacement must verify; failure restores the whole set.

AuditEdf41.ps1 pins RTTI, constructors, callers, helpers, faulting lookup and
teardown. The original suite at test-output/diagnostics-20260904T030725Z passed
on that historical DLL.

## Current room-UI boundary

UiOnlineRoom::refresh_members stores four weak references to
UiOnlineRoom_MemberWindow at owner+0x240..+0x258. Index four reaches an unrelated
xgs::ui::Object at +0x260; index five reads non-pointer layout state.
The original function locks and dynamic-casts these references without an
expanded-row allocation.

Current native_roster_patch.cpp protects weak-lock call 0x4C5C04 (native target
0xB29D0) and branch 0x4C5CCC, keeping overflow members headless.
It records room_ui_sites=2, room_ui_member_windows=4,
room_ui_overflow_mode=headless and patched_sites=10.
These protections do not create extra native windows or establish Ready,
mission, spawn, gameplay replication or result support above four.
