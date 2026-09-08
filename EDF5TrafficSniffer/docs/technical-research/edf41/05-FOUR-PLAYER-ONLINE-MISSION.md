# EDF 4.1 first four-player online mission

## Capture

Session 20260903T193300.685Z_pid30564 used EDF41_MultiSlotMod 0.6.57,
Diagnostics/Balanced, for 406 seconds with 344 gap-free numbered events.
A client joined an existing room with three remote peers. No warning, error,
P2P failure, raw payload or crash occurred.

ModLoader recorded normal unload while sniffer status remained running.
The incomplete sidecar must not be interpreted as a crash. Real SteamIDs/names
are omitted here; internal game.log contains plaintext names/chat and must be
sanitized before publication.

## Room-browser hotfix

RequestLobbyList returned a valid async handle. SteamAPICallCompleted arrived as
a simple callback; LobbyMatchList arrived as a call-result with io_failure=false,
the same handle and eight rooms. JoinLobby completed with LobbyEnter response 1
and an unlocked room. After leaving, another search completed with seven rooms.

This live test validates the 0.6.57 CCallbackBase ordering correction and resolves
0.6.56's endless-refresh regression.

## Three-peer authentication

The client issued three 234-byte tickets, handles 2..4, one per peer. Incoming
tickets were 234, 240 and 270 bytes; BeginAuthSession returned 0 for each.
Exit cancelled all three tickets and ended all three sessions.

Callback 143 had exactly 20 bytes. Three callback objects each received three
deliveries, totaling nine. ValidateAuthTicketResponse_t uses four-byte alignment:

| Offset | Bytes | Field |
| --- | --- | --- |
| 0x00 | 8 | Validated SteamID |
| 0x08 | 4 | EAuthSessionResponse |
| 0x0C | 8 | Ticket-owner SteamID |

Version 0.6.58 decodes these fields without logging ticket bytes.

## P2P channels and callsites

All real packets passed through SteamNetworking005 without failures.

| Channel | Direction | Packets | Bytes | Observed use |
| --- | --- | --- | --- | --- |
| 0 | Outgoing | 6,712 | 517,541 | Room control and continuous gameplay |
| 0 | Incoming | 8,065 | 1,720,078 | Control, snapshots and gameplay |
| 1 | Incoming | 11 | 4,246 | Pre-mission burst |
| 2 | Outgoing | 3 | 702 | Three local 234-byte tickets |
| 2 | Incoming | 3 | 744 | Remote tickets: 234/240/270 bytes |

Channel 0 was bidirectional with all three peers. Channel 1 came from one peer
in a 19..713-byte burst and did not recur during gameplay. Authoritative/preparation
data from a special peer, likely the host, is an inference, not a proven role.

| Return RVA | Operation |
| --- | --- |
| 0x3815D7 | Read channels 0, 1 and 2 |
| 0x381DAC | Normal channel-0 send |
| 0x382003 | Channel-2 ticket send |

Static follow-up identifies:

- 0x381510: receive polling/routing, local 0x800 buffer, channel iteration.
- 0x381D40: channel-0 send wrapper, caller 0x3B566F.
- 0x381DE0: similar channel/type-1 wrapper, caller 0x3B57AA; not observed
  outgoing in this session.
- 0x381F80: ticket creation in a 0x400 buffer and channel-2 send,
  direct caller 0x381CA5.
- 0x381E90: peer ticket/auth shutdown, callers 0x380D04, 0x38149B and 0x381BCA.

These remain documented candidates, not additional detours: Steam interface
hooks already observe the same boundaries with a verified ABI.

## Internal game.log evidence

The existing loader hook revealed room preparation exit code 0, exactly four
PlayerIndex lines P0-P3, four synchronized player objects with consecutive IDs
after map loading, synchronized enemy/NPC/vehicle creation/removal, MissionScript
events and clean auth/P2P shutdown followed by room-browser return.

Coop8 must therefore separately map room participants, mission player objects
and synchronized-object distribution. Raising Steam lobby capacity alone does
not create four additional actors.

## Next captures

Capture a host with three clients to determine channel-1 sender and initial
object-table ownership; use a short bounded deep capture from Ready through
early mission to classify channel-0/1 headers; complete a natural mission to
map EDF 4.1 results, rewards and room return. Sanitize shared evidence.
