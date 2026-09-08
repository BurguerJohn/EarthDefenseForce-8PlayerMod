# Steam lobby networking and replication

## Steam interfaces used by EDF5

Relevant slots in the context returned by SteamInternal_ContextInit:

| Slot | Interface |
| --- | --- |
| 1 | ISteamUser |
| 2 | ISteamFriends |
| 4 | ISteamMatchmaking |
| 8 | ISteamNetworking |
| 11 | ISteamHTTP |

Wrappers copy the expected version's full vtable, replace only required methods,
and forward the rest without changing arguments or returns. Confirmed versions:

- SteamUser019: GetSteamID slot 2, BeginAuthSession 14, EndAuthSession 15.
- SteamFriends015: persona slot 7, invite dialog 33.
- SteamMatchmaking009: 38 slots; CreateLobby 13, Join 14, Leave 15,
  members 17/18, data 19..25, chat 26/27 and member limit 31.
- SteamNetworking005: 22 slots.
- SteamHTTP002: 25 slots.

MorePlayers requires SteamInternal_ContextInit, SteamAPI_Shutdown,
SteamAPI_RunCallbacks, SteamAPI_RegisterCallback and SteamAPI_UnregisterCallback.
Missing/inconsistent hooks quarantine the plugin; Winsock cannot substitute.

## Lobby ownership and capacity

After CreateLobby, the first public_slot write identifies the host's owned lobby.
Only a confirmed owned lobby can have its capacity rewritten.

- Creation/member-limit arguments use max(requested value, MaxPlayers).
- public_slot/open_public add MaxPlayers - 4, clamped to 0..MaxPlayers.
- Other or unconfirmed lobbies pass through unchanged.
- Join/Leave clear relevant synthetic state to prevent identities crossing rooms.

## Fillers and Local Mission Harness

Reported count is min(MaxPlayers, real members + fillers). New real players evict
fillers from the end. The local harness disarms whenever real count differs from
one, preventing laboratory state from mixing with real multiplayer.

Synthetic identities preserve the host SteamID's upper 32 bits and, where
possible, use descending lower account IDs. This preserves a recognizable format
without copying the host identity. Normal filler names are EDF Bot N; harness
names are Harness Dummy N. These are local test identities, not real accounts.

## Synthetic callbacks

Known callbacks include LobbyChatUpdate_t (506, 32 bytes) and
ValidateAuthTicketResponse_t (143, 24 bytes). Dispatch invokes slot zero of the
registered callback vtable.

Synthetic BeginAuthSession returns success (0) and queues validation response 0.
Synthetic EndAuthSession does not reach Steam. Synthetic P2P state appears active
with loopback 127.0.0.1. Real identities/tickets retain native Steam behavior.

## Synthetic P2P channels

Channel 2 provides a handshake response, accepting packets up to 1 MiB:

1. Read the local SteamID at offset 12.
2. Replace occurrences with the filler identity.
3. If the advertised limit at offset 60 is exactly four, replace it with MaxPlayers.
4. Queue the copy on the same channel.

The queue holds at most 128 packets. An undersized read buffer does not consume
the packet: report required size so the caller can retry.

Channel 0 contact triggers observation and mirroring of l1/l2 from a real equipped
source. It never fabricates gameplay packets. Only the structurally understood
handshake is cloned; opaque gameplay is not invented.

## Ready and logical properties

Synthetic UserImpl receives cm=c1, ds=ds and l1/l2 copied from the real mission
source through native property setters. Transport must be ready and the source
valid. A newly equipped filler must not become its own source.

## Game replication

### Outgoing

Producer `0x45EAD0` calls serializer `0x432D20` at `0x45EB9B`.
Target builder `0x45ED80` uses vector layout `0x45EDB8`, append `0x45EE26`
and route copy `0x45EE3F`. Resolver `0x433F40` reads the index at `0x433F6E`.

Target descriptors are eight bytes: opaque key UserImpl+0xC4 and route index
UserImpl+0xC8. The former 16-byte SharedProperty interpretation was wrong.

Sending passes through `0x453890`; target/dispatch are `0x41ABE0/0x41A770`.
The special path uses vtable `0xEC2038`, target `0x4335A0` and enqueue `0x434CD0`.

### Incoming ownership

Pump `0x4336F0` traverses the table from `0x4337A3`, calling parser
`0x435670` at `0x4339DC`. Construction proves:

```text
parser + 0x498 -> route object
route  + 0x058 -> user control
control+ 0x008 -> UserImpl
```

Route constructor `0x435DA0` copies control at `0x435E37`; parser constructor
`0x4351F0` stores its owner at `0x4352F0`. The route holds its parser at
route+0x88. The old parser-0x88 calculation is incorrect and must not return.

Route lifecycle:

- Register `0x433BD0`, read `0x433C78`.
- Unregister `0x433DD0`, removal read `0x433E3C`.
- Call/return pairs `0x451B64/0x451B69` and `0x451AF6/0x451AFB`.
- Slot allocator `0x45C8E3`, UserImpl constructor call `0x45C948`.

Manager lock/vector/capacity/count are +0x80/+0xD0/+0xD8/+0xE0 with stride
0x10. The table is dynamic; no four-player limit was found in parser/serializer.
Observed logical families are 0x3300 and 0x3400.

Five-player live evidence proved this table represents remote routes and may
contain empty preallocated slots. The local participant must not appear.
Completeness is `total_mask & ~local_mask`; resolved users need not equal
physical vector count/capacity.

The ownership chain is statically correct, but the 0.6.52 parser TLS scope ended
before logical dispatch. Fan-out and transport are verified; per-message incoming
attribution remains pending a boundary with safe lifetime.

## Identity invariants

- One distinct UserImpl per active participant.
- +0xC8 is transport route, +0x190 local control, +0xF8 logical mission/loadout.
- Fan-out contains exactly expected remotes.
- P0/P4 collision, missing host or out-of-range route is a failure, not a reason
  for silent remapping.
- Sanitized reports exclude SteamIDs, opaque route keys, endpoints and payloads.

## Chat UI

The banner/help are local system messages, once per room:

```text
*** EDF5_MultiSlotMod v0.6.64 ***
If you have 4 players in the room,
press F4 to invite more.
```

Each line is at most 34 characters. The path uses constructor `0x3F0680`,
vtable `0xEBEDA8`, assignment `0x3F06B8` and system publisher `0x3F09D0`
(kind=1). Normal publishing is `0x3F0B70`. Displaying these messages does not
send Steam chat, inspect other messages or require captured identity.

## Canonical sources

[Participant state](../../src/games/edf5/coop8/more_players.cpp),
[Steam bootstrap](../../src/games/edf5/sniffer/steam_hooks.cpp),
[matchmaking](../../src/shared/steam_legacy/steam_matchmaking.cpp),
[networking](../../src/shared/steam_legacy/steam_networking.cpp),
[authentication](../../src/shared/steam_legacy/steam_user_auth.cpp),
[friends](../../src/shared/steam_legacy/steam_friends.cpp),
[HTTP](../../src/games/edf5/sniffer/steam_http.cpp),
[shared ABI](../../src/shared/steam_legacy/steam_legacy_interfaces.h) and
[EDF5 interface composition](../../src/games/edf5/sniffer/steam_interfaces.h).
