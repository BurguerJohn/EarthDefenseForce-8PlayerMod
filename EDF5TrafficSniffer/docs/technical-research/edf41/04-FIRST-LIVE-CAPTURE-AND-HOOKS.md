# EDF 4.1 first live capture and derived hooks

## Capture

The first manual session used Diagnostics 0.6.55 on 2026-09-03. The host opened
the game and created/entered a room. Local session identifier:
20260903T185522.541Z_pid25500 under Mods/TrafficSniffer/logs.

The loader recognized EDF41, called EML4_Load and recorded normal unload.
Both PE guards matched, MinHook started, 24 Winsock hooks installed and the
sniffer reported usable=true. No crash, quarantine, write error or raw payload occurred.

status.json remained running after process exit. Normal loader unload and no
crash artifacts indicate incomplete asynchronous finalization, not proof of a
crash. Describe it as normal ModLoader unload with incomplete sniffer status
until an earlier shutdown boundary is available.

## Observations

The capture contains 62 events over approximately 47 seconds:

- RequestLobbyList and call-result 510 registration.
- One persona identity represented only by private tokens.
- Registrations for LobbyDataUpdate 505, LobbyChatUpdate 506,
  P2PSessionRequest 1202 and P2PSessionConnectFail 1203.
- CreateLobby type 2, requested/effective limit 4.
- LobbyCreated 513 associated with an async handle.
- LeaveLobby with a valid lobby identity.
- Only local socket closures; no P2P send/read, peer auth or remote member.

Limit four is proven at the Steam boundary. Missing P2P/member traffic is
consistent with a host-only room, but that interpretation initially needed a
host/client capture.

## Identified gap

Version 0.6.55 observed callback registration, not execution. It proved
LobbyCreated was requested but not its result, LobbyEnter or membership changes.
Local ticket creation/cancellation was also unobserved.

## Passive hooks introduced in 0.6.56

callback_dispatch.cpp uses CCallbackBase's three-entry vtable: two Run overloads
and GetCallbackSizeBytes, with no virtual destructor. Each registered object gets
a shadow table. Detours observe payloads and invoke the original exactly once;
unregister restores the original table by compare/exchange.

Typed decoding covers GameLobbyJoinRequested, LobbyInvite, LobbyEnter,
LobbyDataUpdate, LobbyChatUpdate, LobbyChatMsg, LobbyGameCreated, LobbyMatchList,
LobbyKicked, LobbyCreated, SteamAPICallCompleted, P2PSessionRequest,
P2PSessionConnectFail and observed stats callbacks.

Raw payload still requires F10 deep capture; Balanced retains structured fields.
Auth tickets are never copied into this telemetry: only handle, capacity,
written length and ticket_payload_logged=false.

| Interface | Slot | Strong callsite | Event |
| --- | --- | --- | --- |
| SteamFriends015 | 33 | 0x4E159D | Invite dialog |
| SteamUser018 | 13 | 0x381FC5 | Auth ticket creation |
| SteamUser018 | 16 | 0x381EFB | Auth ticket cancellation |

The harness delivers synthetic LobbyChatUpdate/LobbyCreated, checks decoding,
single passthrough and vtable restoration, and requires ticket creation/
cancellation and invite without secret bytes. EDF5 regression follows separately.

## ABI correction in 0.6.57

The first two 0.6.56 live sessions left the room browser refreshing indefinitely.
Persistent SteamAPICallCompleted 703 arrived in slot 0 using the wrong detour
signature, while call-result LobbyMatchList 510 arrived in slot 1 with the
opposite mismatch. Absurd io_failure/api_call values made the problem deterministic.

The actual EDF 4.1 Steam ABI orders Run(payload, io_failure, api_call) in slot 0,
Run(payload) in slot 1 and GetCallbackSizeBytes in slot 2. Version 0.6.57 fixed
shadow-table assignment and original-call selection. The fixture was corrected
to that real ordering so it could no longer conceal the same regression.

## Existing loader evidence

EDFModLoader 1.0.10 already hooks EDF 4.1's internal debug function at RVA 0x91790
to write game.log. Its Patcher provides chat/censor/FOV signatures, but those do
not prove roster capacity or network protocol and were not promoted to Coop8 hooks.

The local ModLoader.ini originally had GameLog=False. Enabling the existing
loader feature adds internal logging without duplicating its hook. Installed
410780, 411380 and DEFAULTPACKAGE directories contained SGO sidecars, not
reusable multiplayer code/hooks.

## Follow-up

The [four-player 0.6.57 session](05-FOUR-PLAYER-ONLINE-MISSION.md) linked
callbacks 504..507 to room methods and verified P2P/auth lifecycle.
The [room laboratory](06-ROOM-BOT-LAB.md) records subsequent P5 failures
and native roster/UI protections.
