# EDF 4.1 passive sniffer

## Implementation

EML4_Load selects EDF 4.1 and reads the sidecar INI. Diagnostics can install
the pinned executable/Steam guard, shared logging/crash handling, MinHook,
four direct Steam accessors, callback/call-result registration metadata,
per-object shadow vtables for both CCallbackBase::Run overloads, typed lobby/P2P
events, User018 ticket lifecycle, Friends015 invitations and shared Winsock hooks.

The sniffer itself does not use ContextInit or EDF5 layouts and does not patch
EDF41.exe memory. The separately enabled Coop8 laboratory has its own native
patches. A failed guard/required export leaves the profile loaded but quarantined.

## Sniffer-only configuration

```ini
[EDF41.Sniffer]
Enabled=true

[EDF41.Coop8]
Enabled=false

[Capture]
Steam=true
SteamCallbacks=true
Winsock=true
```

Capture.Enabled=false retains essential diagnostics but suppresses raw network
telemetry. Users contains no logger, crash handler, EDF 4.1 bootstrap/laboratory
or Winsock capture; the INI cannot reactivate excluded code.

Relative log paths resolve under the active game, default Mods/TrafficSniffer/logs.
Payload persistence requires Maximum/F10; shared reports use the sanitizer.

## Dedicated offline gate

tools/edf41_steam_harness.cpp loads fake Steam with four legacy interfaces and
checks direct accessors, four callback exports, both dispatch forms calling the
original exactly once, and original vtable restoration at unregister.

Friends015/MatchMaking009/Networking005/User018 forward real calls. CreateLobby(4)
remains 4, proving EDF5's eight-player policy does not leak. Invite, ticket
creation/cancellation, P2P send and auth begin/end pass through once. Logs must
contain fixture guard, bootstrap, callbacks, lobby and auth evidence.

The initial passive harness reported callback_dispatch=3. The current combined
room-lab harness exercises more callbacks (14) and additionally validates the
roster/UI transaction; use current suite expectations rather than the historical
callback total.

RunDiagnosticsTests.ps1 runs EDF 4.1 and EDF5 integration in separate processes,
requiring EDF 4.1 passthrough and EDF5 capacity rewriting through the same ABI layer.

## Manual evidence

The [first host-only capture](04-FIRST-LIVE-CAPTURE-AND-HOOKS.md) proved clean
CreateLobby(4). The later [four-player client mission](05-FOUR-PLAYER-ONLINE-MISSION.md)
validated remote callbacks, P2P/auth and shutdown after the 0.6.57 ABI correction.

Further sniffer-only tests should verify startup without quarantine, both
edf41_version.pe_identity records, LobbyCreated/LobbyEnter/member events,
member limits/data/counts, channels/sizes, leave and clean menu return.
Keep Coop8 disabled when measuring the native protocol. Document only sanitized evidence.
