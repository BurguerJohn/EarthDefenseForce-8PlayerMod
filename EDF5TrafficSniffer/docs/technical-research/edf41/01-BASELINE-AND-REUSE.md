# EDF 4.1 baseline and reuse matrix

## Pinned build

These measurements belong to the binary pair analyzed on 2026-09-02.

| Component | Bytes | SHA-256 | PE identity |
| --- | --- | --- | --- |
| EDF41.exe | 13,896,192 | `39B4ABF7FE722175741A5E0A154063B27EF8C589A1AA5F86C84853571AC7BDA8` | timestamp 0x57AAB039, image 0xD98000, entry 0x666B20 |
| steam_api64.dll | 204,880 | `E61F3A4C3833CE48629D48D655C124F0ED552198D5A6CF82EB2F431688C00D2A` | timestamp 0x5627DE8A, image 0x37000, entry 0x8624, file version 03.04.27.90 |

The installed winmm.dll was EDFModLoader 1.0.10, SHA-256
`B80E4DA6AE7264F0E9774C992DE3C5F9B6E9BC9422146ADEEB5BB2BD681E112E`.
The loader identifies EDF41 and calls EML4_Load.

version_guard.cpp checks all three PE properties of both modules before hooks.
Full hashes are recorded here; local BUILDINFO.json is excluded from the public tree.

## Observed Steam architecture

EDF 4.1 imports direct accessors rather than EDF5's SteamInternal_ContextInit.

| Imported accessor | EDF41 IAT RVA | DLL interface | .text xrefs |
| --- | --- | --- | --- |
| SteamMatchmaking | 0x918C38 | SteamMatchMaking009 | 47 |
| SteamNetworking | 0x918C40 | SteamNetworking005 | 9 |
| SteamFriends | 0x918C48 | SteamFriends015 | 11 |
| SteamUser | 0x918C90 | SteamUser018 | 45 |
| SteamAPI_Init | 0x918C80 | C export | 1 |

Version strings came from the installed Steam DLL. Virtual callsites verify:

- MatchMaking009: 38 slots; CreateLobby slot 13 at
  0x3BBB59 -> 0x3BBB6B, byte offset 0x68.
- Networking005: 22 slots; directly observed 0, 1, 2, 3, 4 and 6 cover
  send, availability, read and P2P sessions.
- Friends015: persona slot 7; invite slot 33 at
  0x4E1585 -> 0x4E159D, offset 0x108.
- User018: only slots 2/13/14/15/16 are locally verified.
  Ticket creation: 0x381FA5 -> 0x381FC5, offset 0x68.
  Cancellation: 0x381EE9 -> 0x381EFB, offset 0x80.
  BeginAuthSession: 0x3817C0 -> 0x3817DD, offset 0x70, with ticket/size/SteamID.
  EndAuthSession: 0x381F15 -> 0x381F24, offset 0x78.

## Reused components

| Component | Decision | Reason |
| --- | --- | --- |
| Logger, crash capture, JSONL | Shared | Game-independent with privacy/retention tests |
| MinHook/fail-closed lifecycle | Shared | Infrastructure without game addresses |
| Winsock capture | Shared | Export hooks, not game RVAs |
| Friends015, MatchMaking009, Networking005 wrappers | Shared | Exact versions and slots match |
| User slots 2/14/15 | Shared with version labels | Independently verified in User018/019; 13/16 remain User018-specific |
| Steam behavior policy | Shared dispatcher | Real EDF 4.1 traffic passes through; its optional room lab is separate from EDF5 Coop8 |
| Inventory/scanner methodology | Reused as a method | EDF5 output is not an EDF 4.1 expectation |

## Non-reusable components

Do not reuse EDF5 ContextInit/CSteamAPIContext/CreateInterface bootstrap, any
game-patch RVA/signature/object offset/size, EDF5 scanner known-candidate lists,
unverified User018 vtable slots, or participant/spawn/loadout/result protocols
without independent observation and EDF 4.1 callsite evidence.

The boundary is physical: shared legacy ABI in src/shared/steam_legacy,
EDF 4.1 bootstrap in src/games/edf41/sniffer, EDF5 patches in src/games/edf5/coop8.

From the project directory, repeat the baseline without launching the game:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\AuditEdf41.ps1
```

The audit rejects changed binaries, interfaces, IAT/xrefs, strong callsites or
negative portability results.
