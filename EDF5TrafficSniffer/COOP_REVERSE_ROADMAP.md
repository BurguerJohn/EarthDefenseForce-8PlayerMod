# Cooperative reverse-engineering roadmap

The guiding rule is to observe a native boundary before changing its behavior.
A patch requires a verified ABI, callers, ownership and invariants in the supported
executable and at least one real report.

## Verified map in 0.6.53

Gameplay replication has two halves:

1. Producer `0x4328C0` associates the message with its source `UserImpl`.
2. Serializer `0x432D20` receives a dynamic destination vector built at
   `0x45ED80`, using transport index `UserImpl+0xC8`.
3. Registration `0x433BD0` installs a route in the dynamic receive vector at
   `manager+0xD0`, with `0x10`-byte entries and count at `+0xE0`.
4. Each entry points to a `0xA8`-byte route object built at `0x435DA0`, not
   directly to a `UserImpl`.
5. The route retains the user's control block at `route+0x58`; the actual
   object is at `control+0x08`.
6. The parser built at `0x4351F0` retains the route at `parser+0x498`.
   Pump `0x4336F0` fetches `route+0x88` and calls parser `0x435670`.

The correct incoming ownership chain is:

`parser+0x498 -> route+0x58 -> control+0x08 -> UserImpl`.

The old `parser-0x88` calculation was wrong and has been removed. Exact
signatures and `player_flow_scanner` protect every link and the constructors'
only direct callers.

Real 0.6.52 reports proved the vector contains remote routes and preallocated
empty slots; the local participant must not appear. They also proved parser TLS
scope ends before dispatch. Structural ownership and the remote matrix are
verified, but per-message incoming attribution to P0-P7 remains unproven.

The end-of-mission pipeline is also delimited:

- `Exec_Begin`: `0x42FD20`, with two direct callers.
- `Update`: `0x430C20`, callers `0x42AC9F` and `0x12AA8D`.
- `Finally`: `0x42F090`, callers `0x42AC28` and `0x12AAA9`.
- `Sync_MissionResult`, `ResolveResult`, `ApplyResult` and room return have
  independent checkpoints.

`Update` returns `bool`, whose meaning depends on the caller. Preserve and
measure both outcomes rather than assuming either means success. `Finally`
remains `void`. Similarly, `ApplyResult` returns auxiliary state, not reward success.

## Instrumentation for the next test

| Event | Question answered |
| --- | --- |
| `user_transport_route_assignment` | Which `UserImpl+0xC8` index was assigned, in what order, and were there pre-mission collisions? |
| `replication_receive_route_lifecycle` | Did register/unregister use the native caller, resolve the intended user and share the allocator's manager? |
| `replication_receive_route_map` | Is there exactly one readable, unique route per remote participant? |
| `replication_participant_first_observed` | Outgoing is attributed locally; incoming remains pending because parser scope does not reach dispatch. |
| `replication_send_fanout` | Did each local producer send to one unique destination per remote participant? |
| `mission_result_exec_update` / `mission_result_exec_finally` | Where did post-victory shutdown stop, without changing the native decision? |

These events contain no payload, IP address, endpoint, SteamID, nickname, chat
text or pointer. Allocator/receive-manager equality is recorded only as a boolean.

## Decisions supported by reports

| Evidence | Next step |
| --- | --- |
| Duplicate transport indices before register | Isolate allocator `0x45C8E3`, prove its traversed layout, then fix slot selection. |
| Unique indices, but register stores/resolves another user | Fix ownership or index use in `0x433BD0/0x433DD0`. |
| Correct vector, unresolved incoming participant | Review parser ownership and route lifetime; leave the serializer unchanged. |
| Correct incoming attribution, fan-out omits P4 | Investigate builder `0x45ED80` or resolver `0x433F40`. |
| Complete replication, stationary characters | Follow `0x3300/0x3400` handlers into actor/control ownership and remaining four-entry tables. |
| Correct gameplay, stalled `Update/Finally` | Work only on the missing result-pipeline stage. |

The eight-byte loop at `0x45C8E3` and the 16-byte receive vector are not
necessarily the same object just because offsets resemble one another.
The constructor privately retains the index allocator's owner; lifecycle code
compares it to the real manager and emits only
`allocator_owner_matches_receive_manager`. That boolean determines whether the
apparent asymmetry warrants a patch or is a coincidence between classes.

## Next research boundaries

1. **Per-participant incoming traffic:** find a boundary inside parser lifetime,
   or safely carry its owner into dispatch without logging pointers or identities.
2. **Destruction/disconnect:** map route unregister, `UserImpl` destruction,
   actor removal, result closure and roster reconstruction after leave/peer loss.
3. **Runtime nicknames:** correlate private `PlayerInfo` tokens with sender/actor.
   Change behavior only when a report identifies the consumer aliasing P4 and P0.
4. **Remaining physical tables:** use contextual scanners from a real crash RVA
   or failed handler. A reserve of four is not automatically a player limit.
5. **Long-lived memory:** compare working set/private bytes at four and five
   players before attributing the isolated `RADAR_PRE_LEAK_64` event to the mod.
6. **Six through eight players:** repeat the five-player matrices sequentially.
   Solutions must use `MaxPlayers` or P4-P7 sidecars, not a separate P4-only path.

## Coordinated report gate

Collect host and client reports from the same DLL, then run:

```powershell
python tools\analyze_player_controls.py <reports> `
  --expected-players 5 `
  --require-transport-route-identity `
  --require-receive-route-lifecycle `
  --require-receive-route-matrix `
  --require-replication-send-fanout `
  --require-result-reward-chain `
  --require-result-room-return `
  --require-result-exec-pipeline `
  --strict
```

`--require-replication-association`, `--require-replication-matrix`,
`--require-name-identity` and `--require-chat-name-association` are separate
research gates. They must keep failing until incoming traffic or names are
actually observed; they are not part of the current success claim.

Use real players, a fixed host and natural victory without F5 or the Local
Mission Harness. The game is not part of the automated suite.
