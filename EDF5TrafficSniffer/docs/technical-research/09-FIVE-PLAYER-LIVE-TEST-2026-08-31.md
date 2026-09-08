# Five-player live test — 2026-08-31

## Findings

Build 0.6.52 completed the first coordinated end-to-end test with five real
players on every machine: distinct identities, one local actor per process,
crash-free entry/gameplay, enemies across two missions, synchronized results,
complete reward matrix 0x1F, room return, another mission/return and clean
shutdown without lost events or write errors.

The test found no functional defect requiring gameplay changes. It exposed
seven incorrect/incomplete telemetry interpretations. Version 0.6.53 corrects
those classifications and local-sender association without changing roster,
enemies, loadout, results or rewards.

## Analyzed material

Five sanitized reports remained in the local ignored Reports directory:

| Report | Local role | Events | Info | Warning | Error | Sequence |
| --- | --- | --- | --- | --- | --- | --- |
| server.zip | P0 | 1,974 | 1,958 | 16 | 0 | Complete, no gaps |
| client 01.zip | P1 | 1,885 | 1,874 | 11 | 0 | Complete, no gaps |
| client 2.zip | P2 | 1,827 | 1,814 | 13 | 0 | Complete, no gaps |
| client 3.zip | P3 | 1,840 | 1,826 | 14 | 0 | Complete, no gaps |
| client 4.zip | P4 | 1,941 | 1,930 | 11 | 0 | Complete, no gaps |

All identify EDF5_MultiSlotMod 0.6.52,
`edf5mp-0.6.52-startup-fail-closed-win64`, the same supported executable and
24 expected Winsock/Steam hooks. Final status/health were clean: zero
dropped_events, dropped_bytes or write_errors and drained queues.

## Identity, control and actor creation

Each process observed five distinct sources/participants, mask 0x1F and no
duplicate identity. Cross-report ownership closed exactly once per participant:

```text
server=P0  client01=P1  client2=P2  client3=P3  client4=P4
```

P0-P3 retained native flow. P4 had its own logical identity and used physical
fallbacks only where a four-entry boundary required them: sidecar-synthesized
loadout, invalid native class 256/257 corrected to class 1, and visual slot 0.
Logical index, UserImpl, control and transport index remained distinct.

The native parser overwrote 37..46 bytes of the temporary block and sometimes
changed local-profile count from 1 to -1. Bytewise rollback restored 1 and
captured the sidecar before subsequent consumers. This is live evidence of
actual overlapping-layout corruption being intercepted, not merely prevention.

## Replication and fan-out

Each process's four observed fan-out families had exactly four unique resolved
remote destinations:

| Local process | Destination mask | Excluded bit |
| --- | --- | --- |
| P0 | 0x1E | Local P0 |
| P1 | 0x1D | Local P1 |
| P2 | 0x1B | Local P2 |
| P3 | 0x17 | Local P3 |
| P4 | 0x0F | Local P4 |

Version 0.6.52 warned on all 20 events because the producer's SharedProperty
owner did not resolve the sender, so it incorrectly expected five destinations.
Version 0.6.53 falls back to the unique local-control assignment verified by
MissionPlayerCreate, still rejecting ambiguous masks with multiple local bits.

The receive vector is a preallocated remote-route table: empty slots and missing
local participant are normal. Version 0.6.53 expects total_mask & ~local_mask,
distinguishes empty from nonempty-unresolved slots, does not require
runtime_user_count == route_count, and separately records local, missing and
unexpected participants.

Per-message incoming attribution was not observed at dispatch because parser TLS
scope ended earlier. This is an observability gap, not evidence of transport
failure. A safe boundary is still needed to attribute individual messages to P0-P7.

## Enemies and native scaling

Thousands of confirmed common-boundary instantiations occurred across two
missions. Summaries showed logical participant_count=5, native difficulty clamp
to physical capacity 4, no missing sources, no failed scale restoration,
experimental multiplier off/effective 1, and GeneratorPoll eventually reaching
common spawn.

Each process's first GeneratorPoll Update skipped spawn, consistent with
cooldown/quota. Version 0.6.53 changes that initial event from Warning to Info;
later summaries remain decisive evidence.

## Results, rewards and second mission

Every process observed result 1, expected/observed Items 0x1F, P4 folded into
physical accumulator 0, completed sync, ResolveResult, ApplyResult and room return.

| Process | First clear to room return |
| --- | --- |
| P4 | 12.5 s |
| P1 | 14.3 s |
| P2 | 16.0 s |
| P3 | 17.5 s |
| P0/host | 73.7 s |

The host delay is consistent with manual time on the result screen; this is an
inference, not a measured explanation. There was no final stall: the room returned
and another mission started. The second transition, result 2, also returned on
every machine.

Each generation queued defensive Exec_Begin recovery, but the native path arrived
during its grace window. All ten queues were cancelled with native argument
200001; no synthetic fallback duplicated finalization.

### ApplyResult semantics

All ten mission_reward_apply events returned false despite completed checkpoints
and observed rewards. Disassembly at 0x3E3160 shows an unconditional call to worker
0x199D50 at 0x3E3175, a return byte initialized to zero and set only by an auxiliary
condition. That bool is not reward success.

Version 0.6.53 preserves it and records call_completed, native_result and
native_result_is_apply_success=false separately. Legacy reports remain accepted
because their event was emitted only after the original call returned. False
must not produce a warning or fail a reward gate.

## Reclassified warnings

The 65 warnings did not establish a functional error:

| Event | Count | Final interpretation |
| --- | --- | --- |
| flow_stalled | 2 | Lobby/matching wait before all players joined |
| generator_poll_update_path | 5 | Normal initial update without spawn |
| hotkey_rejected | 6 | Test key outside a valid room |
| mission_result_exec_recovery_queued | 10 | Fallback cancelled by native flow |
| mission_result_progress | 12 | Intermediate checkpoint followed by completion |
| mission_reward_apply | 10 | Auxiliary false return after completed call |
| replication_send_fanout | 20 | Correct four remotes; unresolved local sender |

The analyzer calls a result checkpoint a stall only if no later completion exists.
It requires nickname identity only when that gate is requested. Queueing recovery
during grace is Info; rejected application remains a warning.

## External memory event

Only client 01.zip contained Windows Error Reporting RADAR_PRE_LEAK_64 for
EDF5.exe at 2026-08-31 19:11:18Z. There was no crash, dump, plugin error or
interruption; the session continued and ended cleanly.

An isolated RADAR event does not prove a leak or attribute it to the mod.
Repeat a long session, measure working set/private bytes per mission and compare
four players, five with the mod and, if possible, unmodified gameplay.
Reproducible growth plus heap/stack attribution is needed before a fix.

## Remaining limits

This scenario does not establish real six/seven/eight-player support,
per-participant incoming dispatch attribution, mission nickname/chat association,
absence of long-session leaks, every leave/disconnect path or enemy multiplication.
Mission PlayerInfo tokens were unavailable despite valid persona identities.

The five-report analysis with control, loadout, sidecar, rollback, fan-out,
remote-route, transport, spawn, scaling, result, reward and return gates concluded:

```text
Cross-capture local ownership: P0=1 P1=1 P2=1 P3=1 P4=1
Assessment: consistent
```

The subsequent 0.6.53 offline suite also had zero failed gates. Nickname/chat and
incoming association remain deliberately outside the success claim until real
telemetry supports them.
