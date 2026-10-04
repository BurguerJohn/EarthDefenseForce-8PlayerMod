# Diagnostics, testing and privacy

## Profiles and artifacts

Logger profiles are Essential, Balanced and Maximum; dump modes are Off, Mini
and Full. A session may contain:

| Artifact | Purpose |
| --- | --- |
| session.json | Run metadata, version, termination and safe configuration |
| events.jsonl | Structured chronological events |
| payloads.bin | Deep-capture bytes only while explicitly enabled |
| status.json | Session state |
| health.json | Health, queues, drops and watchdog |
| crashes/*.json | Structured exception context |
| crashes/*.dmp | Policy-selected mini/full dump |
| crashes/*.breadcrumbs | Minimal trail if writing/dumping fails |
| snapshots | Hotkey-triggered diagnostic package |

Documented defaults: F9 snapshot, F10 deep-capture toggle, 15 s stall watchdog,
20 clean sessions, 1024 MiB retention target, queue 8192 items/16 MiB, 64 MiB
rotation, 128 MiB deep-capture cap, 65,536-byte payload cap, 64-byte preview and
flush batches of 32. Effective values come from [config.ini](../../config.ini)
and [logger.h](../../src/shared/diagnostics/logger.h).

## Retention and crash behavior

Automatic retention removes only recognized clean sessions. Crashed/abnormal
sessions survive, including the test with 20 clean + 1 crash directories.
Temporary files and shutdown state must not misclassify an interrupted run as clean.

The crash handler avoids allocation/complex operations on fragile paths, records
breadcrumbs and respects dump mode Off. Missing dumps must not hide structured
exception evidence when writing remains possible.

Since 0.6.65 the crash JSON (including /GS fast-fail) also records all general
registers and `stack_frames`: up to 48 frames unwound with dbghelp
`StackWalk64` on the crash worker, reading memory only through
`ReadProcessMemory` so a smashed stack truncates the trace instead of faulting.
Each frame is `{module, rva, rva_hex}`; absolute addresses are never emitted,
so frames survive the sanitized report while registers are redacted. The
first-chance record's heuristic stack scan now also recognizes plugin code
(`"module":"plugin"`) besides the main image.

`tools/EnableCrashDumps.ps1` (with a `.bat` wrapper) is an out-of-process
fallback for any build flavor: it enables Windows Error Reporting LocalDumps
for EDF5.exe (Mini by default, elevated automatically) and `-Action Status`
lists recent `Application Error` events as module/code/offset only. WER dumps
contain process memory and are never part of the sanitized report.

## Privacy boundaries

Local diagnostics, especially deep captures, can contain SteamIDs, network
addresses/ports, payload bytes, usernames and local paths. Never commit or publish
raw artifacts. The repository .gitignore excludes build outputs, reports, tests,
dumps, logs, payloads and common secrets. Generate a sanitized report and review
its ZIP before sharing.

MorePlayers diagnostic events use counts, masks, generations and private
session-local tokens rather than SteamID, route key, endpoint or payload.
Tokens correlate records within a session, not accounts outside it.

The banner is local and does not read other players' text. Name audits verify
origin/collisions without requiring original names in shared reports.

## Validation suite

Entry point: [RunDiagnosticsTests.ps1](../../tools/RunDiagnosticsTests.ps1).
The historical 0.6.53 run recorded:

```text
test-output/diagnostics-20260831T203022Z
failed gates: 0
```

That result is offline evidence for code, reference-executable signatures, relays
and fixtures. The separate [five-player live audit](09-FIVE-PLAYER-LIVE-TEST-2026-08-31.md)
documents coordinated 0.6.52 gameplay.

### Static gates

- Slot scanner: exactly eight proven anchors, 24 experimental pairs, eleven
  deferred and six reviewed non-roster candidates.
- Player-flow scanner: 28 getter callers and route/parser lifecycle/ownership.
- Result scanner: 12 ranges, 2,882 decoded instructions, expected constants,
  wrappers and callers.
- Spawn/result validator: 24 enemy callers, 56 scaling reads, GeneratorPoll chain
  and result layout.

A changed RVA, signature or count fails the audit. Exact counts detect drift:
a new candidate needs deliberate classification, not a wildcard.

### Pure tests and relays

Tests cover transactional install/restore and negative signatures; registers,
flags and return values; 56-read clamp without changing source count; atomic
Item folding; zero-scale CAS preserving concurrent mutations; 400-actor
saturation and multiplier opt-in; result recovery and native/generation
cancellation; layouts, ranges, nulls and impossible values.

### Positive and negative fixtures

Fixtures cover controls, UserImpl order, class/loadout, names, replication,
routes, fan-out, results, UI close, rewards, spawn and GeneratorPoll.
Negative cases must detect duplicate identity/missing host, route collisions,
incomplete fan-out, late loadout-index restore, invalid class, inconsistent
result events/missing close, duplicate cancellation, result-only spawn,
zero caller, unsafe owner, pointer leaks and unknown gates.

### Logger and integration

Scenarios include disabled diagnostics, clean shutdown, snapshot, network,
deep capture/cap, flood, rotation, crash, crash_off, fast_fail and retention.
Fake Steam covers the full path and a variant missing SteamAPI_RunCallbacks
that must quarantine. The current EDF 4.1 marker also checks eight roster
operands plus two room-UI sites and four visible windows with headless overflow.

## Interpreting evidence

Distinguish supported-executable disassembly, reproducible scanners/fixtures,
identified live reports, consistent but untested inference, and refuted historical
hypotheses. Offline tests do not prove real latency, Steam callback ordering,
cross-machine synchronization, teardown or post-victory behavior.

The five-player test covered its executed scenario. Six through eight players,
per-message incoming attribution, mission nicknames and long-session memory
remain pending.

## Useful reports

Record plugin version, executable hash, exact config, machine roles and player
count. Note the sequence from lobby/Ready through loading, gameplay, result and
return. Capture a snapshot near the anomaly and bound deep capture to the needed
interval. Keep originals locally, generate a sanitized copy, inspect it, and
never add reports, dumps, payloads or secrets to Git.

## Tools

[Report generator](../../tools/CreateDebugReport.ps1),
[diagnostic validator](../../tools/validate_diagnostics.py),
[MorePlayers validator](../../tools/validate_more_players.py),
[minidump analyzer](../../tools/analyze_minidump.py),
[capture summary](../../tools/summarize_capture.py) and
[local payload extraction](../../tools/extract_payload.py).
