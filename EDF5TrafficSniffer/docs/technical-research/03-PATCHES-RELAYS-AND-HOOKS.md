# Patches, relays and hooks

## Safety rule

All RVAs here belong exclusively to the EDF5.exe with SHA-256
`3512D2A2E61D532C5D12DC0C5FD1AC61F6743E13349AE21301BB8449DD4BAE5F`.
Runtime resolves RVAs from the loaded module base and validates signatures before writing.

Transactions validate all required bytes/targets, prepare relay pages and hooks,
and install only a consistent complete set. Failure must not leave partial
installation. Removal restores only exact known replacement bytes; unknown bytes
are never overwritten.

## Proven roster limits

The baseline contains 22 operands verified to control participant vectors/lists.

| Structure | Construction/growth | Capacity operands |
| --- | --- | --- |
| Primary roster | Constructor `0x448840`, region `0x44894B` | `0x44894B`, `0x448961` |
| Secondary roster | Constructor `0x4328C0`, grow `0x436990`, former fault `0x7D9B0` | `0x432AF9`, `0x432B14`, `0x432B2C`, `0x436996`, `0x4369B2`, `0x4369DB`, `0x436AAC` |
| Tertiary roster | Constructor `0x419550`, grow `0x41BB30`, former fault `0x25A5C` | `0x419789`, `0x4197A4`, `0x4197BC`, `0x41BB36`, `0x41BB52`, `0x41BB76`, `0x41BC0D` |
| Room boxes | Constructor `0x5A5910`, resize `0x5A7180`, grow `0x5A7240`, update `0x5A5BD0`, fault caller `0x5A5EB6` | `0x5A59FC`, `0x5A5A14`, `0x5A7261`, `0x5A726D`, `0x5A7281`, `0x5A72DC` |

The primary roster operands share a 41-byte region. Original values are four;
replacements use the validated configured preallocation capacity.

## Experimental reserves

There are 24 coherent `capacity < 4` / `reserve(4)` pairs, totaling 48
operands. `ExperimentalReservePatches=true` enables this group; each owner
has not yet been semantically identified.

| Anchor | Reserve operand | Anchor | Reserve operand |
| --- | --- | --- | --- |
| `0x014958D` | `0x0149594` | `0x01CDCF2` | `0x01CDCF9` |
| `0x01CE773` | `0x01CE77A` | `0x01D8176` | `0x01D817D` |
| `0x01D95AD` | `0x01D95B4` | `0x01F7D70` | `0x01F7D77` |
| `0x01FBF2A` | `0x01FBF31` | `0x01FC508` | `0x01FC50F` |
| `0x025D408` | `0x025D40F` | `0x0263925` | `0x026392C` |
| `0x02769A2` | `0x02769A9` | `0x0282612` | `0x0282619` |
| `0x029CBA2` | `0x029CBA9` | `0x02A27A5` | `0x02A27AC` |
| `0x02A6F6F` | `0x02A6F76` | `0x02B0242` | `0x02B0249` |
| `0x02B837D` | `0x02B8384` | `0x02BB10D` | `0x02BB114` |
| `0x02C4B67` | `0x02C4B6E` | `0x02D17F3` | `0x02D17FA` |
| `0x034EAA0` | `0x034EAA7` | `0x035037A` | `0x0350381` |
| `0x047A4CF` | `0x047A4D6` | `0x04AECFE` | `0x04AED05` |

Eleven comparisons remain HOLD without patches: `0x005B6C1`, `0x00D2238`,
`0x00D25B6`, `0x02BD3CF`, `0x0971940`, `0x09722C7`, `0x0C3B97C`,
`0x0C3B9FA`, `0x0C3BA2D`, `0x0C3BC1A` and `0x0C3BC76`.
They resemble state/type/dispatch comparisons, not reserves. See the
[individual rationale](../../EXPERIMENTAL_SLOT_PATCHES.md).

## Room member buttons

Loop `0x565A9D` assumed four stack pointers and could fault at `0x4E4773`.
Sites `0x565AA9`, `0x565AB0`, `0x565ABD` and `0x565AC4` use a safe mapping:
index zero selects the master resource at `0xED7FE8`; all others select the
member resource at `0xED7FC8`. Replacement storage is zeroed before population.

## Participant helper and sidecars

Native helper `0x126C90` receives an external eight-int buffer. The producer is
`0x11D5E0`, relevant write `0x11D7A9`, and cookie-protected return `0x126D57`.
Callsites `0x126CE0` and `0x126D24` connect producer and lookup `0x7E240`.

Creator `0x11D860` calls builder `0x11CE60`, which uses shared copy
`0x6E010`. The classic `0x6E022` failure demonstrated that the fifth control
integer could not safely occupy adjacent native memory.

Native records are `0x18` bytes starting at `+0x138`. The theoretical first
extra address is `+0x198`; it is redirected to one of four sidecars rather
than used as native storage.

- Primary redirect: `0x11DB90`, return `0x11DB98`, loop `0x11DD68`.
- Copy: `0x11DF95`, return `0x11DF9B`.
- Append redirect: `0x11E2A0`, return `0x11E2A7`, backedge `0x11E2FE`.
- Motivating faults: `0x11DC95` and `0x11E2DC`.
- Existing-record flow: `0x11E1A0`, native source `0x11E1AE`,
  extra return `0x11E1CC`.

### Spawn transform loop (six-player crash, 0.6.65)

Before creating participants, `0x11D860` runs a first loop at
`0x11DAB1..0x11DB25` that normalizes (`0x7CDC0`) and rotates `spawn[edi]` in
place at `rbp+0x1E0+edi*0x10` until `edi` equals the participant count at
`[rsp+0x50]`. Only four records exist (`0x11D9E3` initializes four, `0x11DA46`
copies four positions) and the function's /GS cookie is stored at
`rbp+0x230` (`0x11D8A7`) and checked at `0x11E414`.

| Participant | Write target | Effect |
| --- | --- | --- |
| P4 (5 players) | `rbp+0x220..0x22F` | unused padding; five players survive |
| P5 (6 players) | `rbp+0x230..0x23F` | overwrites the cookie; `__report_gsfailure` fast-fails `0xC0000409` when `0x11D860` returns |
| P6/P7 | `rbp+0x240..0x25F` | overwrite the caller's saved `xmm9`/`xmm8` |

This is a deterministic crash on every machine at mission entry with six or
more participants. It was invisible in the Users DLL because fast-fail
bypasses normal exception filters. The relay replaces only the backedge
`cmp edi,[rsp+0x50]; jne 0x11DAB1` at `0x11DB21` (six bytes, `jmp`+`nop`):
it exits natively when `edi` reaches the count, loops only while `edi < 4`,
and otherwise increments a clamp counter and exits. The creation loop already
reads `spawn[index % 4]` through the primary redirect, so extras reuse the
four transformed records. Signature, rollback and quarantine are shared with
the other mission-spawn sites; the micro-harness replays the exact backedge
bytes unpatched (six iterations) and patched (1/4/5/6/8 participants).

The sibling script command `0x11E7A0` (called from `0x115C6C`) stores the
participant producer's four control integers at `rbp+0x100` directly below
its cookie at `rbp+0x110`. It was not observed in any five-player report
(only `mission_entry_primary`), builds matrices per local profile and is left
unpatched pending evidence. `mission_player_control_assignment` with
`context=mission_entry_secondary` and `participant_index>=4` is the signal
to watch.

Result participant filters are `0x42DB4C` and `0x430F23`. They follow
MaxPlayers while physical Item capacity remains four; extras are folded,
never written past the array.

## Mission relay page

A nearby executable page contains stubs and auxiliary data. See the
[memory map](02-MEMORY-MAP.md). Relative jumps require an in-range target
and matching signature. Stubs preserve the original register/flag contract.
Counters/masks are outside code ranges. Prepare the page before patching and
restore call/jump sites before releasing supporting storage.

### Native scaling clamp

There are 56 verified reads of `owner+0x245A0`. Relays limit only those
consumers' observed value to four; the real count remains available to expanded
flows. Destination registers may be EAX, R8D, R9D or R10D; other registers and
flags are preserved.

Leaf sites `0x0008ADCF` and `0x002D0913` have no unwind entry. Getter
`0x11E48E` stays unchanged. See the [full RVA list](08-RVA-REFERENCE.md).

### Mission script record reads (0.6.77)

`0x121C43` (12 bytes, mission in rsi) and `0x127393` (19 bytes, mission in
r13) compute `mission+0x140+i*0x18` before locking the record weak_ptr with
`0x6D730`. Stubs at relay page `0x1300/0x1380` keep `i < 4` native, map
`i = 4..7` to sidecar `0x400 + (i-4)*0x18 + 8` and `i >= 8` to the empty
record at `0x1408`, counting sidecar/empty reads at `0x1420/0x1428`. rax,
rcx and flags are dead until the following `lea rdx` and call. Context bytes
(`movsxd rax,edi` before, lock call after) are validated with the sites.

### Vehicle rear seats and enemy HP (0.6.78, ported from PR #1)

Ported from mi9202's pull request to BurguerJohn/EarthDefenseForce-8PlayerMod
(fix/6-player-support), re-verified against this EDF5.exe and re-laid out on
this relay page, which grew to 0x4000.

- Rear seats: the Caliban (`0x34F9AD`) and Vehicle_Car (`0x374EED`) seat
  pickers write `vec[0] = vec[index+1] = index` into an int vector sized by
  the seat count; index 4+ writes past it and those players could only
  drive. Stubs at `0x1480/0x1580` keep the native seat when it exists, give
  P5-P8 rear seat `1 + index % rear_seats`, and open every rear seat when the
  preferred one is occupied (seat array `[vehicle+0x418]`, stride `0x340`,
  occupant control `+0x268`, uses `+8`, as in `0x355BE0`). Counters at
  `0x1430/0x1438`.
- Enemy HP: 24 enemy initializers multiply HP by a four-entry per-player
  table (`mulss xmmN,[base+index*4+8]`, index `3*(count-1)`), which the
  participant-scaling clamp leaves at the four-player entry for 5+. Stubs at
  `0x2000 + i*0x100` apply, for a real count 5..8 and index 9 only,
  `max(t3, t3 + (n-4)*(t3-t2))` or `EnemyHealth<n>Players * t3`, preserving
  flags, xmm15 and every GPR. Data at `0x1440..0x1470` (applied counter,
  site mask, enabled flag, last factor/count, four INI multipliers).

## Damage meter (0.6.74)

Two optional hooks, installed only when every signature (ApplyDamage, its
health/amount reads, the single message-handler call, the flush and both
projectile call sites, the two RTTI names) matches; a mismatch disables the
meter without quarantine. `0x2DB370` measures health before/after the native
call and credits the attacker only when its address equals a soldier created
for P0-P7 by `0x11CE60` (the attacker is never dereferenced for that).
`0x2D9720` records the projectile (`list - 0x80`) in a thread-local while the
projectile system flushes, so ApplyDamage knows which projectile hit. The
weapon is the first pointer inside the projectile whose RTTI derives from
WeaponBase, discovered once per projectile class (8 attempts, readable-memory
and image-RTTI validated). Result 3 keeps the measurement across a two-part
mission; another result ends it; the host prints it to its own room chat with
the native system-message publisher on room return.

0.6.79: the chat print is off by default (`DamageMeterChat=false`). A live
13-minute mission (0.6.77, 5 players) credited the Ranger 361 and the Fencer
818 damage on the host, so the host's ApplyDamage view is incomplete for
remote players. The summary now also records, per participant, the raw
`GameDamageInfo +0x50` amount of the hits applied on this machine (including
hits that lowered no health) and the source side: every `0x2D9720` flush on
this machine sums the entries (`[list+8]` data, `[list+0x18]` count, 0xA0
stride, target `+0`, attacker `+0x20`, amount `+0x60`) whose attacker is a
registered soldier and whose target is not. Each machine's log therefore holds
what its own player sent, for comparison with the host's received totals.

0.6.80: total damage instead of DPS, correct for every player. The objects'
message pre-filter (vtable slot 7 `0x2DAC10` -> NetworkObject component at
`object+0xC0`, `0x402C00`) leaves a `0x80000000` damage message local while
the attacker weak_ptr (`GameDamageInfo +0x18`) is alive; with no live attacker
a non-authoritative machine rewrites it to `0x4000004`. Network-delivered
damage arrives as `0x4000001` and the same filter unwraps it into
`0x80000000` without a live attacker. So every machine applies its own
soldiers' hits through ApplyDamage, and only that machine sees all of them.
Each participant now records whether it is locally controlled (the
MissionPlayerCreate controller resolution). At a measurement start every
machine clears its lobby member data key `edf5mp_dmg`; at mission end it
writes `1;<index>:<steam id>:<damage>:<hits>` for its local participants
through the original SetLobbyMemberData. Back in the room each machine reads
the real lobby members (fillers excluded) every 250 ms for up to 10 s and
accepts an entry only for a registered participant that is not local and
whose SteamID equals the declared one (the member's own ID when unknown);
a second claim is a conflict and members that left are not awaited. The
summary is printed with the native local system-message publisher on every
machine (`DamageMeterChat`, default true); missing totals show `? (no data)`.
Damage whose attacker is not the soldier (vehicles, deployed weapons, air
raids) is still not credited.

0.6.80 stats overlay (Tab): local participants only. A kill is a credited hit
that takes the target's health from above zero to zero or below (the same
`0 >= health` test as `0x2DAC60`, which then sets `object+0x280 |= 0x10`) on a
target the game does not treat as friendly. That is ApplyDamage's own test:
attacker team `GameDamageInfo +0x24` and target team `object+0x218`
(`0x2DB408`/`0x2DB411`); only when both are valid, the relation
`*(int*)(*(*(G+0x38) + attacker*0x38 + 0x18) + target*4)` with `G` the
global loaded at `0x2DB421` (RVA `0x125AB80`) equal to 1 means friendly and
2 hostile. A killing blow unregisters the target from its team inside
ApplyDamage, so its team reads -1 afterwards (live 0.6.80, players are teams 0
and 2): the target team is read before the native call and a kill counts only
for relation 2, the radar's definition. The reads are signature-checked
separately; a mismatch only hides kills, and an unreadable table falls back
to "different valid team".

Distance: the soldier's world position is the translation row `+0xA0`
(x, y up, z) of the GameObjectBase world matrix at `+0x70`; a census of
position subtractions (`movaps [a+D]`/`subps [b+D]`) ranks `+0xA0` first among
object registers. Each `Mission()` update adds the step of every local
soldier; steps above 30 m (spawn, teleport, part change) or below 1 mm are
ignored, and nothing is read while a two-part transition is pending. Live
0.6.80: plausible against walked distance.

Living enemies: `0x32C7D0(G, team, functor)` is the radar's enumerator
(HUiHudRader slot 2 at `0x4CDADE`, nine other callers). Under G's critical
section (G+8) it walks every team whose relation to `team` is 2, visits each
object of that team's `std::set` (node value `+0x20`) with health > 0 and no
`+0x280` flag `0x80`, and calls `functor->vtable[1](object)`. Every 250 ms the
mission update calls it, outside the plugin's locks, with the local soldier's
team and a counting functor; the overlay shows counts at most 2 s old. Live
0.6.80: matches the mission's enemies. The spawn boundary's global counter
(`[0x124DD8C]`, compared with the 400 cap) did not match and is not used.
A Wing Diver flight flag was not identified; that metric was dropped.

Ultrawide (screens wider than 16:9, keep-aspect option on): EDF5 lays out a
centred 16:9 area (`0x60C120`) and every consumer of the keep-aspect byte
uses it. The swap chain, depth buffer and several effect targets are already
screen-sized; the scene renders deferred into view render targets sized by
the view rect (from the screen object's 16:9 size), and the camera takes its
aspect from that rect (vertical FOV), so a full-screen rect gives Hor+.
`0x6153A0` widens a rect equal to the area; `0x5EF930` moves back viewports
the wider rect would push past the right edge (camera and layer paths add
the area offset); the composite (`0x3D8920`) takes the screen path and the
screen size for its 2D projection. HUD corners: the UI viewport
(`0x3D7D30`) and the layer/HUD viewport (`0x623FF7`) take the screen path,
every UI projection built from `0x4B2FB0`, `0x4B2390` and slot 10
`0x4B2590` is compressed on x by area/screen, and the power gauge, radar and
weapon panels (RTTI-checked vtables) move by the area offset to their side.
The picture is switched in the scene update `0x611BB0` (game thread, where
EDF5 refreshes views itself); the render thread only reads the state.
It is only used during missions, from one second after the damage meter
sees the mission until it ends: UI built while the full-screen UI viewport
is active scales itself to it (the title came out zoomed 1.33x when the
picture was on from the first frame), so the title, menus, room and
result screens keep the original picture.
A plain C++ detour on `0x5BE700` crashed (caller at `0x4B4309` used r8/r9
after the call): every ultrawide hook enters through a stub that preserves
all general and XMM registers.

Friendly fire (players only): a credited hit whose target is another
registered player soldier adds the health it removed to the shooter's
friendly fire and counts a friendly kill when it takes that player from above
zero to zero or below; it never counts as enemy damage. For the players' own
hits the hook also reads the relation of the target's team (read before the
native call): relation 1 (allied NPC soldiers) is excluded from both enemy
damage and friendly fire. Hits by non-players skip the relation lookup. Overlay hooks: Present and
Present1 (slot 22) with a re-entry guard; EDF5's back buffer is
R8G8B8A8_UNORM with 8x MSAA, so the view must be TEXTURE2DMS (an
intermediate copy is used for back buffers without render-target binding). Stage time
accumulates on each `Mission()` update (`0x3E1890`), counting at most 1 s per
gap so pauses and loading are excluded. Recent DPS sums per-second buckets of
the last 10 s. Multi-part targets with their own health count once per part.

## Hook installation criteria

Require an exact supported signature, a known callsite ABI (volatile registers,
stack and return value included), and a testable shutdown/restoration path.

Observational hooks must not alter state. Corrective hooks are narrow and
require valid extra-player mission, generation, index, pointers and ranges.
Unreadable or contradictory inputs fall back to native flow.

## Canonical sources

[Patch implementation](../../src/games/edf5/coop8/game_patches.cpp),
[participant hooks](../../src/games/edf5/coop8/more_players.cpp),
[spawn policy](../../src/games/edf5/coop8/mission_spawn.cpp),
[result recovery](../../src/games/edf5/coop8/mission_result_recovery.cpp),
[lifecycle](../../src/games/edf5/edf5_module.cpp),
[slot scanner](../../tools/slot_capacity_scanner.cpp),
[player-flow scanner](../../tools/player_flow_scanner.cpp),
[multiplayer validator](../../tools/validate_more_players.py) and
[spawn/result validator](../../tools/validate_spawn_result_layout.py).
