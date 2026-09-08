# Memory map and index domains

These layouts are verified in the supported executable. Object offsets are
relative to the stated pointer; RVAs are relative to `EDF5.exe`.

## Distinct player indices

| Domain | Field/source | Meaning | Can it be 4..7? |
| --- | --- | --- | --- |
| Logical participant/loadout | `UserImpl+0xF8` | Mission map, parser and replication identity | Yes |
| Transport route | `UserImpl+0xC8` | Slot in the dynamic receive manager | Yes, if allocated |
| Opaque route key | `UserImpl+0xC4` | First destination descriptor dword | Do not interpret as an index |
| Local control | `UserImpl+0x190` | Position in this PC's controlled subset | Usually 0; not a global position |
| Final mission order | Post-sort vector | Descending key order at `+0x184` | Yes |
| Physical visual slot | Transient resolver output | One of four native UI/HUD resources | No; use logical % 4 |
| Physical spawn | Native table | One of four position/orientation records | No; use logical % 4 |
| Result accumulator | Four native Items | Reward/result bucket | No; fold P4-P7 by logical % 4 |
| Difficulty profile | `participant_count-1` | Native profile for 1..4 players | No; clamp the local read to 4 |

Logical indices must remain unique. Temporarily reducing one to 0..3 is allowed
only inside a proven four-entry native consumer. Restore it before identity
consumers at `0x11D0DD` and `0x11E05D`.

## net::UserImpl

Associated RVAs:

- Constructor: `0x452C50`.
- Scalar destructor: `0x452F70`.
- Vtable: `0xEC2730`.
- SteamID getter, virtual slot 10: `0x452E70`.
- Flag initialization: `0x4525CA`.
- Property getter/setter: `0x461CE0 / 0x462000`.
- Shared-property release: `0x7DD20`.

| Offset | Observed size | Verified use |
| --- | --- | --- |
| `+0x78` | CRITICAL_SECTION | Transport/Ready state lock |
| `+0xC0` | byte | Transport/Ready predicate; initialized to zero |
| `+0xC1` | byte | Active/present user; must be true |
| `+0xC4` | dword | Opaque destination route key |
| `+0xC8` | signed dword | Transport route index assigned during construction |
| `+0xE8/+0xF0` | shared pointer | Control/object of participant property map |
| `+0xF8` | signed dword | Logical mission/loadout index, not selected class |
| `+0x100` | dword | Voice-chat state; never modify for Ready |
| `+0x184` | qword/identity | Descending mission-sort key; do not log its value |
| `+0x190` | signed dword | Local controller index, not global room index |

Ready uses `cm="c1"` and `ds="ds"`. MissionStart state 4 additionally requires
consistent `l1` and `l2` for every participant.

## Native shared handles

```cpp
struct SharedProperty {
    void* control;  // +0x00
    void* object;   // +0x08
};                  // sizeof = 0x10
```

Many game vectors store this pair rather than a direct object pointer.
Confusing control/object causes identity aliases or invalid dereferences.
Observed handle vectors use:

```text
+0x00 reserved
+0x08 entries pointer
+0x10 capacity
+0x18 size
sizeof = 0x20
```

MissionSourceVector and PlayerInfoVector entries are `0x10` bytes each.

## Transport and replication

### Outgoing destination descriptor

Builder `0x45ED80` copies adjacent dwords `UserImpl+0xC4/+0xC8`:

```cpp
struct GameplayReplicationTargetDescriptor {
    uint32_t opaque_route_key;      // +0x00
    int32_t transport_route_index;  // +0x04
};                                  // sizeof = 0x08
```

Its vector has entries/capacity/size at `+0x08/+0x10/+0x18`, total size
`0x20`. It is not a SharedProperty vector: stride `0x10` reads past an entry.

### Receive manager

| Manager offset | Use |
| --- | --- |
| `+0x80` | Pump lock |
| `+0xD0` | Dynamic SharedProperty vector start |
| `+0xD8` | Capacity |
| `+0xE0` | Count |

Each `0x10`-byte slot references a `0xA8`-byte route object. Register/unregister
index it with `UserImpl+0xC8`.

### Incoming ownership

Parser `0x435670` is not embedded next to UserImpl:

```text
parser + 0x498 -> route object
route  + 0x58  -> user control block
control+ 0x08  -> actual UserImpl
route  + 0x88  -> parser owned by this route
```

The route constructor is `0x435DA0`; user-control copy is `0x435E37`.
Parser construction is `0x4351F0`; its owner store at `+0x498` is `0x4352F0`.
The historical `parser-0x88` calculation is invalid: `route+0x88` points to a
parser and does not establish inline allocation.

## Room PlayerInfo

Each PlayerInfo is `0x60` bytes. Vector construction: `0x421EA0`; defaults:
`0x422E00`; conversion from UserImpl: `0x422F00`; room copy: `0x560B2B`.

| Offset | Field |
| --- | --- |
| `+0x08` | Native name string/SSO storage |
| `+0x18` | Name length |
| `+0x20` | Name capacity; inline up to 7 |
| `+0x28` | Selected class |
| `+0x2C` | Secondary/derived loadout |
| `+0x30` | Six equipment IDs |
| `+0x48` | Equipment validity |
| `+0x54` | Armor |

Preserve the `0x422F00` return in RAX. Name, class and loadout index are
independent domains. Diagnostics use private name tokens without logging text.

## Room UI

The UI owner has a vector at `object+0x148`, with storage/capacity/size at
`+0x150/+0x158/+0x160`. Each panel is `0x50` bytes. Native construction makes
four. Accessing a fifth without expanding reserve/grow/size writes to an
unconstructed wide string and caused the fault below `0x5A5EB6`.

PlayersGroup is a `ui::Layout`, not an HUiScrollBar:

- Layout vtable: `0xEC8628`.
- Vertical model: `Layout+0xC0`.
- Rendered position: `model+0x00`.
- Requested position: `model+0x04`.
- Enabled flag: `model+0x0C`.
- Mod wheel step: `0.25`.
- Native clamp: `0x4A9080`.

## Mission loadout/result state

The global state pointer used by the parser is at RVA `0x125AB30`.

### Four native loadout blocks

- First selected block: `state+0x14B30`.
- First record: `state+0x14B38`.
- Block stride: `0x3E90`.
- Per-class record: `0x18`.
- Valid classes: 0..3.
- Six equipment IDs per class.
- Armor: `block+0xF8`.

Consumer `0x3123A0` uses `UserImpl+0xF8` as a block index. Within the block,
`0x31241A..0x3124D2` reads class at `+0`, equipment at
`+8+class*0x18` and the corresponding armor.

### Critical P4 overlap

```text
state+0x24570  hypothetical fifth 0x3E90-byte block
state+0x2457C  four native result Items, 8 bytes each
state+0x2459C  local reward-profile count (native capacity 2)
state+0x245A0  logical participant count
```

Items occupy exactly `0x2457C..0x2459B`. Direct P4-P7 parsing corrupts results
and rewards. The hook snapshots the extra range, captures only sanitized fields
into sidecars and restores the range bytewise. The participant-count write at
`0x42FA69` is unconditional and can be valid even when the parser returns false.

## Result/UI state

The global mission-manager pointer is at RVA `0x125AB40`.

| Object | Offset | Field |
| --- | --- | --- |
| Mission manager | `+0x28` | UI pointer/handle |
| Mission manager | `+0x34` | Result |
| Mission UI | `+0xF8` | State: 1 running, 2 finishing, 3 finished |
| Mission UI | `+0xFC` | Visual result |
| UI object | `+0x18` | Flags; bit 0x1 means closing |
| UI object | `+0x78` | Object ID; expected close payload targets ID 2 |

The event publisher occupies global slot RVA `0x125AB70`. Event type 1,
payload 2, must reach UI object ID 2.

## Persistent mission records and participant spawn

Four native persistent `0x18`-byte records start at `mission_object+0x138`.
The hypothetical extra record at `+0x198` does not exist in the original object.
P4-P7 records live in four relay-page sidecars.

Only four native spawn/orientation records exist, each `0x10` bytes.
Extras use `spawn[logical_index % 4]`.

Helper `0x126C90` originally had an int32 array at `rsp+0x68` and /GS cookie
at `rsp+0x78`; the fifth write already reached the cookie. Two relays replace
only call arguments with an external eight-int32 buffer, preserving frame/unwind.

## Relay page

A `0x2000`-byte executable page is allocated within `0x70000000` of the
original site to keep rel32 jumps/calls in range.

| Page offset | Contents |
| --- | --- |
| `0x000` | Primary record redirect |
| `0x080` | Legacy copy/micro-harness stub |
| `0x100` | Existing-record redirect |
| `0x200` | Append redirect |
| `0x300` | Participant-array producer relay |
| `0x340` | Participant-array consumer relay |
| `0x400` | Mission-record sidecars |
| `0x470` | Primary redirect counter |
| `0x478` | Existing-record redirect counter |
| `0x480` | Append redirect counter |
| `0x500` | External eight-participant buffer |
| `0x600` | First of 56 scaling relays |
| `0x30` | Stride of each scaling relay (not a separate region) |
| `0x1100` | Total clamp counter |
| `0x1108` | Clamped-site mask |

## Enemy spawn and GeneratorPoll

Common boundary `0x1C1650` owner:

| Offset | Use |
| --- | --- |
| `+0x290` | Scale numerator |
| `+0x294` | Scale denominator |
| `+0x2B0` | Source/descriptor owner; required for repair |

GeneratorPoll object:

| Offset | Use |
| --- | --- |
| Vtable `+0xA0` | Concrete Update `0x1F8B40` |
| Vtable `+0x108` | Concrete Spawn `0x1F90A0` |
| `+0x1F8` | Period scale |
| `+0x1FC` | Current time |
| `+0x400` | Embedded gate state |
| Gate `+0x00` | Remaining/quota |
| Gate `+0x04` | Signed cooldown |
| Gate `+0x08` | Last time |
| `+0x788` | Manager required to reach common boundary |

The observed signed cooldown threshold is `0x1CC`.

## Canonical sources

[Participant hooks](../../src/games/edf5/coop8/more_players.cpp),
[patches](../../src/games/edf5/coop8/game_patches.cpp),
[spawn policy](../../src/games/edf5/coop8/mission_spawn.h),
[player-flow scanner](../../tools/player_flow_scanner.cpp) and
[spawn/result validator](../../tools/validate_spawn_result_layout.py).
