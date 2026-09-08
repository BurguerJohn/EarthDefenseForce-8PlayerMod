# RVA reference

## Scope

All values below are RVAs, not absolute virtual addresses, and apply only to
EDF5.exe with SHA-256
`3512D2A2E61D532C5D12DC0C5FD1AC61F6743E13349AE21301BB8449DD4BAE5F`.
Add an RVA to the loaded module base only after validating its fingerprint
and signature.

This is a lookup sheet. Other chapters explain semantics, limits and evidence.

## UserImpl and properties

| RVA | Meaning |
|---:|---|
| `0x452C50` | UserImpl constructor |
| `0x452F70` | destructor |
| `0x4525CA` | user flags |
| `0x4327B2` | Ready reader |
| `0x4526F4` | property initialization |
| `0x461CE0` | property getter |
| `0x462000` | property setter |
| `0x07DD20` | shared object release |
| `0x452E70` | ID getter |
| `0xEC2730` | vtable |
| `0x45C8E3` | route slot allocator |
| `0x45C948` | lifecycle constructor call |

Main offsets: +0x78 lock, +0xC0 transport/Ready, +0xC1 active, +0xC4 opaque
route key, +0xC8 route index, +0xE8/+0xF0 shared property, +0xF8 logical/loadout
index, +0x100 voice, +0x184 sort key and +0x190 local control.

## Replication and routes

| RVA | Meaning |
|---:|---|
| `0x453890` | send |
| `0x41ABE0` | target |
| `0x41A770` | dispatch |
| `0xEC2038` | special-path vtable |
| `0x4335A0` | special target |
| `0x434CD0` | enqueue |
| `0x45EAD0` | producer |
| `0x432D20` | serializer |
| `0x45EB9B` | serializer call |
| `0x45ED80` | target builder |
| `0x45EDB8` | vector layout |
| `0x45EE26` | target append |
| `0x45EE3F` | route copy |
| `0x433F40` | route resolver |
| `0x433F6E` | route index read |
| `0x4336F0` | receive pump |
| `0x4337A3` | receive loop |
| `0x435670` | parser |
| `0x4339DC` | parser call |
| `0x435DA0` | route object constructor |
| `0x435E37` | user-control copy into route |
| `0x4351F0` | parser constructor |
| `0x4352F0` | parser owner store |
| `0x433BD0` | register route |
| `0x433C78` | registration read |
| `0x433DD0` | unregister route |
| `0x433E3C` | removal read |
| `0x451B64/0x451B69` | lifecycle call/return |
| `0x451AF6/0x451AFB` | teardown call/return |

## PlayerInfo, chat and room

| RVA | Meaning |
|---:|---|
| `0x421EA0` | PlayerInfo builder |
| `0x422E00` | defaults |
| `0x422F00` | populate from UserImpl |
| `0x42395A` | builder return |
| `0x560B2B` | copy to room UI |
| `0x3F0680` | Chat_Room constructor |
| `0x3F06B8` | vtable assignment |
| `0xEBEDA8` | Chat_Room vtable |
| `0x3F09D0` | system publish |
| `0x3F0B70` | normal publish |
| `0x4A9B90` | UI cast/layout |
| `0x4A9080` | UI clamp |
| `0x4AAB40` | UI destructor |
| `0x56580A/0x565817` | PlayersGroup call/return |
| `0x5617F0` | room update |
| `0x565A9D` | member-button loop |
| `0x4E4773` | former button fault |
| `0xED7FE8` | `ButtonMaster` |
| `0xED7FC8` | `Member` |

PlayerInfo is 0x60 bytes: name storage +0x08, length +0x18, capacity +0x20
(inline up to 7), class +0x28, secondary +0x2C, weapons +0x30, validity +0x48,
armor +0x54.

## Capacity patches

```text
primary:   44894B 448961
secondary: 432AF9 432B14 432B2C 436996 4369B2 4369DB 436AAC
tertiary:  419789 4197A4 4197BC 41BB36 41BB52 41BB76 41BC0D
room UI:   5A59FC 5A5A14 5A7261 5A726D 5A7281 5A72DC
buttons:   565AA9 565AB0 565ABD 565AC4
```

Related constructors/growth/faults: `0x448840`, `0x4328C0`, `0x436990`,
`0x7D9B0`, `0x419550`, `0x41BB30`, `0x25A5C`, `0x5A5910`, `0x5A7180`,
`0x5A7240`, `0x5A5BD0`, `0x5A5EB6`.

The 24 experimental pairs and eleven holds are listed in
[03-PATCHES-RELAYS-AND-HOOKS.md](03-PATCHES-RELAYS-AND-HOOKS.md).

## Helpers, records and creation

| RVA | Meaning |
|---:|---|
| `0x126C90` | participant helper |
| `0x11D5E0` | producer |
| `0x11D7A9` | control write |
| `0x126D57` | return/cookie |
| `0x126CE0` | producer call |
| `0x126D24` | lookup call |
| `0x7E240` | source lookup |
| `0x11D860` | spawn/create function |
| `0x11CE60` | player builder |
| `0x6E010` | shared copy |
| `0x6E022` | dereference exposing a null source |
| `0x11DC95` | historical record fault |
| `0x11DB90/0x11DB98` | record redirect/return |
| `0x11DD68` | record loop |
| `0x11DF95/0x11DF9B` | copy/return |
| `0x11E2DC` | historical append fault |
| `0x11E2A0/0x11E2A7` | append redirect/return |
| `0x11E2FE` | backedge |
| `0x11E1A0` | existing-record redirect |
| `0x11E1AE` | native source |
| `0x11E1CC` | extra return |
| `0x42DB4C` | result participant filter |
| `0x430F23` | Item filter up to MaxPlayers |
| `0x430EF6` | physical Item initialization; must remain four |
| `0x132BB0` | extra Item sink/fold |

## Loadout, class and visuals

```text
state slot             125AB30
parser                 42F480
class resolver         4B6710
visual table read      4BB5E1
visual submit          4BBC37
native class read      4B6886
class text table       4BB5CE
class text select      4BC266
invalid read observed  5E741C
shared render copy     0B1CF0
shared ref read        0B1D60
consumer block/record  31240C / 31242E
parser stride/record   42F7C9 / 42F881
parser count write     42FA69
source call/return     11CF08 / 11CF0D
transfer/return        11DFCE / 11DFD3
append/return          11E057 / 11E05C
consumer               3123A0
identity reads         11D0DD / 11E05D
collection copy        12B200
copy calls             11D6AA / 11D6CF
player-create calls    11DC34 / 11ECE9
```

## Result pipeline

```text
ExecBegin               42FD20
native setup/call/ret   1153E9 / 1153EE / 1153F3
script wrapper/call/ret 42AC40 / 42AC48 / 42AC4D

Update                  430C20
script wrapper/call/ret 42AC60 / 42AC9F / 42ACA4
native caller/call/ret  12AA30 / 12AA8D / 12AA92

Finally                 42F090
script wrapper/call/ret 42AC20 / 42AC28 / 42AC2D
native call/return      12AAA9 / 12AAAE

named sync begin/poll   41F820 / 41F920
script sync calls       3E2DD8 / 3E2DE4
network sync calls      42C134 / 42C13B
reward resolve/apply    3E3150 / 3E3160
reward count/base       3E3190 / 3E31A4
reward stride/setter    3E32AE / 055830
```

```text
result setter/publish   111080 / 111098
apply UI                114BB0
event publish           61E950
publisher slot          125AB70
UI dispatch             4A1B70
script dispatch         114D50
clear apply return      114FEF
natural clear/call      3D814B / 3D8153
manager load            3E197D
manager UI reads        3E1A10 / 3E1A40
preserve point          114C51
manager slot            125AB40
mission update          3E1890
```

## Verified enemy-spawn callers (24)

```text
1D0477 1D517A 1D7560 1D80DA 1DBD54 1E0862
1F9120 1FA763 243CAD 245F8F 261BF8 262D98
26FDED 2755C9 28D4B4 291030 297FE5 299709
2C0C3B 2C1AE4 2C9C6E 2CFF51 2D3452 2D7586
```

Common function 0x1C1650, count/cap 0x1C16C6, layout 0x1C16EF.

## GeneratorPoll and spawn chain

```text
GeneratorPoll update/spawn    1F8B40 / 1F90A0
vtable / entries              EA0E38 / EA0ED8 / EA0F40
base update / call            2DA720 / 1F8B5B
tail / call                   2DA9DD / 2DA9F4
gate / virtual call           2DC7C0 / 2DC821
manager gate                  1F90E8
common call / return          1F9120 / 1F9480
```

## Native participant-scaling reads (56)

Each RVA below reads owner+0x245A0 in the supported executable and is redirected
to a relay returning at most four to its native consumer:

```text
0008ADCF 001CFEFF 001DDBE8 001DDDC9 001DDF0B 001E424D
001E6497 001E8309 001EABC3 001ECBAA 001ECDCF 001ECF17
001ECFA0 001ED021 001F872C 001F89DA 001FF74F 001FFAB8
001FFB28 001FFBB7 0020AA06 0020AC34 00214E8C 00214F2E
0021EC6D 0021EEF3 0021EFCF 0021F04E 00227381 0022A94A
002428CA 0024EBCB 00255221 00255361 0025C341 0025D830
0026406E 0026802A 0026EC0E 002786E0 0027883D 0028344F
0028538F 0028C6F0 0028C888 00294944 002949C0 00297F0C
0029A98C 002A1402 002A73C7 002C0746 002CADB4 002D0913
002D4B29 0033DEFE
```

The real getter 0x11E48E is not patched. 0x0008ADCF and 0x002D0913 are leaf
sites without their own unwind entries.

## Global constants and useful layouts

```text
route manager: lock +80, vector +D0, capacity +D8, count +E0, stride 10
route descriptor: key +0, route index +4, size 8
parser owner: parser+498 -> route; route+58 -> control; control+08 -> UserImpl
route parser: route+88

loadout block stride 3E90
selected +14B30; records +14B38 stride 18; armor +F8
fifth block 24570 (overlaps result; never materialize)
Items base 2457C; rewards count 2459C; participant count 245A0

enemy scale owner: numerator +290; denominator +294; source +2B0
native spawn cap 400; sane denominator max 1,000,000
```

## Canonical sources

Compiled tables in
[`game_patches.cpp`](../../src/games/edf5/coop8/game_patches.cpp),
[`more_players.cpp`](../../src/games/edf5/coop8/more_players.cpp) and
[`mission_spawn.cpp`](../../src/games/edf5/coop8/mission_spawn.cpp) take precedence over
this sheet. Update code, scanners/fixtures and this document together when an RVA changes.
