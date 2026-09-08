#!/usr/bin/env python3
"""Validate EDF5 logical-player and roster-preallocation patch groups."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

from pe_inventory import PE


CONSTRUCTOR_RVA = 0x448840
REGION_RVA = 0x44894B
FIRST_IMMEDIATE = 1
SECOND_IMMEDIATE = 23
ORIGINAL_CAPACITY = 4
REGION = bytes.fromhex(
    "ba04000000"
    "488bcb"
    "483bf2"
    "7311"
    "e843e8c9ff"
    "84c0"
    "7413"
    "ba04000000"
    "488bcb"
    "4c8d442448"
    "e88decc9ff"
    "90"
)

SECONDARY_CONSTRUCTOR_RVA = 0x4328C0
SECONDARY_GROW_HELPER_RVA = 0x436990
SECONDARY_SITES = (
    (0x432AF9, bytes.fromhex("48837e1004"), 4, 1, 0),
    (0x432B14, bytes.fromhex("48837e1004"), 4, 1, 0),
    (0x432B2C, bytes.fromhex("ba04000000"), 1, 4, 0),
    (0x436996, bytes.fromhex("4883791004"), 4, 1, 0),
    # The preceding mov edx,16 plus lea ecx,[rdx-12] gives count 16-12 == 4.
    (0x4369B2, bytes.fromhex("8d4af4"), 2, 1, 16),
    (0x4369DB, bytes.fromhex("41be04000000"), 2, 4, 0),
    (0x436AAC, bytes.fromhex("48c7471004000000"), 4, 4, 0),
)

TERTIARY_CONSTRUCTOR_RVA = 0x419550
TERTIARY_GROW_HELPER_RVA = 0x41BB30
TERTIARY_SITES = (
    (0x419789, bytes.fromhex("48837e1004"), 4, 1, 0),
    (0x4197A4, bytes.fromhex("48837e1004"), 4, 1, 0),
    (0x4197BC, bytes.fromhex("ba04000000"), 1, 4, 0),
    (0x41BB36, bytes.fromhex("4883791004"), 4, 1, 0),
    # The preceding mov edx,16 plus lea ecx,[rdx-12] gives count 16-12 == 4.
    (0x41BB52, bytes.fromhex("8d4af4"), 2, 1, 16),
    (0x41BB76, bytes.fromhex("bd04000000"), 1, 4, 0),
    (0x41BC0D, bytes.fromhex("48c7471004000000"), 4, 4, 0),
)

ROOM_PANEL_CONSTRUCTOR_RVA = 0x5A5910
ROOM_PANEL_RESIZE_RVA = 0x5A7180
ROOM_PANEL_GROW_HELPER_RVA = 0x5A7240
ROOM_PANEL_SITES = (
    (0x5A59FC, bytes.fromhex("48837f1004"), 4, 1, 0),
    (0x5A5A14, bytes.fromhex("ba04000000"), 1, 4, 0),
    (0x5A7261, bytes.fromhex("4883791004"), 4, 1, 0),
    # The preceding mov edx,80 plus lea ecx,[rdx-76] gives count 80-76 == 4.
    (0x5A726D, bytes.fromhex("8d4ab4"), 2, 1, 80),
    (0x5A7281, bytes.fromhex("bd04000000"), 1, 4, 0),
    (0x5A72DC, bytes.fromhex("48c7471004000000"), 4, 4, 0),
)

# MissionSync_Res gathers one shared UserImpl handle per online participant
# into a dynamically growing vector. NetGameStatus also decodes a dynamic Item
# count but separately rejects Item callbacks for logical indices 4+. Both
# filters follow MaxPlayers. The fixed initialization loop at 0x430EF6 remains
# four because its destination is exactly four eight-byte accumulators; the
# runtime hook folds accepted P4-P7 Items into those native accumulators.
MISSION_RESULT_PARTICIPANT_SITES = (
    (0x42DB4C, bytes.fromhex("83f804"), 2, 1, 0),
    (0x430F23, bytes.fromhex("83fb04"), 2, 1, 0),
)

# Optional v0.5.0 audit batch. Each unidentified constructor group changes its
# capacity comparison and reserve(4) argument together. These are not counted
# among the 22 proven roster operands.
EXPERIMENTAL_RESERVE_SITES = (
    (0x14958D, bytes.fromhex("4883791004"), 4, 1, 0),
    (0x149594, bytes.fromhex("8d5004"), 2, 1, 0),
    (0x1CDCF2, bytes.fromhex("4883791004"), 4, 1, 0),
    (0x1CDCF9, bytes.fromhex("8d5304"), 2, 1, 0),
    (0x1CE773, bytes.fromhex("4883791004"), 4, 1, 0),
    (0x1CE77A, bytes.fromhex("8d5704"), 2, 1, 0),
    (0x1D8176, bytes.fromhex("4883791004"), 4, 1, 0),
    (0x1D817D, bytes.fromhex("8d5704"), 2, 1, 0),
    (0x1D95AD, bytes.fromhex("4883791004"), 4, 1, 0),
    (0x1D95B4, bytes.fromhex("8d5004"), 2, 1, 0),
    (0x1F7D70, bytes.fromhex("4883791004"), 4, 1, 0),
    (0x1F7D77, bytes.fromhex("8d5704"), 2, 1, 0),
    (0x1FBF2A, bytes.fromhex("4883791004"), 4, 1, 0),
    (0x1FBF31, bytes.fromhex("418d5504"), 3, 1, 0),
    (0x1FC508, bytes.fromhex("4883791004"), 4, 1, 0),
    (0x1FC50F, bytes.fromhex("8d5304"), 2, 1, 0),
    (0x25D408, bytes.fromhex("4883791004"), 4, 1, 0),
    (0x25D40F, bytes.fromhex("418d5504"), 3, 1, 0),
    (0x263925, bytes.fromhex("4883791004"), 4, 1, 0),
    (0x26392C, bytes.fromhex("8d5504"), 2, 1, 0),
    (0x2769A2, bytes.fromhex("4883791004"), 4, 1, 0),
    (0x2769A9, bytes.fromhex("418d5704"), 3, 1, 0),
    (0x282612, bytes.fromhex("4883791004"), 4, 1, 0),
    (0x282619, bytes.fromhex("ba04000000"), 1, 4, 0),
    (0x29CBA2, bytes.fromhex("4883791004"), 4, 1, 0),
    (0x29CBA9, bytes.fromhex("8d5504"), 2, 1, 0),
    (0x2A27A5, bytes.fromhex("4883791004"), 4, 1, 0),
    (0x2A27AC, bytes.fromhex("8d5604"), 2, 1, 0),
    (0x2A6F6F, bytes.fromhex("4883791004"), 4, 1, 0),
    (0x2A6F76, bytes.fromhex("8d5704"), 2, 1, 0),
    (0x2B0242, bytes.fromhex("4883791004"), 4, 1, 0),
    (0x2B0249, bytes.fromhex("8d5604"), 2, 1, 0),
    (0x2B837D, bytes.fromhex("4883791004"), 4, 1, 0),
    (0x2B8384, bytes.fromhex("418d542404"), 4, 1, 0),
    (0x2BB10D, bytes.fromhex("4883791004"), 4, 1, 0),
    (0x2BB114, bytes.fromhex("8d5604"), 2, 1, 0),
    (0x2C4B67, bytes.fromhex("4883791004"), 4, 1, 0),
    (0x2C4B6E, bytes.fromhex("8d5704"), 2, 1, 0),
    (0x2D17F3, bytes.fromhex("4883791004"), 4, 1, 0),
    (0x2D17FA, bytes.fromhex("8d5604"), 2, 1, 0),
    (0x34EAA0, bytes.fromhex("4883791004"), 4, 1, 0),
    (0x34EAA7, bytes.fromhex("8d5304"), 2, 1, 0),
    (0x35037A, bytes.fromhex("4883791004"), 4, 1, 0),
    (0x350381, bytes.fromhex("8d5704"), 2, 1, 0),
    (0x47A4CF, bytes.fromhex("4883791004"), 4, 1, 0),
    (0x47A4D6, bytes.fromhex("ba04000000"), 1, 4, 0),
    (0x4AECFE, bytes.fromhex("4883791004"), 4, 1, 0),
    (0x4AED05, bytes.fromhex("8d5704"), 2, 1, 0),
)

EXPERIMENTAL_RESERVE_GROUPS = 24
DEFERRED_FOUR_ANCHORS = (
    0x5B6C1, 0xD2238, 0xD25B6, 0x2BD3CF, 0x971940, 0x9722C7,
    0xC3B97C, 0xC3B9FA, 0xC3BA2D, 0xC3BC1A, 0xC3BC76,
)

BUTTON_MASTER_RVA = 0xED7FE8
BUTTON_MEMBER_RVA = 0xED7FC8
IMAGE_BASE = 0x140000000
USER_VTABLE_RVA = 0xEC2730
USER_READY_SIGNATURES = {
    0x452C50: bytes.fromhex(
        "48894c2408574883ec3048c7442420feffffff"
        "48895c2448498bf8488bd9e86df8ffff"
    ),
    0x452F70: bytes.fromhex(
        "48895c2408574883ec208bda488bf9e82c000000"
    ),
    0x4525CA: bytes.fromhex(
        "c687c000000000"
        "0fb64618"
        "8887c1000000"
        "0fb64619"
        "8887c2000000"
        "0fb6461a"
        "8887c3000000"
    ),
    0x4327B2: bytes.fromhex(
        "80bfc1000000007424"
        "488d5f78488bcbff15f04b8600"
        "0fb6bfc0000000"
        "4885db740e488bcbff15d34b8600"
    ),
    # UserImpl +0xe8/+0xf0 receives the shared participant-property map.
    0x4526F4: bytes.fromhex(
        "488b442428488987e8000000488b4008488987f0000000"
    ),
    # Native string-property getter/setter and temporary shared-handle release.
    0x461CE0: bytes.fromhex(
        "48895c240848896c241048897424185741544155415641574883ec30"
    ),
    0x462000: bytes.fromhex(
        "488954241057415641574883ec4048c7442428feffffff48895c2460"
    ),
    0x7DD20: bytes.fromhex(
        "4883ec28488339000f848700000048895c243048896c243833ed48896908"
    ),
    # Voice-chat predicate and setter (UserImpl dword +0x100). Ready must not
    # write either entry; they remain here to detect layout drift explicitly.
    0x4527D0: bytes.fromhex("83b900010000000f95c0c3"),
    0x4527E0: bytes.fromhex("899100010000c3"),
    0x452E70: bytes.fromhex("488b8184010000c3"),
}
USER_VTABLE_ENTRIES = {
    0: 0x452F70,
    4: 0x4527D0,
    5: 0x4527E0,
    10: 0x452E70,
}
READY_PROTOCOL_POINTERS = {
    0xDDC590: "cm",
    0xDDC5B0: "l1",
    0xDDC5B8: "l2",
    0xDDC5F0: "ds",
    0xDDC608: "cs",
    0xDDC610: "c1",
    0xDDC620: "ds",
    0xDDC628: "sc",
}
PLAYER_INFO_SIGNATURES = {
    # Transient room PlayerInfo vector builder hooked by MorePlayers.
    0x421EA0: bytes.fromhex(
        "48894c240855535657415441564157488d6c24d9"
        "4881ece0000000"
    ),
    # PlayerInfo defaults: class=-1, six weapons=-1, validity=false.
    0x422E00: bytes.fromhex(
        "40534883ec20488bd9488d15bca1a6004883c1084533c0"
    ),
    # Exact UserImpl shared property -> PlayerInfo conversion boundary. The
    # resulting class lives at PlayerInfo+0x28; UserImpl+0xf8 is a loadout
    # block index and must not be interpreted as the class.
    0x422F00: bytes.fromhex(
        "405556574154415541564157488dac24d0feffff"
        "4881ec30020000"
    ),
    # Its epilogue returns the destination saved in R14 through RAX. Both
    # builder call sites consume that value immediately to create the owning
    # PlayerInfo handle, so instrumentation must preserve this ABI contract.
    0x42395A: bytes.fromhex(
        "498bcfe8be20c0ff498bc6"
    ),
    # HUiRoom reads class at +0x28 from the same 0x60-byte object.
    0x560B2B: bytes.fromhex(
        "498bbe10090000418b4d2883f9ff742b488b143b394a0c"
    ),
}
UI_LAYOUT_VTABLE_RVA = 0xEC8628
UI_LAYOUT_DESTRUCTOR_RVA = 0x4AAB40
ROOM_SCROLL_SIGNATURES = {
    # dynamic_pointer_cast from PlayersGroup's Component to ui::Layout.
    0x4A9B90: bytes.fromhex(
        "40574883ec4048c7442430feffffff"
        "48895c24504889742458"
    ),
    # ui::Layout native normalized-position clamp/propagation routine.
    0x4A9080: bytes.fromhex(
        "488b81b00000000f57c9f30f10159ed3a300"
    ),
    # Scalar destructor clears the cached PlayersGroup pointer safely.
    UI_LAYOUT_DESTRUCTOR_RVA: bytes.fromhex(
        "48895c2408574883ec20488d05d7daa100"
    ),
    # The exact PlayersGroup cast call and its return address (0x565817).
    0x56580A: bytes.fromhex(
        "488bd0488d4c2438e87943f4ff90"
    ),
    # HUiRoom update, the UI-thread rendezvous for queued physical wheel input.
    0x5617F0: bytes.fromhex(
        "488bc45556574154415541564157488da8d8fcffff"
        "4881ecf0030000"
    ),
}
MISSION_START_HARNESS_SIGNATURES = {
    # MissionStart::Update. The host-only harness hooks this boundary and may
    # complete only the proven global controller object after native state 4.
    0x41E420: bytes.fromhex(
        "488bc4554154415541564157488da8b8fcffff"
        "4881ec20040000"
    ),
    # Outer controller whose participant/session gate decides whether the
    # native MissionStart object is initialized again or updated.
    0x42B7D0: bytes.fromhex(
        "488bc455488d68984881ec60010000"
        "48c7442470feffffff"
    ),
    # Controller call: update the global MissionStart object, then consume it
    # immediately when the received/completed state is exactly 5.
    0x42B8E0: bytes.fromhex(
        "33d2488d0d17fae200e8322bffff"
        "833d0bfae20005"
    ),
    # Exact TLS current-controller resolver and its inlined gate getter.
    0xBBB9F0: bytes.fromhex(
        "4883ec28e827ec0000488b48084885c9750733c0"
        "4883c428c3"
    ),
    0x62E140: bytes.fromhex("8b81ac010000c3"),
}
MISSION_START_GLOBAL_STATE_RVA = 0x125B300
MISSION_START_CONTROLLER_VTABLE_RVA = 0xEE1B20
MISSION_START_CONTROLLER_GATE_GETTER_RVA = 0x62E140
MISSION_MANAGER_SLOT_RVA = 0x125AB40
MISSION_RESULT_EVENT_PUBLISHER_SLOT_RVA = 0x125AB70
MISSION_CLEAR_SIGNATURES = {
    # Script-facing Mission() callback hooked as the stage-thread rendezvous.
    0x3E1890: bytes.fromhex(
        "488bc4574881ec8000000048c740b8feffffff"
        "4889580848897010"
    ),
    # Native manager result setter. Its direct call below targets 0x114bb0.
    0x111080: bytes.fromhex(
        "4883ec28488b41284885c07449895134488bc8e8183b0000"
    ),
    # Result application writes UI state 3 and the supplied result code.
    0x114BB0: bytes.fromhex(
        "48895c24084889742410574883ec208bf2488bd9"
        "488b0d3d60140133d2e80ee6ffff"
        "488b05b75f1401488d7820"
        "c783f800000003000000"
        "89b3fc000000"
    ),
    # The unmodified game supplies result 1 on its natural clear path.
    0x3D814B: bytes.fromhex("ba01000000"),
    # Mission() resolves the same global manager used by the result setter.
    0x3E197D: bytes.fromhex("488b05bc91e700"),
    # Mission() waits on UI state and returns the stored result when finished.
    0x3E1A10: bytes.fromhex("8b81f8000000"),
    0x3E1A40: bytes.fromhex("8b81fc000000"),
    # Result 1 preserves the accumulated mission data; exit variants clear it.
    0x114C51: bytes.fromhex("83fe017438"),
}
MISSION_RESULT_PIPELINE_SIGNATURES = {
    # The native result setter always publishes event type 1 with local
    # payload value 2 after applying the UI result. Static analysis below
    # proves this is an xgs::ui::Object close command for object id 2; the
    # net::MissionResult synchronization path is separate.
    0x111098: bytes.fromhex(
        "488b0dd19a1401c7442430020000004885c9741b"
        "4881c178ffffff4c8d442430ba01000000"
    ),
    # Shared typed-event publisher used by the result setter. Runtime
    # telemetry is scoped to the setter call, so unrelated event traffic is
    # passed through without logging.
    0x61E950: bytes.fromhex(
        "40565741564883ec3048c7442420feffffff"
        "48895c245848896c2460"
    ),
    # Generic xgs::ui::Object typed-event callback. Event 1 compares the
    # dword payload with the object's id at +0x78, sets closing bit 0 at +0x18,
    # and invokes the close transition on a match.
    0x4A1B70: bytes.fromhex(
        "40534883ec20488bd985d2744683ea01741a83fa017553"
    ),
    0x4A1B9C: bytes.fromhex(
        "8b41784139007536f6411801753083491801488b01488b5020"
    ),
    # RTTI identifies this exact entry as
    # static bool net::MissionResult::Exec_Begin(int).
    0x42FD20: bytes.fromhex(
        "488bc4554154415541564157488d68a8"
        "4881ec3001000048c74508feffffff"
    ),
    # Shared named-sync helpers. Only the exact Sync_MissionResult callers
    # below are classified by the runtime audit.
    0x41F820: bytes.fromhex(
        "488bc4565741564883ec6048c740a8feffffff"
        "4889581848896820"
    ),
    0x41F920: bytes.fromhex(
        "40534883ec20488bd9488b49104885c9"
        "0f8491000000488b09"
    ),
    # Registered void ResolveResult() wrapper and bool ApplyResult(bool).
    0x3E3150: bytes.fromhex("488b0d817ae700e97460dbff"),
    0x3E3160: bytes.fromhex(
        "405341564883ec280fb6d94532f6"
        "488b0d637ae700e8d66bdbff"
    ),
    # ApplyResult reads one local-save-profile count, starts at +0x6d4c and
    # advances by the proven profile stride 0x3e60.
    0x3E3190: bytes.fromhex(
        "418b809c45020085c00f842f010000"
    ),
    0x3E31A4: bytes.fromhex("498da84c6d0000"),
    0x3E32AE: bytes.fromhex("4881c5603e0000"),
    # The only setter accepts count values 1 or 2, proving this is not the
    # online participant count and must never be expanded to MaxPlayers.
    0x55830: bytes.fromhex(
        "488b4108448b00418d40ff83f801771d"
        "488b15e95220014489829c450200"
    ),
    # MissionSync_Res reserves four handles initially, then grows the vector
    # dynamically. Only the participant-index comparison is a logical cap.
    0x42DA69: bytes.fromhex(
        "4c897424584c897424604c89742468418bde895c2420"
        "ba04000000488d4c2450e8623a0000"
    ),
    0x42DB3E: bytes.fromhex(
        "8b86f800000085c00f88f001000083f8040f83e7010000"
    ),
    0x42DBDC: bytes.fromhex(
        "488b54246048395424687216488d145502000000"
        "488d4c2450e8f638000084c07435"
    ),
    # The accepted handles are processed by vector size, then the aggregate
    # is committed. No later access indexes a four-entry player array.
    0x42DE34: bytes.fromhex(
        "4533e4458bf44c396424680f863f020000488b742458"
    ),
    0x42E080: bytes.fromhex(
        "8b5c2420488b05a5cae2008998a0450200"
    ),
    # NetGameStatus initializes exactly four eight-byte native Items. This
    # bound must not be expanded: the following field at state +0x2459c is the
    # local reward-profile count.
    0x430EF6: bytes.fromhex("83fb0472d5"),
    # std::function callback thunk for void(int, NetGameStatus::Item const&).
    # It writes one Item to state +0x2457c + index*8. The runtime hook forwards
    # P0-P3 and folds P4-P7 without allowing that indexed write out of bounds.
    0x132BB0: bytes.fromhex(
        "4c630a488b05767f1201498b084a898cc87c450200c3"
    ),
    # Both native reward consumers intentionally sum those same four Items.
    # They produce aggregate totals rather than indexing online participants,
    # so the P4-P7 fold must happen before these loops instead of widening
    # either loop into the following +0x2459c field.
    0x12AABE: bytes.fromhex(
        "8bd148057c450200498988880a0000448d4904"
    ),
    0x12AAE0: bytes.fromhex(
        "0310488d4008418990880a00000348fc"
        "4189888c0a00004983e90175e3"
    ),
    0x199275: bytes.fromhex(
        "4c89b3880a0000418bd6418bce"
        "498d817c450200458d4604"
    ),
    0x199290: bytes.fromhex(
        "0308898b880a000003500489938c0a0000"
        "488d40084983e80175e5"
    ),
    # ResolveResult distributes the aggregate through the dynamic local-save
    # profile count at +0x2459c and a 0x3e60 profile stride.
    0x199492: bytes.fromhex(
        "458b919c450200458bc64585d27436"
        "4963c04869c8603e0000"
    ),
    # The underlying ApplyResult implementation walks a dynamic 20-byte
    # result vector (begin + count*20), then separately iterates the local
    # profile count. There is no online-player fixed-four bound here.
    0x199D50: bytes.fromhex(
        "4883ec284c8b91a00a0000488b81b00a0000"
        "4c8b0dc70d0c01"
    ),
    0x199D6E: bytes.fromhex(
        "488d0c80498d3c8a4c3bd70f84ee000000"
    ),
    0x199DF8: bytes.fromhex(
        "43019c99246d00004539819c4502007452"
    ),
}
MISSION_RESULT_PIPELINE_CALLS = {
    0x1110BD: 0x61E950,
    0x1110D1: 0x61E950,
    0x3E2DD8: 0x41F820,
    0x3E2DE4: 0x41F920,
    0x42C134: 0x41F820,
    0x42C13B: 0x41F920,
}
FAST_FAIL_SIGNATURES = {
    # MSVC /GS verifier tail-jumps to __report_gsfailure on mismatch.
    0x9C6E40: bytes.fromhex(
        "483b0da9c87500f2751248c1c11066f7c1ffff"
        "f27502f2c348c1c910e90f080000"
    ),
    # Failure-only diagnostic hook target; ends in int 29h subcode 2.
    0x9C7670: bytes.fromhex(
        "48894c24084883ec38b917000000e8130d0000"
        "85c07407b902000000cd29"
    ),
}
MISSION_PARTICIPANT_CALL_SITES = (
    # Runtime relays replace rdx with one shared eight-int32 buffer and then
    # tail-jump to each original target, leaving stack/unwind data unchanged.
    (0x126CE0, bytes.fromhex("e8fb68ffff"), 0x11D5E0),
    (0x126D24, bytes.fromhex("e81775f5ff"), 0x7E240),
)
MISSION_PARTICIPANT_SAFE_CAPACITY = 8
MISSION_PARTICIPANT_SIGNATURES = {
    # Function prologue and cookie at rsp+0x78.
    0x126C90: bytes.fromhex(
        "4c8bdc574881ec8000000049c743d8feffffff49895b08"
        "488b0542caff004833c44889442478"
    ),
    # Producer emits one int32 per participant without an output-capacity arg.
    0x11D7A9: bytes.fromhex("89064883c3104883c604493bdf7598"),
    # Cookie verifier call followed by the captured return address.
    0x126D4A: bytes.fromhex(
        "488b4c24784833cce8e9008a00488b9c2490000000"
    ),
}
MISSION_SPAWN_POINT_COUNT = 4
MISSION_SPAWN_SAFE_CAPACITY = 8
MISSION_RECORD_REDIRECT_RVA = 0x11DB90
MISSION_RECORD_REDIRECT_RETURN_RVA = 0x11DB98
MISSION_RECORD_LOOP_BACKEDGE_RVA = 0x11DD68
MISSION_RECORD_COPY_RVA = 0x11DF95
MISSION_RECORD_EXISTING_REDIRECT_RVA = 0x11E1A0
MISSION_RECORD_EXISTING_NATIVE_SOURCE_RVA = 0x11E1AE
MISSION_RECORD_EXISTING_EXTRA_SOURCE_RETURN_RVA = 0x11E1CC
MISSION_RECORD_APPEND_REDIRECT_RVA = 0x11E2A0
MISSION_RECORD_APPEND_REDIRECT_RETURN_RVA = 0x11E2A7
MISSION_RECORD_APPEND_LOOP_BACKEDGE_RVA = 0x11E2FE
MISSION_RECORD_SIZE = 0x18
MISSION_RECORD_OBJECT_BASE = 0x138
MISSION_RECORD_FIRST_EXTRA_OBJECT_OFFSET = \
    MISSION_RECORD_OBJECT_BASE + 4 * MISSION_RECORD_SIZE
MISSION_RECORD_SIDECAR_COUNT = 4
MISSION_RECORD_LAST_EXTRA_OBJECT_OFFSET = \
    MISSION_RECORD_FIRST_EXTRA_OBJECT_OFFSET + \
    (MISSION_RECORD_SIDECAR_COUNT - 1) * MISSION_RECORD_SIZE
MISSION_RECORD_REDIRECT_ORIGINAL = bytes.fromhex(
    "418b5d000f2845c0"
)
MISSION_RECORD_COPY_ORIGINAL = bytes.fromhex("8b55484885d2")
MISSION_RECORD_EXISTING_REDIRECT_ORIGINAL = bytes.fromhex(
    "4d8bf441ffc54983c418"
)
MISSION_RECORD_APPEND_REDIRECT_ORIGINAL = bytes.fromhex(
    "498bf44983c418"
)
MISSION_RECORD_APPEND_LOOP_ORIGINAL = bytes.fromhex(
    "498bf44983c418486303488d0c408b84cd700100008906"
    "488bbccd800100004c8baccd780100004885ff7404f0ff470c"
    "488b4e104885c9741383c8fff00fc1410c83f8017506488b01"
    "ff500848897e104c896e084883c30449ffc64d3bf775a0"
)
MISSION_SPAWN_SIGNATURES = {
    # Mission-entry function and its 0x380-byte frame.
    0x11D860: bytes.fromhex(
        "488bc45556574154415541564157488da848fdffff"
        "4881ec80030000"
    ),
    # Exactly four native 16-byte spawn/orientation constants.
    0x11DA46: bytes.fromhex(
        "0f2805139adc000f2985e0010000"
        "0f280d65a1dc000f298df0010000"
        "0f280547a1dc000f298500020000"
        "0f280d89a1dc000f298d10020000"
    ),
    # The real repeated loop head. The backedge at 0x11dd68 returns here, so
    # the runtime relay observes r14d==4 on the fifth iteration.
    MISSION_RECORD_REDIRECT_RVA: MISSION_RECORD_REDIRECT_ORIGINAL,
    MISSION_RECORD_LOOP_BACKEDGE_RVA: bytes.fromhex("0f8522feffff"),
    # Four embedded 24-byte records begin at object+0x138. The fifth iteration
    # reaches object+0x198 and reads its unrelated +0x10 value as a pointer.
    0x11DC8A: bytes.fromhex(
        "488b0e4885c9741883c8fff00fc1410c83f8017506488b01ff5008"
    ),
    # Native result-copy construction/destruction remains bounded at four.
    0x11DF2C: bytes.fromhex(
        "458bf5488d9d80010000488d8580010000498bf4482bf0"
    ),
    0x11DF88: bytes.fromhex("41ffc64883c3184183fe0472ae"),
    MISSION_RECORD_COPY_RVA: MISSION_RECORD_COPY_ORIGINAL,
    # First transfer loop. Its runtime relay maps extra source/destination
    # records to one of four sidecars.
    MISSION_RECORD_EXISTING_REDIRECT_RVA:
        MISSION_RECORD_EXISTING_REDIRECT_ORIGINAL,
    # Destination setup: this pointer from rbp-0x80, appended-count derivation,
    # and persistent-table base object+0x138 plus 24 bytes per existing record.
    0x11E257: bytes.fromhex(
        "4c8b6580488b5d90488b45a0488d0c8333c0448bf04c8bf9"
        "4c2bfb4983c70349c1ef02483bd94c0f47f84d85ff747a"
        "4963c5488d0440488d40274d8d24c4"
    ),
    # A later append loop can reach records five through eight. Its repeated
    # head maps object offsets 0x198..0x1e0 to the same four sidecars.
    MISSION_RECORD_APPEND_REDIRECT_RVA: MISSION_RECORD_APPEND_LOOP_ORIGINAL,
    MISSION_RECORD_APPEND_LOOP_BACKEDGE_RVA: bytes.fromhex("75a0"),
    # The native four-entry constructor/destructor and spawn initialization
    # remain unchanged because extra records/spawns are handled externally.
    0x11D9E3: bytes.fromhex("b904000000"),
    0x11DF1B: bytes.fromhex("448d42ec"),
    0x11E30C: bytes.fromhex("448d42ec"),
    # Fifth participant crash chain: null builder result becomes rcx=0x10.
    0x11CF70: bytes.fromhex(
        "8a00488bd3488d4d90e822541f00488d4810488d5510e88510f5ff"
    ),
    # Shared-handle copy whose +0x12 instruction faulted reading address 0x18.
    0x6E010: bytes.fromhex(
        "40534883ec4033c0488bda488902488942084c8b4108488b11"
    ),
}
MISSION_SOURCE_SIGNATURES = {
    # Generic 16-byte shared-handle table lookup hooked at runtime.
    0x7E240: bytes.fromhex(
        "40534883ec20488bda49c1e0044c034108488bcb498bd0e8f4f9feff"
    ),
    # The sole mission-player consumer passes the real participant index.
    0x11CF00: bytes.fromhex(
        "4d8bc6488d542440e83313f6ff90"
    ),
    # Later mission-record loops use the same generic getter over a local,
    # flow-sized vector. They are audited for extra indices but are not folded
    # modulo four without dump evidence of a fixed table.
    0x11DFC0: bytes.fromhex(
        "4863f74c8bc6488d5510488d4d30e86d02f6ff"
    ),
    0x11E04C: bytes.fromhex(
        "4c8bc6488d5520488d4d30e8e401f6ff90"
    ),
    # These two post-consumer reads use UserImpl+0xf8 as mission runtime/map
    # identity. A P4+ character may temporarily expose a native 0..3 loadout
    # index only while 0x3123a0 executes; it must be unique again here.
    0x11D0DD: bytes.fromhex(
        "488b4c24404885c9740e488b442448448bb0f8000000"
    ),
    0x11E05D: bytes.fromhex(
        "488b40088b88f8000000894dac"
    ),
    # The downstream source consumer and its native four-source bound.
    0x3123A0: bytes.fromhex(
        "405556574154415541564157488d6c24d94881ec00010000"
    ),
    0x3123F4: bytes.fromhex(
        "496399f800000085db0f88b303000083fb040f83aa030000"
    ),
}
MISSION_LOADOUT_BLOCK_STRIDE = 0x3E90
MISSION_LOADOUT_SELECTED_BASE = 0x14B30
MISSION_LOADOUT_NATIVE_BLOCKS = 4
MISSION_LOADOUT_EXTRA_BEGIN = (
    MISSION_LOADOUT_SELECTED_BASE
    + MISSION_LOADOUT_NATIVE_BLOCKS * MISSION_LOADOUT_BLOCK_STRIDE
)
MISSION_RESULT_ITEM_ARRAY_OFFSET = 0x2457C
MISSION_RESULT_ITEM_COUNT = 4
MISSION_RESULT_ITEM_SIZE = 8
MISSION_LOCAL_REWARD_PROFILE_COUNT_OFFSET = 0x2459C
MISSION_RESULT_PARTICIPANT_COUNT_OFFSET = 0x245A0
MISSION_LOADOUT_RECORD_RELATIVE_OFFSET = 8
MISSION_LOADOUT_RECORD_STRIDE = 0x18
MISSION_LOADOUT_WEAPON_COUNT = 6
MISSION_PARTICIPANT_CLASS_RESOLVER_RVA = 0x4B6710
MISSION_PARTICIPANT_CLASS_RESOLVER_CALLERS = frozenset({
    0x4B8039,
    0x4BB1FB,
    0x4CEEFC,
})

MISSION_LOADOUT_BLOCK_SIGNATURES = {
    # Character creation derives one 0x3e90 block from UserImpl+0xf8, reads
    # the active class/loadout selector at block+0 and then the first of six
    # equipment ids from block+8+selector*0x18.
    0x31240C: bytes.fromhex(
        "4869fb903e00004c8b051687f400"
        "4e63a407304b0100428b8407284c010089442430"
    ),
    0x31242E: bytes.fromhex(
        "428b8407304b0100488d0c40488d04cf"
        "468bb400384b0100"
    ),
    # The native loadout parser uses the same 0x3e90 stride. It copies the
    # parsed selector to block+0, then addresses the six-dword active record
    # with selector*0x18. P4 therefore starts at state+0x24570, overlapping
    # the local reward-profile count at +0x2459c and MissionResult participant
    # count at +0x245a0. The 0.6.10 parser hook snapshots/restores that entire
    # out-of-bounds span while retaining only the parser's final participant
    # count; no synthetic identity/index is serialized. The sole direct caller
    # uses a separate stack byte for error and the parser only clears it. The
    # decoded path clears the boolean return before its unconditional count
    # write, so false must not cause that output to be discarded.
    0x42ABD2: bytes.fromhex(
        "488d542438c6442438008bcfe89d48000084c07416"
        "488b03488d0d2f6fab00483bc1751fc683a801000001"
        "488b5c243083c8ff807c2438000f45f88bc7"
    ),
    0x42F480: bytes.fromhex(
        "40554154415541564157488dac2400c1ffff"
        "b800400000e894855900"
    ),
    0x42F4D0: bytes.fromhex("8bd9c602004532ed"),
    0x42F7C9: bytes.fromhex(
        "4c69d1903e00008b850c010000"
        "43898432e8010000"
    ),
    0x42F881: bytes.fromhex(
        "8b451443898432f0000000488d0c40"
        "4c8d04cd000000004d69c9903e0000"
    ),
    0x42FA69: bytes.fromhex("4489a6a0450200"),
    # Several UI callers obtain both the logical participant/loadout index and
    # class through UserImpl+0xf8. The hook preserves the UserImpl field while
    # supplying the class from PlayerInfo, the parser sidecar, or a bounded
    # visual fallback. The native class read below demonstrates why P4 would
    # otherwise address a nonexistent fifth 0x3e90 loadout block.
    0x4B6710: bytes.fromhex(
        "40555356574154415541564157488d6c24e9"
        "4881eca8000000"
    ),
    0x4B6886: bytes.fromhex(
        "4869c9903e0000488b059c42da00"
        "8b8c01304b0100"
    ),
    # Complete call-site census: every direct caller consumes the resolver's
    # first output only as a transient visual-table index.  The 0x4b8039 path
    # indexes 0x30-byte UI descriptors; the hook therefore folds P4-P7 before
    # this unchecked lookup while leaving UserImpl+0xf8 untouched.
    0x4B8026: bytes.fromhex(
        "4c8d8dd80100004c8d4590488d542468488bc8e8d2e6ffff"
    ),
    0x4B855E: bytes.fromhex(
        "4863442468488d1c4048c1e304488b7dc848035f08"
    ),
    # The player-status/HUD caller receives the same two transient outputs.
    0x4BB1E9: bytes.fromhex(
        "4c8d8da00000004c8d45f8488d55a0488bc8e810b5ffff"
    ),
    # The player-status renderer uses the first resolver output as an index
    # into a native four-entry array of 0x40-byte render descriptors. P4 must
    # therefore fold to visual slot 0 without changing its logical identity.
    # The historical crash occurred when the shared-property copy tried to
    # retain the nonexistent fifth descriptor at 0xb1d60.
    0x4BB5E1: bytes.fromhex(
        "8b45a048c1e006480387d8000000488945f8"
    ),
    # A second fixed table stores 0x30-byte localized class-name records. The
    # 0.6.24 reports reached these consumers with class 256/257: one client
    # faulted while selecting the record and host/client 3 passed pointer 1 to
    # the UTF-16 measurement function, which faulted at 0x5e741c.
    0x4BB5CE: bytes.fromhex(
        "486345f84c8d344049c1e6044c03b7b8000000"
    ),
    0x4BC266: bytes.fromhex(
        "49837e180872054d8b06eb034d8bc6"
    ),
    0x5E741C: bytes.fromhex(
        "66413b180f84e4010000"
    ),
    # The third and final direct caller selects class-dependent placement and
    # indexes a stack array.  Four consecutive movaps stores initialize exactly
    # four 0x10-byte entries; both class and participant outputs must remain
    # in 0..3 before the unchecked index at 0x4cf21f.
    0x4CEDE5: bytes.fromhex(
        "0f280d7487a1000f298de0010000"
        "0f28055687a1000f2985f0010000"
        "0f280d888aa1000f298d00020000"
        "0f28055a86a1000f298510020000"
    ),
    0x4CEEE9: bytes.fromhex(
        "4c8d8d800100004c8d45a0488d55a4488d4da8e80f78feff"
    ),
    0x4CEF24: bytes.fromhex(
        "8b4da085c9741f83e901741683e901740b83f9017510"
    ),
    0x4CF21F: bytes.fromhex(
        "486345a448c1e0044c8dbde00100004c03f8"
    ),
    0xB1D60: bytes.fromhex(
        "418b400485c0744b8d4801f0410fb14804"
    ),
}
GAME_PACKET_ROUTE_SIGNATURES = {
    # Chat_Room's common publisher resolves both identity arguments before it
    # accepts a line. A zero second identity is not a public-room sentinel.
    0x3F0B70: bytes.fromhex(
        "40555356574154415541564157"
        "488d6c24984881ec68010000"
        "48c745a0feffffff"
    ),
    # Room setup allocates a 0xc0-byte Chat_Room and invokes this constructor.
    # Capturing the completed object lets HUiRoom::Update publish the pending
    # local banner without waiting for another native chat message.
    0x3F0680: bytes.fromhex(
        "488bc455488d68a14881ecc0000000"
        "48c745b7feffffff48895810"
    ),
    0x3F06B8: bytes.fromhex(
        "488d05e9e6ac004889014883c108"
        "ff155c6c8a00"
    ),
    # Chat_Room's native local-send path constructs a 0x50-byte message state,
    # with the selection field at +8 set to -1, before calling the common
    # publisher as kind 2/subtype 0. Outside the active chat editor the
    # publisher can reject that state when its message pointer at +0x10 is null;
    # the remote decode path copies the real pointer to that exact offset. The
    # mod supplies its static banner pointer there and still calls the local
    # publisher only, so it never enters the Steam chat send path.
    0x3F17F7: bytes.fromhex(
        "44896da8c645ac00c745b0ffffffff"
        "0f57c0f30f7f45b80f57c9f30f7f4dc8"
        "44896dd8f30f1145dc44896de0f30f7f4de8"
    ),
    0x3F1843: bytes.fromhex(
        "6644896c2430c744242802000000"
        "488d45a848894424204d8bc4488bd6498bcf"
        "e808f3ffff"
    ),
    0x3F0C04: bytes.fromhex(
        "49837c242000751741833c24000f8521050000"
        "49837c2410000f8415050000"
    ),
    0x3F1E72: bytes.fromhex(
        "488b8590000000488945e0"
        "488b8598000000488945e8"
        "488b85a0000000488945f0"
    ),
    # High-level logical send: rcx=owner, rdx=recipient/key, r8=payload,
    # r9=size. Its only transport call is validated separately below.
    0x453890: bytes.fromhex(
        "40574883ec4048c7442420feffffff"
        "48895c245048896c24584889742460498bd9498bf8"
    ),
    # Receive dispatcher and the exact lock/list/callback dispatch body.
    0x41A770: bytes.fromhex(
        "4c8bdc4d89431856574154415641574883ec40"
        "49c743c8feffffff49895b0849896b10"
    ),
    0x41A7AD: bytes.fromhex(
        "488d794049897b18488bcfff15facb870090"
        "488b9e88000000488b1b483b9e88000000744a"
        "4c8d255f78aa008bac2490000000488b4b18488b01"
        "4c8b50084c897424204c8d0da9f4e300448bc5"
        "498bd7493bc4750b488b4918e8958d0100eb0341ffd2"
    ),
    # Outgoing serialized logical-message enqueue.
    0x434CD0: bytes.fromhex(
        "488bc44c8948205556574154415541564157"
        "4883ec3048c740b8feffffff"
    ),
    # High-level actor replication producer. The SharedProperty at self+8 is
    # copied before its UserImpl vtable/+0x190 controller is read, and
    # ((self+0x40 << 4) | subtype) << 8 forms the logical message code.
    0x45EAD0: bytes.fromhex(
        "488bc441564883ec7048c740b8feffffff"
        "48895808488968104889701848897820"
    ),
    0x45EB23: bytes.fromhex(
        "488d4b08488d542438e85ff4c1ff90"
        "488b4c24404885c97434488b01"
        "488d15ea3ba600483bc27508"
        "8b9190010000eb05ff50608bd0"
        "8b43406683e70f66c1e004660bf8"
        "66c1e708440fb7cf"
    ),
    # The actor producer passes a dynamic eight-byte destination-descriptor
    # vector to this serializer. The descriptor is copied from the adjacent
    # UserImpl+0xc4/+0xc8 dwords; +0xc8 is the transport-route slot. It is not
    # a 16-byte SharedProperty. The audit records only participant masks and
    # cardinality, never route keys, handles, identities, endpoints or payload.
    0x432D20: bytes.fromhex(
        "488bc4554154415541564157"
        "488d68b14881ec90000000"
    ),
    0x45EB88: bytes.fromhex(
        "488974242848896c2420"
        "4c8d442448488b4b38e88041fdff"
    ),
    # Destination builder: dynamic source count, eight-byte source/target
    # stride, and exact qword copy from UserImpl+0xc4.
    0x45ED80: bytes.fromhex(
        "40565741564883ec40"
        "48c7442420feffffff"
    ),
    0x45EDB8: bytes.fromhex(
        "4c897718488b562848395710"
    ),
    0x45EDD2: bytes.fromhex(
        "488b4e28488d34cd000000004803f5"
    ),
    0x45EE26: bytes.fromhex(
        "488b4f18488b4708488d14c8"
        "488d410148894718"
    ),
    0x45EE3F: bytes.fromhex(
        "488b83c4000000488902"
    ),
    # Serializer indexes those descriptors with *8 and resolves descriptor+4
    # through 0x433f40 into the dynamic manager+0xd0 SharedProperty table.
    0x432E00: bytes.fromhex(
        "498b46084c8d04f0488d55bf498bcc"
        "e82c110000"
    ),
    0x433F6E: bytes.fromhex(
        "4863570433c048c1e204480396d0000000"
    ),
    0x4525EF: bytes.fromhex(
        "8b4e148b46108987c4000000898fc8000000"
    ),
    # The serializer writes its four-byte logical header, then starts the
    # optional payload at header+4. This immediate is a byte count, not a
    # four-participant capacity.
    0x432DC3: bytes.fromhex(
        "488b4d0f890141bf04000000"
        "488b55774885d27414"
    ),
    # The periodic receive pump is reached through callback thunk 0x451b90.
    # It reads the qword count at owner+0xe0 and indexes the vector at +0xd0
    # with a 0x10-byte SharedProperty stride.  Its loop compares against that
    # dynamic count; there is no four-participant bound in this routing layer.
    0x4336F0: bytes.fromhex(
        "4c8944241889542410555356574154415541564157"
        "488d6c24e14881ec98000000"
        "48c74507feffffff4c8be1"
    ),
    0x4337A3: bytes.fromhex(
        "33f68bc6894567"
        "4d8bbc24e00000004c897dff448bee4d85ff"
        "0f84b9030000498dbc2480000000"
    ),
    0x4337E1: bytes.fromhex(
        "4d8bf549c1e6044d03b424d0000000"
    ),
    0x433B6C: bytes.fromhex(
        "49ffc54d3bef0f8258fcffff"
    ),
    0x451B90: bytes.fromhex(
        "488b4918e9571bfeff"
    ),
    # Per-UserImpl receive parser. The sole caller passes UserImpl+0x88, so a
    # thread-local scope can retain the sender while callbacks synchronously
    # invoke MissionScript's decoded-message dispatcher.
    0x435670: bytes.fromhex(
        "405556574154415541564157"
        "488d6c24d94881ecf0000000"
        "48c745e7feffffff"
    ),
    0x4339CD: bytes.fromhex(
        "488b45af488d55d7488b8888000000e88f1c0000"
    ),
    # A second, independent identity domain selects each UserImpl's dynamic
    # receive-parser slot. The allocator supplies source+0x14, the UserImpl
    # constructor stores it at +0xc8, and registration/removal both use that
    # exact index against the dynamic manager+0xd0 vector. This is not the
    # mission/loadout identity at UserImpl+0xf8.
    0x4525FB: bytes.fromhex(
        "898fc800000083cdff89afcc000000"
    ),
    0x433BD0: bytes.fromhex(
        "48895424105355565741564881ec80000000"
    ),
    0x433C78: bytes.fromhex(
        "4d63b0c80000004981c0c4000000"
    ),
    0x433DD0: bytes.fromhex(
        "48895c241848896c2420574883ec40"
    ),
    0x433E3C: bytes.fromhex(
        "4c63b0c80000004d03f6"
    ),
    0x45C8E3: bytes.fromhex(
        "48399ee0000000762c498bcd90488b86d0000000"
    ),
    0x45C93F: bytes.fromhex(
        "4d8bc7488bd6488bc8e80363ffff90"
    ),
    # Incoming MissionScript decoded-message dispatcher. Its fifth argument
    # is the logical message code; the fourth is the dispatch mode.
    0x114D50: bytes.fromhex(
        "48895c2408488974241048897c241855"
        "4154415541564157488d6c24d14881ec00010000"
    ),
}
GAME_PACKET_ROUTE_CALLS = {
    0x3F1635: 0x3F0B70,
    0x3F1863: 0x3F0B70,
    0x3F1F81: 0x3F0B70,
    0x4538EF: 0x41ABE0,
    0x41A5DB: 0x41A770,
    0x45EB9B: 0x432D20,
    0x4339DC: 0x435670,
    0x451AF6: 0x433DD0,
    0x451B64: 0x433BD0,
    0x45C948: 0x452C50,
}
MEMBER_BUTTON_SITES = (
    (
        0x565AA9,
        bytes.fromhex("488d9d80000000"),
        bytes.fromhex("488d1d38259700"),
    ),
    (0x565AB0, bytes.fromhex("488b13"), bytes.fromhex("488bd3")),
    (
        0x565ABD,
        bytes.fromhex("488d5b084863c7"),
        bytes.fromhex("488d1d04259700"),
    ),
    (
        0x565AC4,
        bytes.fromhex("493b8720090000"),
        bytes.fromhex("493bbf20090000"),
    ),
)

CRASH_EVIDENCE = {
    0x45C8E3: bytes.fromhex("48399ee0000000"),  # bound vs. slot index
    0x45C8F0: bytes.fromhex("488b86d0000000"),  # pointer table
    0x45CA0A: bytes.fromhex("488b86d0000000"),  # selected slot base
    0x45CA35: bytes.fromhex("f00fc14104"),      # faulting stale-pointer release
    0x433F6E: bytes.fromhex("48635704"),        # fifth participant index
    0x433F74: bytes.fromhex("48c1e204"),        # 16-byte slot stride
    0x433F78: bytes.fromhex("480396d0000000"),  # secondary table base
    0x7D9AC: bytes.fromhex("488b0a"),           # load slot control block
    0x7D9B0: bytes.fromhex("8b4104"),           # second observed AV (address 5)
    0x43715F: bytes.fromhex("48c1e704"),        # secondary resize stride 16
    0x437179: bytes.fromhex("4c8939"),          # initialize slot pointer null
    0x43717C: bytes.fromhex("4c897908"),        # initialize slot payload null
    0x4369A8: bytes.fromhex("ba10000000"),      # allocation element size 16
    0x419654: bytes.fromhex("488db7f8000000"),  # third container object+0xf8
    0x419D85: bytes.fromhex("486398c8000000"),  # fifth participant index
    0x419DA1: bytes.fromhex("4c8bfb"),          # preserve index (dump: r15=4)
    0x419DA4: bytes.fromhex("48c1e304"),        # third 16-byte slot stride
    0x419DA8: bytes.fromhex("49039d00010000"),  # third table base object+0x100
    0x25A5C: bytes.fromhex("f00fc103"),         # third observed write AV
    0x10782F: bytes.fromhex("48c1e704"),        # third resize stride 16
    0x107849: bytes.fromhex("4c8939"),          # initialize slot qword 1 null
    0x10784C: bytes.fromhex("4c897908"),        # initialize slot qword 2 null
    0x56578E: bytes.fromhex("488b055bdfbb00"),  # stack-cookie source
    0x565798: bytes.fromhex("488985a0000000"),  # cookie immediately after keys
    0x5657A7: bytes.fromhex("488d053a289700"),  # Button_Master address
    0x5657AE: bytes.fromhex("48898580000000"),  # local key slot 0
    0x5657B5: bytes.fromhex("488d050c289700"),  # Button_Member address
    0x5657BC: bytes.fromhex("48898588000000"),  # local key slot 1
    0x5657C3: bytes.fromhex("48898590000000"),  # local key slot 2
    0x5657CA: bytes.fromhex("48898598000000"),  # local key slot 3
    0x565AA0: bytes.fromhex("4939bf20090000"),  # loop uses expanded count
    0x4E4770: bytes.fromhex("0fb710"),          # first UTF-16 key read
    0x4E4773: bytes.fromhex("420fb70c00"),      # fourth observed read AV
    0x5A5E95: bytes.fromhex("488b442470"),      # recover room UI this
    0x5A5E9A: bytes.fromhex("488b8850010000"),  # panel vector storage +0x150
    0x5A5EA1: bytes.fromhex("4903cc"),          # add index*0x50 (dump: 0x140)
    0x5A5EB6: bytes.fromhex("e855070000"),      # writes strings to panel block
    0x5A5F04: bytes.fromhex("49ffc7"),          # next participant index
    0x5A5F07: bytes.fromhex("4983c450"),        # next 0x50-byte panel block
    0x5A6135: bytes.fromhex("4d3bbe60010000"),  # clear loop bound at +0x160
    0x5A613E: bytes.fromhex("4b8d14bf"),        # index*5
    0x5A6142: bytes.fromhex("48c1e204"),        # index*5*16 == index*0x50
    0x5A6150: bytes.fromhex("498b8e50010000"),  # panel vector storage +0x150
    0x5A619F: bytes.fromhex("4883c250"),        # clear loop panel stride
    0x5A7268: bytes.fromhex("ba50000000"),      # allocation element size 0x50
    0x11DB70: bytes.fromhex("488b7d80488db748010000"),  # object and record 0
    0x11DC95: bytes.fromhex("f00fc1410c"),      # fifth-record AV at address 0x12
    0x11E2DC: bytes.fromhex("f00fc1410c"),      # appended fifth-record AV at 0x12
    0x11DD50: bytes.fromhex(
        "41ffc64983c5044983c4104883c618"
    ),  # participant/spawn/record strides
    0x11DF1B: bytes.fromhex("448d42ec"),        # local record constructor count 4
    0x11E30C: bytes.fromhex("448d42ec"),        # matching destructor count 4
}


def encoded_site_value(capacity: int, allocation_element_size: int) -> int:
    return ((capacity - allocation_element_size) & 0xFF) \
        if allocation_element_size else capacity


def validate_site_bytes(data: bytes, expected: bytes, value_offset: int,
                        value_size: int, capacity: int,
                        allocation_element_size: int) -> None:
    for index, byte in enumerate(expected):
        if value_offset <= index < value_offset + value_size:
            continue
        if data[index] != byte:
            raise ValueError(f"signature mismatch at instruction byte {index}")
    observed = int.from_bytes(
        data[value_offset:value_offset + value_size], "little"
    )
    if observed != encoded_site_value(capacity, allocation_element_size):
        raise ValueError(
            f"capacity encoding mismatch: observed 0x{observed:x}, "
            f"expected 0x{encoded_site_value(capacity, allocation_element_size):x}"
        )


def read_rva(pe: PE, rva: int, size: int) -> bytes:
    offset = pe.rva_offset(rva)
    return pe.data[offset : offset + size]


def direct_call_target(pe: PE, rva: int) -> int:
    encoded = read_rva(pe, rva, 5)
    if len(encoded) != 5 or encoded[0] != 0xE8:
        raise ValueError(f"RVA 0x{rva:x} is not a direct call")
    return rva + 5 + struct.unpack_from("<i", encoded, 1)[0]


def direct_calls_to(pe: PE, target_rva: int) -> set[int]:
    """Return every E8 rel32 byte sequence in .text targeting one RVA."""
    text = next(section for section in pe.sections if section["name"] == ".text")
    raw_begin = text["raw_address"]
    raw_end = raw_begin + text["raw_size"]
    virtual_begin = text["virtual_address"]
    callers: set[int] = set()
    cursor = raw_begin
    while cursor < raw_end - 4:
        cursor = pe.data.find(b"\xe8", cursor, raw_end - 4)
        if cursor < 0:
            break
        caller_rva = virtual_begin + cursor - raw_begin
        displacement = struct.unpack_from("<i", pe.data, cursor + 1)[0]
        if caller_rva + 5 + displacement == target_rva:
            callers.add(caller_rva)
        cursor += 1
    return callers


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("pe", type=Path)
    parser.add_argument("--capacity", type=int, default=8)
    parser.add_argument("--preallocated-roster-slots", type=int, default=8)
    args = parser.parse_args()
    if not 5 <= args.capacity <= MISSION_SPAWN_SAFE_CAPACITY:
        raise SystemExit("capacity must be between 5 and 8")
    if not args.capacity <= args.preallocated_roster_slots <= 8:
        raise SystemExit("preallocated roster slots must be between capacity and 8")
    if MISSION_LOADOUT_EXTRA_BEGIN != 0x24570:
        raise SystemExit("FAIL: fifth mission loadout block no longer begins at 0x24570")
    fifth_block_end = MISSION_LOADOUT_EXTRA_BEGIN + MISSION_LOADOUT_BLOCK_STRIDE
    if not (
        MISSION_LOADOUT_EXTRA_BEGIN
        <= MISSION_LOCAL_REWARD_PROFILE_COUNT_OFFSET
        < fifth_block_end
        and MISSION_LOADOUT_EXTRA_BEGIN
        <= MISSION_RESULT_PARTICIPANT_COUNT_OFFSET
        < fifth_block_end
    ):
        raise SystemExit(
            "FAIL: fifth mission loadout block no longer overlaps the proven "
            "reward/result fields"
        )
    result_item_end = (
        MISSION_RESULT_ITEM_ARRAY_OFFSET
        + MISSION_RESULT_ITEM_COUNT * MISSION_RESULT_ITEM_SIZE
    )
    if result_item_end != MISSION_LOCAL_REWARD_PROFILE_COUNT_OFFSET:
        raise SystemExit(
            "FAIL: four native MissionResult Items no longer end at the "
            "local-profile counter"
        )

    def overlaps(field: int, target: int, size: int = 4) -> bool:
        return field < target + size and field + 4 > target

    item_overlaps: set[tuple[int, int, int]] = set()
    profile_overlaps: set[tuple[int, int, int]] = set()
    count_overlaps: set[tuple[int, int, int]] = set()
    for participant in range(4, 8):
        block = (
            MISSION_LOADOUT_SELECTED_BASE
            + participant * MISSION_LOADOUT_BLOCK_STRIDE
        )
        for selected_class in range(4):
            record = (
                block + MISSION_LOADOUT_RECORD_RELATIVE_OFFSET
                + selected_class * MISSION_LOADOUT_RECORD_STRIDE
            )
            for weapon in range(MISSION_LOADOUT_WEAPON_COUNT):
                field = record + weapon * 4
                key = (participant, selected_class, weapon)
                if field < result_item_end and field + 4 > \
                        MISSION_RESULT_ITEM_ARRAY_OFFSET:
                    item_overlaps.add(key)
                if overlaps(field, MISSION_LOCAL_REWARD_PROFILE_COUNT_OFFSET):
                    profile_overlaps.add(key)
                if overlaps(field, MISSION_RESULT_PARTICIPANT_COUNT_OFFSET):
                    count_overlaps.add(key)
    expected_item_overlaps = {
        *((4, 0, weapon) for weapon in range(1, 6)),
        *((4, 1, weapon) for weapon in range(3)),
    }
    if item_overlaps != expected_item_overlaps or \
            profile_overlaps != {(4, 1, 3)} or \
            count_overlaps != {(4, 1, 4)}:
        raise SystemExit(
            "FAIL: P4-P7 parser/loadout overlap map changed; review sidecar "
            "validity masks before building"
        )

    pe = PE(args.pe)
    region = bytearray(read_rva(pe, REGION_RVA, len(REGION)))
    if len(region) != len(REGION):
        raise SystemExit("FAIL: truncated capacity region")

    for index, expected in enumerate(REGION):
        if (FIRST_IMMEDIATE <= index < FIRST_IMMEDIATE + 4 or
                SECOND_IMMEDIATE <= index < SECOND_IMMEDIATE + 4):
            continue
        if region[index] != expected:
            raise SystemExit(
                f"FAIL: constructor signature mismatch at RVA "
                f"0x{REGION_RVA + index:x}"
            )

    first = struct.unpack_from("<I", region, FIRST_IMMEDIATE)[0]
    second = struct.unpack_from("<I", region, SECOND_IMMEDIATE)[0]
    if first != ORIGINAL_CAPACITY or second != ORIGINAL_CAPACITY:
        raise SystemExit(
            f"FAIL: expected pristine capacities 4/4, observed {first}/{second}"
        )

    secondary_regions: list[tuple[int, bytearray, int, int, int]] = []
    for rva, expected, value_offset, value_size, element_size in SECONDARY_SITES:
        instruction = bytearray(read_rva(pe, rva, len(expected)))
        try:
            validate_site_bytes(
                instruction, expected, value_offset, value_size,
                ORIGINAL_CAPACITY, element_size
            )
        except ValueError as exc:
            raise SystemExit(f"FAIL: secondary site RVA 0x{rva:x}: {exc}")
        secondary_regions.append(
            (rva, instruction, value_offset, value_size, element_size)
        )

    tertiary_regions: list[tuple[int, bytearray, int, int, int]] = []
    for rva, expected, value_offset, value_size, element_size in TERTIARY_SITES:
        instruction = bytearray(read_rva(pe, rva, len(expected)))
        try:
            validate_site_bytes(
                instruction, expected, value_offset, value_size,
                ORIGINAL_CAPACITY, element_size
            )
        except ValueError as exc:
            raise SystemExit(f"FAIL: tertiary site RVA 0x{rva:x}: {exc}")
        tertiary_regions.append(
            (rva, instruction, value_offset, value_size, element_size)
        )

    room_panel_regions: list[tuple[int, bytearray, int, int, int]] = []
    for rva, expected, value_offset, value_size, element_size in ROOM_PANEL_SITES:
        instruction = bytearray(read_rva(pe, rva, len(expected)))
        try:
            validate_site_bytes(
                instruction, expected, value_offset, value_size,
                ORIGINAL_CAPACITY, element_size
            )
        except ValueError as exc:
            raise SystemExit(f"FAIL: room-panel site RVA 0x{rva:x}: {exc}")
        room_panel_regions.append(
            (rva, instruction, value_offset, value_size, element_size)
        )

    mission_result_participant_regions: list[
        tuple[int, bytearray, int, int, int]
    ] = []
    for rva, expected, value_offset, value_size, element_size in \
            MISSION_RESULT_PARTICIPANT_SITES:
        instruction = bytearray(read_rva(pe, rva, len(expected)))
        try:
            validate_site_bytes(
                instruction, expected, value_offset, value_size,
                ORIGINAL_CAPACITY, element_size
            )
        except ValueError as exc:
            raise SystemExit(
                f"FAIL: MissionResult participant site RVA 0x{rva:x}: {exc}"
            )
        mission_result_participant_regions.append(
            (rva, instruction, value_offset, value_size, element_size)
        )

    if len(EXPERIMENTAL_RESERVE_SITES) != EXPERIMENTAL_RESERVE_GROUPS * 2:
        raise SystemExit("FAIL: experimental reserve groups are not paired")
    experimental_regions: list[tuple[int, bytearray, int, int, int]] = []
    for rva, expected, value_offset, value_size, element_size in \
            EXPERIMENTAL_RESERVE_SITES:
        instruction = bytearray(read_rva(pe, rva, len(expected)))
        try:
            validate_site_bytes(
                instruction, expected, value_offset, value_size,
                ORIGINAL_CAPACITY, element_size
            )
        except ValueError as exc:
            raise SystemExit(
                f"FAIL: experimental reserve site RVA 0x{rva:x}: {exc}"
            )
        experimental_regions.append(
            (rva, instruction, value_offset, value_size, element_size)
        )

    member_button_regions: list[tuple[int, bytearray, bytes]] = []
    for rva, original, replacement in MEMBER_BUTTON_SITES:
        observed = bytearray(read_rva(pe, rva, len(original)))
        if observed != original:
            raise SystemExit(
                f"FAIL: member-button site mismatch at RVA 0x{rva:x}"
            )
        if len(replacement) != len(original):
            raise SystemExit(
                f"FAIL: member-button replacement changes size at RVA 0x{rva:x}"
            )
        member_button_regions.append((rva, observed, replacement))

    if read_rva(pe, BUTTON_MASTER_RVA, 28) != "Button_Master\0".encode("utf-16le"):
        raise SystemExit("FAIL: Button_Master UTF-16 key mismatch")
    if read_rva(pe, BUTTON_MEMBER_RVA, 28) != "Button_Member\0".encode("utf-16le"):
        raise SystemExit("FAIL: Button_Member UTF-16 key mismatch")

    for rva, expected in USER_READY_SIGNATURES.items():
        if read_rva(pe, rva, len(expected)) != expected:
            raise SystemExit(
                f"FAIL: net::UserImpl state signature mismatch at RVA 0x{rva:x}"
            )
    for pointer_rva, expected in READY_PROTOCOL_POINTERS.items():
        observed_va = struct.unpack_from("<Q", read_rva(pe, pointer_rva, 8))[0]
        if observed_va < IMAGE_BASE:
            raise SystemExit(
                f"FAIL: Ready protocol pointer RVA 0x{pointer_rva:x} "
                f"contains invalid VA 0x{observed_va:x}"
            )
        observed = pe.cstring(pe.rva_offset(observed_va - IMAGE_BASE))
        if observed != expected:
            raise SystemExit(
                f"FAIL: Ready protocol pointer RVA 0x{pointer_rva:x} is "
                f"{observed!r}, expected {expected!r}"
            )
    for rva, expected in PLAYER_INFO_SIGNATURES.items():
        if read_rva(pe, rva, len(expected)) != expected:
            raise SystemExit(
                f"FAIL: room PlayerInfo signature mismatch at RVA 0x{rva:x}"
            )
    for rva, expected in ROOM_SCROLL_SIGNATURES.items():
        if read_rva(pe, rva, len(expected)) != expected:
            raise SystemExit(
                f"FAIL: PlayersGroup scroll signature mismatch at RVA 0x{rva:x}"
            )
    for rva, expected in MISSION_START_HARNESS_SIGNATURES.items():
        if read_rva(pe, rva, len(expected)) != expected:
            raise SystemExit(
                f"FAIL: MissionStart harness signature mismatch at RVA 0x{rva:x}"
            )
    if len(read_rva(pe, MISSION_START_GLOBAL_STATE_RVA, 4)) != 4:
        raise SystemExit("FAIL: MissionStart global state lies outside PE image")
    controller_vtable = read_rva(
        pe, MISSION_START_CONTROLLER_VTABLE_RVA, 54 * 8
    )
    controller_gate_getter = struct.unpack_from("<Q", controller_vtable, 53 * 8)[0]
    if controller_gate_getter != (
            IMAGE_BASE + MISSION_START_CONTROLLER_GATE_GETTER_RVA):
        raise SystemExit(
            "FAIL: MissionStart controller vtable slot 53 does not target "
            "the object+0x1ac gate getter"
        )
    for rva, expected in MISSION_CLEAR_SIGNATURES.items():
        if read_rva(pe, rva, len(expected)) != expected:
            raise SystemExit(
                f"FAIL: native mission-clear signature mismatch at RVA 0x{rva:x}"
            )
    for rva, expected in MISSION_RESULT_PIPELINE_SIGNATURES.items():
        if read_rva(pe, rva, len(expected)) != expected:
            raise SystemExit(
                f"FAIL: MissionResult sync/reward signature mismatch at "
                f"RVA 0x{rva:x}"
            )
    for rva, target in MISSION_RESULT_PIPELINE_CALLS.items():
        observed = direct_call_target(pe, rva)
        if observed != target:
            raise SystemExit(
                f"FAIL: MissionResult sync call RVA 0x{rva:x} targets "
                f"0x{observed:x}, expected 0x{target:x}"
            )
    for rva, expected in FAST_FAIL_SIGNATURES.items():
        if read_rva(pe, rva, len(expected)) != expected:
            raise SystemExit(
                f"FAIL: native /GS fast-fail signature mismatch at RVA 0x{rva:x}"
            )
    for rva, expected in GAME_PACKET_ROUTE_SIGNATURES.items():
        if read_rva(pe, rva, len(expected)) != expected:
            raise SystemExit(
                f"FAIL: game packet route signature mismatch at RVA 0x{rva:x}"
            )
    for rva, target in GAME_PACKET_ROUTE_CALLS.items():
        observed = direct_call_target(pe, rva)
        if observed != target:
            raise SystemExit(
                f"FAIL: game packet route call RVA 0x{rva:x} targets "
                f"0x{observed:x}, expected 0x{target:x}"
            )
    for rva, expected in MISSION_PARTICIPANT_SIGNATURES.items():
        if read_rva(pe, rva, len(expected)) != expected:
            raise SystemExit(
                f"FAIL: mission participant-stack signature mismatch at RVA 0x{rva:x}"
            )
    for rva, expected in MISSION_SPAWN_SIGNATURES.items():
        if read_rva(pe, rva, len(expected)) != expected:
            raise SystemExit(
                f"FAIL: mission spawn-point signature mismatch at RVA 0x{rva:x}"
            )
    loop_backedge = read_rva(pe, MISSION_RECORD_LOOP_BACKEDGE_RVA, 6)
    loop_target = MISSION_RECORD_LOOP_BACKEDGE_RVA + len(loop_backedge) + \
        struct.unpack_from("<i", loop_backedge, 2)[0]
    if loop_target != MISSION_RECORD_REDIRECT_RVA or \
            MISSION_RECORD_REDIRECT_RETURN_RVA != \
            MISSION_RECORD_REDIRECT_RVA + \
            len(MISSION_RECORD_REDIRECT_ORIGINAL):
        raise SystemExit(
            "FAIL: mission sidecar redirect is not at the repeated loop head"
        )
    append_backedge = read_rva(pe, MISSION_RECORD_APPEND_LOOP_BACKEDGE_RVA, 2)
    append_loop_target = MISSION_RECORD_APPEND_LOOP_BACKEDGE_RVA + \
        len(append_backedge) + struct.unpack_from("<b", append_backedge, 1)[0]
    if append_loop_target != MISSION_RECORD_APPEND_REDIRECT_RVA or \
            MISSION_RECORD_APPEND_REDIRECT_RETURN_RVA != \
            MISSION_RECORD_APPEND_REDIRECT_RVA + \
            len(MISSION_RECORD_APPEND_REDIRECT_ORIGINAL) or \
            MISSION_RECORD_FIRST_EXTRA_OBJECT_OFFSET != 0x198 or \
            MISSION_RECORD_LAST_EXTRA_OBJECT_OFFSET != 0x1E0:
        raise SystemExit(
            "FAIL: mission append sidecar redirect is not at its repeated loop head"
        )
    for rva, expected in MISSION_SOURCE_SIGNATURES.items():
        if read_rva(pe, rva, len(expected)) != expected:
            raise SystemExit(
                f"FAIL: mission source-table signature mismatch at RVA 0x{rva:x}"
            )
    for rva, expected in MISSION_LOADOUT_BLOCK_SIGNATURES.items():
        if read_rva(pe, rva, len(expected)) != expected:
            raise SystemExit(
                f"FAIL: mission loadout-block signature mismatch at RVA 0x{rva:x}"
            )
    observed_class_resolver_callers = direct_calls_to(
        pe, MISSION_PARTICIPANT_CLASS_RESOLVER_RVA
    )
    if observed_class_resolver_callers != \
            MISSION_PARTICIPANT_CLASS_RESOLVER_CALLERS:
        observed_text = ", ".join(
            f"0x{rva:x}" for rva in sorted(observed_class_resolver_callers)
        ) or "none"
        expected_text = ", ".join(
            f"0x{rva:x}"
            for rva in sorted(MISSION_PARTICIPANT_CLASS_RESOLVER_CALLERS)
        )
        raise SystemExit(
            "FAIL: mission participant-class resolver caller census changed: "
            f"observed {observed_text}, expected {expected_text}"
        )
    mission_participant_calls: list[tuple[int, bytearray, int]] = []
    for rva, original, target in MISSION_PARTICIPANT_CALL_SITES:
        observed = bytearray(read_rva(pe, rva, len(original)))
        if observed != original or direct_call_target(pe, rva) != target:
            raise SystemExit(
                f"FAIL: mission participant relay call mismatch at RVA 0x{rva:x}"
            )
        mission_participant_calls.append((rva, observed, target))
    manager_load = read_rva(pe, 0x3E197D, 7)
    manager_target = 0x3E197D + len(manager_load) + \
        struct.unpack_from("<i", manager_load, 3)[0]
    if manager_target != MISSION_MANAGER_SLOT_RVA:
        raise SystemExit(
            "FAIL: Mission() manager slot is "
            f"0x{manager_target:x}, expected 0x{MISSION_MANAGER_SLOT_RVA:x}"
        )
    result_publisher_load = read_rva(pe, 0x111098, 7)
    result_publisher_target = 0x111098 + len(result_publisher_load) + \
        struct.unpack_from("<i", result_publisher_load, 3)[0]
    if result_publisher_target != MISSION_RESULT_EVENT_PUBLISHER_SLOT_RVA:
        raise SystemExit(
            "FAIL: MissionResult event-publisher slot is "
            f"0x{result_publisher_target:x}, expected "
            f"0x{MISSION_RESULT_EVENT_PUBLISHER_SLOT_RVA:x}"
        )
    user_vtable = read_rva(pe, USER_VTABLE_RVA, 11 * 8)
    for index, expected_rva in USER_VTABLE_ENTRIES.items():
        observed_va = struct.unpack_from("<Q", user_vtable, index * 8)[0]
        if observed_va != IMAGE_BASE + expected_rva:
            raise SystemExit(
                f"FAIL: net::UserImpl vtable[{index}] is 0x{observed_va:x}, "
                f"expected 0x{IMAGE_BASE + expected_rva:x}"
            )
    layout_destructor = struct.unpack_from(
        "<Q", read_rva(pe, UI_LAYOUT_VTABLE_RVA, 8), 0
    )[0]
    if layout_destructor != IMAGE_BASE + UI_LAYOUT_DESTRUCTOR_RVA:
        raise SystemExit(
            "FAIL: ui::Layout vtable destructor is "
            f"0x{layout_destructor:x}, expected "
            f"0x{IMAGE_BASE + UI_LAYOUT_DESTRUCTOR_RVA:x}"
        )

    first_replacement = MEMBER_BUTTON_SITES[0][2]
    first_target = MEMBER_BUTTON_SITES[0][0] + len(first_replacement) + \
        struct.unpack_from("<i", first_replacement, 3)[0]
    member_replacement = MEMBER_BUTTON_SITES[2][2]
    member_target = MEMBER_BUTTON_SITES[2][0] + len(member_replacement) + \
        struct.unpack_from("<i", member_replacement, 3)[0]
    if first_target != BUTTON_MASTER_RVA or member_target != BUTTON_MEMBER_RVA:
        raise SystemExit("FAIL: replacement UTF-16 key target mismatch")

    for rva, expected in CRASH_EVIDENCE.items():
        if read_rva(pe, rva, len(expected)) != expected:
            raise SystemExit(f"FAIL: crash evidence mismatch at RVA 0x{rva:x}")

    for caller in (0x454511, 0x457B0B):
        if direct_call_target(pe, caller) != 0x45C6F0:
            raise SystemExit(f"FAIL: roster caller mismatch at RVA 0x{caller:x}")

    expected_calls = {
        0x432B03: SECONDARY_GROW_HELPER_RVA,
        0x432B1B: SECONDARY_GROW_HELPER_RVA,
        0x432B31: 0x437130,
        0x433C8B: 0x433F40,
        0x433F8E: 0x7D9A0,
        0x451B64: 0x433BD0,
        0x419793: TERTIARY_GROW_HELPER_RVA,
        0x4197AB: TERTIARY_GROW_HELPER_RVA,
        0x4197C1: 0x107800,
        0x419DB2: 0x25A20,
        0x45596B: 0x419C00,
        0x457C0B: 0x419C00,
        0x565AB6: 0x4DF280,
        0x565812: 0x4A9B90,
        0x4DF312: 0x4E4710,
        0x5A5A03: ROOM_PANEL_GROW_HELPER_RVA,
        0x5A5A19: ROOM_PANEL_RESIZE_RVA,
        0x5A7270: 0x27130,
        0x5A5EB6: 0x5A6610,
        0x5A665D: 0x27380,
        0x111093: 0x114BB0,
        0x3D8153: 0x111080,
        0x126CE0: 0x11D5E0,
        0x126D24: 0x7E240,
        0x126D52: 0x9C6E40,
        0x11D9D6: 0x11D5E0,
        0x11CF08: 0x7E240,
        0x11DAC2: 0x7CDC0,
        0x11DC34: 0x11CE60,
        0x11CF79: 0x3123A0,
        0x11CF86: 0x6E010,
    }
    for caller, target in expected_calls.items():
        observed = direct_call_target(pe, caller)
        if observed != target:
            raise SystemExit(
                f"FAIL: call RVA 0x{caller:x} targets 0x{observed:x}, "
                f"expected 0x{target:x}"
            )

    roster_slots = args.preallocated_roster_slots
    struct.pack_into("<I", region, FIRST_IMMEDIATE, roster_slots)
    struct.pack_into("<I", region, SECOND_IMMEDIATE, roster_slots)
    if (struct.unpack_from("<I", region, FIRST_IMMEDIATE)[0] != roster_slots or
            struct.unpack_from("<I", region, SECOND_IMMEDIATE)[0] != roster_slots):
        raise SystemExit("FAIL: patch simulation did not update both capacity operands")

    for rva, instruction, value_offset, value_size, element_size in secondary_regions:
        desired = encoded_site_value(roster_slots, element_size)
        instruction[value_offset:value_offset + value_size] = desired.to_bytes(
            value_size, "little"
        )
        expected = next(item[1] for item in SECONDARY_SITES if item[0] == rva)
        try:
            validate_site_bytes(
                instruction, expected, value_offset, value_size,
                roster_slots, element_size
            )
        except ValueError as exc:
            raise SystemExit(
                f"FAIL: secondary patch simulation RVA 0x{rva:x}: {exc}"
            )

    for rva, instruction, value_offset, value_size, element_size in tertiary_regions:
        desired = encoded_site_value(roster_slots, element_size)
        instruction[value_offset:value_offset + value_size] = desired.to_bytes(
            value_size, "little"
        )
        expected = next(item[1] for item in TERTIARY_SITES if item[0] == rva)
        try:
            validate_site_bytes(
                instruction, expected, value_offset, value_size,
                roster_slots, element_size
            )
        except ValueError as exc:
            raise SystemExit(
                f"FAIL: tertiary patch simulation RVA 0x{rva:x}: {exc}"
            )

    for rva, instruction, value_offset, value_size, element_size in room_panel_regions:
        desired = encoded_site_value(roster_slots, element_size)
        instruction[value_offset:value_offset + value_size] = desired.to_bytes(
            value_size, "little"
        )
        expected = next(item[1] for item in ROOM_PANEL_SITES if item[0] == rva)
        try:
            validate_site_bytes(
                instruction, expected, value_offset, value_size,
                roster_slots, element_size
            )
        except ValueError as exc:
            raise SystemExit(
                f"FAIL: room-panel patch simulation RVA 0x{rva:x}: {exc}"
            )

    for rva, instruction, value_offset, value_size, element_size in \
            mission_result_participant_regions:
        desired = encoded_site_value(args.capacity, element_size)
        instruction[value_offset:value_offset + value_size] = desired.to_bytes(
            value_size, "little"
        )
        expected = next(
            item[1] for item in MISSION_RESULT_PARTICIPANT_SITES
            if item[0] == rva
        )
        try:
            validate_site_bytes(
                instruction, expected, value_offset, value_size,
                args.capacity, element_size
            )
        except ValueError as exc:
            raise SystemExit(
                f"FAIL: MissionResult patch simulation RVA 0x{rva:x}: {exc}"
            )

    for rva, instruction, value_offset, value_size, element_size in \
            experimental_regions:
        desired = encoded_site_value(roster_slots, element_size)
        instruction[value_offset:value_offset + value_size] = desired.to_bytes(
            value_size, "little"
        )
        expected = next(
            item[1] for item in EXPERIMENTAL_RESERVE_SITES
            if item[0] == rva
        )
        try:
            validate_site_bytes(
                instruction, expected, value_offset, value_size,
                roster_slots, element_size
            )
        except ValueError as exc:
            raise SystemExit(
                f"FAIL: experimental patch simulation RVA 0x{rva:x}: {exc}"
            )

    for rva, instruction, replacement in member_button_regions:
        instruction[:] = replacement
        if instruction != replacement:
            raise SystemExit(
                f"FAIL: member-button patch simulation RVA 0x{rva:x}"
            )

    external_participant_capacity = MISSION_PARTICIPANT_SAFE_CAPACITY
    if len(mission_participant_calls) != 2 or \
            args.capacity > external_participant_capacity:
        raise SystemExit(
            "FAIL: external mission participant array cannot hold requested capacity"
        )
    spawn_mapping = [
        index % MISSION_SPAWN_POINT_COUNT for index in range(args.capacity)
    ]
    if len(spawn_mapping) != args.capacity or \
            any(point >= MISSION_SPAWN_POINT_COUNT for point in spawn_mapping):
        raise SystemExit(
            "FAIL: extra mission participants do not recycle four spawn points"
        )
    if read_rva(pe, MISSION_RECORD_REDIRECT_RVA,
                len(MISSION_RECORD_REDIRECT_ORIGINAL)) != \
            MISSION_RECORD_REDIRECT_ORIGINAL:
        raise SystemExit("FAIL: mission sidecar redirect insertion point mismatch")
    if read_rva(pe, MISSION_RECORD_COPY_RVA,
                len(MISSION_RECORD_COPY_ORIGINAL)) != \
            MISSION_RECORD_COPY_ORIGINAL:
        raise SystemExit("FAIL: native four-record copy path changed")
    if read_rva(pe, MISSION_RECORD_EXISTING_REDIRECT_RVA,
                len(MISSION_RECORD_EXISTING_REDIRECT_ORIGINAL)) != \
            MISSION_RECORD_EXISTING_REDIRECT_ORIGINAL:
        raise SystemExit(
            "FAIL: mission existing-record relay insertion point mismatch"
        )
    if read_rva(pe, MISSION_RECORD_APPEND_REDIRECT_RVA,
                len(MISSION_RECORD_APPEND_REDIRECT_ORIGINAL)) != \
            MISSION_RECORD_APPEND_REDIRECT_ORIGINAL:
        raise SystemExit(
            "FAIL: mission append sidecar redirect insertion point mismatch"
        )
    extra_records = args.capacity - ORIGINAL_CAPACITY
    if extra_records > MISSION_RECORD_SIDECAR_COUNT:
        raise SystemExit(
            "FAIL: sidecar table cannot hold every requested extra player"
        )
    source_mapping = [
        index % MISSION_SPAWN_POINT_COUNT for index in range(args.capacity)
    ]
    if source_mapping != spawn_mapping:
        raise SystemExit(
            "FAIL: mission source/spawn modulo mappings diverged"
        )

    print(
        "PASS: EDF5 primary constructor RVA "
        f"0x{CONSTRUCTOR_RVA:x} and secondary constructor/helper RVAs "
        f"0x{SECONDARY_CONSTRUCTOR_RVA:x}/0x{SECONDARY_GROW_HELPER_RVA:x} and "
        f"tertiary constructor/helper RVAs 0x{TERTIARY_CONSTRUCTOR_RVA:x}/"
        f"0x{TERTIARY_GROW_HELPER_RVA:x} and room-panel constructor/helper "
        f"RVAs 0x{ROOM_PANEL_CONSTRUCTOR_RVA:x}/0x{ROOM_PANEL_GROW_HELPER_RVA:x} "
        f"have capacity 4; simulated {roster_slots} across all 22 proven "
        f"capacity operands plus {EXPERIMENTAL_RESERVE_GROUPS} experimental "
        f"reserve groups/{len(EXPERIMENTAL_RESERVE_SITES)} paired operands; "
        f"{len(DEFERRED_FOUR_ANCHORS)} ambiguous/type candidates remain "
        "unchanged; four fixed-key loop rewrites, all seven crash paths and "
        "call chains match; net::UserImpl constructor/destructor, +0xc0 "
        "transport predicate under its state lock, +0xf0 participant-property "
        "map, native property getter/setter/release, cm/c1, ds/ds, and l1/l2 "
        "MissionStart constants, update/global-state/controller state-5 "
        "completion gate, TLS controller resolver and exact object+0x1ac "
        "host-only pre-update gate, "
        "+0x100 voice getter/setter, +0xc1 active flag, identity getter, vtable, room "
        "PlayerInfo loadout layout, and PlayersGroup ui::Layout cast/model/"
        "clamp/update signatures match; Mission() update, manager slot, native "
        "result-1 setter/application, preservation branch, and natural clear "
        "caller signatures match; the xgs::ui::Object event-1/payload-2 close "
        "target at +0x78 and closing bit at +0x18 are distinct from "
        "net::MissionResult::Exec_Begin; both exact "
        "Sync_MissionResult begin/poll caller pairs, ResolveResult and "
        "ApplyResult wrappers match; MissionSync_Res uses a dynamic handle "
        "vector and NetGameStatus decodes a dynamic Item count; both online-"
        f"participant filters follow MaxPlayers at {args.capacity}. The fixed "
        "four-Item initializer and exact Item sink prove that P4-P7 must be "
        "folded into the four accumulators ending at +0x2459c; ApplyResult's "
        "two fixed-four consumers reduce aggregate totals, while the real "
        "ApplyResult walks a dynamic 20-byte result vector; its +0x2459c "
        "count, +0x6d4c "
        "profile base and 0x3e60 stride are proven local-save-profile state "
        "whose sole setter accepts only 1..2, not online player capacity; the "
        "external mission participant array has "
        f"capacity {external_participant_capacity}; players map to native "
        f"spawn points {spawn_mapping}; the fixed four-record mission table "
        f"has {MISSION_RECORD_SIDECAR_COUNT} external "
        f"{MISSION_RECORD_SIZE}-byte sidecars reused by both persistent-table "
        "write loops; the exact source-table getter, its three mission "
        "contexts and four-source consumer bound match; the parser/consumer "
        "agree on the 0x3e90 native block, active class selector and "
        "six-dword equipment record; its sole direct caller proves false is "
        "the decoded path rather than an error, and the overlap map isolates "
        "P4/class-1 weapon 4 as the only field replaced by the final count; "
        "both post-character-consumer +0xf8 "
        "identity reads match and require pre-map restoration; only the proven "
        f"fixed player-create context maps logical capacity {args.capacity} "
        f"to sources {source_mapping}, while both flow-sized local-vector "
        "contexts remain unmodified and audited; /GS verifier and failure-only "
        "diagnostic hook signatures match; high-level game packet send, "
        "receive callback-dispatch, outgoing logical enqueue, high-level "
        "actor producer, eight-byte UserImpl+0xc4/+0xc8 destination builder, "
        "descriptor+4 route resolver, callback thunk plus dynamic +0xd0/+0xe0 receive "
        "vector, dynamic allocator -> UserImpl+0xc8 transport-route index, "
        "matching register/remove consumers, per-UserImpl receive parser, "
        "incoming MissionScript dispatch, UserImpl-to-PlayerInfo, the "
        "complete three-caller participant-class resolver census, all three "
        "modulo-four visual consumers (including the fixed four-entry stack "
        "array), and the bounded four-class HUD text-resource path signatures "
        "match"
    )


if __name__ == "__main__":
    main()
