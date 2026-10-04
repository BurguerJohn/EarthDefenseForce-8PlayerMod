#!/usr/bin/env python3
"""Fail-closed byte audit for enemy spawn and MissionResult recovery."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

from pe_inventory import PE


ENEMY_SPAWN_RVA = 0x1C1650
GENERATOR_POLL_UPDATE_RVA = 0x1F8B40
GENERATOR_POLL_SPAWN_RVA = 0x1F90A0
GENERATOR_POLL_VTABLE_RVA = 0xEA0E38
GENERATOR_POLL_VTABLE_UPDATE_ENTRY_RVA = 0xEA0ED8
GENERATOR_POLL_VTABLE_SPAWN_ENTRY_RVA = 0xEA0F40
GENERATOR_POLL_VIRTUAL_UPDATE_OFFSET = 0xA0
GENERATOR_POLL_VIRTUAL_SPAWN_OFFSET = 0x108
GENERATOR_POLL_BASE_UPDATE_RVA = 0x2DA720
GENERATOR_POLL_BASE_UPDATE_CALL_RVA = 0x1F8B5B
GENERATOR_POLL_BASE_GATE_TAIL_RVA = 0x2DA9DD
GENERATOR_POLL_BASE_GATE_TAIL_CALL_RVA = 0x2DA9F4
GENERATOR_POLL_GATE_RVA = 0x2DC7C0
RESULT_EXEC_BEGIN_RVA = 0x42FD20
EXPECTED_RESULT_EXEC_CALLS = (0x1153EE, 0x42AC48)
EXPECTED_ENEMY_CALLS = (
    0x1D0477, 0x1D517A, 0x1D7560, 0x1D80DA,
    0x1DBD54, 0x1E0862, 0x1F9120, 0x1FA763,
    0x243CAD, 0x245F8F, 0x261BF8, 0x262D98,
    0x26FDED, 0x2755C9, 0x28D4B4, 0x291030,
    0x297FE5, 0x299709, 0x2C0C3B, 0x2C1AE4,
    0x2C9C6E, 0x2CFF51, 0x2D3452, 0x2D7586,
)

# All decoded x64 reads of mission_state+0x245A0 in the native enemy/difficulty
# setup code. Their downstream tables expose only profiles 1..4. The runtime
# patch copies these exact loads into relays and clamps only the loaded value;
# the stored participant count remains the real 5..8 value.
PARTICIPANT_SCALING_SIGNATURES = (
    (0x0008ADCF, "418b83a0450200"),
    (0x001CFEFF, "418b83a0450200"),
    (0x001DDBE8, "458b89a0450200"),
    (0x001DDDC9, "458b89a0450200"),
    (0x001DDF0B, "458b80a0450200"),
    (0x001E424D, "418b83a0450200"),
    (0x001E6497, "418b83a0450200"),
    (0x001E8309, "448b93a0450200"),
    (0x001EABC3, "418b83a0450200"),
    (0x001ECBAA, "418b83a0450200"),
    (0x001ECDCF, "418b83a0450200"),
    (0x001ECF17, "418b83a0450200"),
    (0x001ECFA0, "418b83a0450200"),
    (0x001ED021, "418b83a0450200"),
    (0x001F872C, "458b82a0450200"),
    (0x001F89DA, "418b83a0450200"),
    (0x001FF74F, "418b83a0450200"),
    (0x001FFAB8, "418b83a0450200"),
    (0x001FFB28, "418b83a0450200"),
    (0x001FFBB7, "418b83a0450200"),
    (0x0020AA06, "418b83a0450200"),
    (0x0020AC34, "418b83a0450200"),
    (0x00214E8C, "418b83a0450200"),
    (0x00214F2E, "418b83a0450200"),
    (0x0021EC6D, "418b83a0450200"),
    (0x0021EEF3, "418b83a0450200"),
    (0x0021EFCF, "418b83a0450200"),
    (0x0021F04E, "418b83a0450200"),
    (0x00227381, "458b89a0450200"),
    (0x0022A94A, "458b89a0450200"),
    (0x002428CA, "8b87a0450200"),
    (0x0024EBCB, "418b83a0450200"),
    (0x00255221, "418b83a0450200"),
    (0x00255361, "418b83a0450200"),
    (0x0025C341, "418b83a0450200"),
    (0x0025D830, "418b82a0450200"),
    (0x0026406E, "418b83a0450200"),
    (0x0026802A, "418b83a0450200"),
    (0x0026EC0E, "418b83a0450200"),
    (0x002786E0, "458b89a0450200"),
    (0x0027883D, "458b80a0450200"),
    (0x0028344F, "418b83a0450200"),
    (0x0028538F, "448b93a0450200"),
    (0x0028C6F0, "418b83a0450200"),
    (0x0028C888, "8b87a0450200"),
    (0x00294944, "418b83a0450200"),
    (0x002949C0, "418b83a0450200"),
    (0x00297F0C, "418b83a0450200"),
    (0x0029A98C, "418b83a0450200"),
    (0x002A1402, "418b83a0450200"),
    (0x002A73C7, "458b89a0450200"),
    (0x002C0746, "418b83a0450200"),
    (0x002CADB4, "418b83a0450200"),
    (0x002D0913, "418b83a0450200"),
    (0x002D4B29, "458b89a0450200"),
    (0x0033DEFE, "8b83a0450200"),
)
PARTICIPANT_COUNT_GETTER_SIGNATURES = (
    (0x0011E48E, "8b80a0450200"),
)

SIGNATURES = (
    ("enemy_prologue", 0x1C1650,
     "488bc45556574154415541564157488da8d8fdffff4881ecf0020000"),
    ("enemy_count_and_cap", 0x1C16C6,
     "458bc84c8bea488bf98b0db7c60801428d04013d90010000720f"
     "41b990010000442bc90f84e3060000"),
    ("enemy_scale_layout", 0x1C16EF,
     "4883bfb0020000000f84d5060000448b87940200008b8790020000"
     "410fafc1418d48ff03c833d28bc141f7f02bca33d28bc141f7f0"
     "448bc0"),
    # The common generator configurator starts fail-closed at 0/1.  A real
    # scale is copied only from the fourth nested configuration record.  This
    # is mission data, not the participant-count table used by GeneratorPoll.
    ("enemy_scale_config_default", 0x3AD3DE,
     "4489b690020000c7869402000001000000"),
    ("enemy_scale_config_record_gate", 0x3AD3EF,
     "41837f04030f8efa0100004d6367084983c4244d03e7"),
    ("enemy_scale_config_copy", 0x3AD509,
     "49634424084903c4486348448b440144898690020000"
     "49634424084903c4486348448b440150898694020000"),
    # GeneratorPoll selects a timer multiplier through participant_count-1.
    # The timer fields are +0x1f8/+0x1fc on the owning object and are distinct
    # from the common spawn scale at +0x290/+0x294 on the spawn subobject.
    ("generator_poll_participant_timer", 0x1F872C,
     "458b82a0450200496341084883c0484903c1486348084803c8488d0491"
     "486348084883c10c4803c1486350084803d0418d40ff4863c8488d0449"
     "f30f5983f0010000f30f59448208f30f1183f8010000f30f5dc0"
     "f30f1183fc010000"),
    # GeneratorPoll obtains a two-dword positive request before entering the
    # common boundary; its participant table controls a later timer instead.
    ("generator_poll_spawn_call", 0x1F910C,
     "448b442430488d8e300500004403442434488bd5e82b85fcff"),
    # GeneratorPoll's vtable slot +0xA0 is its per-frame update. It forwards
    # self/frame context unchanged to the common GameObject update first.
    ("generator_poll_update", 0x1F8B40,
     "48895c2420574881ecb00000004889ac24c8000000488bf9488beae8c01b0e00"),
    ("generator_poll_base_update", 0x2DA720,
     "40534883ec60f30f1002488bd9f30f588114020000"),
    # The base update always restores its frame and tail-jumps with
    # RCX=owner+0x400, RDX=owner to the shared native gate.
    ("generator_poll_base_gate_tail", 0x2DA9DD,
     "488bcbe84b290000488d8b00040000488bd34883c4605be9c71d0000"),
    # The concrete virtual method has exactly two integer/pointer arguments:
    # it preserves RCX as self and RDX as the descriptor. The gate consumes
    # the low byte of the final RAX return, so the telemetry hook preserves
    # the complete register value instead of guessing a source-level type.
    ("generator_poll_spawn_prologue", 0x1F90A0,
     "48895c241848896c2420565741564881ec800000000f29742470"
     "488b052fa6f2004833c44889442450488d99100d0000488bf1"
     "4c8bc1488bea"),
    ("generator_poll_manager_gate", 0x1F90E8,
     "498b88880700004885c90f84ce000000"),
    ("generator_poll_return", 0x1F9480,
     "488bd5488bcee805150000488b4c24504833cce8a8d97c00"
     "4c8d9c2480000000498b5b30498b6b380f28742470498be3"
     "415e5f5ec3"),
    # The gate's signed cooldown exit precedes the time-window/quota test.
    # Runtime telemetry hooks this exact ABI without modifying either field.
    ("generator_poll_gate", 0x2DC7C0,
     "48895c2408574883ec30ff4904488bfa817904cc010000"
     "488bd90f8d8c000000"),
    # The shared gate calls owner->vtable[0x108] and immediately tests AL.
    ("generator_poll_gate_virtual_call", 0x2DC821,
     "8339007e41488b02488bcfff900801000084c07431"),
    ("result_exec_begin_prologue", 0x42FD20,
     "488bc4554154415541564157488d68a84881ec30010000"
     "48c74508feffffff"),
    # Exec_Begin intentionally owns four fixed Item accumulators. They end at
    # +0x2459c, where the unrelated local reward-profile count begins. This
    # storage must stay four entries because P4-P7 are folded into it.
    ("result_exec_native_item_reset", 0x42FD93,
     "488b0d96ade2004c896c2458498bc54889817c450200"
     "4c896c2458488981844502004c896c24584889818c450200"
     "4c896c245848898194450200"),
    # Both later shared-handle collections use their runtime begin/end range
    # and a 0x10-byte stride. These loops are dynamic; they are not another
    # hidden four-player array and must not be patched to MaxPlayers.
    ("result_exec_dynamic_handle_vector_a", 0x430259,
     "488d55c8ff5028488b4dd0488b55e048c1e2044803d1"
     "483bca74220f1f40000f1f840000000000488b4108"
     "80b8c20000000075094883c110483bca75ea"),
    ("result_exec_dynamic_handle_vector_b", 0x430356,
     "488d55e8ff5028488b4df0488b550048c1e2044803d1"
     "483bca7423488b410880b8c200000000750b4883c110"
     "483bca75ea"),
    ("result_exec_begin_native_caller", 0x1153E9,
     "b9e0b1ffffe82da93100"),
    # Registered as `int ResultSync_Begin(int)`: the wrapper forwards ECX to
    # Exec_Begin and returns the original script argument.
    ("result_exec_begin_script_wrapper", 0x42AC40,
     "40534883ec208bd9e8d35000008bc34883c4205bc3"),
    # Mission entry 0x11d860 keeps its /GS cookie at rbp+0x230 and exactly
    # four 16-byte spawn records at rbp+0x1e0..0x21f. Its first loop
    # transforms spawn[edi] in place until edi equals the participant count
    # at [rsp+0x50], with no four-record bound: participant 5 (sixth player)
    # writes the cookie. The plugin relays the backedge at 0x11db21 so the
    # loop stops after the four native records.
    ("mission_entry_stack_cookie_store", 0x11D8A7, "48898530020000"),
    ("mission_entry_spawn_record_init_four", 0x11D9E3,
     "b904000000488d85e8010000"),
    ("mission_entry_spawn_transform_index", 0x11DAB1,
     "4863c748c1e004488d8de00100004803c8"),
    ("mission_entry_spawn_transform_backedge", 0x11DB1B,
     "ffc74883c3103b7c2450758a"),
    ("mission_entry_stack_cookie_check", 0x11E414,
     "488b8d300200004833cce81d8a8a00"),
    # The mission state object is allocated with exactly 0x24600 bytes.
    ("mission_state_allocation_size", 0x3D6BA4, "b900460200"),
    ("mission_state_allocation_size_alt", 0x926F3, "b900460200"),
    # Parser 0x42F480: r14 = state+0x14A40, block offset = index*0x3E90 in
    # r10 (armor written before the four-block bound) and again in r9.
    ("loadout_parser_block_base", 0x42F77F, "4c8db6404a0100"),
    ("loadout_parser_block_offset", 0x42F7C9,
     "4c69d1903e00008b850c01000043898432e8010000"),
    ("loadout_parser_bulk_copy_bound", 0x42F7E5, "83f9040f8393000000"),
    ("loadout_parser_record_offset", 0x42F898, "4d69c9903e0000"),
    # Message builders: fixed 0x2E8 reserve, then unchecked payload memcpy.
    ("message_1100_reserve", 0x43309E, "bae8020000488bcbe845f6ffff"),
    ("message_1100_payload_copy", 0x433100,
     "498d4d0c4c8bc3e8f8505900488d43044c8d60084981fc78050000"),
    ("message_3300_reserve", 0x432D65, "bae8020000488d4d07e89d2fbfff"),
    ("message_3300_payload_copy", 0x432DDD, "4903cf4c8bc3e81c545900"),
    # Damage meter (0.6.74): ApplyDamage, its health/amount reads, the single
    # message-handler call, the damage-list flush and both projectile sites.
    ("damage_apply", 0x2DB370,
     "488bc4555657415441554156415748"
     "8da808ffffff4881ecc0010000"),
    ("damage_apply_amount_read", 0x2DB47D, "0f2f7650"),
    ("damage_apply_health_read", 0x2DB496, "f30f1087fc010000"),
    ("damage_message_call", 0x2DACCF, "e89c060000"),
    ("damage_list_flush", 0x2D9720, "40535556574155415641574883ec70"),
    # Source-side tally (0.6.79): list data/count*0xA0, info +0x10, stride.
    ("damage_list_layout", 0x2D9744, "488b7108488b4118488d2c8048c1e505"),
    ("damage_list_info", 0x2D97FF, "488d4610"),
    ("damage_list_stride", 0x2D98A2, "4881c6a0000000"),
    ("projectile_flush_site_a", 0x1437E2, "488d8b80000000"),
    ("projectile_flush_call_a", 0x1437FE, "e81d5f1900"),
    ("projectile_flush_site_b", 0x1441DB, "488d8f80000000"),
    ("projectile_flush_call_b", 0x1441E6, "e835551900"),
    # Script record relays (0.6.77): 0x121BE0/0x127260 index the four
    # mission records at +0x138 by the real participant count.
    ("script_record_a_index", 0x121C40, "4863c7"),
    ("script_record_a_address", 0x121C43, "488d4814488d0c48488d0cce"),
    ("script_record_a_lock", 0x121C4F, "488d542420e8d7baf4ff"),
    ("script_record_b_index", 0x127390, "4863c7"),
    ("script_record_b_address", 0x127393,
     "488d4814488d0c48488d0ccd0000000049" "03cd"),
    ("script_record_b_lock", 0x1273A6, "488d542450e88063f4ff"),
    ("participant_count_getter", 0x11E48E, "8b80a0450200"),
    # Caliban/car rear seat pickers and the 24 enemy HP multiplies (0.6.78).
    ("rear_seat_caliban", 0x34F9AD, "45892e418d45014863d045892c96"),
    ("rear_seat_car", 0x374EED, "45892e418d45014863d045892c96"),
    ("rear_seat_caliban_after", 0x34F9BB, "4d8bc6498bd7488bcde897660000"),
    ("rear_seat_car_after", 0x374EFB, "4d8bc6498bd7488bcde85711feff"),
    ("vehicle_seat_layout", 0x356066, "4c6991280400004003000048"),
    ("health_scaling_1cff15", 0x1CFF15, "f30f59449108"),
    ("health_scaling_1ddc40", 0x1DDC40, "f3410f59448008"),
    ("health_scaling_1e4266", 0x1E4266, "f3420f59448208"),
    ("health_scaling_1e64c3", 0x1E64C3, "f30f595c9108"),
    ("health_scaling_1ecbc0", 0x1ECBC0, "f30f59449108"),
    ("health_scaling_1f876e", 0x1F876E, "f30f59448208"),
    ("health_scaling_1f89f0", 0x1F89F0, "f30f594c9108"),
    ("health_scaling_1ff765", 0x1FF765, "f30f59449108"),
    ("health_scaling_20aa1c", 0x20AA1C, "f30f59449108"),
    ("health_scaling_214f44", 0x214F44, "f30f595c9108"),
    ("health_scaling_21ec83", 0x21EC83, "f30f59449108"),
    ("health_scaling_22a994", 0x22A994, "f3410f59448008"),
    ("health_scaling_26ec24", 0x26EC24, "f30f594c9108"),
    ("health_scaling_278732", 0x278732, "f3410f59448008"),
    ("health_scaling_283468", 0x283468, "f30f59449108"),
    ("health_scaling_28c706", 0x28C706, "f30f59449108"),
    ("health_scaling_29495a", 0x29495A, "f30f594c9108"),
    ("health_scaling_297f22", 0x297F22, "f30f594c9108"),
    ("health_scaling_29a9a2", 0x29A9A2, "f30f594c9108"),
    ("health_scaling_2a141a", 0x2A141A, "f30f59449108"),
    ("health_scaling_2a7419", 0x2A7419, "f3410f59448008"),
    ("health_scaling_2c075c", 0x2C075C, "f30f59449108"),
    ("health_scaling_2cadca", 0x2CADCA, "f30f59449108"),
    ("health_scaling_2d4b7e", 0x2D4B7E, "f3410f59448008"),
    ("chat_room_send", 0x3F16C0,
     "405553564154415541564157488d6c24d04881ec30010000"),
    ("rtti_weapon_base_name", 0x11B1AC0,
     "2e3f4156576561706f6e426173654040"),
    ("rtti_soldier_base_name", 0x11A4980,
     "2e3f4156536f6c64696572426173654040"),
)


def rva_bytes(pe: PE, rva: int, size: int) -> bytes:
    offset = pe.rva_offset(rva)
    result = pe.data[offset:offset + size]
    if len(result) != size:
        raise ValueError(f"RVA 0x{rva:x} is truncated")
    return result


def image_base(pe: PE) -> int:
    pe_offset = pe.u32(0x3C)
    optional_header = pe_offset + 24
    return struct.unpack_from("<Q", pe.data, optional_header + 24)[0]


def direct_calls(pe: PE, target_rva: int) -> tuple[int, ...]:
    calls: set[int] = set()
    for section in pe.sections:
        raw = section["raw_address"]
        size = section["raw_size"]
        base_rva = section["virtual_address"]
        data = pe.data[raw:raw + size]
        for index in range(max(0, len(data) - 4)):
            if data[index] != 0xE8:
                continue
            displacement = struct.unpack_from("<i", data, index + 1)[0]
            call_rva = base_rva + index
            if call_rva + 5 + displacement == target_rva:
                calls.add(call_rva)
    return tuple(sorted(calls))


def relative_branch_target(pe: PE, rva: int, opcode: int) -> int:
    encoded = rva_bytes(pe, rva, 5)
    if encoded[0] != opcode:
        raise ValueError(
            f"relative branch opcode changed at RVA 0x{rva:x}: "
            f"expected=0x{opcode:02x} observed=0x{encoded[0]:02x}"
        )
    displacement = struct.unpack_from("<i", encoded, 1)[0]
    return rva + 5 + displacement


def participant_scaling_reads(pe: PE) -> dict[int, bytes]:
    """Find mov r32,[base+0x245a0] without a disassembler dependency."""
    reads: dict[int, bytes] = {}
    displacement = b"\xa0\x45\x02\x00"
    for section in pe.sections:
        if section["name"] != ".text":
            continue
        raw = section["raw_address"]
        size = section["raw_size"]
        base_rva = section["virtual_address"]
        data = pe.data[raw:raw + size]
        for index in range(max(0, len(data) - 6)):
            first = data[index]
            if 0x40 <= first <= 0x4F:
                opcode_at = index + 1
                modrm_at = index + 2
                instruction_size = 7
            else:
                if index != 0 and 0x40 <= data[index - 1] <= 0x4F:
                    # Do not decode the opcode inside a REX-prefixed load a
                    # second time as a synthetic no-REX instruction.
                    continue
                opcode_at = index
                modrm_at = index + 1
                instruction_size = 6
            if data[opcode_at] != 0x8B:
                continue
            modrm = data[modrm_at]
            if modrm >> 6 != 2 or modrm & 7 == 4:
                continue
            displacement_at = modrm_at + 1
            if data[displacement_at:displacement_at + 4] != displacement:
                continue
            reads[base_rva + index] = data[index:index + instruction_size]
    return reads


def validate(image: Path) -> None:
    pe = PE(image)
    if pe.pointer_size != 8:
        raise ValueError("expected a PE32+ x64 image")

    for name, rva, encoded in SIGNATURES:
        expected = bytes.fromhex(encoded)
        observed = rva_bytes(pe, rva, len(expected))
        if observed != expected:
            raise ValueError(
                f"{name} mismatch at RVA 0x{rva:x}: "
                f"expected={expected.hex()} observed={observed.hex()}"
            )
        print(f"PASS {name} rva=0x{rva:x} bytes={len(expected)}")

    enemy_calls = direct_calls(pe, ENEMY_SPAWN_RVA)
    if enemy_calls != EXPECTED_ENEMY_CALLS:
        missing = sorted(set(EXPECTED_ENEMY_CALLS) - set(enemy_calls))
        extra = sorted(set(enemy_calls) - set(EXPECTED_ENEMY_CALLS))
        raise ValueError(
            "enemy caller census changed: "
            f"missing={[hex(value) for value in missing]} "
            f"extra={[hex(value) for value in extra]}"
        )

    generator_update_entry = struct.unpack_from(
        "<Q", pe.data,
        pe.rva_offset(GENERATOR_POLL_VTABLE_UPDATE_ENTRY_RVA)
    )[0]
    generator_entry = struct.unpack_from(
        "<Q", pe.data,
        pe.rva_offset(GENERATOR_POLL_VTABLE_SPAWN_ENTRY_RVA)
    )[0]
    expected_generator_update_entry = (
        image_base(pe) + GENERATOR_POLL_UPDATE_RVA
    )
    expected_generator_entry = image_base(pe) + GENERATOR_POLL_SPAWN_RVA
    if (generator_update_entry != expected_generator_update_entry or
            GENERATOR_POLL_VTABLE_UPDATE_ENTRY_RVA -
            GENERATOR_POLL_VTABLE_RVA !=
            GENERATOR_POLL_VIRTUAL_UPDATE_OFFSET or
            generator_entry != expected_generator_entry or
            GENERATOR_POLL_VTABLE_SPAWN_ENTRY_RVA -
            GENERATOR_POLL_VTABLE_RVA !=
            GENERATOR_POLL_VIRTUAL_SPAWN_OFFSET):
        raise ValueError(
            "GeneratorPoll vtable update/spawn mapping changed: "
            f"update=0x{generator_update_entry:x}/"
            f"0x{expected_generator_update_entry:x} "
            f"spawn=0x{generator_entry:x}/0x{expected_generator_entry:x}"
        )
    print(
        "PASS generator_poll_vtable_update_spawn "
        f"vtable=0x{GENERATOR_POLL_VTABLE_RVA:x} "
        f"update_offset=0x{GENERATOR_POLL_VIRTUAL_UPDATE_OFFSET:x} "
        f"update_method=0x{GENERATOR_POLL_UPDATE_RVA:x} "
        f"offset=0x{GENERATOR_POLL_VIRTUAL_SPAWN_OFFSET:x} "
        f"method=0x{GENERATOR_POLL_SPAWN_RVA:x}"
    )

    update_target = relative_branch_target(
        pe, GENERATOR_POLL_BASE_UPDATE_CALL_RVA, 0xE8
    )
    gate_target = relative_branch_target(
        pe, GENERATOR_POLL_BASE_GATE_TAIL_CALL_RVA, 0xE9
    )
    if (update_target != GENERATOR_POLL_BASE_UPDATE_RVA or
            gate_target != GENERATOR_POLL_GATE_RVA):
        raise ValueError(
            "GeneratorPoll update/base/gate chain changed: "
            f"base=0x{update_target:x} gate=0x{gate_target:x}"
        )
    print(
        "PASS generator_poll_update_gate_chain "
        f"update=0x{GENERATOR_POLL_UPDATE_RVA:x} "
        f"base=0x{GENERATOR_POLL_BASE_UPDATE_RVA:x} "
        f"gate=0x{GENERATOR_POLL_GATE_RVA:x}"
    )

    expected_scaling = {
        rva: bytes.fromhex(encoded)
        for rva, encoded in PARTICIPANT_SCALING_SIGNATURES
    }
    expected_getters = {
        rva: bytes.fromhex(encoded)
        for rva, encoded in PARTICIPANT_COUNT_GETTER_SIGNATURES
    }
    expected_member_reads = expected_scaling | expected_getters
    observed_member_reads = participant_scaling_reads(pe)
    if observed_member_reads != expected_member_reads:
        missing = sorted(set(expected_member_reads) - set(observed_member_reads))
        extra = sorted(set(observed_member_reads) - set(expected_member_reads))
        changed = sorted(
            rva for rva in set(expected_member_reads) & set(observed_member_reads)
            if expected_member_reads[rva] != observed_member_reads[rva]
        )
        raise ValueError(
            "native participant scaling census changed: "
            f"missing={[hex(value) for value in missing]} "
            f"extra={[hex(value) for value in extra]} "
            f"changed={[hex(value) for value in changed]}"
        )
    print(
        "PASS native_participant_scaling_reads "
        f"count={len(expected_scaling)} leaf_functions=2 "
        f"first=0x{min(expected_scaling):x} "
        f"last=0x{max(expected_scaling):x} "
        f"real_count_getters_preserved={len(expected_getters)}"
    )

    result_calls = direct_calls(pe, RESULT_EXEC_BEGIN_RVA)
    if result_calls != EXPECTED_RESULT_EXEC_CALLS:
        raise ValueError(
            "MissionResult Exec_Begin caller census changed: "
            f"expected={[hex(value) for value in EXPECTED_RESULT_EXEC_CALLS]} "
            f"observed={[hex(value) for value in result_calls]}"
        )

    print(
        "summary enemy_callers=24 native_enemy_capacity=400 "
        "scale_offsets=0x290/0x294 source_offset=0x2b0 "
        "scale_default=0/1 scale_config_record=4 "
        "generator_request_precedes_timer=true "
        "participant_table_affects_timer=true "
        "generator_update_virtual_offset=0xa0 "
        "generator_update_method=0x1f8b40 "
        "generator_base_update=0x2da720 "
        "generator_base_tailcalls_gate=true "
        "generator_gate_cooldown_threshold=0x1cc "
        "generator_gate_outcomes=cooldown/quota/spawn_false/spawn_accepted "
        "generator_gate_virtual_offset=0x108 "
        "generator_spawn_method=0x1f90a0 "
        "generator_manager_offset=0x788 "
        "generator_return_low_byte_consumed=true "
        "native_participant_scaling_reads=56 "
        "leaf_scaling_reads=2 "
        "native_scaling_capacity=4 "
        "stored_participant_count_preserved=true "
        "result_native_item_accumulators=4 "
        "result_dynamic_handle_vectors=2 "
        "exec_begin_direct_callers=2 "
        "result_sync_begin_wrapper=true "
        "exec_begin_argument=-20000"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("image", type=Path)
    args = parser.parse_args()
    try:
        validate(args.image)
    except (OSError, ValueError) as error:
        raise SystemExit(f"FAIL {error}") from error


if __name__ == "__main__":
    main()
