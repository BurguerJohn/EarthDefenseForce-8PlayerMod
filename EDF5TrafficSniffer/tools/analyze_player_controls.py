#!/usr/bin/env python3
"""Compare EDF5 participant-to-local-controller assignments across reports."""

from __future__ import annotations

import argparse
import collections
import json
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Iterable


def event_part(name: str) -> tuple[str, int]:
    path = PurePosixPath(name)
    if path.name == "events.jsonl":
        return (str(path.parent), 1)
    try:
        part = int(path.stem.rsplit("-", 1)[1])
    except (IndexError, ValueError):
        part = 2**31 - 1
    return (str(path.parent), part)


def integer_tuple(value: object) -> tuple[int, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(-1 if item is None else int(item) for item in value)


@dataclass(frozen=True)
class ChatNameAudit:
    message_count: int
    message_kind: int
    message_subtype: int
    sender_registered_order: int
    expected_name_token: int
    display_name_token: int
    display_name_owner_registered_order: int
    sender_participant_index: int
    display_name_owner_participant_index: int
    sender_identity_valid: bool
    sender_resolved: bool
    display_name_valid: bool
    display_name_resolved: bool
    association_complete: bool
    name_matches_sender: bool
    identity_name_collision: bool
    sender_identity_logged: bool
    display_name_text_logged: bool
    message_text_logged: bool


@dataclass(frozen=True)
class ReplicationReceiveRouteAudit:
    route_count: int
    inspected_count: int
    runtime_user_count: int
    unique_user_count: int
    unresolved_user_count: int
    empty_slot_count: int
    local_participant_mask: int
    expected_participant_mask: int
    participant_mask: int
    missing_participant_mask: int
    unexpected_participant_mask: int
    duplicate_participant_mask: int
    duplicate_route_mask: int
    transport_route_index_mismatch_mask: int
    route_to_participant: tuple[int, ...]
    route_transport_indices: tuple[int, ...]
    entries_readable: bool
    audit_truncated: bool
    participant_identity_unique: bool
    transport_route_indices_match_slots: bool
    route_complete: bool
    remote_only_semantics: bool


@dataclass(frozen=True)
class TransportRouteAssignmentAudit:
    registered_order: int
    runtime_user: bool
    transport_route_index: int
    local_controller_index: int
    receive_route_eligible: bool
    route_index_nonnegative: bool
    route_index_matches_registered_order: bool
    allocator_scan_stride: int
    receive_vector_stride: int
    allocator_owner_observed: bool
    allocator_owner_equals_receive_manager_proven: bool
    endpoint_identity_captured: bool
    steam_id_logged: bool
    pointer_logged: bool


@dataclass(frozen=True)
class ReplicationReceiveRouteLifecycleAudit:
    call: int
    action: str
    caller_rva: int
    expected_caller: bool
    registered_order: int
    participant_index: int
    allocator_owner_observed: bool
    allocator_owner_matches_receive_manager: bool
    transport_route_index: int
    local_controller_index: int
    route_eligible: bool
    vector_slot_expected: bool
    native_result: bool
    route_count_before: int
    route_count_after: int
    vector_capacity_after: int
    slot_present_before: bool
    slot_present_after: bool
    slot_route_object_readable_before: bool
    slot_route_object_readable_after: bool
    slot_user_control_readable_before: bool
    slot_user_control_readable_after: bool
    slot_user_resolved_before: bool
    slot_user_resolved_after: bool
    slot_matches_user_before: bool
    slot_matches_user_after: bool
    slot_transition_valid: bool
    anomaly: bool
    payload_logged: bool
    endpoint_identity_captured: bool
    steam_id_logged: bool
    pointer_logged: bool


@dataclass(frozen=True)
class ReplicationSendFanoutAudit:
    message_family: int
    message_code: int
    participant_index: int
    participant_association_resolved: bool
    local_lane: int
    target_count: int
    inspected_target_count: int
    valid_transport_route_count: int
    unique_transport_route_count: int
    duplicate_transport_route_target_mask: int
    duplicate_participant_target_mask: int
    unresolved_target_mask: int
    target_participant_mask: int
    expected_remote_participant_mask: int
    missing_remote_participant_mask: int
    unexpected_target_participant_mask: int
    target_vector_shape_valid: bool
    target_entries_readable: bool
    target_transport_routes_unique: bool
    target_participants_resolved: bool
    mapped_participant_count: int
    expected_remote_participant_count: int
    matches_expected_participant_fanout: bool
    serializer_result: bool
    payload_captured: bool
    endpoint_identity_captured: bool
    steam_id_logged: bool
    pointer_logged: bool


@dataclass(frozen=True)
class ResultExecBeginAudit:
    order: int
    call: int
    argument: int
    accepted: bool
    generation: int
    caller_rva: int
    caller_path: str
    caller_reported: bool


@dataclass(frozen=True)
class ResultExecUpdateAudit:
    order: int
    call: int
    outcome_count: int
    argument: int
    generation: int
    caller_rva: int
    caller_path: str
    expected_caller: bool
    native_result: bool
    caller_action: str
    state_handle_present: bool
    payload_logged: bool
    pointer_logged: bool


@dataclass(frozen=True)
class ResultExecFinallyAudit:
    order: int
    call: int
    argument: int
    generation: int
    caller_rva: int
    caller_path: str
    expected_caller: bool
    payload_logged: bool
    pointer_logged: bool


@dataclass(frozen=True)
class ResultExecRecoveryAudit:
    order: int
    event: str
    generation: int
    participant_count: int
    argument: int
    accepted: bool
    host_only: bool
    local_mission_harness: bool
    payload_logged: bool
    native_path_preserved: bool
    stale_pending_discarded: bool
    queue_cleared: bool


@dataclass(frozen=True)
class ResultCompletionAudit:
    order: int
    elapsed_ms: int
    result: int
    setter_calls: int
    apply_calls: int
    completion_signal: str
    room_ui_returned: bool
    diagnostic_phase_before_completion: str
    exec_begin_calls: int
    exec_update_calls: int
    exec_update_true_calls: int
    exec_update_false_calls: int
    exec_finally_calls: int
    sync_complete_calls: int
    reward_resolve_calls: int
    reward_apply_calls: int
    reward_apply_completed_calls: int
    participant_count: int
    expected_item_mask: int
    observed_item_mask: int
    result_items_complete: bool
    reward_contents_logged: bool
    payload_logged: bool


@dataclass
class Capture:
    label: str
    assignments: dict[str, dict[int, set[int]]] = field(
        default_factory=lambda: collections.defaultdict(
            lambda: collections.defaultdict(set)))
    control_resolution: dict[
        str, dict[int, set[tuple[int, int, bool]]]
    ] = field(default_factory=lambda: collections.defaultdict(
        lambda: collections.defaultdict(set)))
    returned: dict[str, set[int]] = field(
        default_factory=lambda: collections.defaultdict(set))
    loadout_blocks: dict[
        int, set[tuple[bool, int, int, int, int, str, int, int,
                       bool, bool, bool, str]]
    ] = field(default_factory=lambda: collections.defaultdict(set))
    loadout_parser_rollbacks: list[
        tuple[int, int, int, int, int, int, int, int, int, int, int, int,
              bool, str, bool, bool, bool, bool, bool]
    ] = field(default_factory=list)
    participant_class_resolutions: dict[
        int, set[tuple[int, int, int, int, str, bool, bool, bool]]
    ] = field(default_factory=lambda: collections.defaultdict(set))
    participant_visual_slots: dict[
        int, set[tuple[int, int, bool, bool, int]]
    ] = field(default_factory=lambda: collections.defaultdict(set))
    participant_names: dict[
        int, set[tuple[bool, int, int, int, int, bool, bool, int, bool]]
    ] = field(default_factory=lambda: collections.defaultdict(set))
    participant_transport_routes: dict[int, set[int]] = field(
        default_factory=lambda: collections.defaultdict(set))
    player_info_sources: list[
        tuple[int, int, int, int, int, bool, int, int, int, bool, bool]
    ] = field(default_factory=list)
    persona_names: dict[
        int, set[tuple[int, int, int, bool, bool, bool, bool]]
    ] = field(default_factory=lambda: collections.defaultdict(set))
    source_resolution: dict[int, set[tuple[int, bool, int, str]]] = field(
        default_factory=lambda: collections.defaultdict(set))
    identity_repairs: dict[
        int, set[tuple[int, int, int, bool]]
    ] = field(default_factory=lambda: collections.defaultdict(set))
    consumer_results: dict[
        int, set[tuple[bool, bool, int, int, int, str]]
    ] = field(default_factory=lambda: collections.defaultdict(set))
    null_character_guarded: set[int] = field(default_factory=set)
    all_user_counts: list[int] = field(default_factory=list)
    local_control_counts: list[int] = field(default_factory=list)
    enemy_spawn_observations: list[
        tuple[str, int, bool, int, int, int, int, int, bool, bool, bool,
              bool, bool, bool]
    ] = field(default_factory=list)
    enemy_spawn_summaries: list[
        tuple[str, int, int, int, int, int, int, int, int, int, int,
              bool, bool, bool, bool]
    ] = field(default_factory=list)
    generator_poll_paths: list[
        tuple[int, bool, bool, int, bool, bool, bool, bool, bool]
    ] = field(default_factory=list)
    generator_poll_update_paths: list[
        tuple[int, bool, bool, int, bool, bool, bool, bool]
    ] = field(default_factory=list)
    generator_poll_update_summaries: list[
        tuple[int, int, int, int]
    ] = field(default_factory=list)
    generator_poll_gate_paths: list[
        tuple[int, str, bool, bool, bool, bool, bool, int, int, int,
              int, int, int, int, bool, int, bool, bool, bool]
    ] = field(default_factory=list)
    generator_poll_gate_summaries: list[
        tuple[int, int, int, int, int, int, int]
    ] = field(default_factory=list)
    generator_poll_summaries: list[
        tuple[int, int, int, int, int, int, int]
    ] = field(default_factory=list)
    enemy_spawn_multiplier_policy_errors: list[str] = field(
        default_factory=list)
    native_participant_scaling_evidence: list[
        tuple[str, int, int, int, bool, int, bool, bool]
    ] = field(default_factory=list)
    result_setters: list[tuple[int, int, bool, int, int, int]] = field(
        default_factory=list)
    result_applies: list[tuple[int, int, int, int, int]] = field(
        default_factory=list)
    result_recoveries: list[tuple[str, int, bool]] = field(
        default_factory=list)
    result_recovery_returns: list[tuple[int, int, bool, bool]] = field(
        default_factory=list)
    result_event_publishes: list[
        tuple[int, int, int, bool, bool, bool]
    ] = field(default_factory=list)
    result_ui_close_dispatches: list[
        tuple[int, int, int, int, bool, bool, bool, bool, bool]
    ] = field(default_factory=list)
    result_item_aggregations: list[
        tuple[int, int, int, int, int, bool, bool, bool]
    ] = field(default_factory=list)
    result_progress: list[
        tuple[int, int, int, str, int, int, int, int, bool]
    ] = field(default_factory=list)
    result_completions: list[ResultCompletionAudit] = field(
        default_factory=list)
    result_exec_begins: list[ResultExecBeginAudit] = field(
        default_factory=list)
    result_exec_updates: list[ResultExecUpdateAudit] = field(
        default_factory=list)
    result_exec_finally: list[ResultExecFinallyAudit] = field(
        default_factory=list)
    result_exec_recoveries: list[ResultExecRecoveryAudit] = field(
        default_factory=list)
    result_sync_begins: list[
        tuple[int, str, int, int, int, bool]
    ] = field(default_factory=list)
    result_sync_polls: list[
        tuple[int, str, int, int, int, bool, bool, bool]
    ] = field(default_factory=list)
    reward_resolves: list[tuple[int, str, int, bool]] = field(
        default_factory=list)
    reward_applies: list[
        tuple[int, bool, bool, bool, int, int, int, int, bool, bool]
    ] = field(default_factory=list)
    reward_profile_repairs: list[
        tuple[str, int, int, int, int, bool, bool, bool]
    ] = field(default_factory=list)
    reward_item_checkpoints: list[
        tuple[str, str, int, bool, int, int, bool, bool, bool]
    ] = field(default_factory=list)
    result_item_checkpoints: list[
        tuple[str, str, int, bool, int, int, bool, bool, bool]
    ] = field(default_factory=list)
    result_item_progress: list[
        tuple[int, int, int, int, bool]
    ] = field(default_factory=list)
    result_pipeline_order: list[str] = field(default_factory=list)
    result_pipeline_progress: list[
        tuple[int, int, int, int, int, int, int, int, int]
    ] = field(default_factory=list)
    replication_counts: dict[tuple[str, int, int], int] = field(
        default_factory=lambda: collections.defaultdict(int))
    replication_context: dict[
        tuple[str, int, int],
        set[tuple[bool, bool, int, int, int, bool, int]]
    ] = field(default_factory=lambda: collections.defaultdict(set))
    replication_maps: list[tuple[int, int, int, int, bool]] = field(
        default_factory=list)
    replication_receive_routes: list[ReplicationReceiveRouteAudit] = field(
        default_factory=list)
    transport_route_assignments: list[TransportRouteAssignmentAudit] = field(
        default_factory=list)
    replication_receive_route_lifecycle: list[
        ReplicationReceiveRouteLifecycleAudit
    ] = field(default_factory=list)
    replication_send_fanouts: list[ReplicationSendFanoutAudit] = field(
        default_factory=list)
    chat_names: list[ChatNameAudit] = field(default_factory=list)
    malformed_lines: int = 0
    more_players_event_order: int = 0

    def consume(self, item: dict[str, object]) -> None:
        if (item.get("layer") == "steam_friends" and
                item.get("event") == "persona_identity_observed"):
            user_token = int(item.get("user_identity_token", 0))
            self.persona_names[user_token].add((
                int(item.get("persona_name_token", 0)),
                int(item.get("persona_name_length", 0)),
                int(item.get("shared_name_user_count", 0)),
                bool(item.get("persona_name_valid", False)),
                bool(item.get("mapping_changed", False)),
                bool(item.get("stored", False)),
                bool(item.get("synthetic", False)),
            ))
            return
        if item.get("layer") != "more_players":
            return
        self.more_players_event_order += 1
        event_order = self.more_players_event_order
        event = item.get("event")
        if event == "mission_player_control_assignment":
            context = str(item.get("context", "unknown"))
            participant = int(item.get("participant_index", -999))
            controller = int(item.get("local_controller_index", -999))
            self.assignments[context][participant].add(controller)
            if "original_local_controller_index" in item:
                original = int(item.get(
                    "original_local_controller_index", controller))
                effective = int(item.get(
                    "effective_local_controller_index", controller))
                corrected = bool(item.get(
                    "control_assignment_corrected", False))
                self.control_resolution[context][participant].add(
                    (original, effective, corrected))
        elif event == "mission_player_create_result":
            participant = int(item.get("participant_index", -999))
            if item.get("output_player_present"):
                context = str(item.get("context", "unknown"))
                self.returned[context].add(
                    participant)
            if "source_transport_route_index" in item:
                self.participant_transport_routes[participant].add(
                    int(item.get("source_transport_route_index", -999)))
            if "temporary_loadout_block_patched" in item:
                block_patched = bool(item.get(
                    "temporary_loadout_block_patched", False))
                self.loadout_blocks[participant].add((
                    block_patched,
                    int(item.get("requested_player_info_class", -1)),
                    int(item.get("temporary_loadout_block_class", -1)),
                    int(item.get(
                        "temporary_loadout_block_first_weapon", -1)),
                    int(item.get("temporary_loadout_block_armor", -1)),
                    str(item.get(
                        "temporary_loadout_block_source",
                        "player_info" if int(item.get(
                            "requested_player_info_class", -1)) in range(4)
                        else "legacy_unreported")),
                    int(item.get(
                        "temporary_loadout_block_weapon_valid_mask",
                        0x3f if block_patched else 0)),
                    int(item.get(
                        "temporary_loadout_block_fallback_weapon_mask", 0)),
                    bool(item.get("temporary_loadout_block_restored", False)),
                    bool(item.get("unique_loadout_index_restored", False)),
                    bool(item.get(
                        "loadout_restored_before_post_create_consumers",
                        False)),
                    str(item.get(
                        "loadout_restoration_phase", "legacy_unreported")),
                ))
            if "player_info_display_name_token" in item:
                self.participant_names[participant].add((
                    bool(item.get("player_info_display_name_valid", False)),
                    int(item.get("player_info_display_name_token", 0)),
                    int(item.get("player_info_display_name_length", 0)),
                    int(item.get("source_registered_order", -1)),
                    int(item.get("source_mission_loadout_index", -999)),
                    bool(item.get(
                        "source_identity_index_matches_participant", False)),
                    "source_mission_loadout_index" in item,
                    int(item.get("source_transport_route_index", -999)),
                    "source_transport_route_index" in item,
                ))
        elif event == "player_info_class_observed":
            self.player_info_sources.append((
                int(item.get("registered_order", -1)),
                int(item.get("source_mission_loadout_index", -999)),
                int(item.get("display_name_token", 0)),
                int(item.get("display_name_length", 0)),
                int(item.get("shared_name_user_count", 0)),
                bool(item.get(
                    "display_name_owned_by_different_user", False)),
                int(item.get("shared_loadout_index_user_count", 0)),
                int(item.get("transport_route_index", -999)),
                int(item.get(
                    "shared_transport_route_index_user_count", 0)),
                bool(item.get("display_name_text_logged", False)),
                bool(item.get("user_identity_logged", False)),
            ))
        elif event == "mission_source_index_audit" and (
                item.get("context") == "player_create"):
            participant = int(item.get("participant_index", -999))
            effective = int(item.get("effective_index", -999))
            recycled = bool(item.get("recycled", False))
            registered = int(item.get("effective_registered_order", -999))
            semantics = str(item.get(
                "source_table_semantics", "legacy_pre_sort_unknown"))
            self.source_resolution[participant].add(
                (effective, recycled, registered, semantics))
        elif event in ("mission_source_identity_repaired",
                       "mission_source_loadout_fallback_installed"):
            participant = int(item.get("participant_index", -999))
            self.identity_repairs[participant].add((
                int(item.get("original_loadout_index",
                             item.get("previous_class_selector", -999))),
                int(item.get("temporary_loadout_index",
                             item.get("repaired_class_selector", -999))),
                int(item.get("fallback_source_index",
                             item.get("class_source_index", -999))),
                bool(item.get("identity_object_preserved", False)),
            ))
        elif event == "mission_source_consumer_result":
            participant = int(item.get("participant_index", -999))
            self.consumer_results[participant].add((
                bool(item.get("direct_result_present", False)),
                bool(item.get("final_result_present", False)),
                int(item.get("successful_retry_source_index", -1)),
                int(item.get("retry_count", 0)),
                int(item.get("retry_source_mask", 0)),
                str(item.get("direct_null_stage", "unknown")),
            ))
        elif event == "mission_null_character_guarded":
            self.null_character_guarded.add(
                int(item.get("participant_index", -999)))
        elif event == "mission_loadout_parser_extra_blocks_restored":
            self.loadout_parser_rollbacks.append((
                int(item.get("protected_extra_blocks", 0)),
                int(item.get(
                    "changed_bytes_excluding_participant_count", 0)),
                int(item.get("changed_extra_block_mask", 0)),
                int(item.get("captured_sidecar_mask", -1)),
                int(item.get("invalid_sidecar_mask", -1)),
                int(item.get(
                    "complete_sidecar_weapon_mask",
                    item.get("captured_sidecar_mask", -1))),
                int(item.get("partial_sidecar_weapon_mask", 0)),
                int(item.get("local_profile_count_before", -1)),
                int(item.get("local_profile_count_during", -1)),
                int(item.get("local_profile_count_after", -1)),
                int(item.get("participant_count_after_parser", -1)),
                int(item.get("participant_count_preserved", -1)),
                bool(item.get(
                    "participant_count_output_valid",
                    item.get("parser_result", False))),
                str(item.get(
                    "participant_count_source",
                    "legacy_parser_return")),
                bool(item.get("local_profile_count_was_corrupted", False)),
                bool(item.get("parser_result", False)),
                bool(item.get("parser_failed", False)),
                bool(item.get(
                    "parser_return_controls_participant_count", True)),
                bool(item.get("restored", False)),
            ))
        elif event == "mission_participant_class_resolved":
            participant = int(item.get("participant_index", -999))
            self.participant_class_resolutions[participant].add((
                int(item.get("native_class", -1)),
                int(item.get("player_info_class", -1)),
                int(item.get("parser_sidecar_class", -1)),
                int(item.get(
                    "resolved_class", item.get("player_info_class", -1))),
                str(item.get(
                    "class_source",
                    "player_info" if int(item.get(
                        "player_info_class", -1)) in range(4)
                    else "legacy_unreported")),
                bool(item.get("class_corrected", False)),
                bool(item.get("logical_index_preserved", False)),
                bool(item.get(
                    "safe_class_in_range",
                    int(item.get("player_info_class", -1)) in range(4))),
            ))
        elif event == "mission_participant_visual_slot_remapped":
            participant = int(item.get("logical_participant_index", -999))
            self.participant_visual_slots[participant].add((
                int(item.get("native_visual_slot", -1)),
                int(item.get("native_visual_slot_count", 0)),
                bool(item.get("logical_user_index_preserved", False)),
                bool(item.get("resolver_output_remapped", False)),
                int(item.get("resolver_caller_rva", 0)),
            ))
        elif event == "mission_source_collection_audit":
            count = int(item.get("source_count", 0))
            collection = item.get("collection")
            if collection == "session_all_users":
                self.all_user_counts.append(count)
            elif collection == "session_local_controls":
                self.local_control_counts.append(count)
        elif event in ("enemy_spawn_observed",
                       "enemy_spawn_scale_repaired"):
            reported_multiplier = int(item.get("multiplier", 1))
            experimental_multiplier = bool(
                item.get("experimental_multiplier_enabled", False))
            if not experimental_multiplier and (
                    reported_multiplier != 1 or
                    bool(item.get("multiplier_applied", False))):
                self.enemy_spawn_multiplier_policy_errors.append(
                    f"{event} applied multiplier={reported_multiplier} "
                    "while the experiment was disabled")
            self.enemy_spawn_observations.append((
                str(event),
                int(item.get("caller_rva", 0)),
                bool(item.get("confirmed_enemy_caller", False)),
                int(item.get("requested_count", 0)),
                int(item.get("effective_requested_count", 0)),
                reported_multiplier,
                int(item.get("scale_numerator", 0)),
                int(item.get("scale_denominator", 0)),
                bool(item.get("spawn_source_present", False)),
                bool(item.get("zero_scale_repair_eligible", False)),
                bool(item.get("scale_field_writable", False)),
                bool(item.get("scale_repaired", False)),
                bool(item.get("actor_pointer_logged", False)),
                bool(item.get("spawn_payload_logged", False)),
            ))
        elif event == "generator_poll_update_path":
            self.generator_poll_update_paths.append((
                int(item.get("call", 0)),
                bool(item.get("original_returned", False)),
                bool(item.get("base_update_and_gate_reached", False)),
                int(item.get("spawn_method_calls_in_update", 0)),
                bool(item.get("spawn_method_reached", False)),
                bool(item.get("generator_pointer_logged", False)),
                bool(item.get("frame_context_pointer_logged", False)),
                bool(item.get("spawn_payload_logged", False)),
            ))
        elif event == "generator_poll_spawn_path":
            self.generator_poll_paths.append((
                int(item.get("call", 0)),
                bool(item.get("manager_field_readable", False)),
                bool(item.get("manager_present", False)),
                int(item.get("common_spawn_calls_in_method", 0)),
                bool(item.get("common_spawn_reached", False)),
                bool(item.get("gate_return_low_byte_nonzero", False)),
                bool(item.get("generator_pointer_logged", False)),
                bool(item.get("descriptor_pointer_logged", False)),
                bool(item.get("spawn_payload_logged", False)),
            ))
        elif event == "generator_poll_gate_path":
            self.generator_poll_gate_paths.append((
                int(item.get("call", 0)),
                str(item.get("outcome", "unknown")),
                bool(item.get("original_returned", False)),
                bool(item.get("owner_is_generator_poll", False)),
                bool(item.get("gate_state_matches_owner_offset", False)),
                bool(item.get("state_readable", False)),
                bool(item.get("owner_time_fields_readable", False)),
                int(item.get("pre_remaining_count", 0)),
                int(item.get("pre_cooldown_ticks", 0)),
                int(item.get("cooldown_after_decrement", 0)),
                int(item.get("post_remaining_count", 0)),
                int(item.get("post_cooldown_ticks", 0)),
                int(item.get("spawn_method_calls_in_gate", 0)),
                int(item.get("spawn_method_true_calls_in_gate", 0)),
                bool(item.get("method_call_count_valid", False)),
                int(item.get("cooldown_threshold", 0)),
                bool(item.get("gate_state_pointer_logged", False)),
                bool(item.get("owner_pointer_logged", False)),
                bool(item.get("spawn_payload_logged", False)),
            ))
        elif event == "enemy_spawn_summary":
            experimental_multiplier = bool(
                item.get("experimental_multiplier_enabled", False))
            effective_multiplier = int(item.get(
                "effective_multiplier", item.get("configured_multiplier", 1)))
            if not experimental_multiplier and effective_multiplier != 1:
                self.enemy_spawn_multiplier_policy_errors.append(
                    "enemy_spawn_summary reported "
                    f"effective_multiplier={effective_multiplier} while the "
                    "experiment was disabled")
            calls = int(item.get("calls", 0))
            confirmed_calls = int(item.get("confirmed_enemy_calls", 0))
            self.enemy_spawn_summaries.append((
                str(item.get("phase", "unknown")),
                calls,
                confirmed_calls,
                int(item.get("requested_total", 0)),
                int(item.get("effective_requested_total", 0)),
                int(item.get("zero_scale_calls", 0)),
                int(item.get("missing_spawn_source_calls", 0)),
                int(item.get("zero_scale_repairs", 0)),
                int(item.get("scale_restore_failures", 0)),
                int(item.get("configured_multiplier", 1)),
                int(item.get("native_enemy_capacity", 0)),
                bool(item.get("common_spawn_reached", calls != 0)),
                bool(item.get(
                    "confirmed_enemy_path_reached", confirmed_calls != 0)),
                bool(item.get("actor_pointer_logged", False)),
                bool(item.get("spawn_payload_logged", False)),
            ))
            if "generator_poll_calls" in item:
                if "generator_poll_update_calls" in item:
                    self.generator_poll_update_summaries.append((
                        int(item.get("generator_poll_update_calls", 0)),
                        int(item.get(
                            "generator_poll_update_completed_calls", 0)),
                        int(item.get(
                            "generator_poll_updates_reaching_spawn_method",
                            0)),
                        int(item.get(
                            "generator_poll_spawn_method_calls_in_updates",
                            0)),
                    ))
                if "generator_poll_native_gate_calls" in item:
                    self.generator_poll_gate_summaries.append((
                        int(item.get(
                            "generator_poll_native_gate_calls", 0)),
                        int(item.get(
                            "generator_poll_native_gate_completed_calls", 0)),
                        int(item.get(
                            "generator_poll_native_gate_cooldown_blocks", 0)),
                        int(item.get(
                            "generator_poll_native_gate_quota_blocks", 0)),
                        int(item.get(
                            "generator_poll_native_gate_spawn_false", 0)),
                        int(item.get(
                            "generator_poll_native_gate_spawn_accepted", 0)),
                        int(item.get(
                            "generator_poll_native_gate_unknown", 0)),
                    ))
                self.generator_poll_summaries.append((
                    int(item.get("generator_poll_calls", 0)),
                    int(item.get(
                        "generator_poll_manager_readable_calls", 0)),
                    int(item.get(
                        "generator_poll_manager_present_calls", 0)),
                    int(item.get(
                        "generator_poll_methods_reaching_common_spawn", 0)),
                    int(item.get(
                        "generator_poll_common_spawn_calls", 0)),
                    int(item.get("generator_poll_gate_true_calls", 0)),
                    int(item.get("generator_poll_gate_false_calls", 0)),
                ))
            if "native_participant_scaling_clamp_hits" in item:
                self.native_participant_scaling_evidence.append((
                    str(event),
                    int(item.get(
                        "native_participant_scaling_clamp_hits", 0)),
                    int(item.get(
                        "native_participant_scaling_clamp_site_mask", 0)),
                    int(item.get(
                        "native_participant_scaling_capacity", 0)),
                    bool(item.get(
                        "participant_count_storage_preserved", False)),
                    0,
                    bool(item.get("payload_logged", False)),
                    bool(item.get("pointer_logged", False)),
                ))
        elif event == "native_participant_scaling_clamp_observed":
            self.native_participant_scaling_evidence.append((
                str(event),
                int(item.get("hits_total", 0)),
                int(item.get("site_mask", 0)),
                int(item.get("native_participant_scaling_capacity", 0)),
                bool(item.get(
                    "participant_count_storage_preserved", False)),
                int(item.get("configured_capacity", 0)),
                bool(item.get("payload_logged", False)),
                bool(item.get("pointer_logged", False)),
            ))
        elif event == "mission_result_setter":
            self.result_setters.append((
                int(item.get("call", 0)),
                int(item.get("result", -999)),
                bool(item.get("natural_clear_caller", False)),
                int(item.get("caller_rva", 0)),
                int(item.get("after_ui_state", -999)),
                int(item.get("after_ui_result", -999)),
            ))
        elif event in ("mission_result_recovery_queued",
                       "mission_result_recovery_applied",
                       "mission_result_recovery_skipped"):
            self.result_recoveries.append((
                str(event),
                int(item.get("mission_generation",
                             item.get("queued_generation", 0))),
                bool(item.get("success", event.endswith("queued"))),
            ))
        elif event == "mission_result_recovery_returned":
            self.result_recovery_returns.append((
                int(item.get("native_update_result", -999)),
                int(item.get("effective_update_result", -999)),
                bool(item.get("stale_zero_overridden", False)),
                bool(item.get("native_update_already_clear", False)),
            ))
        elif event == "mission_result_event_publish":
            self.result_event_publishes.append((
                int(item.get("call", 0)),
                int(item.get("event_type", -999)),
                int(item.get("payload_value", -999)),
                bool(item.get("payload_readable", False)),
                bool(item.get("publisher_present", False)),
                bool(item.get(
                    "expected_ui_close_event",
                    item.get("expected_sync_event", False))),
            ))
        elif event == "mission_result_ui_close_dispatch":
            self.result_ui_close_dispatches.append((
                int(item.get("call", 0)),
                int(item.get("event_type", -999)),
                int(item.get("payload_value", -999)),
                int(item.get("listener_id", -999)),
                bool(item.get("listener_fields_readable", False)),
                bool(item.get("target_match", False)),
                bool(item.get("close_flag_before", False)),
                bool(item.get("close_flag_after", False)),
                bool(item.get("accepted", False)),
            ))
        elif event == "mission_result_apply":
            self.result_applies.append((
                int(item.get("call", 0)),
                int(item.get("result", -999)),
                int(item.get("after_ui_state", -999)),
                int(item.get("after_ui_result", -999)),
                int(item.get("caller_rva", 0)),
            ))
        elif event == "mission_result_item_aggregation":
            self.result_item_aggregations.append((
                int(item.get("call", 0)),
                int(item.get("participant_index", -999)),
                int(item.get("native_accumulator_slot", -999)),
                int(item.get("native_item_capacity", 0)),
                int(item.get("effective_participant_capacity", 0)),
                bool(item.get("aggregated", False)),
                bool(item.get("reward_contents_logged", False)),
                bool(item.get("payload_logged", False)),
            ))
        elif event == "mission_result_progress":
            self.result_progress.append((
                event_order,
                int(item.get("age_ms", 0)),
                int(item.get("checkpoint_ms", 0)),
                str(item.get("diagnostic_phase", "unknown")),
                int(item.get("result", -999)),
                int(item.get("last_ui_state", -999)),
                int(item.get("setter_calls", 0)),
                int(item.get("apply_calls", 0)),
                bool(item.get("transition_pending", True)),
            ))
            if "exec_begin_calls" in item:
                self.result_pipeline_progress.append((
                    int(item.get("checkpoint_ms", 0)),
                    int(item.get("expected_result_event_publish_calls", 0)),
                    int(item.get("exec_begin_calls", 0)),
                    int(item.get("sync_begin_calls", 0)),
                    int(item.get("sync_poll_calls", 0)),
                    int(item.get("sync_complete_calls", 0)),
                    int(item.get("reward_resolve_calls", 0)),
                    int(item.get("reward_apply_calls", 0)),
                    int(item.get(
                        "reward_apply_completed_calls",
                        item.get("reward_apply_calls", 0))),
                ))
            if "expected_result_item_mask" in item:
                self.result_item_progress.append((
                    int(item.get("checkpoint_ms", 0)),
                    int(item.get("result_participant_count", -1)),
                    int(item.get("expected_result_item_mask", 0)),
                    int(item.get("observed_result_item_mask", 0)),
                    bool(item.get("result_items_complete", False)),
                ))
        elif event == "mission_result_transition_completed":
            completion = ResultCompletionAudit(
                order=event_order,
                elapsed_ms=int(item.get("elapsed_ms", 0)),
                result=int(item.get("result", -999)),
                setter_calls=int(item.get("setter_calls", 0)),
                apply_calls=int(item.get("apply_calls", 0)),
                completion_signal=str(item.get(
                    "completion_signal", "legacy_or_unknown")),
                room_ui_returned=bool(item.get("room_ui_returned", False)),
                diagnostic_phase_before_completion=str(item.get(
                    "diagnostic_phase_before_completion", "legacy_or_unknown")),
                exec_begin_calls=int(item.get("exec_begin_calls", 0)),
                exec_update_calls=int(item.get("exec_update_calls", 0)),
                exec_update_true_calls=int(item.get(
                    "exec_update_true_calls", 0)),
                exec_update_false_calls=int(item.get(
                    "exec_update_false_calls", 0)),
                exec_finally_calls=int(item.get("exec_finally_calls", 0)),
                sync_complete_calls=int(item.get("sync_complete_calls", 0)),
                reward_resolve_calls=int(item.get("reward_resolve_calls", 0)),
                reward_apply_calls=int(item.get("reward_apply_calls", 0)),
                reward_apply_completed_calls=int(item.get(
                    "reward_apply_completed_calls",
                    item.get("reward_apply_calls", 0))),
                participant_count=int(item.get("participant_count", -1)),
                expected_item_mask=int(item.get(
                    "expected_result_item_mask", 0)),
                observed_item_mask=int(item.get(
                    "observed_result_item_mask", 0)),
                result_items_complete=bool(item.get(
                    "result_items_complete", False)),
                reward_contents_logged=bool(item.get(
                    "reward_contents_logged", False)),
                payload_logged=bool(item.get("payload_logged", False)),
            )
            self.result_completions.append(completion)
            if (completion.completion_signal == "room_ui_update" and
                    completion.room_ui_returned and
                    "room_return" not in self.result_pipeline_order):
                self.result_pipeline_order.append("room_return")
        elif event == "mission_result_exec_begin":
            accepted = bool(item.get("accepted", False))
            self.result_exec_begins.append(ResultExecBeginAudit(
                order=event_order,
                call=int(item.get("call", 0)),
                argument=int(item.get(
                    "argument", item.get("result", -999))),
                accepted=accepted,
                generation=int(item.get("mission_generation", 0)),
                caller_rva=int(item.get("caller_rva", 0)),
                caller_path=str(item.get(
                    "caller_path", "legacy_or_unknown")),
                caller_reported=("caller_rva" in item or
                                 "caller_path" in item),
            ))
            if accepted:
                self.result_pipeline_order.append("exec_begin")
        elif event == "mission_result_exec_update":
            native_result = bool(item.get("native_result", False))
            self.result_exec_updates.append(ResultExecUpdateAudit(
                order=event_order,
                call=int(item.get("call", 0)),
                outcome_count=int(item.get("outcome_count", 0)),
                argument=int(item.get("argument", -999)),
                generation=int(item.get("mission_generation", 0)),
                caller_rva=int(item.get("caller_rva", 0)),
                caller_path=str(item.get(
                    "caller_path", "legacy_or_unknown")),
                expected_caller=bool(item.get("expected_caller", False)),
                native_result=native_result,
                caller_action=str(item.get(
                    "caller_action_for_result", "unknown")),
                state_handle_present=bool(item.get(
                    "state_handle_present", False)),
                payload_logged=bool(item.get("payload_logged", False)),
                pointer_logged=bool(item.get("pointer_logged", False)),
            ))
            if "exec_update" not in self.result_pipeline_order:
                self.result_pipeline_order.append("exec_update")
        elif event == "mission_result_exec_finally":
            self.result_exec_finally.append(ResultExecFinallyAudit(
                order=event_order,
                call=int(item.get("call", 0)),
                argument=int(item.get("argument", -999)),
                generation=int(item.get("mission_generation", 0)),
                caller_rva=int(item.get("caller_rva", 0)),
                caller_path=str(item.get(
                    "caller_path", "legacy_or_unknown")),
                expected_caller=bool(item.get("expected_caller", False)),
                payload_logged=bool(item.get("payload_logged", False)),
                pointer_logged=bool(item.get("pointer_logged", False)),
            ))
            if "exec_finally" not in self.result_pipeline_order:
                self.result_pipeline_order.append("exec_finally")
        elif event in ("mission_result_exec_recovery_queued",
                       "mission_result_exec_recovery_applied",
                       "mission_result_exec_recovery_skipped",
                       "mission_result_exec_recovery_cancelled",
                       "mission_result_exec_recovery_generation_reset"):
            self.result_exec_recoveries.append(ResultExecRecoveryAudit(
                order=event_order,
                event=str(event),
                generation=int(item.get(
                    "mission_generation", item.get("queued_generation", 0))),
                participant_count=int(item.get("participant_count", -1)),
                argument=int(item.get(
                    "argument", item.get(
                        "exec_begin_argument", item.get(
                            "native_argument", -999)))),
                accepted=bool(item.get("accepted", False)),
                host_only=bool(item.get("host_only", False)),
                local_mission_harness=bool(item.get(
                    "local_mission_harness", False)),
                payload_logged=bool(item.get("payload_logged", False)),
                native_path_preserved=bool(item.get(
                    "native_path_preserved", False)),
                stale_pending_discarded=bool(item.get(
                    "stale_pending_discarded", False)),
                queue_cleared=bool(item.get("queue_cleared", False)),
            ))
        elif event == "mission_result_sync_begin":
            readable = bool(item.get("sync_state_readable", False))
            self.result_sync_begins.append((
                int(item.get("call", 0)),
                str(item.get("origin", "unknown")),
                int(item.get("caller_rva", 0)),
                int(item.get("sync_state", -999)),
                int(item.get("sync_result", -999)),
                readable,
            ))
            self.result_pipeline_order.append("sync_begin")
        elif event == "mission_result_sync_poll":
            complete = bool(item.get("complete", False))
            self.result_sync_polls.append((
                int(item.get("call", 0)),
                str(item.get("origin", "unknown")),
                int(item.get("caller_rva", 0)),
                int(item.get("sync_state", -999)),
                int(item.get("sync_result", -999)),
                bool(item.get("sync_state_readable", False)),
                bool(item.get("first_observation", False)),
                complete,
            ))
            if complete:
                self.result_pipeline_order.append("sync_complete")
        elif event == "mission_reward_resolve":
            phase = str(item.get("phase", "unknown"))
            returned = bool(item.get("returned", False))
            self.reward_resolves.append((
                int(item.get("call", 0)),
                phase,
                int(item.get("local_profile_count", -1)),
                returned,
            ))
            if phase == "original_returned" and returned:
                self.result_pipeline_order.append("reward_resolve")
            if "expected_extra_result_item_mask" in item:
                self.reward_item_checkpoints.append((
                    "resolve",
                    phase,
                    int(item.get("participant_count", -1)),
                    bool(item.get("participant_count_valid", False)),
                    int(item.get("expected_extra_result_item_mask", 0)),
                    int(item.get("observed_extra_result_item_mask", 0)),
                    bool(item.get("extra_result_items_complete", False)),
                    bool(item.get("reward_contents_logged", False)),
                    bool(item.get("payload_logged", False)),
                ))
            if "expected_result_item_mask" in item:
                self.result_item_checkpoints.append((
                    "resolve",
                    phase,
                    int(item.get("participant_count", -1)),
                    bool(item.get("participant_count_valid", False)),
                    int(item.get("expected_result_item_mask", 0)),
                    int(item.get("observed_result_item_mask", 0)),
                    bool(item.get("result_items_complete", False)),
                    bool(item.get("reward_contents_logged", False)),
                    bool(item.get("payload_logged", False)),
                ))
        elif event == "mission_reward_apply":
            # Legacy reports called this boolean `applied`, but static
            # disassembly and the five-player session proved that it is the
            # native function's auxiliary return value, not reward success.
            call_completed = bool(item.get("call_completed", True))
            native_result = bool(item.get(
                "native_result", item.get("applied", False)))
            self.reward_applies.append((
                int(item.get("call", 0)),
                bool(item.get("is_mission_clear", False)),
                call_completed,
                native_result,
                int(item.get("before_local_profile_count", -1)),
                int(item.get("expected_local_profile_count", -1)),
                int(item.get(
                    "effective_local_profile_count",
                    item.get("before_local_profile_count", -1))),
                int(item.get("after_local_profile_count", -1)),
                bool(item.get("local_profile_count_repaired", False)),
                bool(item.get("local_profile_count_valid", False)),
            ))
            if call_completed:
                self.result_pipeline_order.append("reward_apply")
            if "expected_extra_result_item_mask" in item:
                self.reward_item_checkpoints.append((
                    "apply",
                    "original_returned",
                    int(item.get("participant_count", -1)),
                    bool(item.get("participant_count_valid", False)),
                    int(item.get("expected_extra_result_item_mask", 0)),
                    int(item.get("observed_extra_result_item_mask", 0)),
                    bool(item.get("extra_result_items_complete", False)),
                    bool(item.get("reward_contents_logged", False)),
                    bool(item.get("payload_logged", False)),
                ))
            if "expected_result_item_mask" in item:
                self.result_item_checkpoints.append((
                    "apply",
                    "original_returned",
                    int(item.get("participant_count", -1)),
                    bool(item.get("participant_count_valid", False)),
                    int(item.get("expected_result_item_mask", 0)),
                    int(item.get("observed_result_item_mask", 0)),
                    bool(item.get("result_items_complete", False)),
                    bool(item.get("reward_contents_logged", False)),
                    bool(item.get("payload_logged", False)),
                ))
        elif event == "mission_reward_profile_count_repair":
            self.reward_profile_repairs.append((
                str(item.get("phase", "unknown")),
                int(item.get("before_local_profile_count", -1)),
                int(item.get("expected_local_profile_count", -1)),
                int(item.get("observed_compare_value", -1)),
                int(item.get("after_local_profile_count", -1)),
                bool(item.get("repaired", False)),
                bool(item.get("reward_contents_logged", False)),
                bool(item.get("payload_logged", False)),
            ))
        elif event == "replication_participant_map_ready":
            participant_count = int(item.get("participant_count", 0))
            unique_user_count = int(item.get(
                "unique_user_count", participant_count))
            duplicate_mask = int(item.get(
                "duplicate_participant_mask", 0))
            self.replication_maps.append((
                participant_count,
                int(item.get("source_count", 0)),
                unique_user_count,
                duplicate_mask,
                bool(item.get(
                    "participant_identity_unique",
                    unique_user_count == participant_count and
                    duplicate_mask == 0)),
            ))
        elif event == "user_transport_route_assignment":
            self.transport_route_assignments.append(
                TransportRouteAssignmentAudit(
                    registered_order=int(item.get(
                        "registered_order", -1)),
                    runtime_user=bool(item.get("runtime_user", False)),
                    transport_route_index=int(item.get(
                        "transport_route_index", -1)),
                    local_controller_index=int(item.get(
                        "local_controller_index", -1)),
                    receive_route_eligible=bool(item.get(
                        "receive_route_eligible", False)),
                    route_index_nonnegative=bool(item.get(
                        "route_index_nonnegative", False)),
                    route_index_matches_registered_order=bool(item.get(
                        "route_index_matches_registered_order", False)),
                    allocator_scan_stride=int(item.get(
                        "allocator_scan_stride", 0)),
                    receive_vector_stride=int(item.get(
                        "receive_vector_stride", 0)),
                    allocator_owner_observed=bool(item.get(
                        "allocator_owner_observed", False)),
                    allocator_owner_equals_receive_manager_proven=bool(
                        item.get(
                            "allocator_owner_equals_receive_manager_proven",
                            False)),
                    endpoint_identity_captured=bool(item.get(
                        "endpoint_identity_captured", False)),
                    steam_id_logged=bool(item.get(
                        "steam_id_logged", False)),
                    pointer_logged=bool(item.get("pointer_logged", False)),
                ))
        elif event == "replication_receive_route_map":
            self.replication_receive_routes.append(
                ReplicationReceiveRouteAudit(
                    route_count=int(item.get("route_count", 0)),
                    inspected_count=int(item.get("inspected_count", 0)),
                    runtime_user_count=int(item.get(
                        "runtime_user_count", 0)),
                    unique_user_count=int(item.get("unique_user_count", 0)),
                    unresolved_user_count=int(item.get(
                        "unresolved_user_count", 0)),
                    empty_slot_count=int(item.get("empty_slot_count", 0)),
                    local_participant_mask=int(item.get(
                        "local_participant_mask", 0)),
                    expected_participant_mask=int(item.get(
                        "expected_participant_mask", 0)),
                    participant_mask=int(item.get("participant_mask", 0)),
                    missing_participant_mask=int(item.get(
                        "missing_participant_mask", 0)),
                    unexpected_participant_mask=int(item.get(
                        "unexpected_participant_mask", 0)),
                    duplicate_participant_mask=int(item.get(
                        "duplicate_participant_mask", 0)),
                    duplicate_route_mask=int(item.get(
                        "duplicate_route_mask", 0)),
                    transport_route_index_mismatch_mask=int(item.get(
                        "transport_route_index_mismatch_mask", 0)),
                    route_to_participant=integer_tuple(item.get(
                        "route_to_participant", [])),
                    route_transport_indices=integer_tuple(item.get(
                        "route_transport_indices", [])),
                    entries_readable=bool(item.get(
                        "entries_readable", False)),
                    audit_truncated=bool(item.get(
                        "audit_truncated", False)),
                    participant_identity_unique=bool(item.get(
                        "participant_identity_unique", False)),
                    transport_route_indices_match_slots=bool(item.get(
                        "transport_route_indices_match_slots",
                        "transport_route_index_mismatch_mask" not in item)),
                    route_complete=bool(item.get("route_complete", False)),
                    remote_only_semantics=(
                        "local_participant_mask" in item or
                        "empty_slot_count" in item),
                ))
        elif event == "replication_receive_route_lifecycle":
            self.replication_receive_route_lifecycle.append(
                ReplicationReceiveRouteLifecycleAudit(
                    call=int(item.get("call", 0)),
                    action=str(item.get("action", "unknown")),
                    caller_rva=int(item.get("caller_rva", 0)),
                    expected_caller=bool(item.get(
                        "expected_caller", False)),
                    registered_order=int(item.get(
                        "registered_order", -1)),
                    participant_index=int(item.get(
                        "participant_index", -1)),
                    allocator_owner_observed=bool(item.get(
                        "allocator_owner_observed", False)),
                    allocator_owner_matches_receive_manager=bool(item.get(
                        "allocator_owner_matches_receive_manager", False)),
                    transport_route_index=int(item.get(
                        "transport_route_index", -1)),
                    local_controller_index=int(item.get(
                        "local_controller_index", -1)),
                    route_eligible=bool(item.get(
                        "route_eligible", False)),
                    vector_slot_expected=bool(item.get(
                        "vector_slot_expected", False)),
                    native_result=bool(item.get("native_result", False)),
                    route_count_before=int(item.get(
                        "route_count_before", 0)),
                    route_count_after=int(item.get(
                        "route_count_after", 0)),
                    vector_capacity_after=int(item.get(
                        "vector_capacity_after", 0)),
                    slot_present_before=bool(item.get(
                        "slot_present_before", False)),
                    slot_present_after=bool(item.get(
                        "slot_present_after", False)),
                    slot_route_object_readable_before=bool(item.get(
                        "slot_route_object_readable_before", False)),
                    slot_route_object_readable_after=bool(item.get(
                        "slot_route_object_readable_after", False)),
                    slot_user_control_readable_before=bool(item.get(
                        "slot_user_control_readable_before", False)),
                    slot_user_control_readable_after=bool(item.get(
                        "slot_user_control_readable_after", False)),
                    slot_user_resolved_before=bool(item.get(
                        "slot_user_resolved_before", False)),
                    slot_user_resolved_after=bool(item.get(
                        "slot_user_resolved_after", False)),
                    slot_matches_user_before=bool(item.get(
                        "slot_matches_user_before", False)),
                    slot_matches_user_after=bool(item.get(
                        "slot_matches_user_after", False)),
                    slot_transition_valid=bool(item.get(
                        "slot_transition_valid", False)),
                    anomaly=bool(item.get("anomaly", False)),
                    payload_logged=bool(item.get("payload_logged", False)),
                    endpoint_identity_captured=bool(item.get(
                        "endpoint_identity_captured", False)),
                    steam_id_logged=bool(item.get(
                        "steam_id_logged", False)),
                    pointer_logged=bool(item.get("pointer_logged", False)),
                ))
        elif event == "replication_send_fanout":
            self.replication_send_fanouts.append(
                ReplicationSendFanoutAudit(
                    message_family=int(item.get("message_family", 0)),
                    message_code=int(item.get("message_code", 0)),
                    participant_index=int(item.get(
                        "participant_index", -1)),
                    participant_association_resolved=bool(item.get(
                        "participant_association_resolved", False)),
                    local_lane=int(item.get("local_lane", -1)),
                    target_count=int(item.get("target_count", 0)),
                    inspected_target_count=int(item.get(
                        "inspected_target_count", 0)),
                    valid_transport_route_count=int(item.get(
                        "valid_transport_route_count", 0)),
                    unique_transport_route_count=int(item.get(
                        "unique_transport_route_count", 0)),
                    duplicate_transport_route_target_mask=int(item.get(
                        "duplicate_transport_route_target_mask", 0)),
                    duplicate_participant_target_mask=int(item.get(
                        "duplicate_participant_target_mask", 0)),
                    unresolved_target_mask=int(item.get(
                        "unresolved_target_mask", 0)),
                    target_participant_mask=int(item.get(
                        "target_participant_mask", 0)),
                    expected_remote_participant_mask=int(item.get(
                        "expected_remote_participant_mask", 0)),
                    missing_remote_participant_mask=int(item.get(
                        "missing_remote_participant_mask", 0)),
                    unexpected_target_participant_mask=int(item.get(
                        "unexpected_target_participant_mask", 0)),
                    target_vector_shape_valid=bool(item.get(
                        "target_vector_shape_valid", False)),
                    target_entries_readable=bool(item.get(
                        "target_entries_readable", False)),
                    target_transport_routes_unique=bool(item.get(
                        "target_transport_routes_unique", False)),
                    target_participants_resolved=bool(item.get(
                        "target_participants_resolved", False)),
                    mapped_participant_count=int(item.get(
                        "mapped_participant_count", 0)),
                    expected_remote_participant_count=int(item.get(
                        "expected_remote_participant_count", 0)),
                    matches_expected_participant_fanout=bool(item.get(
                        "matches_expected_participant_fanout", False)),
                    serializer_result=bool(item.get(
                        "serializer_result", False)),
                    payload_captured=bool(item.get(
                        "payload_captured", False)),
                    endpoint_identity_captured=bool(item.get(
                        "endpoint_identity_captured", False)),
                    steam_id_logged=bool(item.get(
                        "steam_id_logged", False)),
                    pointer_logged=bool(item.get("pointer_logged", False)),
                ))
        elif event in ("replication_participant_first_observed",
                       "replication_participant_progress"):
            key = (
                str(item.get("direction", "unknown")),
                int(item.get("message_family", 0)),
                int(item.get("participant_index", -1)),
            )
            count = int(item.get(
                "messages_total", item.get("messages", 0)))
            self.replication_counts[key] = max(
                self.replication_counts[key], count)
            if event == "replication_participant_first_observed":
                self.replication_context[key].add((
                    bool(item.get(
                        "participant_association_resolved", False)),
                    bool(item.get("context_runtime_user", False)),
                    int(item.get("source_registered_order", -1)),
                    int(item.get("mission_loadout_index", -1)),
                    int(item.get("transport_route_index", -1)),
                    bool(item.get(
                        "player_info_display_name_valid", False)),
                    int(item.get(
                        "player_info_display_name_token", 0)),
                ))
        elif event == "chat_name_association":
            self.chat_names.append(ChatNameAudit(
                message_count=int(item.get("message_count", 0)),
                message_kind=int(item.get("message_kind", -1)),
                message_subtype=int(item.get("message_subtype", -1)),
                sender_registered_order=int(item.get(
                    "sender_registered_order", -1)),
                expected_name_token=int(item.get(
                    "expected_player_info_name_token", 0)),
                display_name_token=int(item.get("display_name_token", 0)),
                display_name_owner_registered_order=int(item.get(
                    "display_name_owner_registered_order", -1)),
                sender_participant_index=int(item.get(
                    "sender_participant_index", -1)),
                display_name_owner_participant_index=int(item.get(
                    "display_name_owner_participant_index", -1)),
                sender_identity_valid=bool(item.get(
                    "sender_identity_valid", False)),
                sender_resolved=bool(item.get("sender_resolved", False)),
                display_name_valid=bool(item.get(
                    "display_name_valid", False)),
                display_name_resolved=bool(item.get(
                    "display_name_resolved", False)),
                association_complete=bool(item.get(
                    "association_complete", False)),
                name_matches_sender=bool(item.get(
                    "name_matches_sender", False)),
                identity_name_collision=bool(item.get(
                    "identity_name_collision", False)),
                sender_identity_logged=bool(item.get(
                    "sender_identity_logged", False)),
                display_name_text_logged=bool(item.get(
                    "display_name_text_logged", False)),
                message_text_logged=bool(item.get(
                    "message_text_logged", False)),
            ))


def parse_lines(label: str, lines: Iterable[str]) -> Capture:
    capture = Capture(label)
    for line in lines:
        try:
            item = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            capture.malformed_lines += 1
            continue
        if isinstance(item, dict):
            capture.consume(item)
    return capture


def captures_from_zip(path: Path) -> list[Capture]:
    groups: dict[str, list[str]] = collections.defaultdict(list)
    with zipfile.ZipFile(path) as archive:
        names = sorted(
            (name for name in archive.namelist()
             if PurePosixPath(name).name.startswith("events")
             and name.endswith(".jsonl")),
            key=event_part)
        for name in names:
            parent = str(PurePosixPath(name).parent)
            groups[parent].extend(
                archive.read(name).decode("utf-8", errors="replace").splitlines())
    if not groups:
        return [Capture(path.name)]
    multiple = len(groups) > 1
    return [
        parse_lines(f"{path.name}:{parent}" if multiple else path.name, lines)
        for parent, lines in groups.items()
    ]


def captures_from_path(path: Path) -> list[Capture]:
    if path.suffix.casefold() == ".zip":
        return captures_from_zip(path)
    if path.is_file():
        return [parse_lines(str(path), path.read_text(
            encoding="utf-8", errors="replace").splitlines())]
    event_files = sorted(path.rglob("events*.jsonl"),
                         key=lambda item: (str(item.parent), event_part(item.name)))
    groups: dict[Path, list[Path]] = collections.defaultdict(list)
    for event_file in event_files:
        groups[event_file.parent].append(event_file)
    return [
        parse_lines(str(parent), (
            line
            for event_file in files
            for line in event_file.read_text(
                encoding="utf-8", errors="replace").splitlines()))
        for parent, files in groups.items()
    ]


def validate_result_exec_native_cancellation(
        capture: Capture, required: bool) -> list[str]:
    """Validate the native-wins branch of the Exec_Begin grace window."""
    problems: list[str] = []
    healthy_generations: set[int] = set()
    cancellations = [
        item for item in capture.result_exec_recoveries
        if item.event == "mission_result_exec_recovery_cancelled"
    ]
    for generation in sorted({item.generation for item in cancellations}):
        generation_cancellations = [
            item for item in cancellations if item.generation == generation
        ]
        queued = [
            item for item in capture.result_exec_recoveries
            if item.event == "mission_result_exec_recovery_queued" and
            item.generation == generation
        ]
        applied = [
            item for item in capture.result_exec_recoveries
            if item.event == "mission_result_exec_recovery_applied" and
            item.generation == generation
        ]
        native_begins = [
            item for item in capture.result_exec_begins
            if item.generation == generation and item.accepted and
            item.order > generation_cancellations[0].order
        ]
        cancellation = generation_cancellations[0]
        has_prior_queue = any(item.order < cancellation.order for item in queued)
        if generation <= 0:
            problems.append(
                f"{capture.label}: native Exec_Begin cancellation has no "
                "mission generation")
        if len(generation_cancellations) != 1:
            problems.append(
                f"{capture.label}: mission generation {generation} has "
                f"{len(generation_cancellations)} native Exec_Begin cancellations")
        if not has_prior_queue:
            problems.append(
                f"{capture.label}: native Exec_Begin cancellation has no prior "
                f"queued recovery for generation {generation}")
        if applied:
            problems.append(
                f"{capture.label}: mission generation {generation} both "
                "cancelled and applied the Exec_Begin recovery")
        if len(native_begins) != 1:
            problems.append(
                f"{capture.label}: mission generation {generation} has "
                f"{len(native_begins)} accepted native Exec_Begin calls after "
                "cancellation")
        elif native_begins[0].argument != cancellation.argument:
            problems.append(
                f"{capture.label}: native Exec_Begin argument changed across "
                f"cancellation ({cancellation.argument} -> "
                f"{native_begins[0].argument})")
        if (generation > 0 and len(generation_cancellations) == 1 and
                has_prior_queue and not applied and len(native_begins) == 1 and
                cancellation.native_path_preserved and
                native_begins[0].argument == cancellation.argument):
            healthy_generations.add(generation)
    if required and not healthy_generations:
        problems.append(
            f"{capture.label}: no healthy native Exec_Begin recovery "
            "cancellation")
    return problems


def summarize(captures: list[Capture], expected_players: int,
              expected_local: int, require_exact_loadout: bool,
              require_pre_map_loadout_restore: bool,
              require_name_identity: bool,
              require_chat_name_association: bool,
              require_replication_association: bool,
              require_replication_matrix: bool,
              require_replication_send_fanout: bool,
              require_receive_route_matrix: bool,
              require_receive_route_lifecycle: bool,
              require_transport_route_identity: bool,
              require_result_event_publish: bool,
              require_result_ui_close_dispatch: bool,
              require_result_reward_chain: bool,
              require_result_room_return: bool,
              require_loadout_parser_rollback: bool,
              require_class_sidecar: bool,
              require_visual_slot_remap: bool,
              require_effective_result_recovery: bool,
              require_extra_result_items: bool,
              require_result_item_matrix: bool,
              require_enemy_spawn: bool,
              require_enemy_spawn_repair: bool,
              require_native_participant_scaling_clamp: bool,
              require_result_exec_recovery: bool,
              require_result_exec_native_cancel: bool,
              require_result_exec_pipeline: bool) -> list[str]:
    problems: list[str] = []
    ownership: collections.Counter[int] = collections.Counter()
    expected = set(range(expected_players))
    for capture in captures:
        capture_local_owners: set[int] = set()
        print(f"\nCapture: {capture.label}")
        if capture.malformed_lines:
            problems.append(
                f"{capture.label}: {capture.malformed_lines} malformed line(s)")
        if capture.all_user_counts or capture.local_control_counts:
            print("  collections: all_users=" +
                  (str(max(capture.all_user_counts))
                   if capture.all_user_counts else "?") +
                  " local_controls=" +
                  (str(max(capture.local_control_counts))
                   if capture.local_control_counts else "?"))
        persona_users_by_name: dict[int, set[int]] = collections.defaultdict(set)
        for user_token, values in sorted(capture.persona_names.items()):
            rendered = ", ".join(
                f"name={name_token} length={length} shared={shared} "
                f"valid={str(valid).lower()} changed={str(changed).lower()} "
                f"stored={str(stored).lower()} synthetic={str(synthetic).lower()}"
                for name_token, length, shared, valid, changed, stored,
                synthetic in sorted(values))
            print(f"  persona user_token={user_token}: {rendered}")
            for name_token, _, shared, valid, _, stored, _ in values:
                if name_token:
                    persona_users_by_name[name_token].add(user_token)
                if not user_token or not valid or not stored or not name_token:
                    problems.append(
                        f"{capture.label}: invalid private persona mapping for "
                        f"user token {user_token}")
                if shared > 1:
                    problems.append(
                        f"{capture.label}: persona name token {name_token} "
                        f"reported for {shared} user identities")
        for name_token, users in sorted(persona_users_by_name.items()):
            if len(users) > 1:
                problems.append(
                    f"{capture.label}: persona name token {name_token} shared "
                    f"by user tokens {sorted(users)}")
        if not capture.assignments:
            problems.append(f"{capture.label}: no control-assignment telemetry")
            print("  assignments: none (report predates v0.5.6 or mission did not enter builder)")
        for context, mapping in sorted(capture.assignments.items()):
            rendered: list[str] = []
            local_participants: list[int] = []
            for participant in sorted(mapping):
                controllers = mapping[participant]
                values = "/".join(str(value) for value in sorted(controllers))
                rendered.append(f"P{participant}={values}")
                if any(value >= 0 for value in controllers):
                    local_participants.append(participant)
                    capture_local_owners.add(participant)
                if len(controllers) != 1:
                    problems.append(
                        f"{capture.label}/{context}: P{participant} changed controller")
            print(f"  {context}: " + " ".join(rendered))
            print("    locally controlled: " +
                  (", ".join(f"P{item}" for item in local_participants)
                   if local_participants else "none"))
            resolution = capture.control_resolution.get(context, {})
            if resolution:
                details = []
                for participant, values in sorted(resolution.items()):
                    rendered_values = "/".join(
                        f"{original}->{effective}" +
                        (" corrected" if corrected else " preserved")
                        for original, effective, corrected in sorted(values))
                    details.append(f"P{participant}={rendered_values}")
                print("    native/effective: " + " ".join(details))
            observed = {item for item in mapping if item >= 0}
            missing = sorted(expected - observed)
            if missing:
                problems.append(
                    f"{capture.label}/{context}: missing participants {missing}")
            if len(local_participants) != expected_local:
                problems.append(
                    f"{capture.label}/{context}: expected {expected_local} local, "
                    f"observed {len(local_participants)}")
            not_returned = sorted(observed - capture.returned.get(context, set()))
            if not_returned:
                problems.append(
                    f"{capture.label}/{context}: builder did not return for {not_returned}")
        for participant, values in sorted(capture.source_resolution.items()):
            rendered = ", ".join(
                f"effective={effective} registered={registered} "
                f"semantics={semantics} "
                f"recycled={str(recycled).lower()}"
                for effective, recycled, registered, semantics
                in sorted(values))
            print(f"  source P{participant}: {rendered}")
            # Registered construction order is intentionally not compared to
            # participant index. EDF5 sorts the final table descending by its
            # UserImpl ID after the collection-copy telemetry point.
            if participant >= 4 and any(recycled for _, recycled, _, _ in values):
                problems.append(
                    f"{capture.label}: P{participant} reused another UserImpl identity")
        for participant, values in sorted(capture.identity_repairs.items()):
            rendered = ", ".join(
                f"loadout={previous}->{repaired} source=P{source} "
                f"identity_preserved={str(preserved).lower()}"
                for previous, repaired, source, preserved in sorted(values))
            print(f"  temporary loadout P{participant}: {rendered}")
            if any(not preserved for _, _, _, preserved in values):
                problems.append(
                    f"{capture.label}: P{participant} identity repair replaced its object")
        for participant, values in sorted(capture.loadout_blocks.items()):
            rendered = ", ".join(
                f"patched={str(patched).lower()} "
                f"class={requested_class}->{selected_class} "
                f"first_weapon={first_weapon} armor={armor} source={source} "
                f"weapons=0x{weapon_valid_mask:x}/"
                f"fallback=0x{fallback_weapon_mask:x} "
                f"block_restored={str(block_restored).lower()} "
                f"identity_index_restored={str(index_restored).lower()} "
                f"pre_map_restore={str(pre_map_restore).lower()} "
                f"phase={restoration_phase}"
                for patched, requested_class, selected_class, first_weapon,
                armor, source, weapon_valid_mask, fallback_weapon_mask,
                block_restored, index_restored, pre_map_restore,
                restoration_phase
                in sorted(values))
            print(f"  exact loadout block P{participant}: {rendered}")
            if participant >= 4 and any(
                    not patched or selected_class not in range(4)
                    or source not in ("player_info", "parser_sidecar",
                                      "legacy_unreported")
                    or (source == "player_info" and
                        requested_class in range(4) and
                        selected_class != requested_class)
                    or armor < 0
                    or (weapon_valid_mask | fallback_weapon_mask) != 0x3f
                    or (weapon_valid_mask & fallback_weapon_mask) != 0
                    or (source == "player_info" and
                        weapon_valid_mask != 0x3f)
                    or not block_restored or not index_restored
                    for patched, requested_class, selected_class, _, armor,
                    source, weapon_valid_mask, fallback_weapon_mask,
                    block_restored, index_restored, _, _ in values):
                problems.append(
                    f"{capture.label}: P{participant} exact class/loadout/identity restore failed")
            if participant >= 4 and require_pre_map_loadout_restore and any(
                    not pre_map_restore or
                    restoration_phase != "after_character_consumer"
                    for *_, pre_map_restore, restoration_phase in values):
                problems.append(
                    f"{capture.label}: P{participant} loadout identity was not "
                    "restored before native participant-map consumers")
        if require_exact_loadout or require_pre_map_loadout_restore:
            missing_loadout = [
                participant for participant in range(4, expected_players)
                if participant not in capture.loadout_blocks
            ]
            if missing_loadout:
                problems.append(
                    f"{capture.label}: exact loadout telemetry missing for "
                    f"{missing_loadout}")
        if capture.loadout_parser_rollbacks:
            print("  extra loadout parser rollback: " + "; ".join(
                f"blocks={blocks} changed={changed} mask=0x{mask:x} "
                f"sidecar=0x{captured:x} invalid=0x{invalid:x} "
                f"complete_weapons=0x{complete:x} "
                f"partial_weapons=0x{partial:x} "
                f"profiles={profiles_before}->{profiles_during}->"
                f"{profiles_after} participants={participants_after}->"
                f"{participants_preserved} count_source={count_source} "
                f"count_valid={str(count_valid).lower()} "
                f"profile_corrupted={str(profile_corrupted).lower()} "
                f"parser={str(parser_result).lower()} "
                f"parser_failed={str(parser_failed).lower()} "
                f"return_controls_count={str(return_controls).lower()} "
                f"restored={str(restored).lower()}"
                for blocks, changed, mask, captured, invalid, complete,
                partial, profiles_before, profiles_during, profiles_after,
                participants_after, participants_preserved, count_valid,
                count_source, profile_corrupted, parser_result, parser_failed,
                return_controls, restored
                in capture.loadout_parser_rollbacks))
            if any(
                    not restored or
                    profiles_after != profiles_before or
                    (count_valid and
                     participants_preserved != participants_after) or
                    (parser_failed and count_valid) or
                    (captured >= 0 and
                     (complete | partial) != captured)
                    for _, _, _, captured, _, complete, partial,
                    profiles_before, _, profiles_after,
                    participants_after, participants_preserved, count_valid,
                    _, _, _, parser_failed, _, restored
                    in capture.loadout_parser_rollbacks):
                problems.append(
                    f"{capture.label}: extra loadout parser rollback did not "
                    "restore reward state or preserve participant count")
        if require_loadout_parser_rollback and expected_players > 4:
            required_blocks = min(expected_players, 8) - 4
            if not any(
                    restored and blocks >= required_blocks
                    for blocks, *_, restored
                    in capture.loadout_parser_rollbacks):
                problems.append(
                    f"{capture.label}: no successful P4+ loadout parser "
                    "rollback telemetry")
        for participant, values in sorted(
                capture.participant_class_resolutions.items()):
            rendered = ", ".join(
                f"native={native} player_info={player_info} "
                f"parser_sidecar={parser_sidecar} resolved={resolved} "
                f"source={source} safe={str(safe).lower()} "
                f"corrected={str(corrected).lower()} "
                f"index_preserved={str(index_preserved).lower()}"
                for native, player_info, parser_sidecar, resolved, source,
                corrected, index_preserved, safe
                in sorted(values))
            print(f"  class sidecar P{participant}: {rendered}")
            if participant >= 4 and any(
                    resolved not in range(4) or not safe or
                    not index_preserved
                    for _, _, _, resolved, _, _, index_preserved, safe
                    in values):
                problems.append(
                    f"{capture.label}: P{participant} class sidecar invalid")
        if require_class_sidecar:
            missing_class_sidecar = [
                participant for participant in range(4, expected_players)
                if participant not in capture.participant_class_resolutions
            ]
            if missing_class_sidecar:
                problems.append(
                    f"{capture.label}: class sidecar telemetry missing for "
                    f"{missing_class_sidecar}")
            for participant in range(4, expected_players):
                if participant not in capture.participant_class_resolutions:
                    continue
                if all(
                        source not in ("player_info", "parser_sidecar",
                                       "native_resolver",
                                       "legacy_unreported")
                        for _, _, _, _, source, *_
                        in capture.participant_class_resolutions[participant]):
                    problems.append(
                        f"{capture.label}: P{participant} has only emergency "
                        "visual class fallback, no observed loadout class")
        for participant, values in sorted(
                capture.participant_visual_slots.items()):
            rendered = ", ".join(
                f"slot={slot}/{count} logical_preserved="
                f"{str(logical_preserved).lower()} remapped="
                f"{str(remapped).lower()} caller=0x{caller:x}"
                for slot, count, logical_preserved, remapped, caller
                in sorted(values))
            print(f"  visual slot P{participant}: {rendered}")
            if participant >= 4 and any(
                    count != 4 or slot != participant % count or
                    not logical_preserved or not remapped
                    for slot, count, logical_preserved, remapped, _ in values):
                problems.append(
                    f"{capture.label}: P{participant} visual slot remap invalid")
        if require_visual_slot_remap:
            missing_visual_slots = [
                participant for participant in range(4, expected_players)
                if participant not in capture.participant_visual_slots
            ]
            if missing_visual_slots:
                problems.append(
                    f"{capture.label}: visual slot remap telemetry missing for "
                    f"{missing_visual_slots}")
        if capture.player_info_sources:
            print("  PlayerInfo source/name audit:")
        for registered, source_index, token, length, shared_names, \
                foreign_owner, shared_indices, route_index, shared_routes, \
                text_logged, \
                identity_logged in capture.player_info_sources:
            print(
                f"    R{registered} source=P{source_index} token={token} "
                f"length={length} shared_names={shared_names} "
                f"shared_indices={shared_indices} "
                f"transport_route={route_index} "
                f"shared_transport_routes={shared_routes} "
                f"foreign_name_owner={str(foreign_owner).lower()}")
            if text_logged or identity_logged:
                problems.append(
                    f"{capture.label}: PlayerInfo audit retained nickname "
                    "text or user identity")
            if foreign_owner or shared_names > 1:
                problems.append(
                    f"{capture.label}: PlayerInfo name token {token} was "
                    "constructed for more than one UserImpl")
            if shared_routes > 1:
                problems.append(
                    f"{capture.label}: transport route {route_index} was "
                    "assigned to more than one UserImpl")
        participants_by_name: dict[int, set[int]] = collections.defaultdict(set)
        for participant, values in sorted(capture.participant_names.items()):
            rendered = ", ".join(
                f"token={token} length={length} valid={str(valid).lower()} "
                f"registered={registered} source=P{source_index} "
                f"identity_match={str(identity_match).lower()} "
                f"identity_reported={str(identity_reported).lower()} "
                f"transport_route={route_index} "
                f"transport_reported={str(route_reported).lower()}"
                for valid, token, length, registered, source_index,
                identity_match, identity_reported, route_index,
                route_reported in sorted(values))
            print(f"  display name P{participant}: {rendered}")
            tokens = {token for valid, token, *_ in values
                      if valid and token > 0}
            for token in tokens:
                participants_by_name[token].add(participant)
            if require_name_identity and (
                    len(tokens) != 1 or any(
                        not valid or token <= 0 or length <= 0
                        for valid, token, length, *_ in values)):
                problems.append(
                    f"{capture.label}: P{participant} display-name identity invalid or changed")
            if any(
                    identity_reported and
                    (source_index != participant or not identity_match)
                    for _, _, _, _, source_index, identity_match,
                    identity_reported, _, _ in values):
                problems.append(
                    f"{capture.label}: P{participant} display name came from "
                    "a mismatched logical UserImpl source")
        for name_token, participants in sorted(participants_by_name.items()):
            if len(participants) > 1:
                problems.append(
                    f"{capture.label}: display-name token {name_token} shared "
                    f"by participants {sorted(participants)}")
        participants_by_transport_route: dict[int, set[int]] = (
            collections.defaultdict(set))
        if capture.participant_transport_routes:
            print("  participant transport routes: " + " ".join(
                f"P{participant}={sorted(routes)}"
                for participant, routes in sorted(
                    capture.participant_transport_routes.items())))
        for participant, routes in sorted(
                capture.participant_transport_routes.items()):
            valid_routes = {route for route in routes if route >= 0}
            if len(valid_routes) != 1 or len(routes) != 1:
                problems.append(
                    f"{capture.label}: P{participant} transport route is "
                    "invalid or changed")
            for route_index in valid_routes:
                participants_by_transport_route[route_index].add(participant)
        for route_index, participants in sorted(
                participants_by_transport_route.items()):
            if len(participants) > 1:
                problems.append(
                    f"{capture.label}: transport route {route_index} shared "
                    f"by participants {sorted(participants)}")
        if require_transport_route_identity:
            missing_transport_routes = sorted(
                expected - set(capture.participant_transport_routes))
            if missing_transport_routes:
                problems.append(
                    f"{capture.label}: transport-route telemetry missing for "
                    f"{missing_transport_routes}")
        if require_name_identity:
            missing_names = [
                participant for participant in range(expected_players)
                if participant not in capture.participant_names
            ]
            if missing_names:
                problems.append(
                    f"{capture.label}: display-name telemetry missing for "
                    f"{missing_names}")
        participant_tokens_by_registered_order: dict[int, set[int]] = (
            collections.defaultdict(set))
        for values in capture.participant_names.values():
            for valid, token, _, registered, *_ in values:
                if valid and token > 0 and registered >= 0:
                    participant_tokens_by_registered_order[registered].add(
                        token)
        complete_chat_senders: set[int] = set()
        if capture.chat_names:
            print("  chat sender/name audit:")
        for audit in capture.chat_names:
            sender = (f"R{audit.sender_registered_order}"
                      if audit.sender_registered_order >= 0
                      else "unresolved")
            owner = (f"R{audit.display_name_owner_registered_order}"
                     if audit.display_name_owner_registered_order >= 0
                     else "unresolved")
            sender_participant = (
                f"P{audit.sender_participant_index}"
                if audit.sender_participant_index >= 0 else "P?")
            owner_participant = (
                f"P{audit.display_name_owner_participant_index}"
                if audit.display_name_owner_participant_index >= 0 else "P?")
            print(
                f"    message={audit.message_count} kind={audit.message_kind}/"
                f"{audit.message_subtype} sender={sender}/"
                f"{sender_participant} "
                f"expected={audit.expected_name_token} "
                f"display={audit.display_name_token} owner={owner}/"
                f"{owner_participant} "
                f"complete={str(audit.association_complete).lower()} "
                f"match={str(audit.name_matches_sender).lower()} "
                f"collision={str(audit.identity_name_collision).lower()}")
            if (audit.sender_identity_logged or
                    audit.display_name_text_logged or
                    audit.message_text_logged):
                problems.append(
                    f"{capture.label}: chat audit retained sensitive identity, "
                    "nickname or message text")
            collision = audit.identity_name_collision or (
                audit.association_complete and not audit.name_matches_sender)
            if collision:
                problems.append(
                    f"{capture.label}: chat sender {sender} used display name "
                    f"owned by {owner}")
            if audit.association_complete and audit.name_matches_sender:
                complete_chat_senders.add(audit.sender_registered_order)
                if (audit.sender_registered_order !=
                        audit.display_name_owner_registered_order):
                    problems.append(
                        f"{capture.label}: chat sender {sender} matched a name "
                        f"owned by {owner}")
                expected_tokens = participant_tokens_by_registered_order.get(
                    audit.sender_registered_order, set())
                if (expected_tokens and
                        (audit.expected_name_token not in expected_tokens or
                         audit.display_name_token not in expected_tokens)):
                    problems.append(
                        f"{capture.label}: chat sender {sender} name token "
                        "disagrees with character creation")
                if (audit.sender_participant_index >= 0 and
                        audit.display_name_owner_participant_index >= 0 and
                        audit.sender_participant_index !=
                        audit.display_name_owner_participant_index):
                    problems.append(
                        f"{capture.label}: chat sender "
                        f"P{audit.sender_participant_index} used a name owned "
                        f"by P{audit.display_name_owner_participant_index}")
        if require_chat_name_association:
            if not capture.chat_names:
                problems.append(
                    f"{capture.label}: no chat sender/name association telemetry")
            elif not complete_chat_senders:
                problems.append(
                    f"{capture.label}: no complete matching chat sender/name "
                    "association")
            else:
                print("    complete matching senders: " + ", ".join(
                    f"R{sender}" for sender in sorted(complete_chat_senders)))
        for participant, values in sorted(capture.consumer_results.items()):
            rendered = ", ".join(
                f"direct={str(direct).lower()} final={str(final).lower()} "
                f"retry_source={retry_source} retries={retry_count} "
                f"retry_mask=0x{retry_mask:x} null_stage={null_stage}"
                for direct, final, retry_source, retry_count, retry_mask,
                null_stage
                in sorted(values))
            print(f"  consumer P{participant}: {rendered}")
            if any(not final for _, final, _, _, _, _ in values):
                problems.append(
                    f"{capture.label}: P{participant} character consumer returned null")
        if capture.null_character_guarded:
            guarded = sorted(capture.null_character_guarded)
            print("  null-character guard: " +
                  ", ".join(f"P{item}" for item in guarded))
            problems.append(
                f"{capture.label}: null character guarded for {guarded}")
        if capture.enemy_spawn_observations:
            print("  enemy spawn observations: " + "; ".join(
                f"{event} caller=0x{caller:x} confirmed={str(confirmed).lower()} "
                f"count={requested}->{effective} multiplier={multiplier} "
                f"scale={numerator}/{denominator} "
                f"source={str(source).lower()} eligible={str(eligible).lower()} "
                f"writable={str(writable).lower()} repaired={str(repaired).lower()}"
                for event, caller, confirmed, requested, effective,
                multiplier, numerator, denominator, source, eligible,
                writable, repaired, _, _
                in capture.enemy_spawn_observations))
            for event, _, _, requested, effective, multiplier, numerator, \
                    denominator, source, eligible, writable, repaired, \
                    actor_logged, payload_logged in \
                    capture.enemy_spawn_observations:
                if actor_logged or payload_logged:
                    problems.append(
                        f"{capture.label}: enemy spawn telemetry retained "
                        "an actor pointer or spawn payload")
                if not 1 <= multiplier <= 8 or not 0 <= effective <= 400:
                    problems.append(
                        f"{capture.label}: enemy spawn count policy exceeded "
                        "its multiplier/cap bounds")
                if event == "enemy_spawn_scale_repaired" and (
                        not eligible or not writable or not repaired or
                        not source or requested <= 0 or numerator != 0 or
                        denominator <= 0):
                    problems.append(
                        f"{capture.label}: unsafe enemy zero-scale repair")
        if capture.generator_poll_update_paths:
            print("  GeneratorPoll update paths: " + "; ".join(
                f"call={call} returned={str(returned).lower()} "
                f"base_gate={str(base_gate).lower()} "
                f"spawn_calls={spawn_calls} "
                f"spawn_reached={str(spawn_reached).lower()}"
                for call, returned, base_gate, spawn_calls, spawn_reached,
                _, _, _ in capture.generator_poll_update_paths))
            for call, returned, base_gate, spawn_calls, spawn_reached, \
                    generator_logged, frame_logged, payload_logged in \
                    capture.generator_poll_update_paths:
                if call <= 0 or not returned or not base_gate or \
                        spawn_calls < 0 or \
                        spawn_reached != (spawn_calls != 0):
                    problems.append(
                        f"{capture.label}: invalid GeneratorPoll update "
                        "telemetry")
                if generator_logged or frame_logged or payload_logged:
                    problems.append(
                        f"{capture.label}: GeneratorPoll telemetry retained "
                        "a pointer or spawn payload")
        if capture.generator_poll_gate_paths:
            print("  GeneratorPoll gate paths: " + "; ".join(
                f"call={call} outcome={outcome} "
                f"remaining={remaining} cooldown={cooldown}->{after} "
                f"spawn={spawn_calls}/{true_calls}"
                for call, outcome, _, _, _, _, _, remaining, cooldown,
                after, _, _, spawn_calls, true_calls, _, _, _, _, _ in
                capture.generator_poll_gate_paths))
            valid_outcomes = {
                "cooldown_blocked",
                "quota_blocked_inside_time_window",
                "spawn_returned_false",
                "spawn_accepted",
            }
            for call, outcome, returned, owner_is_poll, state_matches, \
                    state_readable, _, remaining, _, after_decrement, \
                    _, _, spawn_calls, true_calls, count_valid, threshold, \
                    state_pointer_logged, owner_pointer_logged, \
                    payload_logged in capture.generator_poll_gate_paths:
                invalid = (
                    call <= 0 or not returned or not owner_is_poll or
                    not state_matches or not count_valid or
                    threshold != 0x1CC or spawn_calls < 0 or
                    true_calls < 0 or true_calls > spawn_calls or
                    spawn_calls > 1 or outcome not in valid_outcomes)
                if outcome == "cooldown_blocked":
                    invalid = invalid or not state_readable or \
                        spawn_calls != 0 or \
                        after_decrement < threshold
                elif outcome == "quota_blocked_inside_time_window":
                    invalid = invalid or not state_readable or \
                        spawn_calls != 0 or \
                        after_decrement >= threshold or remaining > 0
                elif outcome == "spawn_returned_false":
                    invalid = invalid or spawn_calls != 1 or \
                        true_calls != 0
                elif outcome == "spawn_accepted":
                    invalid = invalid or spawn_calls != 1 or \
                        true_calls != 1
                if invalid:
                    problems.append(
                        f"{capture.label}: invalid or unresolved "
                        "GeneratorPoll native gate telemetry")
                if state_pointer_logged or owner_pointer_logged or \
                        payload_logged:
                    problems.append(
                        f"{capture.label}: GeneratorPoll telemetry retained "
                        "a pointer or spawn payload")
        if capture.generator_poll_paths:
            print("  GeneratorPoll paths: " + "; ".join(
                f"call={call} manager_readable={str(readable).lower()} "
                f"manager_present={str(present).lower()} "
                f"common_calls={common_calls} "
                f"gate_true={str(gate_true).lower()}"
                for call, readable, present, common_calls, _, gate_true,
                _, _, _ in capture.generator_poll_paths))
            for call, readable, present, common_calls, common_reached, _, \
                    generator_logged, descriptor_logged, payload_logged in \
                    capture.generator_poll_paths:
                if call <= 0 or present and not readable or common_calls < 0 or \
                        common_reached != (common_calls != 0):
                    problems.append(
                        f"{capture.label}: invalid GeneratorPoll path telemetry")
                if generator_logged or descriptor_logged or payload_logged:
                    problems.append(
                        f"{capture.label}: GeneratorPoll telemetry retained "
                        "a pointer or spawn payload")
        if capture.enemy_spawn_summaries:
            print("  enemy spawn summary: " + "; ".join(
                f"phase={phase} calls={calls}/{confirmed} "
                f"count={requested}->{effective} zero_scale={zero_scale} "
                f"missing_source={missing_source} repairs={repairs} "
                f"restore_failures={restore_failures} multiplier={multiplier} "
                f"capacity={capacity}"
                for phase, calls, confirmed, requested, effective,
                zero_scale, missing_source, repairs, restore_failures,
                multiplier, capacity, _, _, _, _
                in capture.enemy_spawn_summaries))
            for _, calls, confirmed, _, _, _, _, repairs, restore_failures, \
                    multiplier, capacity, common_reached, confirmed_reached, \
                    actor_logged, payload_logged in \
                    capture.enemy_spawn_summaries:
                if (calls < confirmed or repairs > confirmed or
                        restore_failures != 0 or not 1 <= multiplier <= 8 or
                        capacity != 400 or
                        common_reached != (calls != 0) or
                        confirmed_reached != (confirmed != 0)):
                    problems.append(
                        f"{capture.label}: invalid enemy spawn summary")
                if actor_logged or payload_logged:
                    problems.append(
                        f"{capture.label}: enemy spawn summary retained "
                        "an actor pointer or spawn payload")
        if capture.generator_poll_update_summaries:
            print("  GeneratorPoll update summary: " + "; ".join(
                f"calls={calls} completed={completed} "
                f"updates_to_spawn={updates_to_spawn} "
                f"spawn_calls={spawn_calls}"
                for calls, completed, updates_to_spawn, spawn_calls in
                capture.generator_poll_update_summaries))
            for calls, completed, updates_to_spawn, spawn_calls in \
                    capture.generator_poll_update_summaries:
                if calls < 0 or not 0 <= completed <= calls or \
                        not 0 <= updates_to_spawn <= completed or \
                        spawn_calls < updates_to_spawn:
                    problems.append(
                        f"{capture.label}: invalid GeneratorPoll update "
                        "summary")
        if capture.generator_poll_gate_summaries:
            print("  GeneratorPoll gate summary: " + "; ".join(
                f"calls={calls} completed={completed} "
                f"cooldown={cooldown} quota={quota} "
                f"spawn_false={spawn_false} accepted={accepted} "
                f"unknown={unknown}"
                for calls, completed, cooldown, quota, spawn_false,
                accepted, unknown in
                capture.generator_poll_gate_summaries))
            for calls, completed, cooldown, quota, spawn_false, accepted, \
                    unknown in capture.generator_poll_gate_summaries:
                classified = cooldown + quota + spawn_false + accepted + \
                    unknown
                if calls < 0 or not 0 <= completed <= calls or \
                        min(cooldown, quota, spawn_false, accepted,
                            unknown) < 0 or classified != completed or \
                        unknown != 0:
                    problems.append(
                        f"{capture.label}: invalid or unresolved "
                        "GeneratorPoll native gate summary")
        if capture.generator_poll_summaries:
            print("  GeneratorPoll summary: " + "; ".join(
                f"calls={calls} readable={readable} present={present} "
                f"methods_to_common={methods} common_calls={common} "
                f"gate={gate_true}/{gate_false}"
                for calls, readable, present, methods, common, gate_true,
                gate_false in capture.generator_poll_summaries))
            for calls, readable, present, methods, common, gate_true, \
                    gate_false in capture.generator_poll_summaries:
                if calls < 0 or not 0 <= present <= readable <= calls or \
                        not 0 <= methods <= calls or common < methods or \
                        gate_true < 0 or gate_false < 0 or \
                        gate_true + gate_false != calls:
                    problems.append(
                        f"{capture.label}: invalid GeneratorPoll summary")
        for update_summary, spawn_summary in zip(
                capture.generator_poll_update_summaries,
                capture.generator_poll_summaries):
            if update_summary[3] > spawn_summary[0]:
                problems.append(
                    f"{capture.label}: GeneratorPoll update summary exceeds "
                    "the observed spawn-method calls")
        for update_summary, gate_summary in zip(
                capture.generator_poll_update_summaries,
                capture.generator_poll_gate_summaries):
            if gate_summary[0] > update_summary[0] or \
                    gate_summary[1] > update_summary[1] or \
                    gate_summary[4] + gate_summary[5] > update_summary[3]:
                problems.append(
                    f"{capture.label}: GeneratorPoll gate summary exceeds "
                    "its enclosing update observations")
        for gate_summary, spawn_summary in zip(
                capture.generator_poll_gate_summaries,
                capture.generator_poll_summaries):
            if gate_summary[4] + gate_summary[5] > spawn_summary[0] or \
                    gate_summary[5] > spawn_summary[5] or \
                    gate_summary[4] > spawn_summary[6]:
                problems.append(
                    f"{capture.label}: GeneratorPoll gate outcomes exceed "
                    "the observed spawn-method returns")
        for policy_error in capture.enemy_spawn_multiplier_policy_errors:
            problems.append(
                f"{capture.label}: experimental enemy multiplier policy: "
                f"{policy_error}")
        confirmed_enemy_spawns = any(
            confirmed for _, _, confirmed, *_
            in capture.enemy_spawn_observations) or any(
                confirmed > 0 for _, _, confirmed, *_
                in capture.enemy_spawn_summaries)
        repaired_enemy_scale = any(
            repaired for *_, repaired, _, _
            in capture.enemy_spawn_observations) or any(
                repairs > 0 for _, _, _, _, _, _, _, repairs, *_
                in capture.enemy_spawn_summaries)
        if require_enemy_spawn and not confirmed_enemy_spawns:
            problems.append(
                f"{capture.label}: no confirmed enemy spawn telemetry")
        if require_enemy_spawn_repair and not repaired_enemy_scale:
            problems.append(
                f"{capture.label}: no successful P5 enemy zero-scale repair")
        if capture.native_participant_scaling_evidence:
            print("  native participant scaling: " + "; ".join(
                f"{event} hits={hits} mask=0x{mask:x} "
                f"capacity={capacity} configured={configured} "
                f"stored_count_preserved={str(preserved).lower()}"
                for event, hits, mask, capacity, preserved, configured, _, _
                in capture.native_participant_scaling_evidence))
            for event, hits, mask, capacity, preserved, configured, \
                    payload_logged, pointer_logged in \
                    capture.native_participant_scaling_evidence:
                if capacity != 4 or not preserved or \
                        payload_logged or pointer_logged:
                    problems.append(
                        f"{capture.label}: invalid/private native participant "
                        "scaling evidence")
                if event == "native_participant_scaling_clamp_observed" and (
                        hits <= 0 or mask == 0 or not 5 <= configured <= 8):
                    problems.append(
                        f"{capture.label}: invalid participant scaling clamp "
                        "event")
        if require_native_participant_scaling_clamp and not any(
                hits > 0 and mask != 0 and capacity == 4 and preserved
                for _, hits, mask, capacity, preserved, *_
                in capture.native_participant_scaling_evidence):
            problems.append(
                f"{capture.label}: no proven native participant scaling "
                "clamp for a 5+ player mission")
        if capture.result_setters:
            print("  result setter: " + "; ".join(
                f"call={call} result={result} caller=0x{caller:x} "
                f"natural={str(natural).lower()} ui={state}/{ui_result}"
                for call, result, natural, caller, state, ui_result
                in capture.result_setters))
            if any(natural and state != 3
                   for _, _, natural, _, state, _ in capture.result_setters):
                problems.append(
                    f"{capture.label}: natural clear setter did not finish result UI")
        if capture.result_applies:
            print("  result apply: " + "; ".join(
                f"call={call} result={result} caller=0x{caller:x} "
                f"ui={state}/{ui_result}"
                for call, result, state, ui_result, caller
                in capture.result_applies))
        successful_extra_result_items: set[int] = set()
        if capture.result_item_aggregations:
            print("  result extra Items: " + "; ".join(
                f"call={call} P{participant}->slot{slot} "
                f"native={native_capacity} effective={effective_capacity} "
                f"aggregated={str(aggregated).lower()}"
                for call, participant, slot, native_capacity,
                effective_capacity, aggregated, _, _
                in capture.result_item_aggregations))
            for _, participant, slot, native_capacity, effective_capacity, \
                    aggregated, reward_logged, payload_logged in \
                    capture.result_item_aggregations:
                expected_slot = participant % 4 if participant >= 4 else -1
                if (not aggregated or participant < 4 or
                        native_capacity != 4 or slot != expected_slot or
                        effective_capacity < expected_players):
                    problems.append(
                        f"{capture.label}: invalid extra MissionResult Item "
                        f"aggregation for P{participant}")
                else:
                    successful_extra_result_items.add(participant)
                if reward_logged or payload_logged:
                    problems.append(
                        f"{capture.label}: MissionResult Item telemetry retained "
                        "reward or payload contents")
        if require_extra_result_items:
            expected_extra_result_items = set(range(4, expected_players))
            missing_result_items = sorted(
                expected_extra_result_items - successful_extra_result_items)
            if missing_result_items:
                rendered = ", ".join(
                    f"P{participant}" for participant in missing_result_items)
                problems.append(
                    f"{capture.label}: missing extra MissionResult item "
                    f"aggregation for {rendered}")
        if capture.reward_item_checkpoints:
            print("  reward Item checkpoints: " + "; ".join(
                f"{event}/{phase} participants={participants} "
                f"expected=0x{expected_mask:x} "
                f"observed=0x{observed_mask:x} "
                f"complete={str(complete).lower()}"
                for event, phase, participants, _, expected_mask,
                observed_mask, complete, _, _
                in capture.reward_item_checkpoints))
            required_mask = (
                ((1 << expected_players) - 1) & ~0xf
                if expected_players > 4 else 0)
            for event, phase, participants, participant_count_valid, \
                    expected_mask, observed_mask, complete, reward_logged, \
                    payload_logged in capture.reward_item_checkpoints:
                if reward_logged or payload_logged:
                    problems.append(
                        f"{capture.label}: {event}/{phase} reward checkpoint "
                        "retained reward or payload contents")
                if (require_extra_result_items and
                        phase == "before_original" and
                        participants >= expected_players and
                        (not participant_count_valid or
                         expected_mask != required_mask or
                         (observed_mask & required_mask) != required_mask or
                         not complete)):
                    problems.append(
                        f"{capture.label}: {event}/{phase} reached rewards "
                        "before every extra MissionResult Item was present")
        if capture.result_item_progress:
            print("  result Item progress: " + "; ".join(
                f"{checkpoint}ms participants={participants} "
                f"expected=0x{expected_mask:x} "
                f"observed=0x{observed_mask:x} "
                f"complete={str(complete).lower()}"
                for checkpoint, participants, expected_mask,
                observed_mask, complete in capture.result_item_progress))
        if capture.result_item_checkpoints:
            print("  full result Item checkpoints: " + "; ".join(
                f"{event}/{phase} participants={participants} "
                f"expected=0x{expected_mask:x} "
                f"observed=0x{observed_mask:x} "
                f"complete={str(complete).lower()}"
                for event, phase, participants, _, expected_mask,
                observed_mask, complete, _, _
                in capture.result_item_checkpoints))
            for event, phase, _, _, _, _, _, reward_logged, \
                    payload_logged in capture.result_item_checkpoints:
                if reward_logged or payload_logged:
                    problems.append(
                        f"{capture.label}: {event}/{phase} full result Item "
                        "checkpoint retained reward or payload contents")
        if require_result_item_matrix:
            required_item_mask = (1 << expected_players) - 1
            matrix_observations = [
                (participants, expected_mask, observed_mask, complete)
                for _, _, participants, participant_count_valid,
                expected_mask, observed_mask, complete, _, _
                in capture.result_item_checkpoints
                if participant_count_valid
            ] + [
                (participants, expected_mask, observed_mask, complete)
                for _, participants, expected_mask, observed_mask, complete
                in capture.result_item_progress
            ]
            if not any(
                    participants >= expected_players and
                    expected_mask == required_item_mask and
                    (observed_mask & required_item_mask) ==
                        required_item_mask and complete
                    for participants, expected_mask, observed_mask, complete
                    in matrix_observations):
                problems.append(
                    f"{capture.label}: no complete P0-P{expected_players - 1} "
                    "MissionResult Item matrix")
        if capture.result_recoveries:
            print("  result recovery: " + "; ".join(
                f"{event} generation={generation} "
                f"success={str(success).lower()}"
                for event, generation, success in capture.result_recoveries))
        if capture.result_recovery_returns:
            print("  result recovery return: " + "; ".join(
                f"native={native} effective={effective} "
                f"stale_zero_overridden={str(overridden).lower()} "
                f"native_clear={str(native_clear).lower()}"
                for native, effective, overridden, native_clear
                in capture.result_recovery_returns))
            if any(
                    native == 0 and
                    (effective != 1 or not overridden)
                    for native, effective, overridden, _
                    in capture.result_recovery_returns):
                problems.append(
                    f"{capture.label}: late MissionResult recovery returned "
                    "the stale native zero")
        if require_effective_result_recovery:
            recovery_applied = any(
                event == "mission_result_recovery_applied" and success
                for event, _, success in capture.result_recoveries)
            if recovery_applied and not any(
                    effective == 1 and (overridden or native_clear)
                    for _, effective, overridden, native_clear
                    in capture.result_recovery_returns):
                problems.append(
                    f"{capture.label}: successful MissionResult recovery "
                    "did not expose effective result 1")
        if capture.result_event_publishes:
            print("  result event publish: " + "; ".join(
                f"call={call} type={event_type} payload={payload} "
                f"readable={str(readable).lower()} "
                f"publisher={str(publisher).lower()} "
                f"expected={str(expected).lower()}"
                for call, event_type, payload, readable, publisher, expected
                in capture.result_event_publishes))
            if any(not readable or not publisher or not expected
                   for _, _, _, readable, publisher, expected
                   in capture.result_event_publishes):
                problems.append(
                    f"{capture.label}: MissionResult setter did not publish "
                    "the expected UI close event (type 1 / object id 2)")
        if require_result_event_publish and not any(
                expected for *_, expected
                in capture.result_event_publishes):
            problems.append(
                f"{capture.label}: expected MissionResult UI close event "
                "was not observed")
        if capture.result_ui_close_dispatches:
            print("  result UI close dispatch: " + "; ".join(
                f"call={call} type={event_type} payload={payload} "
                f"listener={listener_id} readable={str(readable).lower()} "
                f"match={str(match).lower()} close={str(before).lower()}->"
                f"{str(after).lower()} accepted={str(accepted).lower()}"
                for call, event_type, payload, listener_id, readable, match,
                before, after, accepted
                in capture.result_ui_close_dispatches))
            if any(match and (not readable or not after or not accepted)
                   for _, _, _, _, readable, match, _, after, accepted
                   in capture.result_ui_close_dispatches):
                problems.append(
                    f"{capture.label}: UI object id 2 received the mission "
                    "close event but did not complete its close transition")
        if require_result_ui_close_dispatch and not any(
                readable and match and after and accepted
                for _, _, _, _, readable, match, _, after, accepted
                in capture.result_ui_close_dispatches):
            problems.append(
                f"{capture.label}: mission result UI close event did not reach "
                "and close object id 2")
        if capture.result_progress:
            print("  result progress: " + "; ".join(
                f"{checkpoint}ms(age={age}, phase={phase}, result={result}, "
                f"ui={state}, setter={setter}, apply={apply}, "
                f"pending={str(pending).lower()})"
                for _, age, checkpoint, phase, result, state, setter, apply,
                pending
                in capture.result_progress))
            if any(
                    checkpoint >= 5000 and pending and not any(
                        completion.order > order
                        for completion in capture.result_completions)
                    for order, _, checkpoint, _, _, _, _, _, pending
                    in capture.result_progress):
                problems.append(
                    f"{capture.label}: result transition still pending after 5 seconds")
        if capture.result_completions:
            print("  result completion: " + "; ".join(
                f"elapsed={item.elapsed_ms}ms result={item.result} "
                f"setter={item.setter_calls} apply={item.apply_calls} "
                f"signal={item.completion_signal} "
                f"room={str(item.room_ui_returned).lower()} "
                f"from={item.diagnostic_phase_before_completion} "
                f"pipeline={item.exec_begin_calls}/"
                f"{item.exec_update_calls}/"
                f"{item.exec_finally_calls}/"
                f"{item.sync_complete_calls}/"
                f"{item.reward_resolve_calls}/"
                f"{item.reward_apply_completed_calls} "
                f"items=0x{item.observed_item_mask:x}/"
                f"0x{item.expected_item_mask:x}"
                for item in capture.result_completions))
            for item in capture.result_completions:
                expected_room_flag = item.completion_signal == "room_ui_update"
                if item.room_ui_returned != expected_room_flag:
                    problems.append(
                        f"{capture.label}: result completion room signal/flag mismatch")
                if item.reward_contents_logged or item.payload_logged:
                    problems.append(
                        f"{capture.label}: result completion retained reward or payload contents")
        if require_result_room_return and not any(
                item.completion_signal == "room_ui_update" and
                item.room_ui_returned and item.result == 1
                for item in capture.result_completions):
            problems.append(
                f"{capture.label}: no confirmed clear-result return to room UI")
        if ("room_return" in capture.result_pipeline_order and
                "reward_apply" in capture.result_pipeline_order and
                capture.result_pipeline_order.index("room_return") <
                capture.result_pipeline_order.index("reward_apply")):
            problems.append(
                f"{capture.label}: room UI returned before reward application")
        if capture.result_exec_begins:
            print("  MissionResult Exec_Begin: " + "; ".join(
                f"call={item.call} generation={item.generation} "
                f"argument={item.argument} "
                f"accepted={str(item.accepted).lower()} "
                f"caller={item.caller_path}/0x{item.caller_rva:x} "
                f"caller_reported={str(item.caller_reported).lower()}"
                for item in capture.result_exec_begins))
            if any(not item.accepted for item in capture.result_exec_begins):
                problems.append(
                    f"{capture.label}: net::MissionResult rejected Exec_Begin")
            expected_exec_callers = {
                "mission_script_dispatch": 0x1153F3,
                "result_sync_begin_wrapper": 0x42AC4D,
                "mod_recovery": 0,
            }
            for item in capture.result_exec_begins:
                expected_caller = expected_exec_callers.get(item.caller_path)
                if (item.caller_reported and expected_caller is not None and
                        item.caller_rva != expected_caller):
                    problems.append(
                        f"{capture.label}: Exec_Begin caller path "
                        f"{item.caller_path} reported unexpected RVA "
                        f"0x{item.caller_rva:x}")
        if capture.result_exec_updates:
            print("  MissionResult ResultSync_Update: " + "; ".join(
                f"call={item.call} generation={item.generation} "
                f"argument={item.argument} "
                f"result={str(item.native_result).lower()} "
                f"outcome_count={item.outcome_count} "
                f"caller={item.caller_path}/0x{item.caller_rva:x} "
                f"action={item.caller_action}"
                for item in capture.result_exec_updates))
            for item in capture.result_exec_updates:
                if not item.expected_caller:
                    problems.append(
                        f"{capture.label}: ResultSync_Update has an "
                        f"unexpected caller 0x{item.caller_rva:x}")
                if item.payload_logged or item.pointer_logged:
                    problems.append(
                        f"{capture.label}: ResultSync_Update retained payload "
                        "or pointer data")
        if capture.result_exec_finally:
            print("  MissionResult ResultSync_Finally: " + "; ".join(
                f"call={item.call} generation={item.generation} "
                f"argument={item.argument} "
                f"caller={item.caller_path}/0x{item.caller_rva:x}"
                for item in capture.result_exec_finally))
            for item in capture.result_exec_finally:
                if not item.expected_caller:
                    problems.append(
                        f"{capture.label}: ResultSync_Finally has an "
                        f"unexpected caller 0x{item.caller_rva:x}")
                if item.payload_logged or item.pointer_logged:
                    problems.append(
                        f"{capture.label}: ResultSync_Finally retained payload "
                        "or pointer data")
        if require_result_exec_pipeline:
            if not any(item.expected_caller
                       for item in capture.result_exec_updates):
                problems.append(
                    f"{capture.label}: no expected ResultSync_Update caller")
            if not any(item.expected_caller
                       for item in capture.result_exec_finally):
                problems.append(
                    f"{capture.label}: no expected ResultSync_Finally caller")
        if capture.result_exec_recoveries:
            print("  MissionResult Exec_Begin recovery: " + "; ".join(
                f"{item.event} generation={item.generation} "
                f"participants={item.participant_count} "
                f"argument={item.argument} "
                f"accepted={str(item.accepted).lower()} "
                f"host_only={str(item.host_only).lower()} "
                f"harness={str(item.local_mission_harness).lower()} "
                f"native_preserved={str(item.native_path_preserved).lower()} "
                f"stale_discarded={str(item.stale_pending_discarded).lower()} "
                f"queue_cleared={str(item.queue_cleared).lower()}"
                for item in capture.result_exec_recoveries))
            for item in capture.result_exec_recoveries:
                if item.payload_logged:
                    problems.append(
                        f"{capture.label}: result Exec_Begin recovery retained "
                        "a payload")
                if item.host_only or item.local_mission_harness:
                    problems.append(
                        f"{capture.label}: result Exec_Begin recovery used "
                        "an invalid host/harness scope")
                if item.event == "mission_result_exec_recovery_applied" and (
                        item.argument != -20000 or not item.accepted):
                    problems.append(
                        f"{capture.label}: result Exec_Begin recovery was rejected")
                if (item.event == "mission_result_exec_recovery_cancelled" and
                        not item.native_path_preserved):
                    problems.append(
                        f"{capture.label}: native Exec_Begin cancellation did "
                        "not preserve the native path")
                if (item.event ==
                        "mission_result_exec_recovery_generation_reset" and
                        (not item.stale_pending_discarded or
                         not item.queue_cleared)):
                    problems.append(
                        f"{capture.label}: mission generation did not fully "
                        "discard stale Exec_Begin recovery state")
        problems.extend(validate_result_exec_native_cancellation(
            capture, require_result_exec_native_cancel))
        if require_result_exec_recovery and not any(
                item.event == "mission_result_exec_recovery_applied" and
                item.argument == -20000 and item.accepted
                for item in capture.result_exec_recoveries):
            problems.append(
                f"{capture.label}: no accepted result Exec_Begin recovery")
        if capture.result_sync_begins:
            print("  Sync_MissionResult begin: " + "; ".join(
                f"call={call} origin={origin} caller=0x{caller:x} "
                f"state={state}/{result} readable={str(readable).lower()}"
                for call, origin, caller, state, result, readable
                in capture.result_sync_begins))
            if any(not readable for _, _, _, _, _, readable
                   in capture.result_sync_begins):
                problems.append(
                    f"{capture.label}: Sync_MissionResult begin state unreadable")
        if capture.result_sync_polls:
            print("  Sync_MissionResult poll: " + "; ".join(
                f"call={call} origin={origin} caller=0x{caller:x} "
                f"state={state}/{result} first={str(first).lower()} "
                f"complete={str(complete).lower()}"
                for call, origin, caller, state, result, readable, first,
                complete in capture.result_sync_polls))
            if any(not readable for _, _, _, _, _, readable, _, _
                   in capture.result_sync_polls):
                problems.append(
                    f"{capture.label}: Sync_MissionResult poll state unreadable")
        if capture.reward_resolves:
            print("  ResolveResult rewards: " + "; ".join(
                f"call={call} phase={phase} local_profiles={profiles} "
                f"returned={str(returned).lower()}"
                for call, phase, profiles, returned
                in capture.reward_resolves))
        if capture.reward_applies:
            print("  ApplyResult rewards: " + "; ".join(
                f"call={call} clear={str(clear).lower()} "
                f"completed={str(completed).lower()} "
                f"native_result={str(native_result).lower()} "
                f"profiles={before}->{effective}->{after} "
                f"expected={expected_profiles} "
                f"repaired={str(repaired).lower()} "
                f"valid={str(valid).lower()}"
                for call, clear, completed, native_result, before,
                expected_profiles,
                effective, after, repaired, valid
                in capture.reward_applies))
            if any(clear and (
                    not completed or not valid or after not in (1, 2))
                   for _, clear, completed, _, _, _, _, after, _, valid
                   in capture.reward_applies):
                problems.append(
                    f"{capture.label}: clear reward ApplyResult call did not "
                    "complete or used "
                    "an invalid local-profile count")
        if capture.reward_profile_repairs:
            print("  reward profile-count repair: " + "; ".join(
                f"phase={phase} profiles={before}->{after} "
                f"expected={expected_profiles} observed={observed} "
                f"repaired={str(repaired).lower()}"
                for phase, before, expected_profiles, observed, after,
                repaired, _, _ in capture.reward_profile_repairs))
            for phase, before, expected_profiles, observed, after, repaired, \
                    reward_logged, payload_logged in \
                    capture.reward_profile_repairs:
                if (not repaired or before in (1, 2) or
                        expected_profiles not in (1, 2) or
                        observed != before or after != expected_profiles):
                    problems.append(
                        f"{capture.label}: invalid reward local-profile "
                        f"repair at {phase}")
                if reward_logged or payload_logged:
                    problems.append(
                        f"{capture.label}: reward profile-count repair "
                        "retained reward or payload contents")
        if capture.result_pipeline_order:
            print("  result/reward pipeline: " +
                  " -> ".join(capture.result_pipeline_order))
        if capture.result_pipeline_progress:
            print("  result/reward checkpoints: " + "; ".join(
                f"{checkpoint}ms(event={event_publish}, exec={exec_begin}, "
                f"begin={sync_begin}, "
                f"poll={sync_poll}, complete={sync_complete}, "
                f"resolve={resolve}, apply={apply}/{success})"
                for checkpoint, event_publish, exec_begin, sync_begin, sync_poll,
                sync_complete, resolve, apply, success
                in capture.result_pipeline_progress))
        if require_result_reward_chain:
            missing_pipeline: list[str] = []
            if not any(item.accepted for item in capture.result_exec_begins):
                missing_pipeline.append("Exec_Begin(accepted)")
            if not capture.result_sync_begins:
                missing_pipeline.append("Sync_MissionResult begin")
            if not any(complete for *_, complete
                       in capture.result_sync_polls):
                missing_pipeline.append("Sync_MissionResult completion")
            if not any(phase == "original_returned" and returned
                       for _, phase, _, returned
                       in capture.reward_resolves):
                missing_pipeline.append("ResolveResult return")
            if not any(clear and completed and valid and after in (1, 2)
                       for _, clear, completed, _, _, _, _, after, _, valid
                       in capture.reward_applies):
                missing_pipeline.append("ApplyResult(clear) completion")
            if missing_pipeline:
                problems.append(
                    f"{capture.label}: incomplete result/reward chain: " +
                    ", ".join(missing_pipeline))
        if capture.transport_route_assignments:
            print("  transport route assignments: " + "; ".join(
                f"registered={audit.registered_order} "
                f"route={audit.transport_route_index} "
                f"lane={audit.local_controller_index} "
                f"eligible={str(audit.receive_route_eligible).lower()} "
                f"order_match="
                f"{str(audit.route_index_matches_registered_order).lower()} "
                f"owner_observed="
                f"{str(audit.allocator_owner_observed).lower()} "
                f"strides={audit.allocator_scan_stride}/"
                f"{audit.receive_vector_stride}"
                for audit in capture.transport_route_assignments))
            route_owners: dict[int, set[int]] = collections.defaultdict(set)
            for audit in capture.transport_route_assignments:
                if (audit.endpoint_identity_captured or
                        audit.steam_id_logged or audit.pointer_logged):
                    problems.append(
                        f"{capture.label}: transport route assignment "
                        "retained endpoint, Steam identity or pointer data")
                if (audit.runtime_user and audit.receive_route_eligible and
                        audit.local_controller_index == 0 and
                        not audit.route_index_nonnegative):
                    problems.append(
                        f"{capture.label}: eligible registered user "
                        f"{audit.registered_order} received no transport route")
                if (audit.registered_order >= 0 and
                        audit.transport_route_index >= 0):
                    route_owners[audit.transport_route_index].add(
                        audit.registered_order)
            for route_index, registered_orders in sorted(route_owners.items()):
                if len(registered_orders) > 1:
                    problems.append(
                        f"{capture.label}: transport route {route_index} was "
                        f"assigned to registered users "
                        f"{sorted(registered_orders)}")
        if capture.replication_maps:
            print("  replication participant map: " + "; ".join(
                f"participants={participants} sources={sources} "
                f"unique={unique} duplicate_mask=0x{duplicate_mask:x} "
                f"identity_unique={str(identity_unique).lower()}"
                for participants, sources, unique, duplicate_mask,
                identity_unique in capture.replication_maps))
            if any(not identity_unique or unique != participants or
                   duplicate_mask != 0
                   for participants, _, unique, duplicate_mask,
                   identity_unique in capture.replication_maps):
                problems.append(
                    f"{capture.label}: replication participant map contains "
                    "a duplicated UserImpl identity")
        if capture.replication_receive_routes:
            print("  replication receive routes: " + "; ".join(
                f"routes={audit.route_count}/{audit.inspected_count} "
                f"runtime={audit.runtime_user_count} "
                f"unique={audit.unique_user_count} "
                f"empty={audit.empty_slot_count} "
                f"local=0x{audit.local_participant_mask:x} "
                f"mask=0x{audit.participant_mask:x}/"
                f"0x{audit.expected_participant_mask:x} "
                f"missing=0x{audit.missing_participant_mask:x} "
                f"unexpected=0x{audit.unexpected_participant_mask:x} "
                f"duplicate_participant="
                f"0x{audit.duplicate_participant_mask:x} "
                f"duplicate_route=0x{audit.duplicate_route_mask:x} "
                f"route_index_mismatch="
                f"0x{audit.transport_route_index_mismatch_mask:x} "
                f"route_to_participant={list(audit.route_to_participant)} "
                f"route_indices={list(audit.route_transport_indices)} "
                f"complete={str(audit.route_complete).lower()}"
                for audit in capture.replication_receive_routes))
            if any(
                    audit.duplicate_participant_mask != 0 or
                    audit.duplicate_route_mask != 0 or
                    audit.transport_route_index_mismatch_mask != 0 or
                    not audit.transport_route_indices_match_slots or
                    not audit.participant_identity_unique
                    for audit in capture.replication_receive_routes):
                problems.append(
                    f"{capture.label}: replication receive vector contains "
                    "a duplicated UserImpl/participant route")
        if require_receive_route_matrix:
            expected_mask = (1 << expected_players) - 1
            local_mask = sum(1 << participant
                             for participant in capture_local_owners)
            expected_remote_mask = expected_mask & ~local_mask
            expected_remote_count = len(expected - capture_local_owners)
            if not any(
                    audit.entries_readable and
                    not audit.audit_truncated and
                    audit.route_count >= expected_remote_count and
                    audit.duplicate_participant_mask == 0 and
                    audit.duplicate_route_mask == 0 and
                    audit.transport_route_index_mismatch_mask == 0 and
                    audit.participant_identity_unique and
                    audit.transport_route_indices_match_slots and
                    (
                        (audit.remote_only_semantics and
                         audit.runtime_user_count == expected_remote_count and
                         audit.unique_user_count == expected_remote_count and
                         audit.participant_mask == expected_remote_mask and
                         audit.unresolved_user_count == 0 and
                         audit.local_participant_mask == local_mask and
                         audit.expected_participant_mask ==
                         expected_remote_mask and
                         audit.missing_participant_mask == 0 and
                         audit.unexpected_participant_mask == 0 and
                         audit.route_complete) or
                        (not audit.remote_only_semantics and (
                            (audit.runtime_user_count == expected_players and
                             audit.unique_user_count == expected_players and
                             audit.participant_mask == expected_mask) or
                            (audit.runtime_user_count ==
                             expected_remote_count and
                             audit.unique_user_count ==
                             expected_remote_count and
                             audit.participant_mask ==
                             expected_remote_mask)
                        ))
                    )
                    for audit in capture.replication_receive_routes):
                problems.append(
                    f"{capture.label}: no complete unique receive route "
                    f"vector for {expected_remote_count} remote participants")
        if capture.replication_receive_route_lifecycle:
            print("  replication receive route lifecycle: " + "; ".join(
                f"{audit.action}#{audit.call} "
                f"registered={audit.registered_order} "
                f"participant={audit.participant_index} "
                f"route={audit.transport_route_index} "
                f"lane={audit.local_controller_index} "
                f"same_manager="
                f"{str(audit.allocator_owner_matches_receive_manager).lower()} "
                f"slots={audit.route_count_before}->"
                f"{audit.route_count_after}/"
                f"{audit.vector_capacity_after} "
                f"present={str(audit.slot_present_before).lower()}->"
                f"{str(audit.slot_present_after).lower()} "
                f"resolved={str(audit.slot_user_resolved_before).lower()}->"
                f"{str(audit.slot_user_resolved_after).lower()} "
                f"match={str(audit.slot_matches_user_before).lower()}->"
                f"{str(audit.slot_matches_user_after).lower()} "
                f"valid={str(audit.slot_transition_valid).lower()} "
                f"anomaly={str(audit.anomaly).lower()}"
                for audit in capture.replication_receive_route_lifecycle))
            for audit in capture.replication_receive_route_lifecycle:
                if (audit.payload_logged or
                        audit.endpoint_identity_captured or
                        audit.steam_id_logged or audit.pointer_logged):
                    problems.append(
                        f"{capture.label}: receive route lifecycle retained "
                        "payload, endpoint, Steam identity or pointer data")
                if audit.anomaly or not audit.expected_caller:
                    problems.append(
                        f"{capture.label}: anomalous receive route "
                        f"{audit.action} for transport slot "
                        f"{audit.transport_route_index}")
        if require_receive_route_lifecycle:
            registrations = [
                audit for audit in
                capture.replication_receive_route_lifecycle
                if audit.action == "register"
            ]
            if not registrations:
                problems.append(
                    f"{capture.label}: no receive route registration "
                    "lifecycle telemetry")
            elif not any(
                    audit.expected_caller and audit.native_result and
                    audit.slot_transition_valid and
                    (not audit.vector_slot_expected or
                     audit.slot_user_resolved_after)
                    for audit in registrations):
                problems.append(
                    f"{capture.label}: no valid native receive route "
                    "registration transition")
        fanouts_by_participant_family: dict[
            tuple[int, int], list[ReplicationSendFanoutAudit]
        ] = collections.defaultdict(list)
        expected_participant_mask = (1 << expected_players) - 1

        def fanout_participant(
                audit: ReplicationSendFanoutAudit) -> int:
            if audit.participant_index >= 0:
                return audit.participant_index
            if len(capture_local_owners) != 1:
                return -1
            local_participant = next(iter(capture_local_owners))
            expected_remote_mask = (
                expected_participant_mask & ~(1 << local_participant))
            # v0.6.52 could not associate the producer owner, but its target
            # vector itself unambiguously identifies the sole local sender.
            if audit.target_participant_mask == expected_remote_mask:
                return local_participant
            return -1

        if capture.replication_send_fanouts:
            print("  replication send fan-out:")
        for audit in capture.replication_send_fanouts:
            effective_participant = fanout_participant(audit)
            fanouts_by_participant_family[
                (effective_participant, audit.message_family)].append(audit)
            participant = (f"P{effective_participant}"
                           if effective_participant >= 0 else "unresolved")
            inferred = (effective_participant >= 0 and
                        audit.participant_index < 0)
            print(
                f"    family=0x{audit.message_family:04x} {participant} "
                f"inferred={str(inferred).lower()} "
                f"lane={audit.local_lane} targets={audit.target_count}/"
                f"{audit.expected_remote_participant_count} "
                f"valid_routes={audit.valid_transport_route_count} "
                f"unique_routes={audit.unique_transport_route_count} "
                f"participants=0x{audit.target_participant_mask:x}/"
                f"0x{audit.expected_remote_participant_mask:x} "
                f"missing=0x{audit.missing_remote_participant_mask:x} "
                f"unexpected=0x{audit.unexpected_target_participant_mask:x} "
                f"duplicate_route="
                f"0x{audit.duplicate_transport_route_target_mask:x} "
                f"unresolved=0x{audit.unresolved_target_mask:x} "
                f"serializer={str(audit.serializer_result).lower()} "
                f"matches={str(audit.matches_expected_participant_fanout).lower()}")
            if (audit.payload_captured or audit.endpoint_identity_captured or
                    audit.steam_id_logged or audit.pointer_logged):
                problems.append(
                    f"{capture.label}: replication send fan-out audit retained "
                    "payload, endpoint, Steam identity or pointer data")
            if (audit.duplicate_transport_route_target_mask != 0 or
                    audit.duplicate_participant_target_mask != 0 or
                    audit.unresolved_target_mask != 0 or
                    not audit.target_transport_routes_unique or
                    not audit.target_participants_resolved):
                problems.append(
                    f"{capture.label}: replication send fan-out contains "
                    "a duplicated or unresolved transport-route target")
        replication_directions: set[str] = set()
        replication_participants: dict[str, set[int]] = {
            "outgoing": set(),
            "incoming": set(),
        }
        inferred_outgoing_local_families: set[tuple[int, int]] = set()
        unresolved_replication: list[tuple[str, int, int]] = []
        for (direction, family, participant), count in sorted(
                capture.replication_counts.items()):
            replication_directions.add(direction)
            effective_participant = participant
            inferred = False
            if (participant < 0 and direction == "outgoing" and
                    len(capture_local_owners) == 1):
                local_participant = next(iter(capture_local_owners))
                if (local_participant, family) in fanouts_by_participant_family:
                    effective_participant = local_participant
                    inferred = True
                    inferred_outgoing_local_families.add(
                        (local_participant, family))
            label = (f"P{effective_participant}"
                     if effective_participant >= 0 else "unresolved")
            print(
                f"  replication {direction} family=0x{family:04x} "
                f"{label}: messages={count} inferred={str(inferred).lower()}")
            if effective_participant < 0:
                unresolved_replication.append((direction, family, count))
                continue
            if count > 0 and direction in replication_participants:
                replication_participants[direction].add(effective_participant)
            if inferred:
                continue
            context_values = capture.replication_context.get(
                (direction, family, participant), set())
            if context_values and any(
                    not resolved or not runtime_user
                    for resolved, runtime_user, _, _, _, _, _
                    in context_values):
                problems.append(
                    f"{capture.label}: {direction} replication family "
                    f"0x{family:04x} P{participant} did not retain its "
                    "runtime UserImpl association")
            observed_name_tokens = {
                token for _, _, _, _, _, valid, token in context_values
                if valid and token > 0
            }
            observed_transport_routes = {
                route for _, _, _, _, route, _, _ in context_values
                if route >= 0
            }
            participant_transport_routes = {
                route for route in capture.participant_transport_routes.get(
                    participant, set()) if route >= 0
            }
            if (observed_transport_routes and participant_transport_routes and
                    observed_transport_routes !=
                    participant_transport_routes):
                problems.append(
                    f"{capture.label}: {direction} replication family "
                    f"0x{family:04x} P{participant} transport route "
                    "disagrees with character creation")
            participant_name_tokens = {
                token for valid, token, *_
                in capture.participant_names.get(participant, set())
                if valid and token > 0
            }
            if (observed_name_tokens and participant_name_tokens and
                    observed_name_tokens != participant_name_tokens):
                problems.append(
                    f"{capture.label}: {direction} replication family "
                    f"0x{family:04x} P{participant} name token disagrees "
                    "with character creation")
        if require_replication_association:
            for direction in ("outgoing", "incoming"):
                if direction not in replication_directions:
                    problems.append(
                        f"{capture.label}: no {direction} participant "
                        "replication telemetry")
            if unresolved_replication:
                rendered = ", ".join(
                    f"{direction}/0x{family:04x}={count}"
                    for direction, family, count in unresolved_replication)
                problems.append(
                    f"{capture.label}: unresolved participant replication "
                    f"observed ({rendered})")
        if require_replication_matrix:
            if not any(
                    participants == expected_players and
                    sources == expected_players and
                    unique == expected_players and
                    duplicate_mask == 0 and identity_unique
                    for participants, sources, unique, duplicate_mask,
                    identity_unique in capture.replication_maps):
                problems.append(
                    f"{capture.label}: no complete unique replication map "
                    f"for {expected_players} participants")
            if not capture_local_owners:
                problems.append(
                    f"{capture.label}: replication matrix has no local "
                    "participant ownership")
            missing_local_outgoing = sorted(
                capture_local_owners - replication_participants["outgoing"])
            if missing_local_outgoing:
                problems.append(
                    f"{capture.label}: no outgoing gameplay replication for "
                    f"local participants {missing_local_outgoing}")
            expected_remote = expected - capture_local_owners
            missing_remote_incoming = sorted(
                expected_remote - replication_participants["incoming"])
            if missing_remote_incoming:
                problems.append(
                    f"{capture.label}: no incoming gameplay replication for "
                    f"remote participants {missing_remote_incoming}")
        if require_replication_send_fanout:
            expected_remote_count = max(expected_players - 1, 0)
            outgoing_local_families = {
                (participant, family)
                for (direction, family, participant), count
                in capture.replication_counts.items()
                if direction == "outgoing" and count > 0 and
                participant in capture_local_owners
            }
            outgoing_local_families.update(
                inferred_outgoing_local_families)
            if not outgoing_local_families:
                problems.append(
                    f"{capture.label}: no outgoing local replication family "
                    "available for send fan-out validation")
            for participant, family in sorted(outgoing_local_families):
                audits = fanouts_by_participant_family.get(
                    (participant, family), [])
                if not audits:
                    problems.append(
                        f"{capture.label}: missing replication send fan-out "
                        f"for local P{participant} family 0x{family:04x}")
                    continue
                expected_remote_mask = (
                    ((1 << expected_players) - 1) & ~(1 << participant))
                if not any(
                        fanout_participant(audit) == participant and
                        audit.message_family == family and
                        audit.target_vector_shape_valid and
                        audit.target_entries_readable and
                        audit.target_transport_routes_unique and
                        audit.target_participants_resolved and
                        audit.duplicate_transport_route_target_mask == 0 and
                        audit.duplicate_participant_target_mask == 0 and
                        audit.unresolved_target_mask == 0 and
                        audit.target_count == expected_remote_count and
                        audit.inspected_target_count == expected_remote_count and
                        audit.valid_transport_route_count ==
                        expected_remote_count and
                        audit.unique_transport_route_count ==
                        expected_remote_count and
                        audit.target_participant_mask == expected_remote_mask and
                        audit.mapped_participant_count == expected_players and
                        audit.serializer_result
                        for audit in audits):
                    problems.append(
                        f"{capture.label}: incomplete replication send fan-out "
                        f"for local P{participant} family 0x{family:04x}; "
                        f"expected {expected_remote_count} unique remote targets")
        ownership.update(capture_local_owners)

    print("\nCross-capture local ownership:")
    if ownership:
        print("  " + " ".join(
            f"P{participant}={ownership.get(participant, 0)}"
            for participant in range(expected_players)))
    else:
        print("  unavailable")
    duplicated = [participant for participant, count in ownership.items()
                  if count > 1]
    if duplicated:
        problems.append(f"local ownership duplicated across captures: {duplicated}")
    if len(captures) >= expected_players:
        missing_owners = sorted(expected - set(ownership))
        if missing_owners:
            problems.append(
                f"no capture claimed local ownership for {missing_owners}")
    return problems


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="+", type=Path,
                        help="Session directories, events.jsonl files or sanitized report ZIPs")
    parser.add_argument("--expected-players", type=int, default=5)
    parser.add_argument("--expected-local-per-process", type=int, default=1)
    parser.add_argument(
        "--require-exact-loadout", action="store_true",
        help="Require v0.6.2 exact class/loadout restoration telemetry for P4+")
    parser.add_argument(
        "--require-pre-map-loadout-restore", action="store_true",
        help=("Require v0.6.7 P4+ loadout identity restoration immediately "
              "after character construction and before native map consumers"))
    parser.add_argument(
        "--require-name-identity", action="store_true",
        help="Require private PlayerInfo display-name tokens for every participant")
    parser.add_argument(
        "--require-chat-name-association", action="store_true",
        help="Require at least one private matching chat sender/name association")
    parser.add_argument(
        "--require-replication-association", action="store_true",
        help="Require resolved outgoing/incoming 0x3300/0x3400 participant telemetry")
    parser.add_argument(
        "--require-replication-matrix", action="store_true",
        help=("Require each capture to observe outgoing gameplay replication "
              "for its local participant and incoming replication for every "
              "remote participant"))
    parser.add_argument(
        "--require-replication-send-fanout", action="store_true",
        help=("Require every observed local gameplay-replication family to "
              "reach one unique serializer target per remote participant"))
    parser.add_argument(
        "--require-receive-route-matrix", action="store_true",
        help=("Require the dynamic receive vector to contain one unique "
              "UserImpl route for every expected remote participant"))
    parser.add_argument(
        "--require-receive-route-lifecycle", action="store_true",
        help=("Require at least one valid native register transition at the "
              "dynamic receive-route lifecycle boundary"))
    parser.add_argument(
        "--require-transport-route-identity", action="store_true",
        help=("Require every participant to retain one unique UserImpl+0xc8 "
              "transport route and every receive-vector entry to match it"))
    parser.add_argument(
        "--require-result-event-publish", action="store_true",
        help="Require the setter-scoped MissionResult UI close event (type 1 / id 2)")
    parser.add_argument(
        "--require-result-ui-close-dispatch", action="store_true",
        help="Require the UI close event to match object id 2 and set its closing flag")
    parser.add_argument(
        "--require-result-reward-chain", action="store_true",
        help=("Require Sync_MissionResult completion plus completed "
              "ResolveResult/ApplyResult telemetry"))
    parser.add_argument(
        "--require-result-room-return", action="store_true",
        help="Require a clear-result transition back to the room UI")
    parser.add_argument(
        "--require-loadout-parser-rollback", action="store_true",
        help=("Require v0.6.10 rollback of P4+ native loadout blocks "
              "without corrupting the local reward-profile count"))
    parser.add_argument(
        "--require-class-sidecar", action="store_true",
        help=("Require a bounded PlayerInfo/parser/native class resolution "
              "for every P4+ participant, not only the emergency visual fallback"))
    parser.add_argument(
        "--require-visual-slot-remap", action="store_true",
        help=("Require every P4+ participant to use a modulo-four slot only "
              "at the native player-status renderer"))
    parser.add_argument(
        "--require-effective-result-recovery", action="store_true",
        help=("When host-only result recovery runs, require Mission() to "
              "surface effective clear result 1"))
    parser.add_argument(
        "--require-extra-result-items", action="store_true",
        help=("Require a safe NetGameStatus Item aggregation for every "
              "expected participant beyond the four native accumulators"))
    parser.add_argument(
        "--require-result-item-matrix", action="store_true",
        help=("Require the sanitized NetGameStatus presence matrix to "
              "contain every expected participant P0-P7"))
    parser.add_argument(
        "--require-enemy-spawn", action="store_true",
        help="Require at least one confirmed enemy-instantiation observation")
    parser.add_argument(
        "--require-enemy-spawn-repair", action="store_true",
        help="Require a successful guarded P5 enemy zero-scale repair")
    parser.add_argument(
        "--require-native-participant-scaling-clamp", action="store_true",
        help=("Require evidence that a 5+ participant read was clamped to "
              "the native four-player scaling profile"))
    parser.add_argument(
        "--require-result-exec-recovery", action="store_true",
        help="Require an accepted -20000 Exec_Begin result recovery")
    parser.add_argument(
        "--require-result-exec-native-cancel", action="store_true",
        help=("Require native Exec_Begin to cancel its queued fallback without "
              "requeue or duplicate application"))
    parser.add_argument(
        "--require-result-exec-pipeline", action="store_true",
        help=("Require expected native callers for ResultSync_Update and "
              "ResultSync_Finally"))
    parser.add_argument("--strict", action="store_true",
                        help="Exit nonzero when an inconsistency is found")
    args = parser.parse_args()
    captures = [capture for path in args.paths
                for capture in captures_from_path(path)]
    if not captures:
        raise SystemExit("No events*.jsonl files found")
    problems = summarize(captures, args.expected_players,
                         args.expected_local_per_process,
                         args.require_exact_loadout,
                         args.require_pre_map_loadout_restore,
                         args.require_name_identity,
                         args.require_chat_name_association,
                         args.require_replication_association,
                         args.require_replication_matrix,
                         args.require_replication_send_fanout,
                         args.require_receive_route_matrix,
                         args.require_receive_route_lifecycle,
                         args.require_transport_route_identity,
                         args.require_result_event_publish,
                         args.require_result_ui_close_dispatch,
                         args.require_result_reward_chain,
                         args.require_result_room_return,
                         args.require_loadout_parser_rollback,
                         args.require_class_sidecar,
                         args.require_visual_slot_remap,
                         args.require_effective_result_recovery,
                         args.require_extra_result_items,
                         args.require_result_item_matrix,
                         args.require_enemy_spawn,
                         args.require_enemy_spawn_repair,
                         args.require_native_participant_scaling_clamp,
                         args.require_result_exec_recovery,
                         args.require_result_exec_native_cancel,
                         args.require_result_exec_pipeline)
    print("\nAssessment: " + ("inconsistencies found" if problems else "consistent"))
    for problem in problems:
        print("  WARN " + problem)
    if args.strict and problems:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
