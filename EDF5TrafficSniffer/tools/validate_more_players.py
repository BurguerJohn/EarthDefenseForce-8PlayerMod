#!/usr/bin/env python3
"""Validate one EDF5 More Players capture against its configured room limit."""

from __future__ import annotations

import argparse
import collections
import contextlib
import itertools
import json
from pathlib import Path


def event_part(path: Path) -> int:
    if path.name == "events.jsonl":
        return 1
    try:
        return int(path.stem.rsplit("-", 1)[1])
    except (IndexError, ValueError):
        return 2**31 - 1


def event_paths(source: Path) -> list[Path]:
    if not source.is_dir():
        return [source]
    return sorted(source.glob("events*.jsonl"), key=event_part)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("session", type=Path, help="Session directory or events.jsonl")
    parser.add_argument("--expected-max", type=int, default=5)
    parser.add_argument("--expected-bots", type=int, default=4)
    parser.add_argument("--require-real-flow-observer", action="store_true")
    parser.add_argument("--require-callsite-audit", action="store_true")
    parser.add_argument(
        "--require-local-harness-matching", action="store_true",
        help="Require the fail-closed host-only MissionStart 4->5 gate event",
    )
    parser.add_argument(
        "--require-local-harness-mission-start-observation",
        action="store_true",
        help="Require native MissionStart state-machine observations",
    )
    parser.add_argument(
        "--require-local-harness-controller-gate",
        action="store_true",
        help="Require the temporary host-only pre-update controller bypass",
    )
    args = parser.parse_args()
    paths = event_paths(args.session)
    if not paths:
        raise SystemExit(f"No events*.jsonl files found under {args.session}")

    owned_lobbies: set[int] = set()
    added: list[int] = []
    removed: list[int] = []
    synthetic_indexes: set[tuple[int, int]] = set()
    entered_callbacks: set[int] = set()
    left_callbacks: list[int] = []
    synthetic_auth_begin: set[int] = set()
    synthetic_auth_callbacks: set[int] = set()
    p2p_sends: collections.Counter[tuple[int, int]] = collections.Counter()
    real_p2p_passthrough = 0
    real_gameplay_contacts: set[int] = set()
    real_auth_passthrough = 0
    max_member_count = 0
    configured_max = 0
    malformed = 0
    unexpected_rejections: list[str] = []
    room_full_milestone = False
    all_fillers_contacted = False
    roster_patch_ready = False
    roster_patch_skipped = False
    roster_patch_failed = False
    roster_patch_capacity = 0
    p2p_callsite_directions: set[str] = set()
    p2p_callsite_rvas: set[int] = set()
    local_harness_matching_events: list[dict[str, object]] = []
    local_harness_mission_start_observations: list[dict[str, object]] = []
    local_harness_controller_gate_observations: list[dict[str, object]] = []

    session_path = paths[0].parent / "session.json"
    process_is_edf5 = False
    if session_path.exists():
        try:
            session_metadata = json.loads(session_path.read_text(encoding="utf-8"))
            process_is_edf5 = (
                Path(str(session_metadata.get("executable", ""))).name.casefold()
                == "edf5.exe"
            )
        except (OSError, json.JSONDecodeError):
            pass

    with contextlib.ExitStack() as stack:
        streams = [stack.enter_context(path.open("r", encoding="utf-8")) for path in paths]
        for line in itertools.chain.from_iterable(streams):
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                malformed += 1
                continue
            layer = item.get("layer")
            event = item.get("event")
            if layer == "more_players" and event == "started":
                configured_max = max(configured_max, int(item.get("max_players", 0)))
            elif layer == "more_players" and event == "owned_lobby_detected":
                owned_lobbies.add(int(item.get("lobby_steam_id", 0)))
                configured_max = max(configured_max, int(item.get("max_players", 0)))
            elif layer == "more_players" and event == "bot_added":
                added.append(int(item.get("bot_steam_id", 0)))
            elif layer == "more_players" and event == "synthetic_room_full":
                room_full_milestone = True
            elif layer == "more_players" and event == "all_fillers_gameplay_contacted":
                all_fillers_contacted = True
            elif (layer == "more_players" and
                  event == "local_mission_harness_matching_gate_completed"):
                local_harness_matching_events.append(item)
            elif (layer == "more_players" and
                  event == "local_mission_harness_mission_start_observed"):
                local_harness_mission_start_observations.append(item)
            elif (layer == "more_players" and
                  event == "local_mission_harness_controller_gate_observed"):
                local_harness_controller_gate_observations.append(item)
            elif layer == "more_players" and event == "roster_capacity_patch_ready":
                roster_patch_ready = True
                roster_patch_capacity = max(
                    roster_patch_capacity, int(item.get("capacity", 0))
                )
            elif layer == "more_players" and event == "roster_capacity_patch_skipped":
                roster_patch_skipped = True
            elif layer == "more_players" and event == "roster_capacity_patch_failed":
                roster_patch_failed = True
            elif layer == "more_players" and event in {
                "bot_removed", "bot_evicted_for_real_member"
            }:
                removed.append(int(item.get("bot_steam_id", 0)))
            elif layer == "more_players" and event == "hotkey_rejected":
                reason = str(item.get("reason", ""))
                if reason != "lobby has no free slot":
                    unexpected_rejections.append(reason or "unknown")
            elif layer == "more_players" and event == "lobby_chat_update_dispatched":
                user = int(item.get("user_steam_id", 0))
                state = int(item.get("state_change", 0))
                if state == 1:
                    entered_callbacks.add(user)
                elif state == 2:
                    left_callbacks.append(user)
            elif layer == "more_players" and event == "auth_validation_dispatched":
                synthetic_auth_callbacks.add(int(item.get("user_steam_id", 0)))
            elif layer == "steam_matchmaking" and event == "get_member_count":
                max_member_count = max(max_member_count, int(item.get("count", 0)))
            elif layer == "steam_matchmaking" and event == "get_member_by_index":
                if item.get("synthetic"):
                    synthetic_indexes.add(
                        (int(item.get("index", -1)), int(item.get("user_steam_id", 0)))
                    )
            elif layer == "steam_user" and event == "begin_auth_session":
                user = int(item.get("user_steam_id", 0))
                if item.get("synthetic"):
                    synthetic_auth_begin.add(user)
                else:
                    real_auth_passthrough += 1
            elif layer == "steam_p2p" and event == "send":
                user = int(item.get("peer_steam_id", 0))
                channel = int(item.get("channel", -1))
                if item.get("synthetic"):
                    if item.get("result"):
                        p2p_sends[(channel, user)] += 1
                else:
                    real_p2p_passthrough += 1
            elif layer == "flow" and event == "real_gameplay_peer_contacted":
                real_gameplay_contacts.add(int(item.get("peer_steam_id", 0)))
            elif layer == "network_summary" and event == "p2p_callsite":
                p2p_callsite_directions.add(str(item.get("direction", "")))
                caller_rva = int(item.get("caller_rva", 0))
                if caller_rva:
                    p2p_callsite_rvas.add(caller_rva)

    unique_added = {user for user in added if user}
    indexed_users = {user for _, user in synthetic_indexes if user}
    channel2_users = {user for channel, user in p2p_sends if channel == 2}
    channel0_users = {user for channel, user in p2p_sends if channel == 0}
    gates = {
        "capture_is_well_formed": malformed == 0,
        "roster_capacity_preflight": (
            roster_patch_ready and roster_patch_capacity == args.expected_max
            if process_is_edf5 else roster_patch_ready or roster_patch_skipped
        ),
        "no_roster_capacity_patch_failure": not roster_patch_failed,
        "configured_limit": configured_max == args.expected_max,
        "owned_lobby_detected": bool(owned_lobbies),
        "fillers_added": len(unique_added) >= args.expected_bots,
        "room_reached_limit": max_member_count >= args.expected_max,
        "room_full_milestone": room_full_milestone,
        "fillers_enumerated": len(indexed_users) >= args.expected_bots,
        "entry_callbacks": len(entered_callbacks) >= args.expected_bots,
        "channel2_handshake": len(channel2_users) >= min(2, args.expected_bots),
        "synthetic_auth": len(synthetic_auth_begin) >= min(2, args.expected_bots),
        "synthetic_auth_callbacks": len(synthetic_auth_callbacks)
        >= min(2, args.expected_bots),
        "gameplay_send_accepted_without_fabricated_input": len(channel0_users)
        >= args.expected_bots,
        "all_fillers_gameplay_contacted": all_fillers_contacted,
        "real_p2p_passthrough": real_p2p_passthrough > 0,
        "real_auth_passthrough": real_auth_passthrough > 0,
        "no_unexpected_rejection": not unexpected_rejections,
    }
    if args.require_real_flow_observer:
        gates["real_gameplay_flow_observer"] = bool(
            {user for user in real_gameplay_contacts if user}
        )
    if args.require_callsite_audit:
        gates["p2p_callsite_audit"] = (
            {"in", "out"} <= p2p_callsite_directions and
            bool(p2p_callsite_rvas)
        )
    if args.require_local_harness_matching:
        expected_mask = (1 << args.expected_bots) - 1
        gates["local_harness_matching_gate"] = any(
            int(item.get("dummy_count", 0)) == args.expected_bots and
            int(item.get("previous_state", -1)) == 4 and
            int(item.get("completed_state", -1)) == 5 and
            int(item.get("expected_mask", 0)) == expected_mask and
            int(item.get("ready_mask", 0)) == expected_mask and
            int(item.get("mission_group_mask", 0)) == expected_mask and
            int(item.get("gameplay_contact_mask", 0)) == expected_mask and
            int(item.get("real_gameplay_peers", -1)) == 0 and
            item.get("test_mode") is False and
            item.get("native_peer_snapshot_received") is False and
            item.get("gameplay_packet_fabricated") is False and
            item.get("completion_scope") == "host_only_local_harness"
            for item in local_harness_matching_events
        )
    if args.require_local_harness_mission_start_observation:
        expected_mask = (1 << args.expected_bots) - 1
        gates["local_harness_mission_start_observation"] = any(
            int(item.get("dummy_count", 0)) == args.expected_bots and
            int(item.get("actual_members", -1)) == 1 and
            int(item.get("expected_mask", 0)) == expected_mask and
            int(item.get("ready_mask", 0)) == expected_mask and
            int(item.get("mission_group_mask", 0)) == expected_mask and
            int(item.get("gameplay_contact_mask", 0)) == expected_mask and
            int(item.get("real_gameplay_peers", -1)) == 0 and
            item.get("mission_groups_synchronized") is True and
            item.get("completion_prerequisites") is True and
            item.get("native_state_forced") is False and
            item.get("observation_point") in {
                "MissionStart::Update", "HUiRoom::Update"
            } and
            isinstance(item.get("native_update_called"), bool) and
            isinstance(item.get("native_before_state"), int) and
            isinstance(item.get("native_after_state"), int)
            for item in local_harness_mission_start_observations
        )
    if args.require_local_harness_controller_gate:
        gates["local_harness_controller_gate"] = any(
            int(item.get("dummy_count", 0)) == args.expected_bots and
            int(item.get("actual_members", -1)) == 1 and
            int(item.get("native_gate_value", -1)) == 0 and
            int(item.get("effective_gate_value", -1)) == 1 and
            1 <= int(item.get("mission_start_before_state", -1)) <= 5 and
            isinstance(item.get("mission_start_after_state"), int) and
            item.get("supported_vtable") is True and
            item.get("gate_writable") is True and
            item.get("completion_prerequisites") is True and
            item.get("bypass_requested") is True and
            item.get("bypass_applied") is True and
            item.get("temporary_value_restored") is True and
            item.get("native_mission_state_forced") is False and
            item.get("native_context_field_persisted") is False
            for item in local_harness_controller_gate_observations
        )

    print(f"Session: {paths[0].parent} ({len(paths)} event part(s))")
    print(
        f"Observed: configured={configured_max} room_max={max_member_count} "
        f"fillers={len(unique_added)} indexed={len(indexed_users)} "
        f"entered={len(entered_callbacks)} removed={len(removed)}"
    )
    for name, passed in gates.items():
        print(f"  {'PASS' if passed else 'FAIL'}  {name}")
    if unexpected_rejections:
        print("Unexpected rejections: " + ", ".join(unexpected_rejections))
    passed = all(gates.values())
    print(f"Result: {'PASS' if passed else 'FAIL'}")
    raise SystemExit(0 if passed else 1)


if __name__ == "__main__":
    main()
