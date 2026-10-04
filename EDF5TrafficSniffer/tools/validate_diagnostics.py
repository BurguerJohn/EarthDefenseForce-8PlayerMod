#!/usr/bin/env python3
"""Validate EDF5MP logging/crash fixtures and sanitized support reports."""

from __future__ import annotations

import argparse
import json
import re
import struct
import zipfile
from pathlib import Path


MODES = ("clean", "snapshot", "network", "deep", "deep_limit", "flood", "rotate",
         "crash", "crash_off", "fast_fail")
PROJECT_ROOT = Path(__file__).resolve().parents[1]


def read_plugin_version() -> str:
    header = (PROJECT_ROOT / "src" / "core" / "mod_info.h").read_text(
        encoding="utf-8"
    )
    match = re.search(r'kVersion\[\]\s*=\s*"([^"]+)"', header)
    if not match:
        raise RuntimeError("could not read kVersion from src/core/mod_info.h")
    return match.group(1)


PLUGIN_VERSION = read_plugin_version()
SECRET_MARKERS = (
    "fixture-secret-token",
    "203.0.113.55",
    "76561198012345678",
    "109775241899999999",
    "secret-ticket-1234567890ABCDEFGH",
    "Fixture Persona",
    "Fixture Persona Exact",
    "private.fixture.invalid",
    "node.fixture.invalid",
    "generic-lobby-secret",
    "FixtureAgent/1.0",
    "https://api.fixture.invalid/private",
    "C:\\private\\EDF5.exe",
    "[2001:db8::55]:27015",
    "dXNlcjpwYXNz",
    "session_cookie_fixture",
    "Fixture Log Persona",
    "\\\\private-server\\Gabriel\\secret.txt",
    "EARTH DEFENSE FORCE 5",
    "109775241799999998",
    "76561198000000001",
    "76561202255233020",
    "76561202255233021",
    "76561202255233022",
    "76561202255233023",
    "fake-original-name",
    "0x00007ff6abcdef01",
    "0x140abcdef",
    "140694844102264",
    "140696810242849",
)


def event_part(path: Path) -> int:
    if path.name == "events.jsonl":
        return 1
    match = re.fullmatch(r"events-(\d+)\.jsonl", path.name)
    return int(match.group(1)) if match else 2**31 - 1


def find_session(mode_root: Path) -> Path:
    if (mode_root / "session.json").is_file():
        return mode_root
    candidates = list(mode_root.glob("Mods/TrafficSniffer/logs/*/session.json"))
    if not candidates:
        candidates = list(mode_root.rglob("session.json"))
    if not candidates:
        raise ValueError(f"no diagnostic session below {mode_root}")
    return max(candidates, key=lambda item: item.stat().st_mtime).parent


def read_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected object in {path}")
    return value


def stack_walk_recorded(context: dict) -> bool:
    """A crash context must carry an unwound, module-relative stack."""
    frames = context.get("stack_frames")
    if not isinstance(frames, list) or len(frames) < 2:
        return False
    if context.get("stack_frame_count") != len(frames):
        return False
    return any(
        isinstance(frame, dict) and
        str(frame.get("module", "")).lower().endswith(".exe") and
        int(frame.get("rva", 0)) > 0 and
        frame.get("rva_hex") == f"0x{int(frame.get('rva', 0)):x}"
        for frame in frames)


def read_events(session: Path) -> tuple[list[dict], list[Path]]:
    paths = sorted(session.glob("events*.jsonl"), key=event_part)
    if not paths:
        raise ValueError(f"no events*.jsonl in {session}")
    events: list[dict] = []
    for path in paths:
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"malformed {path.name}:{line_number}: {error}") from error
            if not isinstance(item, dict) or item.get("schema") != 2:
                raise ValueError(f"unexpected schema in {path.name}:{line_number}")
            events.append(item)
    return events, paths


def dump_streams(path: Path) -> set[int]:
    data = path.read_bytes()
    if data[:4] != b"MDMP" or len(data) < 32:
        raise ValueError(f"invalid minidump signature: {path}")
    count, directory = struct.unpack_from("<II", data, 8)
    if directory + count * 12 > len(data):
        raise ValueError(f"invalid minidump directory: {path}")
    return {struct.unpack_from("<I", data, directory + index * 12)[0]
            for index in range(count)}


class Results:
    def __init__(self) -> None:
        self.failed = 0

    def check(self, condition: bool, name: str, detail: str = "") -> None:
        passed = bool(condition)
        if not passed:
            self.failed += 1
        suffix = f" ({detail})" if detail else ""
        print(f"  {'PASS' if passed else 'FAIL'}  {name}{suffix}")


def validate_mode(mode: str, mode_root: Path, results: Results) -> None:
    print(f"\n[{mode}]")
    try:
        session = find_session(mode_root)
        metadata = read_json(session / "session.json")
        status = read_json(session / "status.json")
        health = read_json(session / "health.json")
        events, parts = read_events(session)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        results.check(False, "session readable", str(error))
        return

    sequences = [item.get("seq") for item in events]
    results.check(metadata.get("schema") == 2, "session schema v2")
    results.check(metadata.get("plugin_version") == PLUGIN_VERSION,
                  f"plugin version {PLUGIN_VERSION}")
    results.check(metadata.get("game") == "EDF5", "EDF5 game profile selected")
    results.check(metadata.get("sniffer_module_enabled") is True,
                  "EDF5 sniffer module enabled")
    results.check(metadata.get("coop8_module_enabled") is True,
                  "EDF5 Coop8 module enabled")
    results.check(bool(events), "events present", f"{len(events)} in {len(parts)} part(s)")
    results.check(all(isinstance(item, int) and item > 0 for item in sequences),
                  "event sequences valid")
    results.check(len(sequences) == len(set(sequences)), "event sequences unique")
    results.check(health.get("write_errors") == 0, "no logger write errors")
    expected_state = "crashed" if mode.startswith("crash") or mode == "fast_fail" else "clean"
    results.check(status.get("state") == expected_state, f"status is {expected_state}")
    results.check(any(item.get("event") == "crash_handler_ready" for item in events),
                  "crash handler initialized")

    if mode == "clean":
        exercised = {item.get("event") for item in events}
        results.check({"winsock_last_error", "win32_last_error"} <= exercised,
                      "Win32/Winsock last-error preservation exercised")

    if mode == "snapshot":
        snapshots = list((session / "snapshots").glob("*_manual_*/state.json"))
        results.check(len(snapshots) == 1, "one live snapshot")
        if snapshots:
            state = read_json(snapshots[0])
            dump = snapshots[0].with_name("snapshot.dmp")
            results.check(state.get("runtime", {}).get("phase") == "matching",
                          "snapshot contains matching state")
            results.check(state.get("runtime", {}).get("real_gameplay_peers") == 1,
                          "snapshot contains real gameplay peer count")
            try:
                streams = dump_streams(dump)
                results.check(4 in streams, "snapshot minidump is parseable")
            except (OSError, ValueError) as error:
                results.check(False, "snapshot minidump is parseable", str(error))

    if mode == "network":
        callsites = [item for item in events
                     if item.get("layer") == "network_summary" and
                     item.get("event") == "p2p_callsite"]
        outgoing = [item for item in callsites
                    if item.get("direction") == "out" and
                    item.get("channel") == 0 and
                    item.get("caller_rva") == 0x123450]
        incoming = [item for item in callsites
                    if item.get("direction") == "in" and
                    item.get("channel") == 2 and
                    item.get("caller_rva") == 0x234560]
        results.check(len(outgoing) == 1, "one outgoing P2P callsite summary")
        if outgoing:
            results.check(outgoing[0].get("packets") == 2 and
                          outgoing[0].get("minimum_packet_bytes") == 246 and
                          outgoing[0].get("maximum_packet_bytes") == 300 and
                          outgoing[0].get("synthetic_packets") == 1,
                          "outgoing callsite aggregation is exact")
        results.check(len(incoming) == 1, "one incoming P2P callsite summary")
        if incoming:
            results.check(incoming[0].get("packets") == 1 and
                          incoming[0].get("failures") == 1 and
                          incoming[0].get("minimum_packet_bytes") == 512 and
                          incoming[0].get("maximum_packet_bytes") == 512,
                          "incoming callsite aggregation is exact")
        results.check(all("peer_steam_id" not in item and
                          "remote_endpoint" not in item for item in callsites),
                      "callsite summaries contain no endpoint identity")
        routes = [item for item in events
                  if item.get("layer") == "network_summary" and
                  item.get("event") == "game_packet_route"]
        send_routes = [item for item in routes
                       if item.get("direction") == "out" and
                       item.get("producer_rva") == 0x345670]
        receive_routes = [item for item in routes
                          if item.get("direction") == "in" and
                          item.get("handler_rva") == 0x456780 and
                          item.get("handler_vtable_rva") == 0x567890]
        results.check(len(send_routes) == 1,
                      "one high-level serializer route summary")
        if send_routes:
            results.check(send_routes[0].get("packets") == 2 and
                          send_routes[0].get("minimum_packet_bytes") == 128 and
                          send_routes[0].get("maximum_packet_bytes") == 622,
                          "serializer route aggregation is exact")
        results.check(len(receive_routes) == 1,
                      "one receive callback route summary")
        if receive_routes:
            results.check(receive_routes[0].get("packets") == 2 and
                          receive_routes[0].get("minimum_packet_bytes") == 172 and
                          receive_routes[0].get("maximum_packet_bytes") == 607,
                          "receive callback route aggregation is exact")
        results.check(all("peer_steam_id" not in item and
                          "payload" not in item and
                          "remote_endpoint" not in item for item in routes),
                      "game route summaries contain no endpoint or payload")
        messages = [item for item in events
                    if item.get("layer") == "network_summary" and
                    item.get("event") == "game_message_route"]
        typed = [item for item in messages
                 if item.get("message_code") == 0x1200 and
                 item.get("message_family") == 0x1200 and
                 item.get("context_handle_present") is True and
                 item.get("producer_rva") == 0x654320]
        multipart = [item for item in messages
                     if item.get("message_code") == 0x11100 and
                     item.get("message_family") == 0x1100 and
                     item.get("message_flags") == 1 and
                     item.get("context_handle_present") is False]
        incoming = [item for item in messages
                    if item.get("direction") == "in" and
                    item.get("observation_point") == "decoded_dispatch" and
                    item.get("message_code") == 3 and
                    item.get("message_flags") == 2 and
                    item.get("producer_rva") == 0x114D50]
        results.check(len(typed) == 1,
                      "one outgoing logical message summary")
        if typed:
            results.check(typed[0].get("messages") == 2 and
                          typed[0].get("bytes") == 16 and
                          typed[0].get("minimum_message_bytes") == 8 and
                          typed[0].get("maximum_message_bytes") == 8 and
                          typed[0].get("header_unavailable") == 0 and
                          typed[0].get("header_length_mismatches") == 0 and
                          typed[0].get("known_multipart_messages") == 0 and
                          typed[0].get("unexpected_framing_mismatches") == 0,
                          "logical message aggregation is exact")
        results.check(len(multipart) == 1 and
                      multipart[0].get("header_length_mismatches") == 1 and
                      multipart[0].get("known_multipart_messages") == 1 and
                      multipart[0].get("unexpected_framing_mismatches") == 0,
                      "known multipart framing is classified without false corruption")
        results.check(len(incoming) == 1 and
                      incoming[0].get("messages") == 1 and
                      incoming[0].get("message_size_available") is False and
                      incoming[0].get("bytes") == 0,
                      "decoded incoming logical message is aggregated without payload size")
        results.check(all("peer_steam_id" not in item and
                          "payload" not in item and
                          "remote_endpoint" not in item and
                          "steam_id" not in item for item in messages),
                      "message summaries contain no endpoint or payload")

    if mode == "deep":
        payload_events = [item for item in events if isinstance(item.get("payload"), dict)]
        results.check(len(payload_events) == 1, "payload only captured while deep mode is on")
        if payload_events:
            payload = payload_events[0]["payload"]
            results.check(payload.get("length") == 4096, "payload cap applied")
            results.check(payload.get("original_length") == 5000,
                          "original payload length retained")
            results.check(payload.get("truncated") is True, "payload marked truncated")
            raw_path = session / str(payload.get("file", ""))
            try:
                raw = raw_path.read_bytes()
                offset = int(payload.get("offset", 0))
                marker = b"secret-ticket-1234567890ABCDEFGH"
                results.check(raw[offset:offset + len(marker)] == marker,
                              "raw payload bytes match fixture")
            except OSError as error:
                results.check(False, "raw payload bytes match fixture", str(error))

    if mode == "deep_limit":
        payload_bytes = sum(path.stat().st_size for path in session.glob("payloads*.bin"))
        results.check(0 < payload_bytes <= 1024 * 1024,
                      "concurrent deep capture obeyed session cap",
                      f"payload_bytes={payload_bytes}")
        results.check(health.get("deep_capture_enabled") is False,
                      "deep capture disabled at limit")
        results.check(any(item.get("event") == "logger_health" and
                          item.get("deep_limit_reached") is True for item in events),
                      "deep limit health event emitted")
        results.check(any(item.get("event") == "deep_capture_rejected" for item in events),
                      "re-enable rejected after session cap")

    if mode == "flood":
        dropped = int(health.get("dropped_events", 0))
        results.check(dropped > 0, "bounded queue reports overload", f"dropped={dropped}")
        results.check(int(health.get("peak_queue_events", 0)) <= 256,
                      "normal queue stayed within configured bound")
        results.check(any(item.get("event") == "logger_health" for item in events),
                      "overload health event emitted")

    if mode == "rotate":
        results.check(len(parts) >= 2, "event log rotated", f"parts={len(parts)}")
        results.check(int(health.get("dropped_events", 0)) == 0,
                      "rotation test lost no events")
        results.check(sum(item.get("event") == "rotation" for item in events) == 20000,
                      "all rotation events retained")
        results.check(sequences == sorted(sequences),
                      "rotated parts preserve chronological order")

    if mode.startswith("crash"):
        emergency_path = session / "crashes" / "first-chance-emergency.json"
        results.check(emergency_path.is_file(),
                      "first-chance emergency context exists")
        if emergency_path.is_file():
            emergency = read_json(emergency_path)
            results.check(emergency.get("kind") == "first_chance_emergency" and
                          emergency.get("exception_code") == 0xC0000005,
                          "first-chance access violation recorded")
            results.check(emergency.get("instruction_pointer") and
                          emergency.get("stack_pointer") and
                          "register_rcx" in emergency,
                          "first-chance registers recorded")
            stack_candidates = emergency.get("stack_code_candidates", [])
            results.check(int(emergency.get("stack_bytes_read", 0)) >= 0x100,
                          "extended first-chance stack captured")
            results.check(isinstance(stack_candidates, list) and any(
                              isinstance(candidate, dict) and
                              int(candidate.get("module_rva", 0)) > 0 and
                              int(candidate.get("stack_offset", -1)) >= 0
                              for candidate in stack_candidates),
                          "first-chance executable stack candidates recorded")
        crash_json = list((session / "crashes").glob("crash-*.json"))
        results.check(len(crash_json) == 1, "one crash context")
        if crash_json:
            context = read_json(crash_json[0])
            dump = crash_json[0].with_suffix(".dmp")
            results.check(context.get("exception_code") == 0xC0000005,
                          "access violation recorded")
            results.check(context.get("hook", {}).get("operation") == "intentional_crash",
                          "active hook scope recorded")
            results.check(context.get("runtime", {}).get("phase") == "matching",
                          "runtime flow state recorded")
            results.check(context.get("runtime", {}).get("real_gameplay_peers") == 1,
                          "real gameplay peer count recorded")
            results.check(stack_walk_recorded(context),
                          "crash stack walk recorded as module+RVA frames")
            results.check("register_rcx" in context and
                          context.get("instruction_pointer"),
                          "crash registers recorded")
            if mode == "crash_off":
                results.check(context.get("dump_mode") == "Off", "dump mode Off recorded")
                results.check(context.get("dump_file") is None, "no dump file advertised")
                results.check(not dump.exists(), "no minidump written")
            else:
                try:
                    streams = dump_streams(dump)
                    results.check(6 in streams, "crash minidump has exception stream")
                except (OSError, ValueError) as error:
                    results.check(False, "crash minidump has exception stream", str(error))
            breadcrumbs = crash_json[0].with_suffix(".breadcrumbs.jsonl")
            results.check(breadcrumbs.is_file() and breadcrumbs.stat().st_size > 0,
                          "crash breadcrumbs preserved")

    if mode == "fast_fail":
        crash_json = list((session / "crashes").glob("crash-*.json"))
        results.check(len(crash_json) == 1, "one fast-fail context")
        if crash_json:
            context = read_json(crash_json[0])
            dump = crash_json[0].with_suffix(".dmp")
            results.check(context.get("exception_code") == 0xC0000409,
                          "stack-cookie fast-fail recorded")
            results.check(context.get("exception_parameter_0") == 2,
                          "fast-fail subcode 2 recorded")
            results.check(context.get("hook", {}).get("operation") ==
                          "simulated_fast_fail",
                          "fast-fail hook scope recorded")
            results.check(stack_walk_recorded(context),
                          "fast-fail stack walk recorded as module+RVA frames")
            try:
                streams = dump_streams(dump)
                results.check(6 in streams,
                              "fast-fail minidump has exception stream")
            except (OSError, ValueError) as error:
                results.check(False,
                              "fast-fail minidump has exception stream",
                              str(error))


def validate_report(path: Path, results: Results) -> None:
    print(f"\n[report {path.name}]")
    try:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            blobs = {name: archive.read(name) for name in names}
    except (OSError, zipfile.BadZipFile) as error:
        results.check(False, "report ZIP readable", str(error))
        return
    results.check(not any(name.lower().endswith(".dmp") for name in names),
                  "minidumps excluded")
    results.check(not any(Path(name).name.lower().startswith("payloads") and
                          name.lower().endswith(".bin") for name in names),
                  "raw payloads excluded")
    combined = b"\n".join(blobs.values()).decode("utf-8", "replace")
    for marker in SECRET_MARKERS:
        results.check(marker not in combined, f"redacted marker: {marker}")
    results.check(re.search(r"(?<!\d)7\d{16}(?!\d)", combined) is None,
                  "no raw Steam IDs")
    results.check(re.search(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?",
                            combined) is None, "no raw IP endpoints")
    results.check(re.search(r"\[[0-9A-Fa-f:]{2,}\](?::\d{1,5})?", combined) is None,
                  "no raw bracketed IPv6 endpoints")
    results.check(re.search(r"\b0x[0-9A-Fa-f]{9,16}\b", combined) is None,
                  "no absolute process addresses")
    results.check(re.search(r'"context"\s*:\s*"player_create"',
                            combined) is not None,
                  "textual diagnostic context preserved")
    results.check("140737488351232" not in combined and
                  re.search(r'"context"\s*:\s*"<redacted_address>"',
                            combined) is not None,
                  "numeric address context redacted")
    gate_event_preserved = (
        '"event":"generator_poll_gate_path"' in combined and
        '"outcome":"quota_blocked_inside_time_window"' in combined and
        '"pre_last_time_bits":1065353216' in combined and
        '"period_scale_bits":1073741824' in combined and
        '"current_time_bits":1077936128' in combined and
        '"cooldown_threshold":460' in combined and
        '"gate_state_pointer_logged":false' in combined and
        '"owner_pointer_logged":false' in combined and
        '"spawn_payload_logged":false' in combined)
    results.check(gate_event_preserved,
                  "GeneratorPoll gate diagnosis preserved without pointers")
    if path.name.startswith("deep-"):
        aliases = ("lobby_1", "steam_", "endpoint_", "identity_", "url_1")
        results.check(all(alias in combined for alias in aliases),
                      "stable aliases preserve communication topology")
        results.check('"original_bytes":5000' in combined and
                      '"captured_bytes":4096' in combined,
                      "payload truncation metadata preserved")
    if path.name.startswith("rotate-"):
        event_parts = [name for name in names if Path(name).name.startswith("events") and
                       name.lower().endswith(".jsonl")]
        rotation_events = combined.count('"event":"rotation"')
        results.check(len(event_parts) == 3, "all rotated event parts included")
        results.check(rotation_events == 20000, "rotated report retained full timeline")
    if path.name.startswith("crash-"):
        results.check(re.search(r'"operation"\s*:\s*"intentional_crash"',
                                combined) is not None,
                      "crash hook scope preserved")
        results.check(re.search(r'"phase"\s*:\s*"matching"', combined) is not None,
                      "crash flow phase preserved")
        results.check(re.search(r'"stack_frames"\s*:\s*\[', combined) is not None and
                      re.search(r'"rva_hex"\s*:\s*"0x[0-9a-f]{1,8}"',
                                combined) is not None,
                      "crash stack frames survive sanitization")
    if path.name.startswith("enabled-"):
        aliases = ("lobby_1", "steam_", "identity_1")
        results.check(all(alias in combined for alias in aliases),
                      "integration topology retained with stable aliases")
        results.check('"real_gameplay_peers":1' in combined,
                      "real gameplay flow retained")
    malformed = 0
    for name, blob in blobs.items():
        if name.lower().endswith(".json"):
            try:
                json.loads(blob)
            except json.JSONDecodeError:
                malformed += 1
        elif name.lower().endswith(".jsonl"):
            for line in blob.splitlines():
                try:
                    json.loads(line)
                except json.JSONDecodeError:
                    malformed += 1
    results.check(malformed == 0, "sanitized JSON is well formed")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path,
                        help="Root containing the diagnostic fixture folders")
    parser.add_argument("--report", type=Path, action="append", default=[])
    args = parser.parse_args()
    results = Results()
    for mode in MODES:
        validate_mode(mode, args.root / mode, results)
    for report in args.report:
        validate_report(report, results)
    print(f"\nResult: {'PASS' if results.failed == 0 else 'FAIL'} ({results.failed} failed gate(s))")
    raise SystemExit(0 if results.failed == 0 else 1)


if __name__ == "__main__":
    main()
