#!/usr/bin/env python3
"""Summarize captured Steam P2P payloads by direction, channel, size and header."""

from __future__ import annotations

import argparse
import collections
import json
import struct
from pathlib import Path


def event_part(path: Path) -> int:
    if path.name == "events.jsonl":
        return 1
    try:
        return int(path.stem.rsplit("-", 1)[1])
    except (IndexError, ValueError):
        return 2**31 - 1


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("session", type=Path)
    parser.add_argument("--details", type=lambda value: int(value, 0))
    parser.add_argument("--limit", type=int, default=40)
    args = parser.parse_args()

    payload_files: dict[str, bytes] = {}
    groups: collections.Counter[tuple[str, int, int, int, str]] = collections.Counter()
    details: list[tuple[int, str, str, int, int, int, str, int]] = []
    event_paths = sorted(args.session.glob("events*.jsonl"), key=event_part)
    for event_path in event_paths:
        with event_path.open("r", encoding="utf-8") as stream:
            for line in stream:
                event = json.loads(line)
                if event.get("layer") != "steam_p2p" or "payload" not in event:
                    continue
                payload = event["payload"]
                filename = str(payload["file"])
                if filename not in payload_files:
                    payload_files[filename] = (args.session / filename).read_bytes()
                offset = int(payload["offset"])
                length = int(payload["length"])
                data = payload_files[filename][offset:offset + length]
                header = struct.unpack_from("<I", data)[0] if len(data) >= 4 else -1
                direction = str(event.get("direction", "?"))
                channel = int(event.get("channel", -1))
                peer = int(event.get("peer_steam_id", 0))
                kind = str(event.get("event", "?"))
                preview = data[:24].hex()
                groups[(direction, channel, length, header, kind)] += 1
                if args.details is None or header == args.details:
                    details.append((int(event["seq"]), str(event["utc"]), direction,
                                    channel, length, header, preview, peer))

    print("count direction channel size header event")
    for key, count in groups.most_common():
        direction, channel, length, header, kind = key
        print(f"{count:6d} {direction:>3} {channel:3d} {length:5d} "
              f"0x{header & 0xffffffff:08x} {kind}")
    if args.details is not None:
        print("\nseq utc direction channel size header peer preview")
        for item in details[:args.limit]:
            seq, utc, direction, channel, length, header, preview, peer = item
            print(f"{seq:7d} {utc} {direction:>3} {channel:3d} {length:5d} "
                  f"0x{header & 0xffffffff:08x} {peer} {preview}")


if __name__ == "__main__":
    main()
