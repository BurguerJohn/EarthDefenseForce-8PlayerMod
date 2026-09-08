#!/usr/bin/env python3
"""Extract one payload by event sequence number and verify its CRC32."""

from __future__ import annotations

import argparse
import json
import zlib
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
    parser.add_argument("sequence", type=int)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    event = None
    event_paths = sorted(args.session.glob("events*.jsonl"), key=event_part)
    for event_path in event_paths:
        with event_path.open("r", encoding="utf-8") as stream:
            for line in stream:
                candidate = json.loads(line)
                if candidate.get("seq") == args.sequence:
                    event = candidate
                    break
        if event is not None:
            break
    if event is None:
        raise SystemExit(f"event seq={args.sequence} not found")
    payload = event.get("payload")
    if not payload:
        raise SystemExit(f"event seq={args.sequence} has no payload")

    payload_path = args.session / payload["file"]
    with payload_path.open("rb") as stream:
        stream.seek(int(payload["offset"]))
        data = stream.read(int(payload["length"]))
    if len(data) != int(payload["length"]):
        raise SystemExit(f"short read: expected {payload['length']}, got {len(data)}")
    actual_crc = f"{zlib.crc32(data) & 0xFFFFFFFF:08x}"
    expected_crc = str(payload["crc32"]).lower()
    if actual_crc != expected_crc:
        raise SystemExit(f"CRC mismatch: expected {expected_crc}, got {actual_crc}")
    args.output.write_bytes(data)
    print(f"wrote {len(data)} bytes to {args.output} (crc32={actual_crc})")


if __name__ == "__main__":
    main()
