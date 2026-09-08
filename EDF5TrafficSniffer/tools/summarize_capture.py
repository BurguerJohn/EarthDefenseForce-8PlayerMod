#!/usr/bin/env python3
"""Summarize one EDF5 Traffic Sniffer session without external packages."""

from __future__ import annotations

import argparse
import collections
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
    args = parser.parse_args()
    paths = event_paths(args.session)
    if not paths:
        raise SystemExit(f"No events*.jsonl files found under {args.session}")

    layers: collections.Counter[str] = collections.Counter()
    kinds: collections.Counter[str] = collections.Counter()
    peers: collections.Counter[str] = collections.Counter()
    endpoints: collections.Counter[str] = collections.Counter()
    payload_events = payload_bytes = malformed = 0
    first_utc = last_utc = None

    for events_path in paths:
        with events_path.open("r", encoding="utf-8") as stream:
            for line in stream:
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    malformed += 1
                    continue
                first_utc = first_utc or item.get("utc")
                last_utc = item.get("utc") or last_utc
                layer = str(item.get("layer", ""))
                event = str(item.get("event", ""))
                layers[layer] += 1
                kinds[f"{layer}/{event}"] += 1
                if item.get("peer_steam_id"):
                    peers[str(item["peer_steam_id"])] += 1
                for key in ("remote_endpoint", "local_endpoint"):
                    if item.get(key):
                        endpoints[str(item[key])] += 1
                payload = item.get("payload")
                if payload:
                    payload_events += 1
                    payload_bytes += int(payload.get("length", 0))

    print(f"Session: {paths[0].parent}")
    print(f"Parts:   {len(paths)}")
    print(f"Time:    {first_utc or '-'} -> {last_utc or '-'}")
    print(f"Events:  {sum(layers.values())} ({malformed} malformed lines)")
    print(f"Payload: {payload_events} events, {payload_bytes} bytes")
    print("\nLayers:")
    for name, count in layers.most_common():
        print(f"  {count:8d}  {name}")
    print("\nEvent types:")
    for name, count in kinds.most_common():
        print(f"  {count:8d}  {name}")
    if peers:
        print("\nSteam peers:")
        for name, count in peers.most_common():
            print(f"  {count:8d}  {name}")
    if endpoints:
        print("\nSocket endpoints:")
        for name, count in endpoints.most_common():
            print(f"  {count:8d}  {name}")


if __name__ == "__main__":
    main()
