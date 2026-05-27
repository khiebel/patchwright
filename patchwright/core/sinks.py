"""
Pluggable result sinks. Each connector check / patch produces a row;
sinks decide where rows go (stdout, jsonl, DDB hiebel-events, Slack, …).

Default sinks: stdout (for CLI) + receipts/patches.jsonl.

The hiebel-events DDB sink is opt-in via env or config so patchwright
stays bus-agnostic by default. When enabled, it writes
  system=patchwright device=<connector> event=<check|patch>
rows that vulns.hiebel.ai already knows how to render.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, is_dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

try:
    import boto3
    _BOTO_OK = True
except ImportError:
    _BOTO_OK = False


def _normalize(v: Any) -> Any:
    if is_dataclass(v) and not isinstance(v, type):
        return {k: _normalize(x) for k, x in asdict(v).items()}
    if isinstance(v, dict):
        return {k: _normalize(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_normalize(x) for x in v]
    return v


class Sink:
    name = "base"

    def emit(self, stage: str, payload: dict) -> None:
        raise NotImplementedError


class StdoutSink(Sink):
    name = "stdout"

    def emit(self, stage: str, payload: dict) -> None:
        p = _normalize(payload)
        # One compact line per event for CLI grepability.
        kv = " ".join(f"{k}={v!r}" for k, v in p.items() if k in
                      ("connector", "device_id", "current", "latest",
                       "needs_patch", "outcome", "result"))
        print(f"[{stage}] {kv}")


class JsonlSink(Sink):
    name = "jsonl"

    def __init__(self, path: Path | None = None):
        self.path = path or (Path.home() / ".patchwright" / "scans.jsonl")

    def emit(self, stage: str, payload: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        row = {
            "stage": stage,
            "ts": datetime.now(timezone.utc).isoformat(),
            **_normalize(payload),
        }
        with self.path.open("a") as f:
            f.write(json.dumps(row, default=str) + "\n")


class HiebelEventsSink(Sink):
    """Writes to the unified hiebel-events DDB so vulns.hiebel.ai surfaces it.

    Schema:
      pk = "patchwright"
      sk = <iso-ts>#<connector>#<device_id>
      system = "patchwright"
      device = <connector name>
      event = stage ("check" | "patch.start" | "patch.done" | "verify")
      detail = json blob (subset of the payload, ≤2KB)
    """
    name = "hiebel-events"

    def __init__(self, table_name: str = "hiebel-events", region: str = "us-east-1"):
        if not _BOTO_OK:
            raise RuntimeError("boto3 not available; install it for HiebelEventsSink")
        self.table = boto3.resource("dynamodb", region_name=region).Table(table_name)

    def emit(self, stage: str, payload: dict) -> None:
        n = datetime.now(timezone.utc)
        connector = payload.get("connector", "patchwright")
        device_id = payload.get("device_id", "")
        # Trim detail aggressively to keep DDB row small
        detail = json.dumps(_normalize(payload), default=str)[:2000]
        try:
            self.table.put_item(Item={
                "pk": f"patchwright#{connector}",
                "sk": n.isoformat() + "#" + (device_id or "noid"),
                "system": "patchwright",
                "device": connector,
                "device_id": device_id,
                "event": stage,
                "detail": detail,
                "timestamp": n.isoformat(),
                "date": n.strftime("%Y-%m-%d"),
                "ttl": int((n + timedelta(days=180)).timestamp()),
            })
        except Exception as e:
            # Best-effort sink — never crash the scan if DDB is unreachable.
            print(f"[hiebel-events sink] put_item failed: {e}")


# ── orchestration ────────────────────────────────────────────────────


class SinkSet:
    """Fan-out emitter. Used by the orchestrator to send to all configured
    sinks with one call."""

    def __init__(self, sinks: list[Sink] | None = None):
        self.sinks: list[Sink] = sinks or []

    def add(self, sink: Sink) -> None:
        self.sinks.append(sink)

    def emit(self, stage: str, payload: dict) -> None:
        for s in self.sinks:
            try:
                s.emit(stage, payload)
            except Exception as e:
                print(f"[sink {s.name}] emit failed: {e}")

    @classmethod
    def from_env(cls) -> "SinkSet":
        """Build a SinkSet from env flags. Convenience for the CLI.

        env:
          PATCHWRIGHT_SINK_STDOUT=1     (default on)
          PATCHWRIGHT_SINK_JSONL=1      (default on)
          PATCHWRIGHT_SINK_HIEBEL=1     (default off — flip on to feed vulns.hiebel.ai)
        """
        ss = cls()
        if os.environ.get("PATCHWRIGHT_SINK_STDOUT", "1") == "1":
            ss.add(StdoutSink())
        if os.environ.get("PATCHWRIGHT_SINK_JSONL", "1") == "1":
            ss.add(JsonlSink())
        if os.environ.get("PATCHWRIGHT_SINK_HIEBEL", "0") == "1" and _BOTO_OK:
            try:
                ss.add(HiebelEventsSink())
            except Exception as e:
                print(f"[sinks] could not init hiebel-events sink: {e}")
        return ss
