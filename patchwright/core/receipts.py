"""
Append-only patch receipts.

Every patch (and every refused patch) gets one row. Local JSONL is the
authoritative store; downstream sinks (DDB, S3, web dashboard) consume
the JSONL.

Receipts are the trust-building mechanism for an open-source IoT
patching tool. The owner needs to be able to look at the log and see
exactly what the framework did to their device, in what order, with
what result. No silent retries. No mystery state.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_DIR = Path.home() / ".patchwright" / "receipts"


def _normalize(v: Any) -> Any:
    if is_dataclass(v) and not isinstance(v, type):
        return {k: _normalize(x) for k, x in asdict(v).items()}
    if isinstance(v, dict):
        return {k: _normalize(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_normalize(x) for x in v]
    return v


def new_id() -> str:
    return f"pw-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}"


def write(stage: str, payload: dict, dest_dir: Path = DEFAULT_DIR) -> str:
    dest_dir.mkdir(parents=True, exist_ok=True)
    rid = payload.get("receipt_id") or new_id()
    row = {
        "receipt_id": rid,
        "stage": stage,
        "ts": datetime.now(timezone.utc).isoformat(),
        **_normalize(payload),
    }
    with (dest_dir / "patches.jsonl").open("a") as f:
        f.write(json.dumps(row, default=str) + "\n")
    return rid


def recent(limit: int = 20, dest_dir: Path = DEFAULT_DIR) -> list[dict]:
    path = dest_dir / "patches.jsonl"
    if not path.exists():
        return []
    lines = path.read_text().splitlines()
    return [json.loads(line) for line in lines[-limit:]]
