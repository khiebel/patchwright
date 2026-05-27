"""
Hard guardrails. Same lessons we learned in agentic-ops, reused here.

Three principles:
1. Default dry-run. Connectors must never patch without explicit dry_run=False.
2. Kill switch wins. /tmp/patchwright-halt freezes all action.
3. Rate caps. No more than N patches per hour, M per day, globally.

Plus an extra one for an open-source framework:
4. Authorization signal. The owner must have asserted "I own this device"
   somewhere in their config. We refuse to patch a device we found that
   has no owner_ack entry.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

KILL_SWITCH = Path("/tmp/patchwright-halt")

# Generous defaults; site operator can tighten.
RATE_LIMIT_HOUR = 10
RATE_LIMIT_DAY = 30

STATE_DIR_DEFAULT = Path.home() / ".patchwright" / "state"
RATE_LOG = "rate_log.json"


class HaltedError(Exception):
    """Kill switch on, rate limit hit, or owner ack missing."""


def _ensure(state_dir: Path) -> None:
    state_dir.mkdir(parents=True, exist_ok=True)


def check_kill_switch() -> None:
    if KILL_SWITCH.exists():
        raise HaltedError(f"kill switch on at {KILL_SWITCH}; rm to resume")


def check_rate_limits(state_dir: Path = STATE_DIR_DEFAULT) -> None:
    _ensure(state_dir)
    path = state_dir / RATE_LOG
    log = []
    if path.exists():
        try:
            log = json.loads(path.read_text())
        except Exception:
            log = []
    now = time.time()
    log = [t for t in log if now - t < 86400]
    hour_count = sum(1 for t in log if now - t < 3600)
    if hour_count >= RATE_LIMIT_HOUR:
        raise HaltedError(f"rate cap: {hour_count}/{RATE_LIMIT_HOUR} patches in last hour")
    if len(log) >= RATE_LIMIT_DAY:
        raise HaltedError(f"rate cap: {len(log)}/{RATE_LIMIT_DAY} patches in last 24h")


def record_patch(state_dir: Path = STATE_DIR_DEFAULT) -> None:
    _ensure(state_dir)
    path = state_dir / RATE_LOG
    log = []
    if path.exists():
        try:
            log = json.loads(path.read_text())
        except Exception:
            log = []
    log.append(time.time())
    path.write_text(json.dumps(log))


def check_owner_ack(device_id: str, ack_path: Path) -> None:
    """The patchwright config file must list this device under `owned_devices:`
    before we'll patch it. Forces the user to make a positive assertion of
    ownership rather than letting an LLM agent silently patch a device it
    discovered.
    """
    if not ack_path.exists():
        raise HaltedError(
            f"owner-ack config not found at {ack_path}; create one and list "
            f"`owned_devices: [...]` before patching"
        )
    try:
        import yaml
        cfg = yaml.safe_load(ack_path.read_text()) or {}
    except ImportError:
        raise HaltedError("pyyaml required for owner-ack check")
    owned = (cfg.get("owned_devices") or [])
    if device_id not in owned:
        raise HaltedError(
            f"device {device_id!r} not in owned_devices in {ack_path}; "
            f"refusing to patch a device you haven't claimed ownership of"
        )
