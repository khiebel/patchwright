"""
Orchestrator — pulls connectors together into the detect→plan→verify→report loop.

This is intentionally NOT an LLM-driven planner — that's a layer above
patchwright (e.g. agentic-ops talks TO patchwright). The orchestrator
just sequences connector calls and writes receipts.

Decoupling matters: someone running patchwright as a plain CLI tool
should not need an LLM to use it.
"""

from __future__ import annotations

import importlib
import pkgutil
import time
from dataclasses import asdict
from pathlib import Path

from .connector import Connector
from .types import (
    CanPatchResult,
    Device,
    PatchOutcome,
    PatchResult,
    SupportTier,
    VerifyResult,
    Version,
)
from . import safety, receipts


def load_connectors(package_name: str = "patchwright.connectors") -> list[Connector]:
    """Import every module in the connectors package and instantiate
    any Connector subclass declared at top level."""
    pkg = importlib.import_module(package_name)
    out: list[Connector] = []
    for finder, mod_name, ispkg in pkgutil.iter_modules(pkg.__path__):
        if mod_name.startswith("_"):
            continue
        full = f"{package_name}.{mod_name}"
        mod = importlib.import_module(full)
        for attr in dir(mod):
            cls = getattr(mod, attr)
            if (
                isinstance(cls, type)
                and issubclass(cls, Connector)
                and cls is not Connector
                and getattr(cls, "NAME", "")
            ):
                try:
                    out.append(cls())
                except Exception as e:
                    receipts.write("orchestrator.connector_init_failed",
                                   {"connector": cls.NAME, "error": str(e)})
    return out


def scan_all(connectors: list[Connector]) -> dict[str, list[Device]]:
    """Discover devices across every connector. Returns name → [Device]."""
    out: dict[str, list[Device]] = {}
    for c in connectors:
        try:
            devs = c.discover()
        except Exception as e:
            receipts.write("orchestrator.discover_failed",
                           {"connector": c.NAME, "error": str(e)})
            devs = []
        out[c.NAME] = devs
    return out


def check_one(connector: Connector, device: Device) -> dict:
    """Per-device: current vs latest, plus can_patch verdict.

    Returns a dict suitable for the CLI / dashboard, also written to receipts.
    """
    record = {
        "connector": connector.NAME,
        "device_id": device.id,
        "device_label": device.label or device.id,
        "vendor": device.vendor,
        "product": device.product,
        "current": None,
        "latest": None,
        "needs_patch": None,
        "can_patch": None,
    }
    try:
        cur = connector.current_version(device)
        record["current"] = cur.raw if cur else None
    except Exception as e:
        record["current_error"] = str(e)
        cur = None

    try:
        latest = connector.latest_version(device)
        record["latest"] = latest.raw if latest else None
    except Exception as e:
        record["latest_error"] = str(e)
        latest = None

    if cur and latest:
        record["needs_patch"] = cur < latest

    try:
        cp = connector.can_patch(device)
        record["can_patch"] = {
            "supported": cp.supported,
            "tier": cp.tier.value,
            "reason": cp.reason,
            "requires_user_action": cp.requires_user_action,
            "user_action": cp.user_action,
        }
    except Exception as e:
        record["can_patch_error"] = str(e)

    receipts.write("check", record)
    return record


def patch_one(
    connector: Connector,
    device: Device,
    target: Version | None = None,
    dry_run: bool = True,
    owner_ack_path: Path | None = None,
) -> PatchResult:
    """Apply a patch with guardrails. Default dry_run=True — caller must
    explicitly pass dry_run=False to actually push a firmware change."""
    safety.check_kill_switch()
    if not dry_run:
        safety.check_rate_limits()
        if owner_ack_path is not None:
            safety.check_owner_ack(device.id, owner_ack_path)

    rid = receipts.new_id()
    receipts.write("patch.start", {
        "receipt_id": rid,
        "connector": connector.NAME,
        "device_id": device.id,
        "target": target.raw if target else None,
        "dry_run": dry_run,
    })

    t0 = time.time()
    try:
        result = connector.apply_patch(device, target=target, dry_run=dry_run)
    except Exception as e:
        result = PatchResult(
            outcome=PatchOutcome.FAILED,
            device_id=device.id,
            from_version=None,
            to_version=None,
            duration_s=time.time() - t0,
            error=f"{type(e).__name__}: {e}",
        )

    receipts.write("patch.done", {
        "receipt_id": rid,
        "connector": connector.NAME,
        "device_id": device.id,
        "result": asdict(result),
    })

    if not dry_run and result.outcome == PatchOutcome.OK:
        safety.record_patch()

    return result


def verify_one(connector: Connector, device: Device, expected: Version | None) -> VerifyResult:
    try:
        return connector.verify(device, expected=expected)
    except Exception as e:
        return VerifyResult(ok=False, expected=expected, actual=None,
                            notes=[f"verify error: {type(e).__name__}: {e}"])
