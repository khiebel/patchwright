"""
Shared data types for patchwright.

Kept dataclass-only and stdlib-only on purpose. Connectors should reach for
these types instead of inventing parallel ones — and the framework itself
should never depend on a specific connector's internals.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class SupportTier(str, Enum):
    """How nicely the vendor cooperates with patching."""

    OFFICIAL_API = "OFFICIAL_API"      # vendor publishes a documented update API
    REVERSED_API = "REVERSED_API"      # we replay calls captured from the vendor's app
    LOCAL_HACK = "LOCAL_HACK"          # cloud-pushed updates triggered by inducing device state
    MANUAL_ONLY = "MANUAL_ONLY"        # we can only detect + tell the user what to do
    UNSUPPORTED = "UNSUPPORTED"        # not even detection works yet


class ReversibilityTier(str, Enum):
    """Same tier system as agentic-ops, for action friction."""

    GREEN = "GREEN"      # trivially reversible, no user impact
    YELLOW = "YELLOW"    # disruptive but reversible (firmware update with rollback)
    RED = "RED"          # hard to reverse (factory reset, cert rotation)


class PatchOutcome(str, Enum):
    OK = "ok"
    NO_OP = "no_op"
    FAILED = "failed"
    PARTIAL = "partial"
    VENDOR_DEFERRED = "vendor_deferred"  # we triggered, vendor will push when ready
    AWAITING_REBOOT = "awaiting_reboot"


@dataclass
class Version:
    """A device firmware version.

    Comparison is semver-aware: equal if the same semantic parts match
    (e.g. 5.1.12 == 5.1.12+a10f0a5 — same numeric version, different
    build hash). Build metadata (after '+') is ignored for ordering.

    Falls back to string compare if no numeric parts can be extracted.
    """

    raw: str
    parts: tuple[int, ...] = ()

    def __post_init__(self):
        if not self.parts and self.raw:
            # Strip semver build metadata (+xxxx) before extracting parts
            clean = self.raw.split("+", 1)[0]
            self.parts = tuple(_extract_ints(clean))

    def __lt__(self, other: "Version") -> bool:
        if self.parts and other.parts:
            return self.parts < other.parts
        return self.raw < other.raw

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return False
        if self.parts and other.parts:
            return self.parts == other.parts
        return self.raw == other.raw

    def __hash__(self) -> int:
        return hash(self.parts) if self.parts else hash(self.raw)

    def __repr__(self) -> str:
        return f"Version({self.raw!r})"


def _extract_ints(s: str) -> list[int]:
    """Grab dot/dash-separated integer runs from a version string."""
    out: list[int] = []
    cur = ""
    for c in s:
        if c.isdigit():
            cur += c
        else:
            if cur:
                out.append(int(cur))
                cur = ""
    if cur:
        out.append(int(cur))
    return out


@dataclass
class Device:
    """A device on the network we want to manage."""

    id: str                          # stable identifier; ip:port or mac or vendor:serial
    vendor: str                      # "ubiquiti", "apple", "signify", "chargepoint", ...
    product: str                     # "udm-se", "macos", "wiz-bulb", ...
    label: str = ""                  # human-friendly ("Kevin's Mac", "Living Room Bulb")
    ip: str = ""
    mac: str = ""
    extra: dict[str, Any] = field(default_factory=dict)  # connector-specific bag


@dataclass
class CanPatchResult:
    """Can this connector actually patch this device right now?"""

    supported: bool
    tier: SupportTier
    reason: str = ""                 # human-readable why-or-why-not
    requires_user_action: bool = False
    user_action: str = ""            # if requires_user_action: what to do
    notes: list[str] = field(default_factory=list)


@dataclass
class PatchResult:
    outcome: PatchOutcome
    device_id: str
    from_version: Version | None
    to_version: Version | None
    duration_s: float
    side_effects: list[str] = field(default_factory=list)
    rollback_id: str = ""             # opaque token a future rollback() can use
    error: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class VerifyResult:
    ok: bool
    expected: Version | None
    actual: Version | None
    notes: list[str] = field(default_factory=list)


@dataclass
class RollbackResult:
    outcome: PatchOutcome             # OK / FAILED / NO_OP (not supported)
    notes: list[str] = field(default_factory=list)
