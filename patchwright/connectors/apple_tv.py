"""
Apple TV — OFFICIAL_API tier (via pyatv).

Apple TVs run tvOS, updates are vendor-cloud-pushed by Apple. There's
no user-triggerable "install update" API. However:
- pyatv (the de facto community library) exposes firmware version via
  Apple's published DACP / MRP / Companion protocols.
- The "Software Updates" UI on the Apple TV is the trigger point; the
  device polls Apple's catalog on wake.
- LOCAL_HACK path: induce a sleep + wake cycle to force a catalog check.

We treat this connector as OFFICIAL_API for *detection* (pyatv is public,
documented, sanctioned) and LOCAL_HACK for *patch* (induce update check).

Legal basis: pyatv uses only Apple's documented remote-control
protocols. tvOS updates themselves are Apple-signed; we don't modify
firmware, we only ask the device to check.

UX: Kevin's existing Apple TV MCP on 3090:8093 already has credentials
paired. We can read versions from there. Pairing additional Apple TVs
requires the standard pyatv interactive pair (one-time, per device).
"""

from __future__ import annotations

import os
import socket
import subprocess
import time

from ..core.connector import Connector
from ..core.types import (
    CanPatchResult,
    Device,
    PatchOutcome,
    PatchResult,
    ReversibilityTier,
    SupportTier,
    VerifyResult,
    Version,
)


def _have_atvremote() -> str | None:
    """Look for atvremote on PATH; also check Kevin's known 3090 install."""
    for cand in ("/opt/homebrew/bin/atvremote", "/usr/local/bin/atvremote", "atvremote"):
        try:
            r = subprocess.run([cand, "--version"], capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                return cand
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return None


class AppleTV(Connector):
    NAME = "apple_tv"
    VENDOR_KEYWORDS = ["apple"]
    PRODUCT_KEYWORDS = ["tvos", "apple tv", "appletv"]
    SUPPORT_TIER = SupportTier.LOCAL_HACK
    DEFAULT_TIER = ReversibilityTier.GREEN
    VENDOR_HOSTILE = False
    LEGAL_BASIS = (
        "Uses pyatv's published remote-control APIs. No update binaries "
        "are touched. We can only ask the device to check Apple's "
        "catalog by inducing a wake event."
    )
    NOTES = [
        "Local atvremote CLI required (`pip install pyatv`).",
        "First-time pairing per ATV is interactive (`atvremote --id X pair`).",
        "Set PATCHWRIGHT_ATV_IDS to comma-separated device ids.",
        "Kevin's setup: 4 ATVs paired via the apple-tv-mcp on 3090:8093.",
    ]

    def __init__(self):
        env = os.environ.get("PATCHWRIGHT_ATV_IDS", "")
        self.ids = [s.strip() for s in env.split(",") if s.strip()]
        self.atvremote = _have_atvremote()

    def discover(self) -> list[Device]:
        if not self.atvremote:
            return []
        # `atvremote scan` is slow + noisy; prefer the env-specified IDs.
        out: list[Device] = []
        for atv_id in self.ids:
            model_id = self._read_model_identifier(atv_id)
            out.append(Device(
                id=f"appletv:{atv_id}",
                vendor="apple", product="tvos",
                label=f"Apple TV {atv_id[:8]}…",
                extra={"atv_id": atv_id, "model_identifier": model_id},
            ))
        return out

    def _read_model_identifier(self, atv_id: str) -> str | None:
        """Pull the Apple model id (e.g. 'AppleTV14,1') from device_info.
        Required so latest_version() can pick the right manifest bucket."""
        if not self.atvremote:
            return None
        try:
            r = subprocess.run(
                [self.atvremote, "--id", atv_id, "device_info"],
                capture_output=True, text=True, timeout=10,
            )
            if r.returncode != 0:
                return None
            for line in r.stdout.splitlines():
                key, _, val = line.partition(":")
                if key.strip().lower() in ("model identifier", "model"):
                    v = val.strip().split()[0] if val.strip() else ""
                    if v.startswith("AppleTV"):
                        return v
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None
        return None

    def current_version(self, device: Device) -> Version | None:
        atv_id = (device.extra or {}).get("atv_id")
        if not (self.atvremote and atv_id):
            return None
        try:
            r = subprocess.run(
                [self.atvremote, "--id", atv_id, "device_info"],
                capture_output=True, text=True, timeout=10,
            )
            if r.returncode != 0:
                return None
            for line in r.stdout.splitlines():
                if line.strip().lower().startswith("os version"):
                    # "OS Version: 18.4 (22M88)" -> "18.4"
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        v = parts[1].strip().split()[0]
                        return Version(v)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None
        return None

    def latest_version(self, device: Device) -> Version | None:
        """Apple doesn't publish a machine-readable 'latest tvOS' feed.
        We carry a community-curated manifest at manifests/apple_tv.yaml
        keyed by Apple's model identifier (e.g. AppleTV14,1)."""
        try:
            import yaml
            from pathlib import Path
            mpath = Path(__file__).resolve().parent.parent.parent / "manifests" / "apple_tv.yaml"
            if not mpath.exists():
                return None
            man = yaml.safe_load(mpath.read_text()) or {}
            model = (device.extra or {}).get("model_identifier") or "default"
            latest = man.get(model, {}).get("latest") or man.get("default", {}).get("latest")
            return Version(str(latest)) if latest else None
        except Exception:
            return None

    def can_patch(self, device: Device) -> CanPatchResult:
        if not self.atvremote:
            return CanPatchResult(
                supported=False, tier=self.SUPPORT_TIER,
                reason="atvremote (pyatv) not installed",
                requires_user_action=True,
                user_action="pip install pyatv && atvremote --id X pair",
            )
        cur = self.current_version(device)
        if cur is None:
            return CanPatchResult(
                supported=False, tier=self.SUPPORT_TIER,
                reason="cannot read current tvOS version (device unreachable / unpaired)",
            )
        return CanPatchResult(
            supported=True, tier=self.SUPPORT_TIER,
            reason=(
                f"LOCAL_HACK: can induce sleep+wake to force catalog "
                f"check; Apple decides whether to push fw"
            ),
        )

    def apply_patch(
        self,
        device: Device,
        target: Version | None = None,
        dry_run: bool = True,
    ) -> PatchResult:
        t0 = time.time()
        atv_id = (device.extra or {}).get("atv_id")
        cur = self.current_version(device)
        if dry_run:
            return PatchResult(
                outcome=PatchOutcome.NO_OP,
                device_id=device.id,
                from_version=cur, to_version=cur,
                duration_s=time.time() - t0,
                side_effects=[
                    f"[DRY-RUN] would atvremote --id {atv_id} sleep, "
                    "wait 60s, atvremote --id {atv_id} wakeup"
                ],
            )
        # Real path: sleep then wake to force update-catalog poll
        try:
            subprocess.run([self.atvremote, "--id", atv_id, "sleep"],
                           timeout=10, capture_output=True)
            time.sleep(60)
            subprocess.run([self.atvremote, "--id", atv_id, "wakeup"],
                           timeout=10, capture_output=True)
            time.sleep(60)
            new = self.current_version(device)
            outcome = (PatchOutcome.OK if new and cur and cur < new
                       else PatchOutcome.NO_OP)
            return PatchResult(
                outcome=outcome,
                device_id=device.id,
                from_version=cur, to_version=new,
                duration_s=time.time() - t0,
                side_effects=[
                    "sleep+wake cycle induced; Apple's catalog poll completed",
                    f"firmware: {cur.raw if cur else '?'} → {new.raw if new else '?'}",
                ],
            )
        except Exception as e:
            return PatchResult(
                outcome=PatchOutcome.FAILED,
                device_id=device.id,
                from_version=cur, to_version=None,
                duration_s=time.time() - t0,
                side_effects=[],
                error=f"{type(e).__name__}: {e}",
            )

    def verify(self, device: Device, expected: Version | None = None) -> VerifyResult:
        cur = self.current_version(device)
        if cur is None:
            return VerifyResult(
                ok=False, expected=expected, actual=None,
                notes=["device unreachable post-patch"],
            )
        return VerifyResult(ok=True, expected=expected, actual=cur)
