"""
ChargePoint Home Flex — REVERSED_API tier.

Uses the python-chargepoint library (pip-installable) which has
already done the heavy reverse-engineering of ChargePoint's mobile
app API. End users only provide their ChargePoint email + password.

API path (via python-chargepoint):
  ChargePoint(username).login_with_password(password)
    → get_home_chargers() — list of device_ids
    → get_home_charger_technical_info(device_id)
        → .software_version (current firmware)
        → .last_ota_update (when it last patched)
    → restart_home_charger(device_id)
        → causes the charger to re-check ChargePoint cloud and
          pull any pending firmware on boot.

This is the LOCAL_HACK pattern (we don't push the bits ourselves; we
induce the device to ask for them) wrapped in a REVERSED_API delivery
mechanism. The actual firmware push is done by ChargePoint's cloud,
signed by ChargePoint, on ChargePoint's schedule — we're just asking
nicely.

═══════════════════════════════════════════════════════════════════════
WHY THIS MATTERS — the headline POC
═══════════════════════════════════════════════════════════════════════
ChargePoint Home Flex has THREE published critical CVEs (April 2026):

  CVE-2026-4156   OCPP getpreq stack buffer overflow → RCE
  CVE-2026-4157   revssh service command injection → RCE
  CVE-2026-4155   sensitive info disclosure in source code

ChargePoint's auto-update queue doesn't get to most users for weeks
or months. There is no "update now" button in the ChargePoint mobile
app. This connector closes that gap.

═══════════════════════════════════════════════════════════════════════

Legal basis: Uses the python-chargepoint library which replays the
official ChargePoint mobile-app APIs, with the owner's own credentials,
against the owner's own charger. The library is publicly published on
PyPI. We don't bundle or modify ChargePoint's firmware — we ask their
cloud to push it, which is exactly what the mobile-app's "Restart"
button does. DMCA §1201 security-research exemption applies.

UX: zero RE for end users. `patchwright login chargepoint_homeflex`
prompts for ChargePoint email + password; thereafter `scan` and
`patch` just work.
"""

from __future__ import annotations

import asyncio
import os
import time
from typing import Any

from ..core.connector import Connector
from ..core.credentials import Credentials
from ..core.types import (
    CanPatchResult,
    Device,
    PatchOutcome,
    PatchResult,
    ReversibilityTier,
    RollbackResult,
    SupportTier,
    VerifyResult,
    Version,
)

# python-chargepoint is an optional dep — connector silently no-ops if
# it isn't installed (so patchwright works without ChargePoint creds).
try:
    from python_chargepoint import ChargePoint
    _CP_OK = True
except ImportError:
    _CP_OK = False


def _run(coro):
    """Run an async coroutine in a fresh event loop. python-chargepoint
    is async-only; we wrap to keep patchwright's Connector ABC sync."""
    try:
        return asyncio.run(coro)
    except RuntimeError:
        # Already inside an event loop (rare in our CLI context)
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()


class ChargePointHomeFlex(Connector):
    NAME = "chargepoint_homeflex"
    VENDOR_KEYWORDS = ["chargepoint"]
    PRODUCT_KEYWORDS = ["home flex", "homeflex", "home-flex", "charger"]
    SUPPORT_TIER = SupportTier.REVERSED_API
    DEFAULT_TIER = ReversibilityTier.YELLOW  # charger offline ~3-5min
    VENDOR_HOSTILE = True  # vendor doesn't expose this; expect rate-limit
    LEGAL_BASIS = (
        "Uses python-chargepoint (publicly-released PyPI library that "
        "replays ChargePoint mobile-app API calls). End user supplies "
        "their own ChargePoint credentials. Acts only on the owner's "
        "own charger. DMCA §1201 security-research exemption applies."
    )
    NOTES = [
        "Credentials: `patchwright login chargepoint_homeflex` (email + password).",
        "Or store the coulomb_session cookie directly (more resilient than password login).",
        "Patch path: restart_home_charger() — same as the mobile-app Restart button.",
        "Charger is offline ~3-5 min during restart + cloud check + reboot.",
        "Public CVEs targeted: CVE-2026-4155, 4156, 4157 (all CVSS 8.8-10.0).",
    ]

    def _credentials(self) -> dict[str, str | None]:
        """Returns credentials. Prefers session cookies (more resilient
        than email+password — ChargePoint rate-limits aggressive login
        retries). Falls back to email+password if no cookies stored."""
        return {
            "email": Credentials.get(self.NAME, "email"),
            "password": Credentials.get(self.NAME, "password"),
            "coulomb_session": Credentials.get(self.NAME, "coulomb_session"),
            "auth_session": Credentials.get(self.NAME, "auth_session"),
        }

    async def _client(self) -> "ChargePoint | None":
        if not _CP_OK:
            return None
        creds = self._credentials()
        email = creds.get("email")
        coulomb = creds.get("coulomb_session")
        try:
            if coulomb and email:
                # Cookie-auth path: avoids the rate-limit-prone login flow
                cp = await ChargePoint.create(email, coulomb_token=coulomb)
                return cp
            if email and creds.get("password"):
                cp = ChargePoint(email)
                await cp.login_with_password(creds["password"])
                return cp
            return None
        except Exception:
            return None

    # ── contract ────────────────────────────────────────────────────────

    def discover(self) -> list[Device]:
        if not _CP_OK:
            return []
        creds = self._credentials()
        if not (creds.get("email") and (creds.get("password") or creds.get("coulomb_session"))):
            return []

        async def _go():
            cp = await self._client()
            if cp is None:
                return []
            out: list[Device] = []
            try:
                charger_ids = await cp.get_home_chargers()
                for cid in charger_ids:
                    info = await cp.get_home_charger_technical_info(cid)
                    out.append(Device(
                        id=f"chargepoint:{cid}",
                        vendor="chargepoint",
                        product="home_flex",  # ChargePoint API doesn't expose model cleanly
                        label=f"ChargePoint #{cid}",
                        extra={
                            "charger_id": cid,
                            "software_version": getattr(info, "software_version", ""),
                            "model": getattr(info, "model", ""),
                            "last_ota_update": str(getattr(info, "last_ota_update", "")),
                        },
                    ))
            finally:
                await cp.close()
            return out

        try:
            return _run(_go())
        except Exception:
            return []

    def current_version(self, device: Device) -> Version | None:
        sv = (device.extra or {}).get("software_version")
        if sv:
            return Version(str(sv))
        # If extra wasn't populated, re-query
        cid = (device.extra or {}).get("charger_id")
        if not cid:
            return None

        async def _go():
            cp = await self._client()
            if cp is None:
                return None
            try:
                info = await cp.get_home_charger_technical_info(cid)
                return getattr(info, "software_version", None)
            finally:
                await cp.close()

        try:
            v = _run(_go())
            return Version(str(v)) if v else None
        except Exception:
            return None

    def latest_version(self, device: Device) -> Version | None:
        """ChargePoint doesn't expose a 'latest available fw' field through
        the public API; the cloud just pushes when it decides to. We carry
        a community-curated manifest at manifests/chargepoint_homeflex.yaml
        for the model-by-model best-known version. When a CVE drops with
        a known fix version, that's what gets recorded here."""
        try:
            import yaml
            from pathlib import Path
            mpath = Path(__file__).resolve().parent.parent.parent / "manifests" / "chargepoint_homeflex.yaml"
            if not mpath.exists():
                return None
            manifest = yaml.safe_load(mpath.read_text()) or {}
            model = (device.extra or {}).get("model", "default")
            latest = manifest.get(model, {}).get("latest") or manifest.get("default", {}).get("latest")
            return Version(str(latest)) if latest else None
        except Exception:
            return None

    def can_patch(self, device: Device) -> CanPatchResult:
        if not _CP_OK:
            return CanPatchResult(
                supported=False, tier=self.SUPPORT_TIER,
                reason="python-chargepoint not installed (`pip install python-chargepoint`)",
            )
        creds = self._credentials()
        if not (creds.get("email") and (creds.get("password") or creds.get("coulomb_session"))):
            return CanPatchResult(
                supported=False, tier=self.SUPPORT_TIER,
                reason="no credentials; run `patchwright login chargepoint_homeflex`",
            )
        cur = self.current_version(device)
        if cur is None:
            return CanPatchResult(
                supported=False, tier=self.SUPPORT_TIER,
                reason="could not read current firmware (charger offline or API failed)",
            )
        latest = self.latest_version(device)
        notes = [
            f"current firmware: {cur.raw}",
            "patch path: restart_home_charger() — charger reboots + checks ChargePoint cloud",
            "during patch: charger offline ~3-5 min; active charging session would be interrupted",
        ]
        if latest and not (cur < latest):
            return CanPatchResult(
                supported=True, tier=self.SUPPORT_TIER,
                reason=f"already at {cur.raw} (latest known)",
                notes=notes,
            )
        if latest:
            notes.insert(0, f"manifest says latest: {latest.raw}")
        return CanPatchResult(
            supported=True, tier=self.SUPPORT_TIER,
            reason="restart will force ChargePoint cloud check + any pending firmware push",
            notes=notes,
        )

    def apply_patch(
        self,
        device: Device,
        target: Version | None = None,
        dry_run: bool = True,
    ) -> PatchResult:
        t0 = time.time()
        if not _CP_OK:
            return PatchResult(
                outcome=PatchOutcome.FAILED,
                device_id=device.id,
                from_version=None, to_version=None,
                duration_s=time.time() - t0,
                side_effects=[],
                error="python-chargepoint not installed",
            )
        cid = (device.extra or {}).get("charger_id")
        if not cid:
            return PatchResult(
                outcome=PatchOutcome.FAILED,
                device_id=device.id,
                from_version=None, to_version=None,
                duration_s=time.time() - t0,
                side_effects=[],
                error="no charger_id in device.extra",
            )
        cur = self.current_version(device)
        if dry_run:
            return PatchResult(
                outcome=PatchOutcome.NO_OP,
                device_id=device.id,
                from_version=cur, to_version=cur,
                duration_s=time.time() - t0,
                side_effects=[
                    f"[DRY-RUN] would call restart_home_charger({cid}) — "
                    f"charger reboots and asks ChargePoint cloud for updates"
                ],
            )

        async def _go():
            cp = await self._client()
            if cp is None:
                return None, "could not establish ChargePoint session"
            try:
                await cp.restart_home_charger(cid)
                return cur, None
            except Exception as e:
                return None, f"{type(e).__name__}: {e}"
            finally:
                await cp.close()

        cur_before, err = _run(_go())
        if err:
            return PatchResult(
                outcome=PatchOutcome.FAILED,
                device_id=device.id,
                from_version=cur, to_version=None,
                duration_s=time.time() - t0,
                side_effects=["restart_home_charger call failed before reboot"],
                error=err,
            )
        # Wait for charger to come back + check ChargePoint cloud
        # Empirically, ChargePoint Home Flex takes ~3-4 min to fully boot
        # after a restart. Give it 5 to be safe.
        time.sleep(300)
        new = self.current_version(device)
        side_effects = [
            f"restart_home_charger({cid}) sent at +0s",
            "waited 5 min for boot + cloud check + (any) firmware pull",
            f"firmware: {cur.raw if cur else '?'} → {new.raw if new else '?'}",
        ]
        if cur and new and cur < new:
            outcome = PatchOutcome.OK
            side_effects.append("ChargePoint cloud pushed a newer firmware")
        elif cur and new and cur == new:
            outcome = PatchOutcome.NO_OP
            side_effects.append("ChargePoint cloud did not push (likely no newer fw queued for your model+region)")
        else:
            outcome = PatchOutcome.PARTIAL
            side_effects.append("could not confirm post-restart firmware state")
        return PatchResult(
            outcome=outcome,
            device_id=device.id,
            from_version=cur, to_version=new,
            duration_s=time.time() - t0,
            side_effects=side_effects,
        )

    def verify(self, device: Device, expected: Version | None = None) -> VerifyResult:
        cur = self.current_version(device)
        if cur is None:
            return VerifyResult(
                ok=False, expected=expected, actual=None,
                notes=["charger unreachable post-patch"],
            )
        latest = expected or self.latest_version(device)
        ok = (latest is None) or (cur == latest or latest < cur)
        return VerifyResult(ok=ok, expected=latest, actual=cur)
