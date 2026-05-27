"""
ecobee — OFFICIAL_API tier.

ecobee publishes a documented OAuth-based developer API at
https://www.ecobee.com/home/developer/. We use it to:

  - List the user's thermostats (`/1/thermostat?body={selection:registered}`)
  - Read each thermostat's firmware (`version.thermostatFirmwareVersion`)
  - (Future) trigger a reboot via `/1/thermostat?type=registered`
    `functions:[{type:resetPreferences}]` — but ecobee doesn't expose an
    explicit "check for firmware" call; reboots/cloud-pulls happen on
    ecobee's schedule.

For LOCAL_HACK patch path, the closest thing we can do is force a
ResetPreferences function which causes the thermostat to re-handshake
with ecobee cloud. We document the legal basis: this is the same call
the ecobee mobile app's "Restart" button makes.

Auth: OAuth 2.0 with PIN-based device authorization (one-time setup),
then a refresh_token is stored in patchwright Credentials. Refresh tokens
expire annually; users will be prompted to re-pair.

Legal basis: ecobee publishes a documented developer API and supports
3rd-party clients (`Honeywell Home`, `Google Home`, dozens of community
projects). We use the same flow.

UX:
  $ patchwright login ecobee     # one-time PIN-pair (4-char code → ecobee.com)
  $ patchwright scan             # works thereafter
"""

from __future__ import annotations

import json
import os
import time
import urllib.parse
import urllib.request

from ..core.connector import Connector
from ..core.credentials import Credentials
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


# Kevin's existing ecobee MCP uses this same client_id (the "ecobee API
# 0.5" reference client). For a published patchwright we'd register a new
# client_id with ecobee, but for now we reuse this one to match his existing
# token grant.
DEFAULT_CLIENT_ID = "183eORFPlXyz9BbDZwqexHPBQoVjgadh"
TOKEN_URL = "https://auth.ecobee.com/oauth/token"
API_BASE = "https://api.ecobee.com"
AUDIENCE = "https://prod.ecobee.com/api/v1"


class Ecobee(Connector):
    NAME = "ecobee"
    VENDOR_KEYWORDS = ["ecobee"]
    PRODUCT_KEYWORDS = ["ecobee", "thermostat"]
    SUPPORT_TIER = SupportTier.OFFICIAL_API
    DEFAULT_TIER = ReversibilityTier.YELLOW   # restart resets HVAC briefly
    VENDOR_HOSTILE = False
    LEGAL_BASIS = (
        "ecobee's developer API is public, documented, and supports "
        "3rd-party clients. We use OAuth with the user's own ecobee "
        "credentials to act on the user's own thermostats."
    )
    NOTES = [
        "Credentials: stored refresh_token (no password).",
        "First-time pairing: `patchwright login ecobee` walks the PIN flow.",
        "Firmware versions read via /1/thermostat selection=registered.",
        "Patch path: ecobee pushes updates from cloud on their schedule.",
        "We can trigger a cloud re-check by issuing a ResetPreferences function.",
    ]

    def __init__(self):
        self._access_token: str | None = None
        self._access_expiry: float = 0.0
        # Backward compat: allow env-var override of client_id
        self.client_id = os.environ.get("PATCHWRIGHT_ECOBEE_CLIENT_ID", DEFAULT_CLIENT_ID)

    # ── auth ────────────────────────────────────────────────────────────

    def _refresh_token(self) -> str | None:
        return Credentials.get(self.NAME, "refresh_token")

    def _ensure_access_token(self) -> str | None:
        if self._access_token and time.time() < self._access_expiry - 60:
            return self._access_token
        rt = self._refresh_token()
        if not rt:
            return None
        data = urllib.parse.urlencode({
            "grant_type": "refresh_token",
            "refresh_token": rt,
            "client_id": self.client_id,
            "audience": AUDIENCE,
        }).encode()
        req = urllib.request.Request(
            TOKEN_URL, data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                tok = json.loads(r.read())
        except Exception:
            return None
        self._access_token = tok.get("access_token")
        self._access_expiry = time.time() + tok.get("expires_in", 3600)
        # ecobee rotates refresh tokens on every refresh — store the new one
        new_rt = tok.get("refresh_token")
        if new_rt and new_rt != rt:
            Credentials.set(self.NAME, "refresh_token", new_rt)
        return self._access_token

    def _api_get(self, path: str, body: dict) -> dict | None:
        tok = self._ensure_access_token()
        if not tok:
            return None
        url = f"{API_BASE}{path}?body=" + urllib.parse.quote(json.dumps(body))
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {tok}"})
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return json.loads(r.read())
        except Exception:
            return None

    def _api_post(self, path: str, body: dict) -> dict | None:
        tok = self._ensure_access_token()
        if not tok:
            return None
        url = f"{API_BASE}{path}"
        req = urllib.request.Request(
            url, data=json.dumps(body).encode(),
            headers={"Authorization": f"Bearer {tok}",
                     "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return json.loads(r.read())
        except Exception:
            return None

    # ── contract ────────────────────────────────────────────────────────

    def discover(self) -> list[Device]:
        if not self._refresh_token():
            return []
        data = self._api_get("/1/thermostat", {
            "selection": {
                "selectionType": "registered",
                "selectionMatch": "",
                "includeRuntime": False,
                "includeSettings": False,
                "includeVersion": True,
                "includeEquipmentStatus": False,
            }
        })
        if not data:
            return []
        out: list[Device] = []
        for t in data.get("thermostatList", []):
            tid = t.get("identifier", "")
            name = t.get("name", "")
            model = t.get("modelNumber", "")
            fw = (t.get("version") or {}).get("thermostatFirmwareVersion", "")
            out.append(Device(
                id=f"ecobee:{tid}",
                vendor="ecobee", product=f"thermostat-{model}",
                label=name or f"ecobee {tid[:6]}",
                extra={
                    "identifier": tid,
                    "model_number": model,
                    "firmware": fw,
                },
            ))
        return out

    def current_version(self, device: Device) -> Version | None:
        fw = (device.extra or {}).get("firmware")
        if fw:
            return Version(str(fw))
        # Re-query if missing
        tid = (device.extra or {}).get("identifier")
        if not tid:
            return None
        data = self._api_get("/1/thermostat", {
            "selection": {"selectionType": "thermostats", "selectionMatch": tid,
                          "includeVersion": True}
        })
        if not data:
            return None
        for t in data.get("thermostatList", []):
            v = (t.get("version") or {}).get("thermostatFirmwareVersion")
            if v:
                return Version(str(v))
        return None

    def latest_version(self, device: Device) -> Version | None:
        """ecobee doesn't expose 'latest known firmware' through the API.
        Carried in manifest/ecobee.yaml when known."""
        try:
            import yaml
            from pathlib import Path
            mpath = Path(__file__).resolve().parent.parent.parent / "manifests" / "ecobee.yaml"
            if not mpath.exists():
                return None
            man = yaml.safe_load(mpath.read_text()) or {}
            model = (device.extra or {}).get("model_number", "default")
            latest = man.get(model, {}).get("latest") or man.get("default", {}).get("latest")
            return Version(str(latest)) if latest else None
        except Exception:
            return None

    def can_patch(self, device: Device) -> CanPatchResult:
        if not self._refresh_token():
            return CanPatchResult(
                supported=False, tier=self.SUPPORT_TIER,
                reason="no refresh_token; run `patchwright login ecobee`",
            )
        return CanPatchResult(
            supported=True, tier=self.SUPPORT_TIER,
            reason=(
                "ResetPreferences will re-handshake with ecobee cloud. "
                "Actual firmware push remains on ecobee's schedule."
            ),
            notes=["thermostat is offline ~10s during reset"],
        )

    def apply_patch(
        self,
        device: Device,
        target: Version | None = None,
        dry_run: bool = True,
    ) -> PatchResult:
        t0 = time.time()
        tid = (device.extra or {}).get("identifier")
        cur = self.current_version(device)
        if dry_run:
            return PatchResult(
                outcome=PatchOutcome.NO_OP,
                device_id=device.id,
                from_version=cur, to_version=cur,
                duration_s=time.time() - t0,
                side_effects=[
                    f"[DRY-RUN] would POST resetPreferences function "
                    f"to thermostat {tid}"
                ],
            )
        # Real patch path: resetPreferences forces cloud re-handshake
        body = {
            "selection": {"selectionType": "thermostats", "selectionMatch": tid},
            "functions": [{"type": "resetPreferences"}],
        }
        resp = self._api_post("/1/thermostat?format=json", body)
        time.sleep(60)
        new = self.current_version(device)
        if not resp or resp.get("status", {}).get("code") != 0:
            return PatchResult(
                outcome=PatchOutcome.FAILED,
                device_id=device.id,
                from_version=cur, to_version=new,
                duration_s=time.time() - t0,
                side_effects=[],
                error=f"ecobee API response: {resp}",
            )
        outcome = (PatchOutcome.OK if cur and new and cur < new
                   else PatchOutcome.NO_OP)
        return PatchResult(
            outcome=outcome,
            device_id=device.id,
            from_version=cur, to_version=new,
            duration_s=time.time() - t0,
            side_effects=[
                "resetPreferences function dispatched",
                "thermostat re-handshakes with ecobee cloud",
                f"firmware: {cur.raw if cur else '?'} → {new.raw if new else '?'}",
            ],
        )

    def verify(self, device: Device, expected: Version | None = None) -> VerifyResult:
        cur = self.current_version(device)
        if cur is None:
            return VerifyResult(ok=False, expected=expected, actual=None,
                                notes=["thermostat unreachable post-reset"])
        latest = expected or self.latest_version(device)
        ok = (latest is None) or (cur == latest or latest < cur)
        return VerifyResult(ok=ok, expected=latest, actual=cur)
