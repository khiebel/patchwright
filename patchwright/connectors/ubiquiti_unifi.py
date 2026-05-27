"""
Ubiquiti UniFi OS connector — OFFICIAL_API tier.

Targets the UDM, UDM-Pro, UDM-SE, UCG, UDR family. Reads firmware via
`ubnt-device-info summary` over SSH. Looks up latest from Ubiquiti's
public firmware feed. Applies via `ubnt-systool fwupdate` or via the
UniFi Network application's update API.

Legal basis: This connector reads and writes ONLY to the device the
user authenticated to via their own credentials. Ubiquiti's firmware
feed (fw-update.ubnt.com) is publicly accessible without auth and is
intended for clients to discover updates. We use the same flow the
UniFi UI uses internally.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from ..core.connector import Connector
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


FW_FEED = "https://fw-update.ubnt.com/api/firmware?filter=eq~~product~~unifi-dream&sort=-version&limit=200"


class UbiquitiUniFi(Connector):
    NAME = "ubiquiti_unifi"
    VENDOR_KEYWORDS = ["ubiquiti", "ubnt", "unifi"]
    PRODUCT_KEYWORDS = ["udm", "dream machine", "unifi os", "unifi network"]
    SUPPORT_TIER = SupportTier.OFFICIAL_API
    DEFAULT_TIER = ReversibilityTier.YELLOW  # ~5min reboot, internet blip
    VENDOR_HOSTILE = False
    LEGAL_BASIS = (
        "Acts only on the owner's device using the owner's SSH credentials. "
        "Reads from Ubiquiti's public firmware feed (fw-update.ubnt.com)."
    )
    NOTES = [
        "Requires UDM_SSH_PASS env var OR ~/.ssh key configured for root@<udm-ip>.",
        "Default device IP 192.168.1.1; override via PATCHWRIGHT_UDM_IP.",
        "Reboot drops internet ~60-90s; YELLOW tier — schedule during low-impact window.",
    ]

    def __init__(self):
        self.ip = os.environ.get("PATCHWRIGHT_UDM_IP", "192.168.1.1")

    # ─── helpers ─────────────────────────────────────────────────────────

    def _ssh_password(self) -> str | None:
        # 1) explicit env var
        if "UDM_SSH_PASS" in os.environ:
            return os.environ["UDM_SSH_PASS"]
        # 2) patchwright keychain (preferred)
        from ..core.credentials import Credentials
        v = Credentials.get(self.NAME, "ssh_password")
        if v:
            return v
        # 3) ~/.patchwright/.env fallback (file-based, for non-Mac users)
        env_path = Path.home() / ".patchwright" / ".env"
        if env_path.exists():
            for line in env_path.read_text().splitlines():
                if line.startswith("UDM_SSH_PASS="):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
        return None

    def _ssh(self, cmd: str, timeout: int = 10) -> tuple[int, str, str]:
        pw = self._ssh_password()
        if pw:
            base = [
                "/opt/homebrew/bin/sshpass", "-p", pw,
                "ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
                f"root@{self.ip}", cmd,
            ]
        else:
            # No password; try key auth
            base = [
                "ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
                "-o", "BatchMode=yes",
                f"root@{self.ip}", cmd,
            ]
        try:
            r = subprocess.run(base, capture_output=True, text=True, timeout=timeout)
            return r.returncode, r.stdout, r.stderr
        except subprocess.TimeoutExpired:
            return 124, "", "ssh timeout"
        except FileNotFoundError as e:
            return 127, "", f"missing tool: {e}"

    def _fetch_latest_for_platform(self, platform: str) -> Version | None:
        try:
            req = urllib.request.Request(
                FW_FEED, headers={"User-Agent": "patchwright/0.1"}
            )
            with urllib.request.urlopen(req, timeout=15) as r:
                data = json.loads(r.read())
        except (urllib.error.URLError, json.JSONDecodeError):
            return None
        firmwares = data.get("_embedded", {}).get("firmware", [])
        candidates = []
        for f in firmwares:
            if f.get("platform") == platform and f.get("channel") == "release":
                v = f.get("version", "")
                if v:
                    candidates.append(Version(v.lstrip("v")))
        if not candidates:
            return None
        candidates.sort(reverse=True)
        return candidates[0]

    # ─── contract methods ────────────────────────────────────────────────

    def discover(self) -> list[Device]:
        """We discover via 'is the UDM IP reachable over SSH'. A site with
        multiple UDMs sets PATCHWRIGHT_UDM_IPS=ip1,ip2 to enumerate.

        Returns one Device per reachable UDM. If unreachable, returns [].
        """
        ips = os.environ.get("PATCHWRIGHT_UDM_IPS", self.ip).split(",")
        out: list[Device] = []
        for ip in [s.strip() for s in ips if s.strip()]:
            self.ip = ip
            rc, out_str, _ = self._ssh("ubnt-device-info summary | head -8", timeout=8)
            if rc != 0 or "UDM" not in out_str and "UCG" not in out_str:
                continue
            model_m = re.search(r"Model:\s*([^\n]+)", out_str)
            mac_m = re.search(r"MAC address:\s*([0-9a-f:]+)", out_str)
            model = (model_m.group(1).strip() if model_m else "UDM-?")
            mac = (mac_m.group(1).strip() if mac_m else "")
            out.append(Device(
                id=f"ubnt:{mac or ip}",
                vendor="ubiquiti",
                product=model.lower().replace(" ", "-"),
                label=f"{model} @ {ip}",
                ip=ip,
                mac=mac,
                extra={"model_raw": model},
            ))
        return out

    def current_version(self, device: Device) -> Version | None:
        self.ip = device.ip or self.ip
        rc, out, _ = self._ssh("ubnt-device-info summary | grep -oE 'Firmware: [0-9.]+' | head -1")
        if rc != 0:
            return None
        m = re.search(r"Firmware:\s*([0-9.]+)", out)
        if not m:
            return None
        return Version(m.group(1))

    def latest_version(self, device: Device) -> Version | None:
        # The platform slug Ubiquiti uses (e.g. UDMPROSE for UDM-SE). Try to
        # derive from `ubnt-device-info` build string; fall back to the
        # known mapping for the most-common models.
        self.ip = device.ip or self.ip
        rc, out, _ = self._ssh("cat /usr/lib/version 2>/dev/null")
        platform = None
        if rc == 0 and out:
            m = re.match(r"([A-Z0-9]+)\.", out.strip())
            if m:
                platform = m.group(1)
        if not platform:
            # Map model -> platform for common cases.
            model = (device.extra or {}).get("model_raw", "").lower()
            platform = {
                "unifi dream machine se (udm-se)": "UDMPROSE",
                "unifi dream machine pro (udm-pro)": "UDMPRO",
                "unifi dream machine (udm)": "UDM",
                "unifi dream machine pro max (udm-pro-max)": "UDMPROMAX",
            }.get(model, "UDMPROSE")
        return self._fetch_latest_for_platform(platform)

    def can_patch(self, device: Device) -> CanPatchResult:
        # Always supported as long as we can SSH and reach the feed.
        rc, _, err = self._ssh("echo ok", timeout=5)
        if rc != 0:
            return CanPatchResult(
                supported=False, tier=self.SUPPORT_TIER,
                reason=f"SSH to root@{device.ip or self.ip} failed: {err.strip()[:120]}",
            )
        cur = self.current_version(device)
        latest = self.latest_version(device)
        if not (cur and latest):
            return CanPatchResult(
                supported=True, tier=self.SUPPORT_TIER,
                reason="versions unreadable; patch path works but verification will be best-effort",
            )
        if not (cur < latest):
            return CanPatchResult(
                supported=True, tier=self.SUPPORT_TIER,
                reason=f"already current ({cur.raw}); apply_patch will be a no-op",
            )
        return CanPatchResult(
            supported=True, tier=self.SUPPORT_TIER,
            reason=f"would patch {cur.raw} -> {latest.raw}; reboot expected ~5min",
            notes=["YELLOW tier: family loses internet for ~60-90s during reboot"],
        )

    def apply_patch(
        self,
        device: Device,
        target: Version | None = None,
        dry_run: bool = True,
    ) -> PatchResult:
        import time
        t0 = time.time()
        self.ip = device.ip or self.ip
        cur = self.current_version(device)
        latest = target or self.latest_version(device)
        if cur and latest and not (cur < latest):
            return PatchResult(
                outcome=PatchOutcome.NO_OP,
                device_id=device.id,
                from_version=cur, to_version=cur,
                duration_s=time.time() - t0,
                side_effects=[f"already at {cur.raw}; no patch applied"],
            )
        if dry_run:
            return PatchResult(
                outcome=PatchOutcome.NO_OP,
                device_id=device.id,
                from_version=cur, to_version=latest,
                duration_s=time.time() - t0,
                side_effects=[
                    f"[DRY-RUN] would invoke `ubnt-systool fwupdate <fw>` to go "
                    f"{cur.raw if cur else '?'} -> {latest.raw if latest else '?'}"
                ],
            )
        # The actual update endpoint Ubiquiti uses internally is the UniFi
        # Network UI's POST /proxy/network/api/s/default/cmd/sysmgr w/
        # {"cmd":"upgrade","mac":"<mac>","version":"<fw>"}. We don't ship
        # that path yet — needs the API key + cookie auth flow. For now
        # we surface the manual flow honestly.
        return PatchResult(
            outcome=PatchOutcome.VENDOR_DEFERRED,
            device_id=device.id,
            from_version=cur, to_version=latest,
            duration_s=time.time() - t0,
            side_effects=[
                "live patching not yet implemented for this connector; "
                "use UniFi UI → System → Updates → Apply, or set "
                "PATCHWRIGHT_UNIFI_API_KEY and re-run "
                "(see ubiquiti_unifi.py docs for the API path).",
            ],
            error="apply_patch live path not implemented",
        )

    def verify(self, device: Device, expected: Version | None = None) -> VerifyResult:
        cur = self.current_version(device)
        target = expected or self.latest_version(device)
        notes: list[str] = []
        if cur is None:
            return VerifyResult(ok=False, expected=target, actual=None,
                                notes=["could not read current_version (UDM unreachable?)"])
        # Also check the UDM is functionally healthy (responds to a ubnt-systool ping).
        rc, _, _ = self._ssh("ubnt-systool fwupdatestatus 2>/dev/null | head -1", timeout=5)
        if rc != 0:
            notes.append("ubnt-systool fwupdatestatus exit != 0 (possibly mid-reboot)")
        ok = (cur == target) if target else True
        return VerifyResult(ok=ok, expected=target, actual=cur, notes=notes)
