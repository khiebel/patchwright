"""
Signify WiZ Connected — LOCAL_HACK tier.

WiZ Wi-Fi smart bulbs/strips speak a JSON-RPC-over-UDP protocol on port
38899 that the official WiZ mobile app uses for direct local control. The
bulb's firmware is cloud-managed by Signify (Philips); end users have NO
official way to trigger an update. But the bulb DOES poll the Signify
cloud after a reboot or factory-reset, and IT WILL pull a newer firmware
if one is available.

This connector therefore implements a LOCAL_HACK patch path: query
firmware over UDP, compare to a community-curated "known latest" table,
and if behind, induce the bulb to reboot (via `restart` or by setting
state off then on) so it checks the cloud and pulls the update on
re-boot. We then re-query to confirm.

Legal basis: We only talk to bulbs on the local network using the bulb's
own published UDP protocol. We do not access Signify's cloud, do not
reverse-engineer their app, and do not bypass any authentication. The
patch is applied BY THE BULB, from Signify's own cloud, on Signify's
schedule — we're just persuading the bulb to ask.

UX: zero credentials required. Plug in the bulb, run `patchwright scan`,
done.
"""

from __future__ import annotations

import json
import socket
import time
from typing import Any

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


WIZ_PORT = 38899
WIZ_TIMEOUT = 2.0


_WIZ_MANIFEST: dict | None = None


def _load_wiz_manifest() -> dict:
    """Load patchwright/manifests/signify_wiz.yaml. Cached after first read."""
    global _WIZ_MANIFEST
    if _WIZ_MANIFEST is not None:
        return _WIZ_MANIFEST
    try:
        import yaml
        from pathlib import Path
        # manifest lives next to the patchwright/ package
        path = Path(__file__).resolve().parent.parent.parent / "manifests" / "signify_wiz.yaml"
        if not path.exists():
            _WIZ_MANIFEST = {}
            return _WIZ_MANIFEST
        _WIZ_MANIFEST = yaml.safe_load(path.read_text()) or {}
    except Exception:
        _WIZ_MANIFEST = {}
    return _WIZ_MANIFEST


def _udp_call(ip: str, method: str, params: dict | None = None,
              timeout: float = WIZ_TIMEOUT) -> dict | None:
    payload = json.dumps({"method": method, "params": params or {}}).encode()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(payload, (ip, WIZ_PORT))
        data, _ = s.recvfrom(4096)
        return json.loads(data.decode())
    except (socket.timeout, json.JSONDecodeError, OSError):
        return None
    finally:
        s.close()


class SignifyWiz(Connector):
    NAME = "signify_wiz"
    VENDOR_KEYWORDS = ["signify", "philips", "wiz"]
    PRODUCT_KEYWORDS = ["wiz"]
    SUPPORT_TIER = SupportTier.LOCAL_HACK
    DEFAULT_TIER = ReversibilityTier.GREEN  # bulb is dark for ~30s
    VENDOR_HOSTILE = False
    LEGAL_BASIS = (
        "Uses ONLY the WiZ bulb's own published UDP control protocol on "
        "the local network. No cloud access, no reverse engineering of "
        "Signify's mobile app, no auth bypass. Update is fetched BY the "
        "bulb from Signify's cloud, on Signify's terms."
    )
    NOTES = [
        "Discovery: broadcast `getPilot` to the LAN. Set PATCHWRIGHT_WIZ_SUBNETS "
        "to override (default: 192.168.1.0/24).",
        "Patch path: reboot the bulb via `restart` method; bulb re-checks "
        "Signify cloud on boot and pulls newer fw if Signify is offering it.",
        "If Signify hasn't published a fix yet, this is a NO_OP.",
        "Some old WiZ FW (< 1.21) doesn't expose `restart`; fallback is "
        "setPilot off then on after 20s pause.",
    ]

    def __init__(self):
        import os
        self.subnets = (os.environ.get("PATCHWRIGHT_WIZ_SUBNETS",
                                       "192.168.1.0/24")).split(",")

    # ── helpers ──────────────────────────────────────────────────────────

    def _scan_subnet(self, subnet: str) -> list[str]:
        """Return IPs that responded to `getDevInfo`."""
        import ipaddress
        try:
            net = ipaddress.IPv4Network(subnet.strip(), strict=False)
        except (ValueError, ipaddress.AddressValueError):
            return []
        found: list[str] = []
        for ip_obj in net.hosts():
            ip = str(ip_obj)
            r = _udp_call(ip, "getDevInfo", timeout=0.25)
            if r and ("result" in r):
                found.append(ip)
        return found

    # ── contract ────────────────────────────────────────────────────────

    def discover(self) -> list[Device]:
        # Discovery here is intentionally lazy — scanning a /24 in tight
        # serial loops is slow. In practice users provide either a list
        # of known IPs (PATCHWRIGHT_WIZ_IPS) or we hit the ARP table via
        # a sister connector. For Wave 1 we accept env-provided IPs only.
        import os
        ips_env = os.environ.get("PATCHWRIGHT_WIZ_IPS", "").strip()
        if not ips_env:
            return []
        out: list[Device] = []
        for ip in [s.strip() for s in ips_env.split(",") if s.strip()]:
            r = _udp_call(ip, "getDevInfo")
            if not r or "result" not in r:
                continue
            info = r["result"]
            mac = info.get("mac", "")
            module = info.get("moduleName", "")
            out.append(Device(
                id=f"wiz:{mac or ip}",
                vendor="signify", product="wiz",
                label=f"WiZ {module or 'bulb'} @ {ip}",
                ip=ip, mac=mac,
                extra={"moduleName": module, "info_raw": info},
            ))
        return out

    def current_version(self, device: Device) -> Version | None:
        if not device.ip:
            return None
        # `getSystemConfig` reliably returns fwVersion on ESP20_SHRGBC_01
        # and ESP10_SOCKET_06 (verified against Kevin's network 2026-05-26).
        # getDevInfo on these modules only returns mac+moduleName+flash —
        # NOT fwVersion — so we must use getSystemConfig.
        r = _udp_call(device.ip, "getSystemConfig")
        if r and "result" in r:
            for k in ("fwVersion", "fw_version", "firmwareVersion"):
                if k in r["result"] and r["result"][k]:
                    return Version(str(r["result"][k]))
        # Some older fw returns it in getDevInfo
        r2 = _udp_call(device.ip, "getDevInfo")
        if r2 and "result" in r2:
            for k in ("fwVersion", "fw_version", "firmwareVersion"):
                if k in r2["result"] and r2["result"][k]:
                    return Version(str(r2["result"][k]))
        return None

    def latest_version(self, device: Device) -> Version | None:
        """No public Signify feed. We carry a community-curated manifest
        of known-good firmware per moduleName. Manifest lives at
        patchwright/manifests/signify_wiz.yaml."""
        module = (device.extra or {}).get("moduleName", "")
        if not module:
            # Try to discover via UDP
            r = _udp_call(device.ip, "getSystemConfig") if device.ip else None
            if r and "result" in r:
                module = r["result"].get("moduleName", "")
        if not module:
            return None
        manifest = _load_wiz_manifest()
        latest = (manifest or {}).get(module, {}).get("latest")
        return Version(str(latest)) if latest else None

    def can_patch(self, device: Device) -> CanPatchResult:
        if not device.ip:
            return CanPatchResult(
                supported=False, tier=self.SUPPORT_TIER,
                reason="no IP for device",
            )
        r = _udp_call(device.ip, "getPilot", timeout=1.0)
        if not r:
            return CanPatchResult(
                supported=False, tier=self.SUPPORT_TIER,
                reason="bulb unreachable on UDP/38899",
            )
        return CanPatchResult(
            supported=True, tier=self.SUPPORT_TIER,
            reason=(
                "LOCAL_HACK path: would reboot bulb via `restart` so it "
                "polls Signify's cloud. If Signify isn't offering a newer "
                "fw for this model, result will be NO_OP (no harm)."
            ),
            notes=["~30s bulb-dark window during reboot + cloud check"],
        )

    def apply_patch(
        self,
        device: Device,
        target: Version | None = None,
        dry_run: bool = True,
    ) -> PatchResult:
        t0 = time.time()
        cur = self.current_version(device)
        if dry_run:
            return PatchResult(
                outcome=PatchOutcome.NO_OP,
                device_id=device.id,
                from_version=cur, to_version=target or cur,
                duration_s=time.time() - t0,
                side_effects=[
                    f"[DRY-RUN] would call `restart` on bulb at {device.ip} to "
                    f"force Signify-cloud firmware check"
                ],
            )
        # Try the supported method first
        r = _udp_call(device.ip, "restart")
        used_fallback = False
        if not r or r.get("error"):
            # Fallback: setPilot off, wait 5s, setPilot on
            _udp_call(device.ip, "setPilot", {"state": False})
            time.sleep(5)
            _udp_call(device.ip, "setPilot", {"state": True})
            used_fallback = True
        # Wait for bulb to come back + check Signify cloud
        time.sleep(45)
        new = self.current_version(device)
        side_effects = [
            f"{'fallback off+on' if used_fallback else 'restart() call'} sent",
            f"waited 45s for bulb to reboot + check Signify cloud",
        ]
        if cur and new:
            if new == cur:
                outcome = PatchOutcome.NO_OP
                side_effects.append("firmware unchanged; Signify likely not pushing new fw for this model")
            else:
                outcome = PatchOutcome.OK
                side_effects.append(f"firmware moved {cur.raw} → {new.raw}")
        else:
            outcome = PatchOutcome.PARTIAL
            side_effects.append("could not read post-restart firmware version")
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
            return VerifyResult(ok=False, expected=expected, actual=None,
                                notes=["bulb unreachable post-patch"])
        if expected is None:
            return VerifyResult(ok=True, expected=None, actual=cur,
                                notes=["no expected version; bulb is reachable + responsive"])
        ok = cur == expected or expected < cur
        return VerifyResult(ok=ok, expected=expected, actual=cur)
