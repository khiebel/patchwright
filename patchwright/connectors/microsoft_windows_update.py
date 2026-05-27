"""
Microsoft Windows Update — OFFICIAL_API tier.

Targets Windows 10/11 hosts reachable via SSH (typically remote Windows
servers like Kevin's 3090). Uses the `PSWindowsUpdate` PowerShell
module: `Get-WindowsUpdate` lists pending, `Install-WindowsUpdate
-AcceptAll -AutoReboot:$false` applies, `(Get-CimInstance
Win32_OperatingSystem).BuildNumber` verifies.

Legal basis: PSWindowsUpdate is the canonical user-facing module for
driving Windows Update. We use it exactly as Microsoft intends. No
vendor APIs are reverse-engineered. The "patches" themselves are
Microsoft-signed cumulative security updates.

UX: end user provides an SSH host alias (or full `user@host:port`).
Set PATCHWRIGHT_WINDOWS_HOSTS=alias1,alias2 to enumerate. SSH key auth
expected (no passwords).
"""

from __future__ import annotations

import json
import os
import re
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


def _ssh(host: str, ps: str, timeout: int = 60) -> tuple[int, str, str]:
    """Run a PowerShell command on the remote Windows host via SSH."""
    cmd = ["ssh", "-o", "ConnectTimeout=5", "-o", "BatchMode=yes",
           host, "powershell", "-NoLogo", "-NoProfile", "-Command", ps]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "ssh timeout"
    except FileNotFoundError:
        return 127, "", "ssh not installed"


class MicrosoftWindowsUpdate(Connector):
    NAME = "microsoft_windows_update"
    VENDOR_KEYWORDS = ["microsoft"]
    PRODUCT_KEYWORDS = ["windows", "win10", "win11"]
    SUPPORT_TIER = SupportTier.OFFICIAL_API
    DEFAULT_TIER = ReversibilityTier.YELLOW  # may need reboot
    VENDOR_HOSTILE = False
    LEGAL_BASIS = (
        "Uses the PSWindowsUpdate PowerShell module — the canonical "
        "user-facing tool to drive Windows Update. No vendor APIs are "
        "reverse-engineered. Patches are Microsoft-signed."
    )
    NOTES = [
        "Set PATCHWRIGHT_WINDOWS_HOSTS=alias1,alias2 to enumerate hosts.",
        "Hosts must have PSWindowsUpdate installed (`Install-Module PSWindowsUpdate`).",
        "Updates may require reboot; we defer with `-AutoReboot:$false`.",
    ]

    def __init__(self):
        env = os.environ.get("PATCHWRIGHT_WINDOWS_HOSTS", "")
        self.hosts = [h.strip() for h in env.split(",") if h.strip()]

    # ── contract ────────────────────────────────────────────────────────

    def discover(self) -> list[Device]:
        out: list[Device] = []
        for host in self.hosts:
            ps = ('$os = Get-CimInstance Win32_OperatingSystem; '
                  '$c = Get-CimInstance Win32_ComputerSystem; '
                  '@{caption=$os.Caption; build=$os.BuildNumber; '
                  '  version=$os.Version; hostname=$c.Name; manufacturer=$c.Manufacturer} '
                  '| ConvertTo-Json')
            rc, out_str, _ = _ssh(host, ps, timeout=15)
            if rc != 0:
                continue
            try:
                info = json.loads(out_str)
            except json.JSONDecodeError:
                continue
            out.append(Device(
                id=f"win:{host}",
                vendor="microsoft", product="windows",
                label=f"{info.get('caption','Windows')} on {host}",
                extra={
                    "ssh_host": host,
                    "version_raw": info.get("version", ""),
                    "build": info.get("build", ""),
                    "hostname": info.get("hostname", ""),
                    "manufacturer": info.get("manufacturer", ""),
                },
            ))
        return out

    def current_version(self, device: Device) -> Version | None:
        host = (device.extra or {}).get("ssh_host")
        if not host:
            return None
        rc, out, _ = _ssh(host,
            '(Get-CimInstance Win32_OperatingSystem).Version + "." + '
            '(Get-CimInstance Win32_OperatingSystem).BuildNumber')
        if rc != 0:
            return None
        return Version(out.strip())

    def latest_version(self, device: Device) -> Version | None:
        """No public 'latest Windows version' feed in a stable format.
        Per Windows Update conventions, 'latest' = current + pending KBs
        applied. We return None and let the orchestrator interpret
        pending_updates() count instead."""
        return None

    def pending_updates(self, device: Device) -> list[dict]:
        host = (device.extra or {}).get("ssh_host")
        if not host:
            return []
        ps = ('Import-Module PSWindowsUpdate -ErrorAction SilentlyContinue; '
              'Get-WindowsUpdate -MicrosoftUpdate -ErrorAction SilentlyContinue '
              '| Select-Object KB, Size, Title, RebootRequired '
              '| ConvertTo-Json')
        rc, out, _ = _ssh(host, ps, timeout=120)
        if rc != 0 or not out.strip():
            return []
        try:
            data = json.loads(out)
            return [data] if isinstance(data, dict) else data
        except json.JSONDecodeError:
            return []

    def can_patch(self, device: Device) -> CanPatchResult:
        host = (device.extra or {}).get("ssh_host")
        if not host:
            return CanPatchResult(
                supported=False, tier=self.SUPPORT_TIER,
                reason="no ssh_host in device.extra",
            )
        # Quick SSH liveness + PSWindowsUpdate module check
        rc, out, err = _ssh(host,
            'if (Get-Module -ListAvailable PSWindowsUpdate) '
            '{ "ok" } else { "missing" }', timeout=15)
        if rc != 0:
            return CanPatchResult(
                supported=False, tier=self.SUPPORT_TIER,
                reason=f"SSH to {host} failed: {err.strip()[:100]}",
            )
        if "missing" in out:
            return CanPatchResult(
                supported=False, tier=self.SUPPORT_TIER,
                reason="PSWindowsUpdate module not installed",
                requires_user_action=True,
                user_action=(
                    f"On {host}: Install-Module PSWindowsUpdate -Force "
                    "(elevated PowerShell required)"
                ),
            )
        pending = self.pending_updates(device)
        if not pending:
            return CanPatchResult(
                supported=True, tier=self.SUPPORT_TIER,
                reason="no pending updates",
            )
        reboot_needed = any(p.get("RebootRequired") for p in pending)
        return CanPatchResult(
            supported=True, tier=self.SUPPORT_TIER,
            reason=(
                f"{len(pending)} update(s) pending"
                + (" (reboot required for at least one)" if reboot_needed else "")
            ),
            notes=[p.get("Title", "")[:120] for p in pending[:5]],
        )

    def apply_patch(
        self,
        device: Device,
        target: Version | None = None,
        dry_run: bool = True,
    ) -> PatchResult:
        t0 = time.time()
        host = (device.extra or {}).get("ssh_host", "")
        cur = self.current_version(device)
        pending = self.pending_updates(device)
        if not pending:
            return PatchResult(
                outcome=PatchOutcome.NO_OP,
                device_id=device.id,
                from_version=cur, to_version=cur,
                duration_s=time.time() - t0,
                side_effects=["no pending updates"],
            )
        if dry_run:
            return PatchResult(
                outcome=PatchOutcome.NO_OP,
                device_id=device.id,
                from_version=cur, to_version=cur,
                duration_s=time.time() - t0,
                side_effects=[
                    f"[DRY-RUN] would Install-WindowsUpdate "
                    f"({len(pending)} KBs) on {host} with -AutoReboot:$false"
                ],
            )
        ps = ('Import-Module PSWindowsUpdate; '
              'Install-WindowsUpdate -MicrosoftUpdate -AcceptAll '
              '-AutoReboot:$false -IgnoreReboot -Confirm:$false '
              '| ConvertTo-Json -Depth 2')
        rc, out, err = _ssh(host, ps, timeout=3600)
        new = self.current_version(device)
        post_pending = self.pending_updates(device)
        side_effects = [f"PSWindowsUpdate result (truncated): {out.strip()[:300]}"]
        reboot_pending = any(p.get("RebootRequired") for p in pending)
        if reboot_pending:
            side_effects.append(
                "AT LEAST ONE KB requires reboot; reboot deferred per --AutoReboot:$false. "
                "Schedule a separate reboot via Task Scheduler."
            )
        if rc != 0:
            return PatchResult(
                outcome=PatchOutcome.FAILED,
                device_id=device.id,
                from_version=cur, to_version=new,
                duration_s=time.time() - t0,
                side_effects=side_effects,
                error=err.strip()[:300],
            )
        outcome = (
            PatchOutcome.AWAITING_REBOOT if reboot_pending and post_pending
            else PatchOutcome.OK if not post_pending
            else PatchOutcome.PARTIAL
        )
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
                                notes=["SSH unreachable post-patch (might be rebooting)"])
        post_pending = self.pending_updates(device)
        notes = []
        if post_pending:
            notes.append(f"{len(post_pending)} update(s) still pending — may need reboot")
        return VerifyResult(
            ok=not post_pending,
            expected=expected, actual=cur, notes=notes,
        )
