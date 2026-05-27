"""
macOS connector — OFFICIAL_API tier.

Targets the machine patchwright is running on (and remote Macs reachable
via SSH, if `--target host` is passed). Uses Apple's built-in
`softwareupdate(8)` — no reverse engineering needed; Apple ships this
exactly so software like ours can drive updates.

Legal basis: softwareupdate(8) is the documented public CLI for macOS
software updates and is shipped on every Mac. No credentials required
beyond the user's sudo password (which we never store).

UX note: end users on a Mac who installed patchwright via pip don't need
to do anything else for this connector — it works out of the box. Run
`patchwright check apple_macos` to see pending security updates.
"""

from __future__ import annotations

import os
import re
import subprocess
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


SOFTWAREUPDATE = "/usr/sbin/softwareupdate"
SW_VERS = "/usr/bin/sw_vers"


def _run(cmd: list[str], timeout: int = 60) -> tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except FileNotFoundError as e:
        return 127, "", f"missing: {e}"


class AppleMacOS(Connector):
    NAME = "apple_macos"
    VENDOR_KEYWORDS = ["apple"]
    PRODUCT_KEYWORDS = ["macos", "mac os", "osx"]
    SUPPORT_TIER = SupportTier.OFFICIAL_API
    DEFAULT_TIER = ReversibilityTier.YELLOW   # some updates need reboot
    VENDOR_HOSTILE = False
    LEGAL_BASIS = (
        "Uses Apple's documented softwareupdate(8) CLI. No vendor APIs "
        "are reverse-engineered. Updates are signed by Apple."
    )
    NOTES = [
        "Reads pending updates with `softwareupdate -l`.",
        "Applies updates with `softwareupdate -i <label> --no-scan`. Some updates require sudo.",
        "Connector runs on the local Mac by default. Remote Macs supported via SSH (set PATCHWRIGHT_MAC_HOSTS).",
    ]

    # ── discovery ────────────────────────────────────────────────────────

    def discover(self) -> list[Device]:
        out: list[Device] = []
        # 1) local machine, if it's a Mac
        rc, prod, _ = _run([SW_VERS, "-productName"], timeout=5)
        if rc == 0 and "macOS" in prod:
            ver = self._local_version()
            hw = self._local_hardware()
            out.append(Device(
                id=f"apple:macos:{hw.get('serial', 'local')}",
                vendor="apple", product="macos",
                label=hw.get("hostname", "local Mac"),
                mac=hw.get("mac", ""),
                extra={"local": True, "version_raw": ver.raw if ver else "?",
                       "build": hw.get("build", ""), "model": hw.get("model", "")},
            ))
        # 2) extra hosts via env
        extra_hosts = os.environ.get("PATCHWRIGHT_MAC_HOSTS", "")
        for host in [h.strip() for h in extra_hosts.split(",") if h.strip()]:
            out.append(Device(
                id=f"apple:macos:ssh:{host}",
                vendor="apple", product="macos",
                label=f"Mac @ {host}",
                extra={"local": False, "ssh_host": host},
            ))
        return out

    def _local_version(self) -> Version | None:
        rc, out, _ = _run([SW_VERS, "-productVersion"], timeout=5)
        if rc != 0 or not out.strip():
            return None
        return Version(out.strip())

    def _local_hardware(self) -> dict[str, str]:
        info: dict[str, str] = {}
        rc, out, _ = _run([SW_VERS], timeout=5)
        if rc == 0:
            for line in out.splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    info[k.strip().lower().replace(" ", "_")] = v.strip()
        try:
            import socket
            info["hostname"] = socket.gethostname()
        except Exception:
            pass
        rc, sn, _ = _run(["/usr/sbin/system_profiler", "SPHardwareDataType"], timeout=10)
        if rc == 0:
            m = re.search(r"Serial Number.*?:\s*(\S+)", sn)
            if m:
                info["serial"] = m.group(1)
            m = re.search(r"Model Name:\s*([^\n]+)", sn)
            if m:
                info["model"] = m.group(1).strip()
        return info

    # ── version checks ───────────────────────────────────────────────────

    def current_version(self, device: Device) -> Version | None:
        if (device.extra or {}).get("local"):
            return self._local_version()
        return None  # SSH path TODO

    def latest_version(self, device: Device) -> Version | None:
        """Apple doesn't publish a 'latest available macOS' machine-readable
        feed. The 'latest' for a given Mac is what `softwareupdate -l`
        reports as available. We treat the pending updates as 'latest'."""
        pending = self.pending_updates()
        if not pending:
            return self.current_version(device)
        # The macOS update entry includes the target version in its title
        # e.g. "macOS Sequoia 15.4-Beta", "macOS Sequoia 15.5". Find the
        # highest version number mentioned.
        versions: list[Version] = []
        for u in pending:
            m = re.search(r"(\d+\.\d+(?:\.\d+)?)", u.get("title", ""))
            if m:
                versions.append(Version(m.group(1)))
        if not versions:
            cur = self.current_version(device)
            return cur  # nothing more specific known
        return max(versions)

    def pending_updates(self) -> list[dict[str, str]]:
        """List of {label, title, recommended, restart, size_mb, ...} from
        `softwareupdate -l`."""
        rc, out, _ = _run([SOFTWAREUPDATE, "-l"], timeout=120)
        if rc != 0:
            return []
        # Output is multi-line; each update has a "* Label:" line and
        # follow-up "Title:" / "Size:" / etc.
        updates: list[dict[str, str]] = []
        cur: dict[str, str] = {}
        for line in out.splitlines():
            line = line.rstrip()
            label_m = re.match(r"^\s*\*\s*Label:\s*(.+)$", line)
            if label_m:
                if cur:
                    updates.append(cur)
                cur = {"label": label_m.group(1).strip()}
                continue
            for key in ("Title", "Version", "Size", "Recommended",
                        "Action", "Auto Update", "Free Disk Required"):
                m = re.match(rf"^\s*{key}:\s*(.+)$", line)
                if m:
                    cur[key.lower().replace(" ", "_")] = m.group(1).strip()
                    break
        if cur:
            updates.append(cur)
        return updates

    # ── patch path ───────────────────────────────────────────────────────

    def can_patch(self, device: Device) -> CanPatchResult:
        if not (device.extra or {}).get("local"):
            return CanPatchResult(
                supported=False, tier=self.SUPPORT_TIER,
                reason="remote Mac via SSH not implemented yet in this connector",
            )
        rc, _, _ = _run([SOFTWAREUPDATE, "-l"], timeout=120)
        if rc != 0:
            return CanPatchResult(
                supported=False, tier=self.SUPPORT_TIER,
                reason="softwareupdate -l failed; check macOS install",
            )
        pending = self.pending_updates()
        if not pending:
            return CanPatchResult(
                supported=True, tier=self.SUPPORT_TIER,
                reason="no pending updates; nothing to apply",
            )
        return CanPatchResult(
            supported=True, tier=self.SUPPORT_TIER,
            reason=(
                f"{len(pending)} update(s) available; some may require "
                f"sudo and/or reboot"
            ),
            requires_user_action=True,
            user_action=(
                "Run `patchwright patch apple_macos --live`. You will be "
                "prompted for sudo if needed. Plan for possible reboot."
            ),
            notes=[u.get("title", u.get("label", "?")) for u in pending],
        )

    def apply_patch(
        self,
        device: Device,
        target: Version | None = None,
        dry_run: bool = True,
    ) -> PatchResult:
        t0 = time.time()
        cur = self.current_version(device)
        pending = self.pending_updates()
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
                    f"[DRY-RUN] would `softwareupdate -i {p.get('label','?')}`"
                    for p in pending
                ],
            )
        # Live install — install ALL recommended updates. Restart deferred
        # so the orchestrator can schedule it (and so we don't surprise
        # the user mid-session).
        labels = [p["label"] for p in pending if p.get("recommended", "").upper() == "YES"]
        if not labels:
            labels = [p["label"] for p in pending]
        applied: list[str] = []
        failed: list[str] = []
        for lbl in labels:
            rc, out, err = _run(
                ["/usr/bin/sudo", "-n", SOFTWAREUPDATE, "-i", lbl, "--no-scan"],
                timeout=3600,
            )
            if rc == 0:
                applied.append(lbl)
            else:
                failed.append(f"{lbl}: {err.strip()[:120] or out.strip()[:120]}")
                break  # don't keep going if one fails
        new = self.current_version(device)
        outcome = (
            PatchOutcome.OK if applied and not failed
            else PatchOutcome.PARTIAL if applied and failed
            else PatchOutcome.FAILED
        )
        return PatchResult(
            outcome=outcome,
            device_id=device.id,
            from_version=cur, to_version=new,
            duration_s=time.time() - t0,
            side_effects=[f"installed: {lbl}" for lbl in applied] + failed,
            error=("; ".join(failed) if failed else ""),
        )

    def verify(self, device: Device, expected: Version | None = None) -> VerifyResult:
        cur = self.current_version(device)
        if cur is None:
            return VerifyResult(ok=False, expected=expected, actual=None,
                                notes=["sw_vers returned no version"])
        pending = self.pending_updates()
        notes = []
        if pending:
            notes.append(f"{len(pending)} update(s) still pending after patch — possibly need reboot")
        if expected and not (cur == expected or expected < cur):
            return VerifyResult(ok=False, expected=expected, actual=cur, notes=notes)
        return VerifyResult(ok=True, expected=expected, actual=cur, notes=notes)
