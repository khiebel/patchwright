"""
The Connector contract. Every supported device class implements this.

A connector is **one Python file** in `patchwright/connectors/`. It owns:
- how to find devices of its kind on the network
- how to read a device's current firmware version
- how to learn the vendor's latest available firmware
- whether (and how) it can actually push a patch
- how to verify the patch took
- how to roll back if available

The contract is intentionally minimal so the "MANUAL_ONLY" tier can still
implement it honestly (apply_patch returns a no-op + instructions; verify
runs as normal). Patchwright treats every device class as patchable in
*some* way — at worst, the connector emits a Signal saying "you need to
open the vendor's app and tap Update; we'll re-verify after".
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from .types import (
    CanPatchResult,
    Device,
    PatchResult,
    ReversibilityTier,
    RollbackResult,
    SupportTier,
    VerifyResult,
    Version,
)


class Connector(ABC):
    """Patcher for one device class."""

    # ── Metadata. Each subclass MUST override. ────────────────────────────

    #: Canonical short id used in receipts + CLI. e.g. "ubiquiti_unifi".
    NAME: str = ""

    #: vendor + product strings used to match devices/CVEs to this connector.
    VENDOR_KEYWORDS: list[str] = []
    PRODUCT_KEYWORDS: list[str] = []

    #: Best support tier this connector can offer.
    SUPPORT_TIER: SupportTier = SupportTier.UNSUPPORTED

    #: Default reversibility friction for apply_patch (the orchestrator may
    #: override per-action based on the planner's recommendation).
    DEFAULT_TIER: ReversibilityTier = ReversibilityTier.YELLOW

    #: Does the vendor actively work against us? (Cert pinning, account
    #: lockout, etc.) Documented; consumers may treat as a warning.
    VENDOR_HOSTILE: bool = False

    #: One-line citation of why this connector is defensible to ship.
    #: Example: "DMCA §1201 security-research exemption (renewed 2024-10);
    #:           only acts on the owner's own device with owner's credentials."
    LEGAL_BASIS: str = ""

    #: Free-form maintainer notes; surfaced in `patchwright check`.
    NOTES: list[str] = []

    # ── Core verbs ────────────────────────────────────────────────────────

    @abstractmethod
    def discover(self) -> list[Device]:
        """Find devices of this kind on the network or in known credentials.

        Should be polite (don't port-scan the whole subnet) and idempotent.
        Returns [] if nothing is found.
        """

    @abstractmethod
    def current_version(self, device: Device) -> Version | None:
        """Return the device's currently-installed firmware version.

        Returns None if the device is unreachable or doesn't expose its
        version. The orchestrator will treat None as "unknown — alert".
        """

    @abstractmethod
    def latest_version(self, device: Device) -> Version | None:
        """Return the vendor's latest published firmware for this device.

        For OFFICIAL_API vendors: hit the public update endpoint.
        For REVERSED_API: hit the reversed mobile-app endpoint.
        For LOCAL_HACK: consult a community-curated manifest (or vendor
        page scrape).
        For MANUAL_ONLY: same as LOCAL_HACK.
        """

    @abstractmethod
    def can_patch(self, device: Device) -> CanPatchResult:
        """Pre-flight: would apply_patch actually work right now?

        Should NOT modify anything. Returns rich diagnostic info so the
        UI/CLI can tell the user *why* a patch isn't available (vendor
        cert pin broke our endpoint, no fix published yet, etc.).
        """

    @abstractmethod
    def apply_patch(
        self,
        device: Device,
        target: Version | None = None,
        dry_run: bool = True,
    ) -> PatchResult:
        """Patch the device. dry_run=True is the default — connectors MUST
        respect it.

        target=None means "to the latest available".

        Behavior expectations:
        - MUST raise no exceptions; return PatchResult.outcome=FAILED instead.
        - MUST tolerate the device being mid-update or rebooting.
        - SHOULD record enough rollback context that rollback() can undo
          the change, even if rollback isn't supported on this device class.
        """

    @abstractmethod
    def verify(self, device: Device, expected: Version | None = None) -> VerifyResult:
        """Confirm the device is at `expected` (or its latest if None) AND
        is functionally healthy. May include connector-specific health
        checks beyond just version (e.g. "the device is actually responding")."""

    def rollback(self, device: Device, rollback_id: str = "") -> RollbackResult:
        """Restore previous firmware if possible.

        Default implementation: returns NO_OP. Subclasses that can roll
        back override this. The orchestrator should treat NO_OP as
        "this device class cannot roll back; warn the user explicitly
        in the planner output before applying".
        """
        from .types import PatchOutcome
        return RollbackResult(
            outcome=PatchOutcome.NO_OP,
            notes=[f"{self.NAME}: rollback not implemented for this device class"],
        )

    # ── Helpers for orchestrator (shouldn't be overridden often) ─────────

    def matches_cve_keywords(self, vendor: str, product: str) -> bool:
        v = (vendor or "").lower()
        p = (product or "").lower()
        any_vendor = any(k.lower() in v for k in self.VENDOR_KEYWORDS) if self.VENDOR_KEYWORDS else True
        any_product = any(k.lower() in p for k in self.PRODUCT_KEYWORDS) if self.PRODUCT_KEYWORDS else True
        return any_vendor and any_product

    def describe(self) -> dict[str, Any]:
        """Compact metadata payload for `patchwright list-connectors`."""
        return {
            "name": self.NAME,
            "vendor_keywords": self.VENDOR_KEYWORDS,
            "product_keywords": self.PRODUCT_KEYWORDS,
            "support_tier": self.SUPPORT_TIER.value,
            "default_action_tier": self.DEFAULT_TIER.value,
            "vendor_hostile": self.VENDOR_HOSTILE,
            "legal_basis": self.LEGAL_BASIS,
            "notes": list(self.NOTES),
        }
