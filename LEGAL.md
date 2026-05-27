# Legal Basis

This is not legal advice. This is the framework's posture, written so that maintainers and contributors can reason about why each connector is defensible.

## The Acts We Perform

Every patchwright connector does some subset of these:

1. Reads a device's currently-installed firmware version (via vendor-published protocol or via the vendor's mobile-app API).
2. Looks up the vendor's latest published firmware (via public feed, scraped vendor page, or replayed mobile-app call).
3. Asks the vendor's cloud to push the latest firmware to a specific device the user owns, using credentials the user supplied to us.
4. Optionally power-cycles or otherwise prods the device to re-check the vendor's cloud after a published-but-not-pushed update.

We do **not**:

- Hit the vendor's cloud on behalf of a device we don't have credentials for.
- Bypass authentication. (We use the user's own credentials to mint tokens the same way the vendor's app does.)
- Distribute firmware binaries.
- Exploit any vulnerability in the firmware itself. The vendor's published fix is what gets applied.
- Disable safety mechanisms in the device.

## DMCA § 1201 — Security Research Exemption

17 U.S.C. § 1201's anti-circumvention prohibition has a "security research" exemption renewed by the Library of Congress every three years (most recently in October 2024). The exemption explicitly permits:

> "good-faith security research" which is "accessing a computer program solely for purposes of good-faith testing, investigation, and/or correction of a security flaw or vulnerability" of a device "lawfully acquired by the researcher"

Patchwright's connectors fall squarely inside this exemption: they exist to **correct security flaws**, on **devices the user lawfully acquired**, accessing the firmware update mechanism only.

References:
- 17 U.S.C. § 1201(f), (j) (interoperability + security research exemptions)
- 37 CFR § 201.40 — current rulemaking
- Library of Congress 2024 ruling extending and broadening the security research exemption

## CFAA (18 U.S.C. § 1030)

The Computer Fraud and Abuse Act prohibits "unauthorized access" to a "protected computer." Patchwright operates with **authorized** access:

- The user provides their own credentials.
- The user (or someone authorized by them) listed the device in `owned_devices` in the patchwright config.
- The vendor's cloud authorizes the call because we authenticated with valid credentials.

The 2021 *Van Buren v. United States* Supreme Court ruling further narrowed CFAA scope: even **misusing** access to information you're authorized to retrieve isn't a CFAA violation. Patchwright doesn't misuse — it does exactly what the official app does.

## Right-to-Repair laws

Several U.S. states have right-to-repair laws on the books that explicitly cover consumer electronics:

- **Massachusetts** — Right to Repair Act (2012, expanded 2020) — covers vehicles and electronics
- **New York** — Digital Fair Repair Act (effective Dec 2023) — covers consumer electronics
- **Minnesota** — Digital Fair Repair Act (effective July 2024)
- **California** — Right to Repair Act (effective July 2024)
- **Colorado / Oregon** — similar laws in effect

The connectors that target devices covered by these laws (which is most of them) have an additional legal basis: the user has an affirmative right to maintain and repair the device, and the vendor's failure to expose firmware updates does not extinguish that right.

EU jurisdictions: see Directive (EU) 2024/1799 (Right to Repair).

## Vendor Terms of Service

Most vendor TOS prohibit "reverse engineering" of the mobile app, "modifying" the cloud service, or "automated access." These provisions are typically:

- **Unenforceable against the device owner's good-faith security research** — federal law (DMCA exemption + CFAA narrowing) supersedes contract terms in this domain.
- **Inapplicable to API replay** — we don't modify the cloud service; we use it as designed, with valid credentials.
- **Civil only** — worst plausible outcome is the vendor terminates the user's account. Patchwright surfaces this risk in connector docstrings tagged with `VENDOR_HOSTILE=True` so users know.

## Per-Connector Documentation Requirement

Every connector in `patchwright/connectors/` MUST include a top-of-file `LEGAL_BASIS` string citing the specific basis for that connector's actions. Reviewers reject PRs that don't.

## What This Project Will Not Do

To stay narrowly inside the defensible posture:

- **No mass scanning of others' devices.** Discovery is limited to the user's own LAN and the user's own cloud accounts. The framework refuses to act on a device not listed in `owned_devices`.
- **No vulnerability publication ahead of vendor disclosure.** If a connector author finds a NEW vulnerability while reverse-engineering, they follow responsible disclosure to the vendor and CERT/CC before the connector lands. The connector applies the vendor's eventual fix, it doesn't ship an exploit.
- **No bricking.** If a patch fails, the framework reports it and attempts vendor-supported rollback. Connectors that can't rollback are flagged YELLOW or RED so the user explicitly assumes that risk.
- **No covering tracks.** All actions write receipts. The receipts are the user's defense if a vendor questions activity on the account.

## When in Doubt

Open an issue on the repo before merging a connector that touches an unfamiliar device class, especially anything that could plausibly affect another user's device (multi-tenant cloud APIs, shared IoT hubs, etc.).
