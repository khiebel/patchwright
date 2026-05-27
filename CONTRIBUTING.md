# Contributing to patchwright

Thanks for considering a contribution. The most valuable thing you can add is **a new connector** for a device class we don't yet support.

## Connector PR template

1. **Pick a device class.** Open an issue first if it isn't obvious which tier it'll be — discussion saves time.

2. **Create `patchwright/connectors/<vendor>_<product>.py`.** Implement the `Connector` ABC.

3. **Top-of-file docstring MUST include**:
   - One-paragraph overview of the device + what tier you're shipping at
   - **REVERSE-ENGINEERING PLAN** (if REVERSED_API tier): the steps a future maintainer would follow to re-capture the endpoints if the vendor changes them
   - **LEGAL_BASIS** string explaining why this connector is defensible
   - **UX notes**: what credentials does the end user provide? Any prerequisites?

4. **Set the metadata constants:**
   - `NAME` — short canonical id (`<vendor>_<product>`)
   - `VENDOR_KEYWORDS` / `PRODUCT_KEYWORDS` — for CVE → connector matching
   - `SUPPORT_TIER` — `OFFICIAL_API`, `REVERSED_API`, `LOCAL_HACK`, `MANUAL_ONLY`
   - `DEFAULT_TIER` — reversibility (`GREEN` / `YELLOW` / `RED`)
   - `VENDOR_HOSTILE` — does the vendor actively try to break our calls?
   - `LEGAL_BASIS` — see `LEGAL.md`

5. **Implement the contract methods.** Every method should:
   - Tolerate the device being unreachable (return `None` / appropriate failure result, never raise)
   - Respect `dry_run=True` by default
   - Be idempotent (calling twice in a row produces the same observable result)

6. **Write tests.** Even if it's hard to test against a real device, write at least:
   - A unit test that parses a captured response and produces the right `Version`
   - A unit test that the dry-run path emits the expected `PatchResult`

7. **Add docs**:
   - Add an entry to the "Connector tiers" table in `README.md`
   - If your connector requires credentials, document them in the module docstring and update `docs/credentials.md`

## Standards we hold connectors to

- **Single Python file.** If you need helpers, put them at the bottom of the same file. Connectors should be readable in one screen of scrolling.
- **stdlib + minimal deps.** PyYAML and `cryptography` are OK if you actually need them. No requests, no aiohttp — `urllib.request` works fine.
- **No vendor app binaries.** Never bundle a vendor's mobile app or extracted credentials.
- **Tests don't require the real device.** Use captured fixtures in `tests/fixtures/<connector>/`.
- **Receipts on every action.** The orchestrator handles this for you if you call into the framework correctly. Don't bypass it.

## What gets rejected

- Connectors that act on devices the user hasn't claimed ownership of
- Connectors that publish a 0-day before the vendor has released a fix
- Connectors that disable safety mechanisms or modify a device beyond firmware update
- Connectors that ship an exploit instead of the vendor's published fix
- Code that calls `subprocess` to run arbitrary shell commands (use specific binaries with full paths and validated args)
- PRs without a corresponding test

## Connector review checklist (we run this on every PR)

```
□ Top-of-file docstring with overview + (RE plan if REVERSED) + LEGAL_BASIS + UX notes
□ Metadata constants all set, no placeholders
□ Implements all Connector ABC methods
□ Dry-run is default; --live required to actually patch
□ No raises on the happy path — failures return result objects with .error set
□ apply_patch records enough rollback context for rollback() (when supported)
□ Tests include at least one captured-fixture test
□ README "Connector tiers" table updated
□ docs/credentials.md updated if creds required
□ LEGAL.md updated if the legal basis introduces a new pattern
```

## Reverse-engineering ethics

If you're capturing API traffic from a vendor's mobile app:

- Use a test account, not the user's production account, where possible.
- Never publish authentication artifacts (tokens, client_secrets, oauth_client_ids) that aren't already extractable from the public app binary.
- Disclose any new vulnerabilities you find to the vendor + CERT/CC before merging the connector.
- Note in the docstring which app version you captured against — vendors change endpoints; future maintainers need to know.

## Code style

- Black-formatted, 88 columns, double-quoted strings.
- Type-annotated public functions.
- Imports sorted by isort defaults.
- Comments only where the WHY isn't obvious from the code — and especially where you'd otherwise lose the RE context.

## Community norms

This is a project explicitly aligned with the right-to-repair movement and the security research community. We will not entertain:

- Issues asking us to add bulk-scanning capabilities, mass-update capabilities, or anything that operates on devices not owned by the user
- Requests to circumvent encryption beyond what's required to apply a vendor's published fix
- Anything that would weaken security to make patching "easier"

If a PR feels adjacent to those, the maintainers will ask hard questions before merging.
