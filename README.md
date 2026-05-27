# patchwright

**Owner-driven IoT firmware patching. Right to repair, for the connected home.**

You own your router, your charger, your lights, your thermostats. The vendor sat on a CVSS-9 vulnerability for six weeks because their auto-update queue hasn't gotten to your serial number yet. Patchwright is the tool that lets you push the update yourself — using the same API the vendor's own mobile app uses — without becoming a security researcher.

## What it does

A connector framework with one file per device class:

- **Discovers** devices on your network or in your cloud accounts
- **Detects** whether each one has a pending firmware update
- **Pushes** the update using whatever path the vendor's app uses (we reverse-engineered it once so you don't have to)
- **Verifies** the device is healthy on the new version
- **Reports** receipts you can audit

```
$ patchwright scan
  4 connector(s) · 7 device(s) discovered

━━━ apple_macos
  Kevin's MacBook Pro                26.4.1 → 26.5             ⚠ patch available

━━━ ubiquiti_unifi
  UniFi Dream Machine SE             5.1.12 (current)          ✓ current

━━━ chargepoint_homeflex
  Home Flex EVSE                     5.5.4.13 → 5.5.4.18       ⚠ patch available  CVE-2026-4156

━━━ signify_wiz
  Living Room Bulb                   1.21.0 (current)          ✓ current
```

## Why it exists

Consumer IoT firmware updates are vendor-controlled by default. Devices you legally own can sit unpatched for months because the vendor's rollout queue is slow, or they've decided you should buy the newer model, or they simply haven't gotten to it.

The same right-to-repair principle that applies to your tractor and your iPhone applies to the rest of your connected home. Patchwright captures the vendor's own update API and replays it for you. Your devices, your network, your data, your right.

## Connector tiers

| Tier | Means | Examples |
|---|---|---|
| **OFFICIAL_API** | Vendor publishes a documented update API | UDM-SE, macOS (`softwareupdate`), Apple TV (`pyatv`) |
| **REVERSED_API** | We captured the mobile/web app's traffic ONCE and replay it | ChargePoint, Eufy (planned), ecobee (planned) |
| **LOCAL_HACK** | Cloud-only firmware, triggered by inducing local device state | WiZ (`restart` over UDP), Apple TV (sleep/wake) |
| **MANUAL_ONLY** | We detect but can't push; we tell you exactly what to tap in the vendor app | Lutron Caseta, Sony BRAVIA |

Every tier is first-class. A `MANUAL_ONLY` connector is still useful — it tells you with vendor-specific precision what to do, and verifies afterward.

## The end-user experience

You never see mitmproxy. You never install Frida. You don't need to know what cert pinning is.

```
$ pip install patchwright
$ patchwright list-connectors           # see what device classes are supported
$ patchwright login chargepoint         # enter your ChargePoint email + password once
$ patchwright scan                       # discovers, version-checks, reports
$ patchwright patch chargepoint --live   # actually push the update
```

The reverse-engineering work happens upstream, ONCE per device class, by the connector maintainer. End users get a working tool.

## Architecture

```
patchwright/
├── core/
│   ├── connector.py        # ABC every connector implements
│   ├── types.py            # Version / Device / PatchResult shared types
│   ├── credentials.py      # macOS Keychain + file + env, in that order
│   ├── safety.py           # kill switch, rate limits, owner-ack
│   ├── receipts.py         # append-only patch history (the trust ledger)
│   ├── sinks.py            # pluggable result destinations (stdout, jsonl, DDB, …)
│   └── orchestrator.py     # detect→plan→verify→report loop
├── connectors/
│   ├── ubiquiti_unifi.py       # OFFICIAL_API
│   ├── apple_macos.py          # OFFICIAL_API
│   ├── signify_wiz.py          # LOCAL_HACK (reboot → cloud check)
│   └── chargepoint_homeflex.py # REVERSED_API (stub — endpoints captured in upcoming RE session)
└── cli.py                  # `patchwright …`
```

## Safety

Every layer of the framework is paranoid because we're touching firmware on production devices:

- **Dry-run by default.** Connectors must explicitly receive `dry_run=False` to actually patch.
- **Kill switch.** `touch /tmp/patchwright-halt` and every connector aborts mid-run.
- **Rate caps.** 10 patches per hour, 30 per day, globally.
- **Owner-ack.** A device must be listed under `owned_devices:` in your config before `apply_patch` will touch it. Forces explicit assertion of ownership — protects against an LLM agent silently patching something you didn't claim.
- **Receipts.** Every action (and every refused action) gets a row in `~/.patchwright/receipts/patches.jsonl`. Append-only. Auditable.

## Status

**Wave 1 — credibility build (this week)**

- ✅ Core ABC + safety + receipts + sinks
- ✅ `ubiquiti_unifi` connector (OFFICIAL_API; UDM family)
- ✅ `apple_macos` connector (OFFICIAL_API; `softwareupdate`)
- ✅ `signify_wiz` connector (LOCAL_HACK; UDP `restart`)
- ✅ `chargepoint_homeflex` connector stub + documented RE plan
- ✅ CLI: `scan`, `check`, `patch`, `verify`, `login`, `logout`, `receipts`, `status`, `halt`, `resume`
- ✅ hiebel-events DDB sink + hourly LaunchAgent

**Wave 2 — the headline (next week)**

- ⏳ ChargePoint Home Flex live reverse session (capture endpoints, replace stub)
- ⏳ Writeup post: "We patched our own EV charger because ChargePoint wouldn't"

**Wave 3 — community (ongoing)**

- ⏳ Connector PR template
- ⏳ Issue tracker for new-device requests
- ⏳ Maintainer pool

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Every new connector follows the same shape: one file in `patchwright/connectors/`, implements the `Connector` ABC, includes a docstring with the RE plan + legal basis + UX notes.

## Legal

See [LEGAL.md](LEGAL.md). TL;DR: We only act on devices the user claims ownership of, using credentials the user provides, hitting endpoints the vendor's own app uses. DMCA §1201 security-research exemption applies. Right-to-repair laws (MA / NY / MN / CA / others) further support this for consumer goods.

## License

MIT. Take it, fork it, improve it.
