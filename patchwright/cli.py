#!/usr/bin/env python3
"""
patchwright — owner-driven IoT firmware patching.

Verbs:
  list-connectors         — what device classes patchwright knows about
  scan                    — discover devices + per-device version check
                            (auto-runs every connector; emits to sinks)
  check <connector>       — same but scoped to one connector
  patch <connector>       — apply patches (dry-run by default!)
  verify <connector>      — re-verify devices' version + health post-patch
  login <connector>       — interactive credential prompt
  logout <connector>      — wipe stored credentials
  receipts [N]            — last N receipts (patch history)
  status                  — kill switch, rate limit, connector inventory
  halt / resume           — flip the kill switch
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Allow running directly without `pip install -e .`
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from patchwright.core import safety, receipts
from patchwright.core.connector import Connector
from patchwright.core.credentials import Credentials
from patchwright.core.orchestrator import (
    load_connectors, scan_all, check_one, patch_one, verify_one,
)
from patchwright.core.sinks import SinkSet


def _find(connectors: list[Connector], name: str) -> Connector | None:
    return next((c for c in connectors if c.NAME == name), None)


def cmd_list_connectors(args):
    for c in load_connectors():
        d = c.describe()
        print(f"  {d['name']:30s} tier={d['support_tier']:13s} "
              f"action={d['default_action_tier']:7s} "
              f"hostile={'Y' if d['vendor_hostile'] else 'N'}")
        if args.verbose and d['notes']:
            for note in d['notes']:
                print(f"    · {note}")
    return 0


def cmd_scan(args):
    sinks = SinkSet.from_env()
    connectors = load_connectors()
    if args.connector:
        connectors = [c for c in connectors if c.NAME == args.connector]
        if not connectors:
            print(f"  no connector named {args.connector!r}", file=sys.stderr)
            return 1
    discovered = scan_all(connectors)
    total = sum(len(d) for d in discovered.values())
    print(f"  {len(connectors)} connector(s) · {total} device(s) discovered")
    for c in connectors:
        devs = discovered.get(c.NAME, [])
        if not devs:
            continue
        print(f"\n━━━ {c.NAME} ({len(devs)} device(s))")
        for d in devs:
            rec = check_one(c, d)
            sinks.emit("check", rec)
            current = rec.get("current") or "?"
            latest = rec.get("latest") or "?"
            needs = rec.get("needs_patch")
            flag = ("⚠ patch available" if needs is True
                    else "✓ current" if needs is False
                    else "? unknown")
            print(f"  {d.label or d.id:40s}  {current} → {latest}  {flag}")
    return 0


def cmd_check(args):
    args.connector = args.connector
    return cmd_scan(args)


def cmd_patch(args):
    sinks = SinkSet.from_env()
    connectors = load_connectors()
    conn = _find(connectors, args.connector)
    if not conn:
        print(f"  no connector named {args.connector!r}", file=sys.stderr)
        return 1
    devs = conn.discover()
    if args.device:
        devs = [d for d in devs if d.id == args.device]
    if not devs:
        print("  no matching devices")
        return 0
    if not args.live:
        print("  (dry-run mode; nothing will be patched; pass --live to apply)")
    ack_path = Path(args.owner_ack) if args.owner_ack else None
    for d in devs:
        print(f"\n  patching {d.label or d.id} ({d.id}) …")
        result = patch_one(conn, d, dry_run=not args.live, owner_ack_path=ack_path)
        sinks.emit("patch.done", {
            "connector": conn.NAME,
            "device_id": d.id,
            "result": result,
        })
        print(f"  outcome: {result.outcome}")
        for s in result.side_effects:
            print(f"  · {s}")
        if result.error:
            print(f"  error: {result.error}")
    return 0


def cmd_verify(args):
    sinks = SinkSet.from_env()
    connectors = load_connectors()
    conn = _find(connectors, args.connector)
    if not conn:
        print(f"  no connector named {args.connector!r}", file=sys.stderr)
        return 1
    for d in conn.discover():
        vr = verify_one(conn, d, expected=None)
        sinks.emit("verify", {
            "connector": conn.NAME,
            "device_id": d.id,
            "result": vr,
        })
        print(f"  {d.label or d.id}: ok={vr.ok} actual={vr.actual.raw if vr.actual else None}")
    return 0


def cmd_login(args):
    print(f"  storing credentials for {args.connector!r}")
    print(f"  (will use macOS Keychain if available, else ~/.patchwright/credentials.json 0600)")
    # We don't know the connector's required keys generically — ask for
    # the standard pair (email + password). Connector authors document
    # any extras in their module docstring.
    email = input("    email: ").strip()
    if email:
        backend = Credentials.set(args.connector, "email", email)
        print(f"    email → {backend}")
    import getpass
    pw = getpass.getpass("    password: ")
    if pw:
        backend = Credentials.set(args.connector, "password", pw)
        print(f"    password → {backend}")
    return 0


def cmd_logout(args):
    Credentials.delete(args.connector)
    print(f"  wiped credentials for {args.connector!r}")
    return 0


def cmd_receipts(args):
    for r in receipts.recent(args.n):
        ts = r.get("ts", "")[:19]
        stage = r.get("stage", "?")
        cnx = r.get("connector", "")
        dev = r.get("device_id", "")
        out = (r.get("result") or {}).get("outcome", "") if isinstance(r.get("result"), dict) else ""
        print(f"  {ts}  {stage:18s}  {cnx:25s}  {dev:30s}  {out}")
    return 0


def cmd_status(args):
    print(f"  kill switch  ({safety.KILL_SWITCH}): "
          f"{'ACTIVE (halted)' if safety.KILL_SWITCH.exists() else 'inactive'}")
    creds = Credentials.all_stored()
    if creds:
        print("  credentials stored (file backend; keychain not enumerated):")
        for conn, keys in creds.items():
            print(f"    {conn}: {keys}")
    else:
        print("  no credentials stored in file backend")
    connectors = load_connectors()
    print(f"  loaded connectors: {[c.NAME for c in connectors]}")
    return 0


def cmd_halt(args):
    safety.KILL_SWITCH.touch()
    print(f"  HALTED — touched {safety.KILL_SWITCH}")
    return 0


def cmd_resume(args):
    if safety.KILL_SWITCH.exists():
        safety.KILL_SWITCH.unlink()
        print(f"  resumed — removed {safety.KILL_SWITCH}")
    else:
        print("  not currently halted")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="patchwright")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("list-connectors", help="show known device classes")
    s.add_argument("--verbose", "-v", action="store_true")
    s.set_defaults(func=cmd_list_connectors)

    s = sub.add_parser("scan", help="discover + check every connector")
    s.add_argument("--connector", help="limit to one connector")
    s.set_defaults(func=cmd_scan)

    s = sub.add_parser("check", help="alias for scan --connector X")
    s.add_argument("connector")
    s.set_defaults(func=cmd_check)

    s = sub.add_parser("patch", help="apply patches (dry-run unless --live)")
    s.add_argument("connector")
    s.add_argument("--device", help="single device id")
    s.add_argument("--live", action="store_true", help="actually apply")
    s.add_argument("--owner-ack", help="path to owner-ack yaml")
    s.set_defaults(func=cmd_patch)

    s = sub.add_parser("verify", help="re-verify version + health")
    s.add_argument("connector")
    s.set_defaults(func=cmd_verify)

    s = sub.add_parser("login", help="store vendor credentials")
    s.add_argument("connector")
    s.set_defaults(func=cmd_login)

    s = sub.add_parser("logout", help="wipe stored credentials")
    s.add_argument("connector")
    s.set_defaults(func=cmd_logout)

    s = sub.add_parser("receipts", help="patch history")
    s.add_argument("n", nargs="?", type=int, default=20)
    s.set_defaults(func=cmd_receipts)

    s = sub.add_parser("status", help="kill switch + connector inventory")
    s.set_defaults(func=cmd_status)

    s = sub.add_parser("halt", help="enable kill switch")
    s.set_defaults(func=cmd_halt)

    s = sub.add_parser("resume", help="disable kill switch")
    s.set_defaults(func=cmd_resume)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
