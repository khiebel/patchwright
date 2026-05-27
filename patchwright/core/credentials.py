"""
Credential storage for vendor cloud APIs.

The patchwright thesis: connector authors do the reverse-engineering ONCE
(captured mobile app traffic, mined OAuth flow, etc.) and ship the
endpoints + token-minting logic baked into the connector. End users only
ever provide their own credentials — never see mitmproxy, never install
Frida, never know about cert pinning.

This module is the credential plumbing that makes that possible:

  $ patchwright login chargepoint
  ChargePoint email: kevin@hiebel.ai
  Password: ******
  → stored in macOS Keychain (service=patchwright.chargepoint)

  $ patchwright login wiz       # no auth needed; LOCAL_HACK tier
  → noted; no credentials required

Backends, in priority order:
  1. macOS Keychain (`security` CLI) — preferred on Mac
  2. ~/.patchwright/credentials.json with 0600 perms — portable fallback
  3. Environment variables `PATCHWRIGHT_<CONNECTOR_UPPER>_<KEY>` — for CI

The connector calls Credentials.get('chargepoint', 'email') / 'password'
and gets back the values without caring where they came from.
"""

from __future__ import annotations

import getpass
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any


CRED_FILE = Path.home() / ".patchwright" / "credentials.json"
KEYCHAIN_SERVICE_PREFIX = "patchwright"


def _keychain_available() -> bool:
    return sys.platform == "darwin" and bool(subprocess.run(
        ["/usr/bin/which", "security"], capture_output=True
    ).stdout)


def _keychain_get(service: str, key: str) -> str | None:
    try:
        r = subprocess.run(
            ["/usr/bin/security", "find-generic-password",
             "-s", service, "-a", key, "-w"],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode != 0:
            return None
        return r.stdout.strip() or None
    except Exception:
        return None


def _keychain_set(service: str, key: str, value: str) -> bool:
    try:
        # `-U` updates if existing, creates otherwise.
        r = subprocess.run(
            ["/usr/bin/security", "add-generic-password",
             "-s", service, "-a", key, "-w", value, "-U"],
            capture_output=True, text=True, timeout=5,
        )
        return r.returncode == 0
    except Exception:
        return False


def _keychain_del(service: str, key: str) -> bool:
    try:
        r = subprocess.run(
            ["/usr/bin/security", "delete-generic-password",
             "-s", service, "-a", key],
            capture_output=True, text=True, timeout=5,
        )
        return r.returncode == 0
    except Exception:
        return False


def _file_load() -> dict:
    if not CRED_FILE.exists():
        return {}
    try:
        return json.loads(CRED_FILE.read_text())
    except Exception:
        return {}


def _file_save(data: dict) -> None:
    CRED_FILE.parent.mkdir(parents=True, exist_ok=True)
    CRED_FILE.write_text(json.dumps(data, indent=2))
    try:
        os.chmod(CRED_FILE, 0o600)
    except OSError:
        pass


# ── public API ──────────────────────────────────────────────────────────


class Credentials:
    """Thin facade over keychain + file + env. Static methods only."""

    @staticmethod
    def env_key(connector: str, key: str) -> str:
        return f"PATCHWRIGHT_{connector.upper()}_{key.upper()}"

    @staticmethod
    def keychain_service(connector: str) -> str:
        return f"{KEYCHAIN_SERVICE_PREFIX}.{connector}"

    @staticmethod
    def get(connector: str, key: str, prompt: bool = False) -> str | None:
        """Resolve a credential. Order: env → keychain → file → optional
        interactive prompt (if `prompt=True` AND stdin is a TTY).

        Returns None if not found and prompt skipped or not a TTY.
        """
        env_val = os.environ.get(Credentials.env_key(connector, key))
        if env_val:
            return env_val
        if _keychain_available():
            v = _keychain_get(Credentials.keychain_service(connector), key)
            if v:
                return v
        data = _file_load()
        v = (data.get(connector) or {}).get(key)
        if v:
            return v
        if prompt and sys.stdin.isatty():
            sensitive = key.lower() in {"password", "token", "secret", "client_secret", "api_key"}
            ask = f"{connector} {key}: "
            v = getpass.getpass(ask) if sensitive else input(ask)
            if v:
                # auto-save to the preferred backend
                Credentials.set(connector, key, v)
            return v or None
        return None

    @staticmethod
    def set(connector: str, key: str, value: str) -> str:
        """Store a credential, returning the backend used."""
        if _keychain_available():
            if _keychain_set(Credentials.keychain_service(connector), key, value):
                return "macos-keychain"
        # fallback to file
        data = _file_load()
        data.setdefault(connector, {})[key] = value
        _file_save(data)
        return "file"

    @staticmethod
    def delete(connector: str, key: str | None = None) -> None:
        """Delete one key or, if key=None, all keys for the connector."""
        if _keychain_available():
            if key:
                _keychain_del(Credentials.keychain_service(connector), key)
            else:
                # We don't know all keys; clear the file backend at least
                pass
        data = _file_load()
        if connector in data:
            if key:
                data[connector].pop(key, None)
                if not data[connector]:
                    data.pop(connector)
            else:
                data.pop(connector)
            _file_save(data)

    @staticmethod
    def all_stored() -> dict[str, list[str]]:
        """Return what connectors have credentials stored (keys only, no
        values). Used by `patchwright credentials list`."""
        out: dict[str, list[str]] = {}
        # File backend only — keychain doesn't enumerate by service prefix
        # without elevated calls. The interactive CLI will surface what
        # connectors have logged in based on this + per-connector probes.
        for conn, kv in _file_load().items():
            out[conn] = sorted(kv.keys())
        return out
