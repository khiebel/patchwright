"""Regression tests for the apple_tv connector.

The CodeRabbit-flagged bug was that discover() stored `atv_id` in
device.extra but latest_version() looked up `model_identifier`. Manifest
buckets per generation never matched — every ATV got the "default"
entry. These tests pin the contract.
"""
from __future__ import annotations

from patchwright.connectors.apple_tv import AppleTV
from patchwright.core.types import Device


def test_latest_version_uses_model_identifier_key():
    """The manifest is keyed by Apple's model identifier
    (e.g. 'AppleTV14,1'). discover() must put that key into
    device.extra so latest_version() can pick the right bucket."""
    c = AppleTV()
    dev = Device(
        id="appletv:abc123",
        vendor="apple", product="tvos",
        label="Apple TV abc12345…",
        extra={"atv_id": "abc123", "model_identifier": "AppleTV14,1"},
    )
    v = c.latest_version(dev)
    assert v is not None, "manifest lookup returned None for known model"
    assert v.raw == "26.5", f"expected 26.5, got {v.raw}"


def test_latest_version_falls_back_to_default_when_unknown():
    c = AppleTV()
    dev = Device(
        id="appletv:xyz", vendor="apple", product="tvos",
        label="Apple TV xyz…",
        extra={"atv_id": "xyz", "model_identifier": "AppleTV99,99"},
    )
    v = c.latest_version(dev)
    assert v is not None, "default manifest entry missing"
    assert v.raw == "26.5"


def test_latest_version_falls_back_to_default_when_no_model_id():
    """If we couldn't read the model id during discovery (older pyatv,
    unpaired ATV, etc.), we should still return *something* — namely
    the default-bucket value — rather than None."""
    c = AppleTV()
    dev = Device(
        id="appletv:nomdl", vendor="apple", product="tvos",
        label="Apple TV nomdl…",
        extra={"atv_id": "nomdl"},  # no model_identifier
    )
    v = c.latest_version(dev)
    assert v is not None
    assert v.raw == "26.5"
