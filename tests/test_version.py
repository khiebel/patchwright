"""Smoke tests for the Version semver-aware comparison."""

from patchwright.core.types import Version


def test_simple_semver_compare():
    assert Version("5.1.12") < Version("5.2.0")
    assert Version("1.33.1") < Version("1.36.0")
    assert Version("5.1.12") == Version("5.1.12")


def test_build_metadata_ignored():
    """The whole point of the semver fix: same version, different build hash."""
    assert Version("5.1.12") == Version("5.1.12+a10f0a5")
    assert not (Version("5.1.12") < Version("5.1.12+a10f0a5"))
    assert not (Version("5.1.12+a10f0a5") < Version("5.1.12"))


def test_unequal_with_build():
    """Different semver parts beat any build metadata."""
    assert Version("5.1.12+aaa") < Version("5.1.13+bbb")
    assert Version("5.2.0") > Version("5.1.99+xyz") if hasattr(Version, "__gt__") else \
        Version("5.1.99+xyz") < Version("5.2.0")


def test_string_fallback():
    """Non-numeric versions fall back to string compare."""
    a = Version("alpha")
    b = Version("beta")
    assert a < b


def test_extracts_parts():
    v = Version("5.1.12")
    assert v.parts == (5, 1, 12)


def test_extracts_parts_with_build():
    v = Version("5.1.12+a10f0a5")
    # parts should be (5, 1, 12) — build metadata stripped
    assert v.parts == (5, 1, 12)
