"""Tests that version is consistent across pyproject.toml and __init__."""

from __future__ import annotations

import re
from pathlib import Path


def _pyproject_version() -> str:
    root = Path(__file__).parent.parent.parent
    text = (root / "pyproject.toml").read_text(encoding="utf-8")
    # Extract version = "x.y.z" from the [project] table
    match = re.search(r'^\s*version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    assert match, "Could not find version in pyproject.toml"
    return match.group(1)


def test_version_consistent_across_pyproject_and_init() -> None:
    import logprivacy

    pyproject_version = _pyproject_version()
    assert logprivacy.__version__ == pyproject_version, (
        f"logprivacy.__version__ ({logprivacy.__version__!r}) "
        f"differs from pyproject.toml ({pyproject_version!r})"
    )


def test_version_is_semver_like() -> None:
    import logprivacy

    parts = logprivacy.__version__.split(".")
    assert len(parts) >= 2
    for part in parts:
        assert part.isdigit(), f"Non-numeric version segment: {part!r}"
