"""Sequence cleaning support."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any


def clean_sequence(sequence: Sequence[Any], cleaner: Any, depth: int) -> Any:
    """Return a cleaned copy of a sequence."""
    cleaned = [cleaner._clean_value(item, depth=depth + 1) for item in sequence]
    if isinstance(sequence, tuple):
        return tuple(cleaned)
    return cleaned
