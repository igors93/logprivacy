"""Small public functions for the most common LogCleaner use cases."""

from __future__ import annotations
from typing import Any
from logcleaner.cleaner import Cleaner
from logcleaner.policy import CleanerPolicy
from logcleaner.result import RedactionResult

_DEFAULT_CLEANER = Cleaner()

def clean(value: Any, *, policy: CleanerPolicy | None = None) -> Any:
    """Return a cleaned copy of a string or structured value."""
    cleaner = _DEFAULT_CLEANER if policy is None else Cleaner(policy=policy)
    return cleaner.clean(value)

def clean_text(text: str, *, policy: CleanerPolicy | None = None) -> str:
    """Return a cleaned string."""
    cleaner = _DEFAULT_CLEANER if policy is None else Cleaner(policy=policy)
    return cleaner.clean_text(text)

def clean_with_result(text: str, *, policy: CleanerPolicy | None = None) -> RedactionResult[str]:
    """Return a rich result containing the cleaned text and detected findings."""
    cleaner = _DEFAULT_CLEANER if policy is None else Cleaner(policy=policy)
    return cleaner.clean_with_result(text)
