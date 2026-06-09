"""Shared limits and fail-closed helpers for structured traversal."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TypeVar, cast

MAX_DEPTH_PLACEHOLDER = "[MAX_DEPTH]"
TRUNCATED_PLACEHOLDER = "[TRUNCATED]"
RECURSIVE_PLACEHOLDER = "[RECURSIVE]"
UNAVAILABLE_PLACEHOLDER = "[UNAVAILABLE]"
TRUNCATED_MAPPING_KEY = "[LOGPRIVACY_TRUNCATED]"
ERROR_MAPPING_KEY = "[LOGPRIVACY_ERROR]"

LIMIT_MAX_DEPTH = "max_depth"
LIMIT_MAX_ITEMS = "max_items"
LIMIT_MAX_FINDINGS = "max_findings"
LIMIT_ITERATION_ERROR = "iteration_error"
LIMIT_REPRESENTATION_ERROR = "representation_error"

_EXACT_SCALAR_TYPES = frozenset({int, float, complex, bool, type(None)})
_T = TypeVar("_T")


@dataclass(slots=True)
class TraversalState:
    """Track one cleaning or audit traversal without leaking source values."""

    remaining_items: int
    remaining_findings: int | None = None
    active: set[int] = field(default_factory=set)
    limitations: list[str] = field(default_factory=list)

    def consume_item(self) -> bool:
        """Consume one global item from the traversal budget."""
        if self.remaining_items <= 0:
            self.mark_limit(LIMIT_MAX_ITEMS)
            return False
        self.remaining_items -= 1
        return True

    def take_findings(self, findings: tuple[_T, ...]) -> tuple[_T, ...]:
        """Return the allowed prefix of findings and record truncation safely."""
        if self.remaining_findings is None:
            return findings
        if self.remaining_findings <= 0:
            if findings:
                self.mark_limit(LIMIT_MAX_FINDINGS)
            return ()
        if len(findings) <= self.remaining_findings:
            self.remaining_findings -= len(findings)
            return findings

        allowed = findings[: self.remaining_findings]
        self.remaining_findings = 0
        self.mark_limit(LIMIT_MAX_FINDINGS)
        return allowed

    def mark_limit(self, reason: str) -> None:
        """Record a non-sensitive limitation once, preserving encounter order."""
        if reason not in self.limitations:
            self.limitations.append(reason)

    @property
    def complete(self) -> bool:
        """Return whether the whole input was inspected within configured limits."""
        return not self.limitations


def safe_mapping_key_text(key: object) -> tuple[str, bool]:
    """Return a bounded key label and whether conversion avoided user code.

    Arbitrary key objects are represented only by their type name. The caller can
    then fail closed by treating the associated value as sensitive.
    """
    key_type = type(key)
    if key_type is str:
        return cast(str, key), True
    if key_type in _EXACT_SCALAR_TYPES:
        return repr(key), True
    if key_type is bytes:
        return cast(bytes, key).decode("utf-8", errors="replace"), True
    if key_type is bytearray:
        return bytes(cast(bytearray, key)).decode("utf-8", errors="replace"), True
    if key_type is memoryview:
        return bytes(cast(memoryview, key)).decode("utf-8", errors="replace"), True
    return f"<{key_type.__name__}>", False
