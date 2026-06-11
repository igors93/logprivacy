"""Public structured field rules for JSON-safe sanitization."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from re import Pattern
from typing import Literal, TypeAlias

FieldAction: TypeAlias = Literal["mask", "remove", "truncate", "block"]
FieldMatchMode: TypeAlias = Literal["exact", "contains", "regex"]

_VALID_ACTIONS = frozenset({"mask", "remove", "truncate", "block"})
_VALID_MATCH_MODES = frozenset({"exact", "contains", "regex"})


@dataclass(frozen=True, slots=True)
class FieldRule:
    """Rule that applies a privacy action to mapping or object field names."""

    match: str
    action: FieldAction = "mask"
    mode: FieldMatchMode = "exact"
    max_chars: int | None = None
    _compiled: Pattern[str] | None = field(default=None, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.match, str) or not self.match.strip():
            raise ValueError("field rule match must be a non-empty string")
        if self.action not in _VALID_ACTIONS:
            raise ValueError("field rule action must be one of: mask, remove, truncate, block")
        if self.mode not in _VALID_MATCH_MODES:
            raise ValueError("field rule mode must be one of: exact, contains, regex")
        if self.action == "truncate":
            if isinstance(self.max_chars, bool) or not isinstance(self.max_chars, int):
                raise ValueError("truncate field rules require max_chars")
            if self.max_chars < 0:
                raise ValueError("max_chars must be greater than or equal to zero")
        elif self.max_chars is not None:
            raise ValueError("max_chars is only supported for truncate field rules")

        if self.mode == "regex":
            try:
                compiled = re.compile(self.match, flags=re.IGNORECASE)
            except re.error as exc:
                raise ValueError("invalid field rule regex") from exc
            object.__setattr__(self, "_compiled", compiled)

    @classmethod
    def exact(
        cls,
        match: str,
        *,
        action: FieldAction = "mask",
        max_chars: int | None = None,
    ) -> FieldRule:
        """Create a rule that matches a normalized field name exactly."""
        return cls(match=match, action=action, mode="exact", max_chars=max_chars)

    @classmethod
    def contains(
        cls,
        match: str,
        *,
        action: FieldAction = "mask",
        max_chars: int | None = None,
    ) -> FieldRule:
        """Create a rule that matches a normalized field-name substring."""
        return cls(match=match, action=action, mode="contains", max_chars=max_chars)

    @classmethod
    def regex(
        cls,
        match: str,
        *,
        action: FieldAction = "mask",
        max_chars: int | None = None,
    ) -> FieldRule:
        """Create a rule that matches the normalized field name with regex."""
        return cls(match=match, action=action, mode="regex", max_chars=max_chars)

    def matches(self, field_name: str) -> bool:
        """Return whether this rule matches ``field_name`` after normalization."""
        normalized_field = normalize_field_name(field_name)
        if self.mode == "exact":
            return normalized_field == normalize_field_name(self.match)
        if self.mode == "contains":
            return normalize_field_name(self.match) in normalized_field

        compiled = self._compiled
        if compiled is None:
            return False
        return compiled.search(normalized_field) is not None


def normalize_field_name(field_name: str) -> str:
    """Normalize field names for matching.

    Normalization trims surrounding whitespace, case-folds, splits camelCase,
    and treats spaces, hyphens, and underscores as the same separator.
    """
    stripped = field_name.strip()
    with_acronyms = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "_", stripped)
    with_boundaries = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", with_acronyms)
    separated = re.sub(r"[\s_-]+", "_", with_boundaries)
    return separated.strip("_").casefold()
