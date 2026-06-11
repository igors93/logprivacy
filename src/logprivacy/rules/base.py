"""Base classes for redaction rules."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from re import Pattern

from logprivacy.exceptions import InputLimitExceededError
from logprivacy.internal.matches import _DetectedMatch
from logprivacy.masking.strategy import MaskingStrategy


class RedactionRule:
    """Base class for objects that find sensitive values in text."""

    name: str
    category: str

    def find(self, text: str) -> tuple[_DetectedMatch, ...]:
        """Return all matches detected in text as internal DetectedMatch objects."""
        raise NotImplementedError

    def find_limited(self, text: str, max_matches: int) -> tuple[_DetectedMatch, ...]:
        """Return matches while enforcing a caller-provided safety budget."""
        matches = self.find(text)
        if len(matches) > max_matches:
            raise InputLimitExceededError(limit="max_matches", maximum=max_matches)
        return matches

    def replacement_for(self, match: _DetectedMatch, masking: MaskingStrategy) -> str:
        """Return replacement text for a detected match."""
        return masking.mask_value(match.matched, match.category)


@dataclass(frozen=True, slots=True)
class RegexRedactionRule(RedactionRule):
    """Redaction rule backed by a compiled regular expression."""

    name: str
    category: str
    pattern: Pattern[str] = field(repr=False)
    reason: str = ""

    @classmethod
    def from_pattern(
        cls,
        *,
        name: str,
        category: str,
        pattern: str,
        flags: int = 0,
        reason: str = "",
    ) -> RegexRedactionRule:
        """Create a regex rule from a pattern string."""
        return cls(name=name, category=category, pattern=re.compile(pattern, flags), reason=reason)

    def find(self, text: str) -> tuple[_DetectedMatch, ...]:
        """Return regex matches as internal DetectedMatch objects."""
        return self._find_matches(text, max_matches=None)

    def find_limited(self, text: str, max_matches: int) -> tuple[_DetectedMatch, ...]:
        """Return regex matches without materializing more than the budget."""
        return self._find_matches(text, max_matches=max_matches)

    def _find_matches(
        self,
        text: str,
        *,
        max_matches: int | None,
    ) -> tuple[_DetectedMatch, ...]:
        matches: list[_DetectedMatch] = []
        for match in self.pattern.finditer(text):
            if max_matches is not None and len(matches) >= max_matches:
                raise InputLimitExceededError(limit="max_matches", maximum=max_matches)
            matches.append(
                _DetectedMatch(
                    rule_name=self.name,
                    category=self.category,
                    start=match.start(),
                    end=match.end(),
                    matched=match.group(0),
                    reason=self.reason,
                )
            )
        return tuple(matches)

    def replacement_for(self, match: _DetectedMatch, masking: MaskingStrategy) -> str:
        """Return replacement via the masking strategy."""
        return masking.mask_value(match.matched, match.category)
