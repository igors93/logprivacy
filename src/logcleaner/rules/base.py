"""Base classes for redaction rules."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from re import Pattern

from logcleaner.masking.strategy import MaskingStrategy
from logcleaner.result import Finding


class RedactionRule:
    """Base class for objects that find sensitive values in text."""

    name: str
    category: str

    def find(self, text: str) -> tuple[Finding, ...]:
        """Return all findings detected in text."""
        raise NotImplementedError

    def replacement_for(self, finding: Finding, masking: MaskingStrategy) -> str:
        """Return replacement text for a finding."""
        return masking.mask(finding)


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

    def find(self, text: str) -> tuple[Finding, ...]:
        """Return regex matches as findings."""
        return tuple(
            Finding(
                rule_name=self.name,
                category=self.category,
                start=match.start(),
                end=match.end(),
                matched=match.group(0),
                reason=self.reason,
            )
            for match in self.pattern.finditer(text)
        )
