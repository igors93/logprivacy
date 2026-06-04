"""Base classes for redaction rules."""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Pattern
from logcleaner.masking.strategy import MaskingStrategy
from logcleaner.result import Finding

class RedactionRule:
    """Base class for objects that find sensitive values in text."""
    name: str
    category: str
    def find(self, text: str) -> tuple[Finding, ...]:
        raise NotImplementedError
    def replacement_for(self, finding: Finding, masking: MaskingStrategy) -> str:
        return masking.mask(finding)

@dataclass(frozen=True, slots=True)
class RegexRedactionRule(RedactionRule):
    """Redaction rule backed by a compiled regular expression."""
    name: str
    category: str
    pattern: Pattern[str] = field(repr=False)
    @classmethod
    def from_pattern(cls, *, name: str, category: str, pattern: str, flags: int = 0) -> "RegexRedactionRule":
        return cls(name=name, category=category, pattern=re.compile(pattern, flags))
    def find(self, text: str) -> tuple[Finding, ...]:
        return tuple(Finding(self.name, self.category, m.start(), m.end(), m.group(0)) for m in self.pattern.finditer(text))
