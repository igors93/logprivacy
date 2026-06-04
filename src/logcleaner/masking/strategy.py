"""Masking strategy interfaces and default placeholder masking."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from logcleaner.masking.placeholders import DEFAULT_PLACEHOLDERS
from logcleaner.result import Finding


class MaskingStrategy(Protocol):
    def mask(self, finding: Finding) -> str: ...
    def mask_category(self, category: str) -> str: ...


@dataclass(frozen=True, slots=True)
class PlaceholderMaskingStrategy:
    """Replace sensitive values with readable placeholders such as [EMAIL]."""

    placeholders: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_PLACEHOLDERS))
    fallback: str = "[REDACTED]"

    def mask(self, finding: Finding) -> str:
        return self.mask_category(finding.category)

    def mask_category(self, category: str) -> str:
        return self.placeholders.get(category, self.fallback)
