"""Masking strategy interfaces and built-in strategies."""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from typing import Protocol

from logcleaner.masking.masks import keep_edges, mask_email, mask_token
from logcleaner.masking.placeholders import DEFAULT_PLACEHOLDERS
from logcleaner.result import Finding


class MaskingStrategy(Protocol):
    """Protocol implemented by objects that know how to mask findings."""

    def mask(self, finding: Finding) -> str:
        """Return the replacement text for a finding."""

    def mask_category(self, category: str) -> str:
        """Return the replacement text for a category."""


@dataclass(frozen=True, slots=True)
class PlaceholderMaskingStrategy:
    """Replace sensitive values with readable placeholders such as [EMAIL]."""

    placeholders: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_PLACEHOLDERS))
    fallback: str = "[REDACTED]"

    def mask(self, finding: Finding) -> str:
        """Return a placeholder for the finding category."""
        return self.mask_category(finding.category)

    def mask_category(self, category: str) -> str:
        """Return a placeholder for a category."""
        return self.placeholders.get(category, self.fallback)


@dataclass(frozen=True, slots=True)
class PartialMaskingStrategy:
    """Mask values while preserving enough shape for debugging."""

    fallback: str = "[REDACTED]"

    def mask(self, finding: Finding) -> str:
        """Return a partially masked value."""
        if finding.category == "email":
            return mask_email(finding.matched)
        if finding.category in {"token", "secret", "credential"}:
            return mask_token(finding.matched)
        if finding.category == "url":
            return "[URL]"
        return keep_edges(finding.matched)

    def mask_category(self, category: str) -> str:
        """Return a safe category placeholder when no concrete value exists."""
        return DEFAULT_PLACEHOLDERS.get(category, self.fallback)


@dataclass(frozen=True, slots=True)
class HashMaskingStrategy:
    """Mask values with stable short hashes for correlation without disclosure."""

    placeholders: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_PLACEHOLDERS))
    salt: str = ""
    length: int = 8

    def mask(self, finding: Finding) -> str:
        """Return a category-prefixed stable hash."""
        digest = sha256(f"{self.salt}{finding.matched}".encode()).hexdigest()
        label = self.placeholders.get(finding.category, "[REDACTED]").strip("[]")
        return f"[{label}:{digest[: self.length]}]"

    def mask_category(self, category: str) -> str:
        """Return a placeholder when no concrete value exists."""
        return self.placeholders.get(category, "[REDACTED]")
