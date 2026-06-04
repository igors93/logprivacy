"""Configuration object for LogCleaner."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Literal

from logcleaner.masking.strategy import (
    HashMaskingStrategy,
    MaskingStrategy,
    PartialMaskingStrategy,
    PlaceholderMaskingStrategy,
)
from logcleaner.rules.base import RedactionRule

MaskingChoice = Literal["placeholder", "partial", "hash"]


_DEFAULT_SENSITIVE_KEYS = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_key",
    "access_token",
    "refresh_token",
    "client_secret",
    "private_key",
    "authorization",
    "cookie",
    "set-cookie",
)


def resolve_masking(masking: MaskingStrategy | MaskingChoice) -> MaskingStrategy:
    """Return a masking strategy from a strategy object or a simple name."""
    if not isinstance(masking, str):
        return masking
    if masking == "placeholder":
        return PlaceholderMaskingStrategy()
    if masking == "partial":
        return PartialMaskingStrategy()
    if masking == "hash":
        return HashMaskingStrategy()
    raise ValueError(f"Unknown masking strategy: {masking!r}")


@dataclass(frozen=True, slots=True)
class CleanerPolicy:
    """
    Configuration for Cleaner.

    A policy answers:
    - which rules are active
    - how findings are masked
    - how structured data should be traversed
    - which categories should be blocked instead of logged
    """

    rules: tuple[RedactionRule, ...] = field(default_factory=tuple)
    masking: MaskingStrategy = field(default_factory=PlaceholderMaskingStrategy)
    sensitive_keys: tuple[str, ...] = _DEFAULT_SENSITIVE_KEYS
    block_categories: tuple[str, ...] = ()
    clean_mapping_keys: bool = False
    max_depth: int = 20
    clean_unknown_objects: bool = False

    def __post_init__(self) -> None:
        """Load default rules when no explicit rule set is provided."""
        if not self.rules:
            from logcleaner.rule_sets.default import default_rules

            object.__setattr__(self, "rules", default_rules())

    @classmethod
    def default(cls, *, masking: MaskingStrategy | MaskingChoice = "placeholder") -> CleanerPolicy:
        """Return the default balanced policy."""
        from logcleaner.rule_sets.default import default_rules

        return cls(rules=default_rules(), masking=resolve_masking(masking))

    @classmethod
    def strict(cls, *, masking: MaskingStrategy | MaskingChoice = "placeholder") -> CleanerPolicy:
        """Return a stricter policy for sensitive environments."""
        from logcleaner.rule_sets.strict import strict_rules

        return cls(rules=strict_rules(), masking=resolve_masking(masking))

    @classmethod
    def web(cls, *, masking: MaskingStrategy | MaskingChoice = "placeholder") -> CleanerPolicy:
        """Return a policy focused on web and HTTP logs."""
        from logcleaner.rule_sets.web import web_rules

        return cls(rules=web_rules(), masking=resolve_masking(masking))

    @classmethod
    def production(cls) -> CleanerPolicy:
        """Return a production-oriented policy that blocks secrets and credentials."""
        return cls.strict().block("credential", "token", "secret", "credit_card")

    def add_rules(self, *rules: RedactionRule) -> CleanerPolicy:
        """Return a new policy with additional rules."""
        return replace(self, rules=(*self.rules, *rules))

    def with_rules(self, *rules: RedactionRule) -> CleanerPolicy:
        """Return a new policy using exactly the given rules."""
        return replace(self, rules=tuple(rules))

    def with_masking(self, masking: MaskingStrategy | MaskingChoice) -> CleanerPolicy:
        """Return a new policy with another masking strategy."""
        return replace(self, masking=resolve_masking(masking))

    def block(self, *categories: str) -> CleanerPolicy:
        """Return a new policy that blocks selected categories."""
        return replace(
            self, block_categories=tuple(dict.fromkeys((*self.block_categories, *categories)))
        )

    def without_categories(self, *categories: str) -> CleanerPolicy:
        """Return a new policy with selected categories disabled."""
        blocked = set(categories)
        return replace(
            self,
            rules=tuple(rule for rule in self.rules if rule.category not in blocked),
        )

    def is_sensitive_key(self, key: object) -> bool:
        """Return True when a mapping key should have its value fully redacted."""
        normalized = str(key).strip().lower().replace("-", "_")
        sensitive = {item.replace("-", "_") for item in self.sensitive_keys}
        return normalized in sensitive
