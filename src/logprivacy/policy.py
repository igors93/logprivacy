"""Configuration object for LogPrivacy."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Literal

from logprivacy.internal.traversal import safe_mapping_key_text
from logprivacy.masking.strategy import (
    HashMaskingStrategy,
    MaskingStrategy,
    PartialMaskingStrategy,
    PlaceholderMaskingStrategy,
)
from logprivacy.rules.base import RedactionRule

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
    Configuration for a ``Cleaner`` instance.

    A policy controls:

    - which rules are active (``rules``)
    - how findings are masked (``masking``)
    - how structured data is traversed (``max_depth``, ``max_items``)
    - how many audit findings are retained (``max_findings``)
    - which mapping keys are treated as sensitive (``sensitive_keys``)
    - which categories raise an exception instead of being redacted (``block_categories``)

    Use the factory class methods to get a sensible starting point, then compose
    further with ``add_rules()``, ``with_masking()``, or ``block()``.

    Example::

        policy = CleanerPolicy.default(masking="partial")
        policy = CleanerPolicy.strict().block("credential")
    """

    rules: tuple[RedactionRule, ...] = field(default_factory=tuple)
    masking: MaskingStrategy = field(default_factory=PlaceholderMaskingStrategy)
    sensitive_keys: tuple[str, ...] = _DEFAULT_SENSITIVE_KEYS
    block_categories: tuple[str, ...] = ()
    clean_mapping_keys: bool = False
    max_depth: int = 20
    max_items: int = 10_000
    max_findings: int = 1_000
    clean_unknown_objects: bool = False

    def __post_init__(self) -> None:
        """Validate traversal limits and load default rules when required."""
        _validate_non_negative_integer("max_depth", self.max_depth)
        _validate_positive_integer("max_items", self.max_items)
        _validate_positive_integer("max_findings", self.max_findings)

        if not self.rules:
            from logprivacy.rule_sets.default import default_rules

            object.__setattr__(self, "rules", default_rules())

    @classmethod
    def default(cls, *, masking: MaskingStrategy | MaskingChoice = "placeholder") -> CleanerPolicy:
        """
        Return the balanced default policy.

        Detects emails, credentials, tokens, secrets, URLs, and credit-card-like values.
        Safe for general-purpose log cleaning.
        """
        from logprivacy.rule_sets.default import default_rules

        return cls(rules=default_rules(), masking=resolve_masking(masking))

    @classmethod
    def strict(cls, *, masking: MaskingStrategy | MaskingChoice = "placeholder") -> CleanerPolicy:
        """
        Return a stricter policy for sensitive environments.

        Extends ``default()`` with IP address and phone number detection.
        Suitable when internal IPs or phone numbers must not appear in logs.
        """
        from logprivacy.rule_sets.strict import strict_rules

        return cls(rules=strict_rules(), masking=resolve_masking(masking))

    @classmethod
    def web(cls, *, masking: MaskingStrategy | MaskingChoice = "placeholder") -> CleanerPolicy:
        """
        Return a policy focused on web and HTTP logs.

        Detects URLs, credentials, tokens, and secrets. Omits email, credit
        card, IP address, and phone rules. Suitable for HTTP access log cleaning.
        """
        from logprivacy.rule_sets.web import web_rules

        return cls(rules=web_rules(), masking=resolve_masking(masking))

    @classmethod
    def production(cls) -> CleanerPolicy:
        """
        Return a production-safety policy that raises on high-risk categories.

        Extends ``strict()`` and blocks the ``credential``, ``token``, ``secret``,
        and ``credit_card`` categories so that a ``LogBlockedError`` is raised if any
        of those values reach a log statement. Use this when you want logging code to
        fail loudly instead of silently masking sensitive data.
        """
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
        """Return whether a mapping key requires fail-closed value redaction.

        Exact scalar and byte-like keys are converted without invoking arbitrary
        user code. Unknown key objects are treated as sensitive because their
        representation cannot be trusted safely.
        """
        key_text, trusted = safe_mapping_key_text(key)
        if not trusted:
            return True
        normalized = key_text.strip().casefold().replace("-", "_")
        sensitive = {item.casefold().replace("-", "_") for item in self.sensitive_keys}
        return normalized in sensitive


def _validate_non_negative_integer(name: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if value < 0:
        raise ValueError(f"{name} must be greater than or equal to zero")


def _validate_positive_integer(name: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if value <= 0:
        raise ValueError(f"{name} must be greater than zero")
