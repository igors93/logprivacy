"""Strict rules for sensitive environments."""

from __future__ import annotations

from logcleaner.rule_sets.default import default_rules
from logcleaner.rules import IPAddressRule, PhoneRule
from logcleaner.rules.base import RedactionRule


def strict_rules() -> tuple[RedactionRule, ...]:
    """Return a stricter rule set that also redacts IP addresses and phone numbers."""
    return (*default_rules(), IPAddressRule(), PhoneRule())
