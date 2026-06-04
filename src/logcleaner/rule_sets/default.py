"""Default rules for balanced log cleaning."""

from __future__ import annotations

from logcleaner.rules import (
    CredentialRule,
    CreditCardRule,
    EmailRule,
    SecretRule,
    TokenRule,
    UrlRule,
)
from logcleaner.rules.base import RedactionRule


def default_rules() -> tuple[RedactionRule, ...]:
    """Return the default rules used by clean()."""
    return (
        UrlRule(),
        CredentialRule(),
        TokenRule(),
        SecretRule(),
        CreditCardRule(),
        EmailRule(),
    )
