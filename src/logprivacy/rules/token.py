"""Token redaction rules."""

from __future__ import annotations

import re

from logprivacy.exceptions import InputLimitExceededError
from logprivacy.internal.matches import _DetectedMatch
from logprivacy.masking.strategy import MaskingStrategy
from logprivacy.masking.value import mask_concrete_value
from logprivacy.rules.base import RedactionRule

_BEARER_PATTERN = re.compile(
    r"(?P<prefix>\bBearer\s+)(?P<value>[A-Za-z0-9._~+/=-]{8,})",
    re.IGNORECASE,
)
_JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")


class TokenRule(RedactionRule):
    """Detect bearer tokens and JWT-like tokens."""

    name = "token"
    category = "token"

    def find(self, text: str) -> tuple[_DetectedMatch, ...]:
        """Return token matches."""
        return self._find_matches(text, max_matches=None)

    def find_limited(self, text: str, max_matches: int) -> tuple[_DetectedMatch, ...]:
        """Return token matches without exceeding the match budget."""
        return self._find_matches(text, max_matches=max_matches)

    def _find_matches(
        self,
        text: str,
        *,
        max_matches: int | None,
    ) -> tuple[_DetectedMatch, ...]:
        matches: list[_DetectedMatch] = []
        for match in _BEARER_PATTERN.finditer(text):
            if max_matches is not None and len(matches) >= max_matches:
                raise InputLimitExceededError(limit="max_matches", maximum=max_matches)
            matches.append(
                _DetectedMatch(
                    rule_name=self.name,
                    category=self.category,
                    start=match.start(),
                    end=match.end(),
                    matched=match.group(0),
                    reason="text matched a bearer token",
                    metadata={
                        "prefix": match.group("prefix"),
                        "value": match.group("value"),
                    },
                )
            )
        for match in _JWT_PATTERN.finditer(text):
            if max_matches is not None and len(matches) >= max_matches:
                raise InputLimitExceededError(limit="max_matches", maximum=max_matches)
            matches.append(
                _DetectedMatch(
                    rule_name=self.name,
                    category=self.category,
                    start=match.start(),
                    end=match.end(),
                    matched=match.group(0),
                    reason="text matched a JWT-like token",
                )
            )
        return tuple(matches)

    def replacement_for(self, match: _DetectedMatch, masking: MaskingStrategy) -> str:
        """Keep the Bearer prefix and mask the concrete token value."""
        prefix = match.metadata.get("prefix", "")
        value = match.metadata.get("value")
        if value is None:
            value = (
                match.matched[len(prefix) :]
                if prefix and match.matched.startswith(prefix)
                else match.matched
            )

        replacement = mask_concrete_value(
            value,
            category=match.category,
            rule_name=match.rule_name,
            reason=match.reason,
            masking=masking,
        )
        return f"{prefix}{replacement}"
