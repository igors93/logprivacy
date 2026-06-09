"""Token redaction rules."""

from __future__ import annotations

import re

from logprivacy.masking.strategy import MaskingStrategy
from logprivacy.masking.value import mask_concrete_value
from logprivacy.result import Finding
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

    def find(self, text: str) -> tuple[Finding, ...]:
        """Return token findings."""
        findings: list[Finding] = []
        for match in _BEARER_PATTERN.finditer(text):
            findings.append(
                Finding(
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
            findings.append(
                Finding(
                    rule_name=self.name,
                    category=self.category,
                    start=match.start(),
                    end=match.end(),
                    matched=match.group(0),
                    reason="text matched a JWT-like token",
                )
            )
        return tuple(findings)

    def replacement_for(self, finding: Finding, masking: MaskingStrategy) -> str:
        """Keep the Bearer prefix and mask the concrete token value."""
        prefix = finding.metadata.get("prefix", "")
        value = finding.metadata.get("value")
        if value is None:
            value = (
                finding.matched[len(prefix) :]
                if prefix and finding.matched.startswith(prefix)
                else finding.matched
            )

        replacement = mask_concrete_value(
            value,
            category=finding.category,
            rule_name=finding.rule_name,
            reason=finding.reason,
            masking=masking,
        )
        return f"{prefix}{replacement}"
