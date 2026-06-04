"""Credential key/value redaction rule."""

from __future__ import annotations

import re

from logcleaner.masking.strategy import MaskingStrategy
from logcleaner.result import Finding
from logcleaner.rules.base import RedactionRule

_CREDENTIAL_PATTERN = re.compile(
    r"(?P<key>\b(?:password|passwd|pwd|secret|api_key|apikey|access_key|access_token|"
    r"refresh_token|token|client_secret|private_key|auth_token|authorization|cookie|set-cookie)\b)"
    r"(?P<sep>\s*[:=]\s*)"
    r"(?P<quote>['\"]?)"
    r"(?P<value>[^'\"\s,;&]+)"
    r"(?P=quote)",
    re.IGNORECASE,
)


class CredentialRule(RedactionRule):
    """Detect values assigned to credential-like keys."""

    name = "credential"
    category = "credential"

    def find(self, text: str) -> tuple[Finding, ...]:
        """Return credential assignments as findings."""
        findings: list[Finding] = []
        for match in _CREDENTIAL_PATTERN.finditer(text):
            findings.append(
                Finding(
                    rule_name=self.name,
                    category=self.category,
                    start=match.start(),
                    end=match.end(),
                    matched=match.group(0),
                    reason=f"key {match.group('key')!r} is considered sensitive",
                    metadata={
                        "key": match.group("key"),
                        "sep": match.group("sep"),
                        "quote": match.group("quote"),
                    },
                )
            )
        return tuple(findings)

    def replacement_for(self, finding: Finding, masking: MaskingStrategy) -> str:
        """Keep the credential key visible and redact only the value."""
        key = finding.metadata.get("key", "secret")
        sep = finding.metadata.get("sep", "=")
        quote = finding.metadata.get("quote", "")
        return f"{key}{sep}{quote}{masking.mask_category('secret')}{quote}"
