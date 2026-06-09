"""Credential key/value redaction rule."""

from __future__ import annotations

import re

from logprivacy.masking.strategy import MaskingStrategy
from logprivacy.result import Finding
from logprivacy.rules.base import RedactionRule

# Authorization values need dedicated handling.  The generic credential pattern
# stops at whitespace, so a value such as ``Bearer actual-token`` would otherwise
# redact only the word ``Bearer`` and leave the credential in the output.
_AUTHORIZATION_PATTERN = re.compile(
    r"(?P<key>\b(?:authorization|proxy[-_]?authorization)\b)"
    r"(?P<sep>\s*[:=]\s*)"
    r"(?P<quote>['\"]?)"
    r"(?P<scheme>Bearer|Basic)"
    r"(?P<scheme_sep>\s+)"
    r"(?P<value>[^'\"\s,;&]+)"
    r"(?P=quote)",
    re.IGNORECASE,
)

_CREDENTIAL_PATTERN = re.compile(
    r"(?P<key>\b(?:password|passwd|pwd|secret|api_key|apikey|access_key|access_token|"
    r"refresh_token|token|client_secret|private_key|auth_token|authorization|cookie|set-cookie)\b)"
    r"(?P<sep>\s*[:=]\s*)"
    r"(?P<quote>['\"]?)"
    r"(?P<value>[^'\"\s,;&]+)"
    r"(?P=quote)",
    re.IGNORECASE,
)


def _ranges_overlap(start: int, end: int, ranges: list[tuple[int, int]]) -> bool:
    """Return whether ``[start, end)`` overlaps any protected range."""
    return any(
        start < protected_end and protected_start < end for protected_start, protected_end in ranges
    )


class CredentialRule(RedactionRule):
    """Detect values assigned to credential-like keys."""

    name = "credential"
    category = "credential"

    def find(self, text: str) -> tuple[Finding, ...]:
        """Return credential assignments as findings."""
        findings: list[Finding] = []
        authorization_ranges: list[tuple[int, int]] = []

        # Detect complete Bearer and Basic authorization values before the
        # generic key/value rule.  Both matches start at the same key, but this
        # finding spans the real credential as well and therefore cannot leave
        # a token behind during overlap resolution.
        for match in _AUTHORIZATION_PATTERN.finditer(text):
            scheme = match.group("scheme")
            category = "token" if scheme.casefold() == "bearer" else "credential"
            findings.append(
                Finding(
                    rule_name=self.name,
                    category=category,
                    start=match.start(),
                    end=match.end(),
                    matched=match.group(0),
                    reason=f"authorization scheme {scheme!r} carries a sensitive credential",
                    metadata={
                        "kind": "authorization",
                        "key": match.group("key"),
                        "sep": match.group("sep"),
                        "quote": match.group("quote"),
                        "scheme": scheme,
                        "scheme_sep": match.group("scheme_sep"),
                        "value": match.group("value"),
                    },
                )
            )
            authorization_ranges.append((match.start(), match.end()))

        for match in _CREDENTIAL_PATTERN.finditer(text):
            # The authorization-specific match is complete and more precise.
            # Avoid returning a second, shorter finding such as
            # ``Authorization: Bearer`` for the same assignment.
            if _ranges_overlap(match.start(), match.end(), authorization_ranges):
                continue

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

        if finding.metadata.get("kind") == "authorization":
            scheme = finding.metadata.get("scheme", "")
            scheme_sep = finding.metadata.get("scheme_sep", " ")
            value = finding.metadata.get("value", "")

            # Mask only the actual credential so partial and hash strategies
            # remain meaningful and never hash or expose the header prefix.
            value_finding = Finding(
                rule_name=finding.rule_name,
                category=finding.category,
                start=0,
                end=len(value),
                matched=value,
                reason=finding.reason,
            )
            replacement = masking.mask(value_finding)
            return f"{key}{sep}{quote}{scheme}{scheme_sep}{replacement}{quote}"

        return f"{key}{sep}{quote}{masking.mask_category('secret')}{quote}"
