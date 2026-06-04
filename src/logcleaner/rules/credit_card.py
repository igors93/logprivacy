"""Credit-card-like redaction rule with Luhn validation."""

from __future__ import annotations

import re

from logcleaner.result import Finding
from logcleaner.rules.base import RedactionRule

_CARD_PATTERN = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")


def _digits(value: str) -> str:
    return "".join(char for char in value if char.isdigit())


def _passes_luhn(value: str) -> bool:
    # Standard Luhn algorithm: double every second digit from the right,
    # subtract 9 when the result exceeds 9, then check that the total is
    # divisible by 10. Used to reject obvious false positives (random numbers
    # have only a ~10 % chance of passing by accident).
    digits = [int(char) for char in value]
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


class CreditCardRule(RedactionRule):
    """Detect credit-card-like values using a Luhn check to reduce false positives."""

    name = "credit_card"
    category = "credit_card"

    def find(self, text: str) -> tuple[Finding, ...]:
        """Return credit card findings."""
        findings: list[Finding] = []
        for match in _CARD_PATTERN.finditer(text):
            digits = _digits(match.group(0))
            if 13 <= len(digits) <= 19 and _passes_luhn(digits):
                findings.append(
                    Finding(
                        rule_name=self.name,
                        category=self.category,
                        start=match.start(),
                        end=match.end(),
                        matched=match.group(0),
                        reason="text matched a credit-card-like value that passed Luhn validation",
                    )
                )
        return tuple(findings)
