"""Audit reports for sensitive data detection."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from logprivacy.result import Finding

_HIGH_RISK = {"credential", "token", "secret", "credit_card"}


@dataclass(frozen=True, slots=True)
class AuditReport:
    """
    A safe report describing whether a value contains sensitive data.

    Created by ``audit()`` or ``Cleaner.audit()``. Never exposes the original
    sensitive values — only categories, counts, and a risk level.

    Example::

        report = audit("Authorization: Bearer secret-token")
        report.safe        # False
        report.risk_level  # "high"
        report.categories  # ("token",)
        report.describe()
    """

    findings: tuple[Finding, ...]

    @property
    def safe(self) -> bool:
        """Return ``True`` when no sensitive values were found."""
        return not self.findings

    @property
    def finding_count(self) -> int:
        """Return the total number of sensitive findings."""
        return len(self.findings)

    @property
    def categories(self) -> tuple[str, ...]:
        """Return distinct finding categories in order of first appearance."""
        seen: list[str] = []
        for finding in self.findings:
            if finding.category not in seen:
                seen.append(finding.category)
        return tuple(seen)

    @property
    def risk_level(self) -> str:
        """
        Return a coarse risk level string: ``"none"``, ``"low"``, ``"medium"``, or ``"high"``.

        High-risk categories are: credential, token, secret, credit_card.
        """
        if not self.findings:
            return "none"
        if any(finding.category in _HIGH_RISK for finding in self.findings):
            return "high"
        if len(self.findings) >= 3:
            return "medium"
        return "low"

    def summary(self) -> dict[str, Any]:
        """Return a structured summary dict that does not include original sensitive values."""
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.category] = counts.get(finding.category, 0) + 1
        return {
            "safe": self.safe,
            "risk_level": self.risk_level,
            "finding_count": self.finding_count,
            "categories": list(self.categories),
            "counts": counts,
        }

    def describe(self) -> str:
        """Return a human-readable safe report."""
        if self.safe:
            return "LogPrivacy audit: safe. No sensitive values were found."

        lines = [
            "LogPrivacy audit",
            "",
            f"Risk level: {self.risk_level}",
            f"Findings: {self.finding_count}",
            f"Categories: {', '.join(self.categories)}",
        ]
        return "\n".join(lines)
