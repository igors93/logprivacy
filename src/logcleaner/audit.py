"""Audit reports for sensitive data detection."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from logcleaner.result import Finding

_HIGH_RISK = {"credential", "token", "secret", "credit_card"}


@dataclass(frozen=True, slots=True)
class AuditReport:
    """A safe report describing whether a value contains sensitive data."""

    findings: tuple[Finding, ...]

    @property
    def safe(self) -> bool:
        """Return True when no sensitive values were found."""
        return not self.findings

    @property
    def finding_count(self) -> int:
        """Return the number of sensitive findings."""
        return len(self.findings)

    @property
    def categories(self) -> tuple[str, ...]:
        """Return distinct finding categories in order of appearance."""
        seen: list[str] = []
        for finding in self.findings:
            if finding.category not in seen:
                seen.append(finding.category)
        return tuple(seen)

    @property
    def risk_level(self) -> str:
        """Return a coarse risk level: none, low, medium, or high."""
        if not self.findings:
            return "none"
        if any(finding.category in _HIGH_RISK for finding in self.findings):
            return "high"
        if len(self.findings) >= 3:
            return "medium"
        return "low"

    def summary(self) -> dict[str, Any]:
        """Return a safe summary that does not include original matched values."""
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
            return "LogCleaner audit: safe. No sensitive values were found."

        lines = [
            "LogCleaner audit",
            "",
            f"Risk level: {self.risk_level}",
            f"Findings: {self.finding_count}",
            f"Categories: {', '.join(self.categories)}",
        ]
        return "\n".join(lines)
