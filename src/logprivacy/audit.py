"""Audit reports for sensitive data detection."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from logprivacy.result import Finding

_HIGH_RISK = {"credential", "token", "secret", "credit_card"}
_MAX_DESCRIBED_FINDINGS = 20


@dataclass(frozen=True, slots=True, repr=False)
class AuditReport:
    """
    A safe report describing whether a value contains sensitive data.

    Created by ``audit()`` or ``Cleaner.audit()``. Findings expose safe source
    locations such as ``$.user.password`` or ``app.log:12:5`` while original
    matched values remain excluded from normal representations and summaries.
    """

    findings: tuple[Finding, ...] = field(repr=False)

    def __repr__(self) -> str:
        """Return a safe representation without nested finding contents."""
        return (
            f"{type(self).__name__}("
            f"safe={self.safe!r}, "
            f"risk_level={self.risk_level!r}, "
            f"finding_count={self.finding_count}, "
            f"categories={self.categories!r}, "
            f"location_count={len(self.locations)})"
        )

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
    def locations(self) -> tuple[str, ...]:
        """Return distinct safe source locations in order of first appearance."""
        seen: list[str] = []
        for finding in self.findings:
            if finding.location and finding.location not in seen:
                seen.append(finding.location)
        return tuple(seen)

    @property
    def risk_level(self) -> str:
        """Return ``none``, ``low``, ``medium``, or ``high``."""
        if not self.findings:
            return "none"
        if any(finding.category in _HIGH_RISK for finding in self.findings):
            return "high"
        if len(self.findings) >= 3:
            return "medium"
        return "low"

    def summary(self) -> dict[str, Any]:
        """Return aggregate safe data, including distinct finding locations."""
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.category] = counts.get(finding.category, 0) + 1
        return {
            "safe": self.safe,
            "risk_level": self.risk_level,
            "finding_count": self.finding_count,
            "categories": list(self.categories),
            "counts": counts,
            "locations": list(self.locations),
        }

    def details(self) -> list[dict[str, Any]]:
        """Return per-finding safe details without matches, metadata, or replacements."""
        return [
            {
                "rule_name": finding.rule_name,
                "category": finding.category,
                "location": finding.location,
                "start": finding.start,
                "end": finding.end,
                "reason": finding.reason,
            }
            for finding in self.findings
        ]

    def describe(self) -> str:
        """Return a bounded human-readable report with safe locations."""
        if self.safe:
            return "LogPrivacy audit: safe. No sensitive values were found."

        lines = [
            "LogPrivacy audit",
            "",
            f"Risk level: {self.risk_level}",
            f"Findings: {self.finding_count}",
            f"Categories: {', '.join(self.categories)}",
        ]

        located = [finding for finding in self.findings if finding.location]
        if located:
            lines.extend(("", "Locations:"))
            for index, finding in enumerate(located[:_MAX_DESCRIBED_FINDINGS], start=1):
                lines.append(
                    f"{index}. {finding.category} at {finding.location} (rule: {finding.rule_name})"
                )
            remaining = len(located) - _MAX_DESCRIBED_FINDINGS
            if remaining > 0:
                lines.append(f"... and {remaining} more finding(s)")

        return "\n".join(lines)
