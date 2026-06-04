"""Result objects returned by LogCleaner."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Generic, TypeVar

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class Finding:
    """
    A sensitive value found in text.

    The original matched value is stored so advanced users can inspect findings.
    Do not log findings directly if you want to avoid exposing sensitive data.
    """

    rule_name: str
    category: str
    start: int
    end: int
    matched: str
    replacement: str = ""
    reason: str = ""
    metadata: dict[str, str] = field(default_factory=dict)

    @property
    def length(self) -> int:
        """Return the number of characters covered by this finding."""
        return self.end - self.start

    def with_replacement(self, replacement: str) -> Finding:
        """Return this finding with a resolved replacement value."""
        return Finding(
            rule_name=self.rule_name,
            category=self.category,
            start=self.start,
            end=self.end,
            matched=self.matched,
            replacement=replacement,
            reason=self.reason,
            metadata=dict(self.metadata),
        )

    def to_dict(self, *, include_match: bool = False) -> dict[str, Any]:
        """Return a JSON-friendly representation."""
        data: dict[str, Any] = {
            "rule_name": self.rule_name,
            "category": self.category,
            "start": self.start,
            "end": self.end,
            "replacement": self.replacement,
            "reason": self.reason,
            "metadata": dict(self.metadata),
        }
        if include_match:
            data["matched"] = self.matched
        return data


@dataclass(frozen=True, slots=True)
class RedactionResult(Generic[T]):
    """A cleaned value plus information about what was changed."""

    original: T
    cleaned: T
    findings: tuple[Finding, ...] = ()

    @property
    def changed(self) -> bool:
        """Return True when the cleaned value differs from the original."""
        return self.original != self.cleaned

    @property
    def finding_count(self) -> int:
        """Return how many findings were redacted."""
        return len(self.findings)

    @property
    def categories(self) -> tuple[str, ...]:
        """Return distinct finding categories in order of appearance."""
        seen: list[str] = []
        for finding in self.findings:
            if finding.category not in seen:
                seen.append(finding.category)
        return tuple(seen)

    def summary(self) -> dict[str, Any]:
        """Return a compact, safe summary without original sensitive values."""
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.category] = counts.get(finding.category, 0) + 1
        return {
            "changed": self.changed,
            "finding_count": self.finding_count,
            "categories": list(self.categories),
            "counts": counts,
        }

    def explain(self) -> str:
        """Return a human-readable explanation of what was redacted."""
        if not self.findings:
            return "LogCleaner found no sensitive values."

        lines = [
            f"LogCleaner found {self.finding_count} sensitive value(s).",
            "",
        ]
        for index, finding in enumerate(self.findings, start=1):
            reason = finding.reason or f"text matched the {finding.rule_name!r} rule"
            lines.extend(
                [
                    f"{index}. {finding.category}",
                    f"   Rule: {finding.rule_name}",
                    f"   Reason: {reason}",
                    f"   Action: replaced with {finding.replacement}",
                    "",
                ]
            )
        return "\n".join(lines).rstrip()
