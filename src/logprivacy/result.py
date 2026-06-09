"""Result objects returned by LogPrivacy."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Generic, TypeVar

T = TypeVar("T")


@dataclass(frozen=True, slots=True, repr=False)
class Finding:
    """
    A sensitive value detected in text.

    ``matched`` and ``metadata`` may contain original sensitive content. They
    remain available for redaction internals and explicit inspection, but are
    deliberately excluded from ``repr()`` and from ``to_dict()`` by default.
    """

    rule_name: str
    category: str
    start: int
    end: int
    matched: str = field(repr=False)
    replacement: str = ""
    reason: str = ""
    metadata: dict[str, str] = field(default_factory=dict, repr=False)
    location: str = ""

    def __repr__(self) -> str:
        """Return a safe representation without matched or derived sensitive values."""
        location = f", location={self.location!r}" if self.location else ""
        return (
            f"{type(self).__name__}("
            f"rule_name={self.rule_name!r}, "
            f"category={self.category!r}, "
            f"start={self.start}, "
            f"end={self.end}, "
            f"has_replacement={bool(self.replacement)!r}"
            f"{location})"
        )

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
            location=self.location,
        )

    def with_location(self, location: str) -> Finding:
        """Return this finding with a safe human-readable source location."""
        return Finding(
            rule_name=self.rule_name,
            category=self.category,
            start=self.start,
            end=self.end,
            matched=self.matched,
            replacement=self.replacement,
            reason=self.reason,
            metadata=dict(self.metadata),
            location=location,
        )

    def to_dict(
        self,
        *,
        include_match: bool = False,
        include_metadata: bool = False,
    ) -> dict[str, Any]:
        """
        Return a JSON-friendly representation.

        Sensitive source text and rule metadata are excluded by default. Use
        ``include_match=True`` or ``include_metadata=True`` only in a trusted
        context that is not written to logs, telemetry, or user-visible output.
        """
        data: dict[str, Any] = {
            "rule_name": self.rule_name,
            "category": self.category,
            "start": self.start,
            "end": self.end,
            "replacement": self.replacement,
            "reason": self.reason,
        }
        if self.location:
            data["location"] = self.location
        if include_match:
            data["matched"] = self.matched
        if include_metadata:
            data["metadata"] = dict(self.metadata)
        return data


@dataclass(frozen=True, slots=True, repr=False)
class RedactionResult(Generic[T]):
    """
    The result of a cleaning operation, pairing the cleaned value with finding metadata.

    ``original`` and the nested findings can contain sensitive values. The
    representation therefore contains only aggregate, non-sensitive state.
    Use ``summary()`` or ``explain()`` for safe diagnostic output.
    """

    original: T = field(repr=False)
    cleaned: T = field(repr=False)
    findings: tuple[Finding, ...] = field(default=(), repr=False)

    def __repr__(self) -> str:
        """Return a safe representation without original or cleaned payloads."""
        return (
            f"{type(self).__name__}("
            f"changed={self.changed!r}, "
            f"finding_count={self.finding_count}, "
            f"categories={self.categories!r})"
        )

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
            return "LogPrivacy found no sensitive values."

        lines = [
            f"LogPrivacy found {self.finding_count} sensitive value(s).",
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
