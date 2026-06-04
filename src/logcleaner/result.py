"""Result objects returned by LogCleaner."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Generic, TypeVar

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class Finding:
    """A sensitive value found in text."""

    rule_name: str
    category: str
    start: int
    end: int
    matched: str
    replacement: str = ""
    metadata: dict[str, str] = field(default_factory=dict)

    @property
    def length(self) -> int:
        return self.end - self.start

    def with_replacement(self, replacement: str) -> Finding:
        return Finding(
            self.rule_name,
            self.category,
            self.start,
            self.end,
            self.matched,
            replacement,
            dict(self.metadata),
        )

    def to_dict(self, *, include_match: bool = False) -> dict[str, Any]:
        data: dict[str, Any] = {
            "rule_name": self.rule_name,
            "category": self.category,
            "start": self.start,
            "end": self.end,
            "replacement": self.replacement,
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
        return self.original != self.cleaned

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def categories(self) -> tuple[str, ...]:
        seen: list[str] = []
        for finding in self.findings:
            if finding.category not in seen:
                seen.append(finding.category)
        return tuple(seen)

    def summary(self) -> dict[str, Any]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.category] = counts.get(finding.category, 0) + 1
        return {
            "changed": self.changed,
            "finding_count": self.finding_count,
            "categories": list(self.categories),
            "counts": counts,
        }
