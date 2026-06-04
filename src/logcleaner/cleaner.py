"""Main cleaning engine."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from logcleaner.audit import AuditReport
from logcleaner.exceptions import LogBlockedError
from logcleaner.internal.replacement import apply_replacements, select_non_overlapping
from logcleaner.policy import CleanerPolicy
from logcleaner.result import Finding, RedactionResult
from logcleaner.structured.mapping import clean_mapping
from logcleaner.structured.sequence import clean_sequence


@dataclass(frozen=True, slots=True)
class Cleaner:
    """
    Clean sensitive data from strings and structured values.

    Cleaner is intentionally small: policies decide what to detect, rules detect
    findings, and masking strategies decide how findings are replaced.
    """

    policy: CleanerPolicy = field(default_factory=CleanerPolicy.default)

    def clean(self, value: Any) -> Any:
        """Return a cleaned copy of a string or structured value."""
        return self._clean_value(value, depth=0)

    def clean_text(self, text: str) -> str:
        """Return a cleaned string."""
        return self.clean_with_result(text).cleaned

    def clean_with_result(self, text: str) -> RedactionResult[str]:
        """Return cleaned text plus safe metadata about the redaction process."""
        findings = select_non_overlapping(self._find(text))
        self._raise_if_blocked(findings)
        cleaned, resolved_findings = apply_replacements(
            text,
            findings,
            rules=self.policy.rules,
            masking=self.policy.masking,
        )
        return RedactionResult(original=text, cleaned=cleaned, findings=resolved_findings)

    def audit(self, value: Any) -> AuditReport:
        """Return an audit report without modifying the input."""
        text = value if isinstance(value, str) else repr(value)
        return AuditReport(select_non_overlapping(self._find(text)))

    def explain(self, text: str) -> str:
        """Return a human-readable explanation of how text is cleaned."""
        return self.clean_with_result(text).explain()

    def _find(self, text: str) -> tuple[Finding, ...]:
        """Return all findings detected by active rules."""
        findings: list[Finding] = []
        for rule in self.policy.rules:
            findings.extend(rule.find(text))
        return tuple(findings)

    def _raise_if_blocked(self, findings: tuple[Finding, ...]) -> None:
        """Raise when policy block categories are present."""
        blocked = tuple(
            dict.fromkeys(
                finding.category
                for finding in findings
                if finding.category in self.policy.block_categories
            )
        )
        if blocked:
            joined = ", ".join(blocked)
            raise LogBlockedError(
                f"LogCleaner blocked sensitive categories: {joined}", categories=blocked
            )

    def _clean_value(self, value: Any, *, depth: int) -> Any:
        """Recursively clean a value according to the active policy."""
        if depth > self.policy.max_depth:
            return value

        if isinstance(value, str):
            return self.clean_text(value)

        if isinstance(value, Mapping):
            return clean_mapping(value, self, depth)

        if isinstance(value, Sequence) and not isinstance(value, bytes | bytearray):
            return clean_sequence(value, self, depth)

        if self.policy.clean_unknown_objects and value is not None:
            return self.clean_text(str(value))

        return value
