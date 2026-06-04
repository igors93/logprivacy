"""Main cleaning engine."""
from __future__ import annotations
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any
from logcleaner.internal.replacement import apply_replacements
from logcleaner.policy import CleanerPolicy
from logcleaner.result import Finding, RedactionResult
from logcleaner.structured.mapping import clean_mapping
from logcleaner.structured.sequence import clean_sequence

@dataclass(frozen=True, slots=True)
class Cleaner:
    """Clean sensitive data from strings and structured values."""
    policy: CleanerPolicy = field(default_factory=CleanerPolicy.default)
    def clean(self, value: Any) -> Any:
        """Return a cleaned copy of a string or structured value."""
        return self._clean_value(value, depth=0)
    def clean_text(self, text: str) -> str:
        """Return a cleaned string."""
        return self.clean_with_result(text).cleaned
    def clean_with_result(self, text: str) -> RedactionResult[str]:
        """Return cleaned text plus metadata about the redaction process."""
        findings = self._find(text)
        cleaned, resolved = apply_replacements(text, findings, rules=self.policy.rules, masking=self.policy.masking)
        return RedactionResult(original=text, cleaned=cleaned, findings=resolved)
    def _find(self, text: str) -> tuple[Finding, ...]:
        findings: list[Finding] = []
        for rule in self.policy.rules:
            findings.extend(rule.find(text))
        return tuple(findings)
    def _clean_value(self, value: Any, *, depth: int) -> Any:
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
