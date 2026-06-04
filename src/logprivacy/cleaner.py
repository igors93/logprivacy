"""Main cleaning engine."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from logprivacy.audit import AuditReport
from logprivacy.exceptions import LogBlockedError
from logprivacy.internal.replacement import apply_replacements, select_non_overlapping
from logprivacy.policy import CleanerPolicy
from logprivacy.result import Finding, RedactionResult
from logprivacy.structured.mapping import clean_mapping
from logprivacy.structured.sequence import clean_sequence


@dataclass(frozen=True, slots=True)
class Cleaner:
    """
    Clean sensitive data from strings and structured values.

    ``Cleaner`` is intentionally small: policies decide what to detect, rules
    detect findings, and masking strategies decide how findings are replaced.

    Example::

        cleaner = Cleaner(policy=CleanerPolicy.strict())
        cleaner.clean("client_ip=192.168.1.1 email=john@example.com")
        # "client_ip=[IP_ADDRESS] email=[EMAIL]"
    """

    policy: CleanerPolicy = field(default_factory=CleanerPolicy.default)

    def clean(self, value: Any) -> Any:
        """Return a cleaned copy of a string, dict, list, or tuple."""
        return self._clean_value(value, depth=0)

    def clean_text(self, text: str) -> str:
        """Return a cleaned string."""
        return self.clean_with_result(text).cleaned

    def clean_with_result(self, text: str) -> RedactionResult[str]:
        """Return cleaned text and a ``RedactionResult`` with finding details."""
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
        """
        Return an audit report without modifying the input.

        Works on strings, dicts, lists, and tuples. Nested structures are
        traversed recursively up to ``policy.max_depth``.

        Example::

            audit({"password": "123"}).safe  # False
            audit(["user@example.com"]).safe  # False
        """
        return AuditReport(self._collect_audit_findings(value, depth=0))

    def _collect_audit_findings(self, value: Any, *, depth: int) -> tuple[Finding, ...]:
        """Recursively collect non-overlapping findings without modifying the input."""
        if depth > self.policy.max_depth:
            return ()

        if isinstance(value, str):
            return select_non_overlapping(self._find(value))

        if isinstance(value, Mapping):
            findings: list[Finding] = []
            for k, v in value.items():
                if self.policy.is_sensitive_key(k):
                    # Sensitive key: treat the whole value as a credential finding
                    val_str = v if isinstance(v, str) else str(v)
                    if val_str:
                        findings.append(
                            Finding(
                                rule_name="sensitive_key",
                                category="credential",
                                start=0,
                                end=len(val_str),
                                matched=val_str,
                                reason=f"value of sensitive key {str(k)!r}",
                            )
                        )
                else:
                    findings.extend(self._collect_audit_findings(v, depth=depth + 1))
            return tuple(findings)

        if isinstance(value, Sequence) and not isinstance(value, bytes | bytearray):
            seq_findings: list[Finding] = []
            for item in value:
                seq_findings.extend(self._collect_audit_findings(item, depth=depth + 1))
            return tuple(seq_findings)

        if value is not None:
            return select_non_overlapping(self._find(str(value)))

        return ()

    def explain(self, text: str) -> str:
        """Return a human-readable explanation of what would be redacted and why."""
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
                f"LogPrivacy blocked sensitive categories: {joined}", categories=blocked
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
