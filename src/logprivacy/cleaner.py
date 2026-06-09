"""Main cleaning engine."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, cast

from logprivacy.audit import AuditReport
from logprivacy.exceptions import LogBlockedError
from logprivacy.internal.audit_location import (
    append_mapping_key,
    append_sequence_index,
    root_location,
    safe_mapping_key_text,
)
from logprivacy.internal.replacement import apply_replacements, select_non_overlapping
from logprivacy.masking.strategy import PlaceholderMaskingStrategy
from logprivacy.policy import CleanerPolicy
from logprivacy.result import Finding, RedactionResult
from logprivacy.structured.mapping import clean_mapping
from logprivacy.structured.sequence import clean_sequence

_EXACT_BYTE_TYPES = frozenset({bytes, bytearray, memoryview})
_EXACT_SCALAR_TYPES = frozenset({int, float, complex, bool})


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

        Structured findings include a safe JSONPath-like location. Text findings
        use ``$`` as the root location. Nested structures are traversed up to
        ``policy.max_depth`` and recursive containers are handled safely.

        Example::

            report = audit({"user": {"password": "123"}})
            report.findings[0].location  # "$.user.password"
        """
        findings = self._collect_audit_findings(
            value,
            depth=0,
            location=root_location(),
            active=set(),
        )
        return AuditReport(findings)

    def _collect_audit_findings(
        self,
        value: Any,
        *,
        depth: int,
        location: str,
        active: set[int],
    ) -> tuple[Finding, ...]:
        """Recursively collect located findings without modifying the input."""
        if depth > self.policy.max_depth:
            return ()

        value_type = type(value)
        if isinstance(value, str):
            return self._locate_findings(select_non_overlapping(self._find(value)), location)

        if isinstance(value, bytes | bytearray | memoryview):
            text = bytes(value).decode("utf-8", errors="replace")
            return self._locate_findings(select_non_overlapping(self._find(text)), location)

        if isinstance(value, Mapping):
            return self._audit_mapping(value, depth=depth, location=location, active=active)

        if value_type is range:
            return ()

        if isinstance(value, Sequence):
            return self._audit_sequence(value, depth=depth, location=location, active=active)

        if value is None or value_type in _EXACT_SCALAR_TYPES:
            return ()

        text = self._safe_unknown_text(value)
        return self._locate_findings(select_non_overlapping(self._find(text)), location)

    def _audit_mapping(
        self,
        value: Mapping[Any, Any],
        *,
        depth: int,
        location: str,
        active: set[int],
    ) -> tuple[Finding, ...]:
        """Audit a mapping while preserving safe paths and preventing cycles."""
        value_id = id(value)
        if value_id in active:
            return ()

        active.add(value_id)
        try:
            findings: list[Finding] = []
            for key, item in value.items():
                key_text = safe_mapping_key_text(key)
                display_key = self._sanitize_location_text(key_text)
                child_location = append_mapping_key(location, display_key)

                if self._is_sensitive_key_text(key_text):
                    matched = self._sensitive_value_marker(item)
                    if matched:
                        findings.append(
                            Finding(
                                rule_name="sensitive_key",
                                category="credential",
                                start=0,
                                end=len(matched),
                                matched=matched,
                                reason="value is associated with a policy-sensitive key",
                                location=child_location,
                            )
                        )
                else:
                    findings.extend(
                        self._collect_audit_findings(
                            item,
                            depth=depth + 1,
                            location=child_location,
                            active=active,
                        )
                    )
            return tuple(findings)
        finally:
            active.discard(value_id)

    def _audit_sequence(
        self,
        value: Sequence[Any],
        *,
        depth: int,
        location: str,
        active: set[int],
    ) -> tuple[Finding, ...]:
        """Audit a sequence while preserving indexes and preventing cycles."""
        value_id = id(value)
        if value_id in active:
            return ()

        active.add(value_id)
        try:
            findings: list[Finding] = []
            for index, item in enumerate(value):
                findings.extend(
                    self._collect_audit_findings(
                        item,
                        depth=depth + 1,
                        location=append_sequence_index(location, index),
                        active=active,
                    )
                )
            return tuple(findings)
        finally:
            active.discard(value_id)

    def _sanitize_location_text(self, text: str) -> str:
        """Redact sensitive content from a location component without block mode."""
        findings = select_non_overlapping(self._find(text))
        if not findings:
            return text
        cleaned, _ = apply_replacements(
            text,
            findings,
            rules=self.policy.rules,
            masking=PlaceholderMaskingStrategy(),
        )
        return cleaned

    def _is_sensitive_key_text(self, key_text: str) -> bool:
        """Classify a stable key string without invoking an arbitrary key again."""
        try:
            return self.policy.is_sensitive_key(key_text)
        except Exception:
            return False

    @staticmethod
    def _sensitive_value_marker(value: Any) -> str:
        """Return a safe internal marker for a value under a sensitive key."""
        value_type = type(value)
        if value is None:
            return ""
        if value_type is str:
            return cast(str, value)
        if value_type in _EXACT_BYTE_TYPES:
            return bytes(value).decode("utf-8", errors="replace")
        if value_type in _EXACT_SCALAR_TYPES:
            return repr(value)
        return f"<{value_type.__name__}>"

    @staticmethod
    def _safe_unknown_text(value: Any) -> str:
        """Convert an unknown object without propagating representation failures."""
        try:
            return str(value)
        except Exception:
            return f"<unprintable {type(value).__name__}>"

    @staticmethod
    def _locate_findings(findings: tuple[Finding, ...], location: str) -> tuple[Finding, ...]:
        """Attach one safe location to a tuple of rule findings."""
        return tuple(finding.with_location(location) for finding in findings)

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
