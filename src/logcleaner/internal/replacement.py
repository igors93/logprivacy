"""Helpers for applying redactions safely."""

from __future__ import annotations

from logcleaner.masking.strategy import MaskingStrategy
from logcleaner.result import Finding
from logcleaner.rules.base import RedactionRule


def select_non_overlapping(findings: tuple[Finding, ...]) -> tuple[Finding, ...]:
    """Return findings that do not overlap. Longer findings win when they start together."""
    selected: list[Finding] = []
    last_end = -1
    for finding in sorted(findings, key=lambda item: (item.start, -item.length)):
        if finding.start < last_end:
            continue
        selected.append(finding)
        last_end = finding.end
    return tuple(selected)


def apply_replacements(
    text: str,
    findings: tuple[Finding, ...],
    *,
    rules: tuple[RedactionRule, ...],
    masking: MaskingStrategy,
) -> tuple[str, tuple[Finding, ...]]:
    """Apply findings to text from right to left and return cleaned text."""
    if not findings:
        return text, ()
    rules_by_name = {rule.name: rule for rule in rules}
    selected = select_non_overlapping(findings)
    resolved: list[Finding] = []
    cleaned = text
    for finding in reversed(selected):
        replacement = rules_by_name[finding.rule_name].replacement_for(finding, masking)
        cleaned = f"{cleaned[: finding.start]}{replacement}{cleaned[finding.end :]}"
        resolved.append(finding.with_replacement(replacement))
    return cleaned, tuple(reversed(resolved))
