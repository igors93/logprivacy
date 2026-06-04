"""Helpers for applying redactions safely."""

from __future__ import annotations

from logcleaner.masking.strategy import MaskingStrategy
from logcleaner.result import Finding
from logcleaner.rules.base import RedactionRule


def select_non_overlapping(findings: tuple[Finding, ...]) -> tuple[Finding, ...]:
    """
    Return findings that do not overlap.

    When two findings start at the same position, the longer one wins.
    This avoids double-redacting values such as emails inside URLs.
    """
    selected: list[Finding] = []
    # Start before the first valid index so the first finding is never skipped.
    last_end = -1

    # Sort by start position; break ties by preferring the longer match so the
    # greedy rule wins when multiple patterns fire at the same offset.
    for finding in sorted(findings, key=lambda item: (item.start, -item.length)):
        if finding.start < last_end:
            # This finding overlaps the previously accepted one — skip it.
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
        rule = rules_by_name[finding.rule_name]
        replacement = rule.replacement_for(finding, masking)
        cleaned = f"{cleaned[: finding.start]}{replacement}{cleaned[finding.end :]}"
        resolved.append(finding.with_replacement(replacement))

    return cleaned, tuple(reversed(resolved))
