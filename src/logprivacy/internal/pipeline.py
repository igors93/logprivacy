"""Separated scanning, conflict resolution, and redaction pipeline stages.

TextScanner   — runs rules against text, validates matches, returns _DetectedMatch list
FindingResolver — resolves overlapping matches deterministically
TextRedactor  — assembles replacements in one pass, produces public Finding objects
"""

from __future__ import annotations

from logprivacy.exceptions import InputLimitExceededError, RuleValidationError
from logprivacy.internal.matches import _DetectedMatch
from logprivacy.masking.strategy import MaskingStrategy
from logprivacy.result import Finding
from logprivacy.rules.base import RedactionRule
from logprivacy.rules.set import RuleSet

DEFAULT_MAX_TEXT_CHARS = 1_000_000
DEFAULT_MAX_MATCHES = 10_000

# ---------------------------------------------------------------------------
# TextScanner
# ---------------------------------------------------------------------------


class TextScanner:
    """Execute rules in order and return validated internal matches.

    Each match is associated with its originating rule so the downstream
    redactor never has to look up a rule by name.
    """

    __slots__ = ("_rule_set", "_max_text_chars", "_max_matches")

    def __init__(
        self,
        rule_set: RuleSet,
        *,
        max_text_chars: int = DEFAULT_MAX_TEXT_CHARS,
        max_matches: int = DEFAULT_MAX_MATCHES,
    ) -> None:
        self._rule_set = rule_set
        self._max_text_chars = max_text_chars
        self._max_matches = max_matches

    def scan(self, text: str) -> tuple[_DetectedMatch, ...]:
        """Return validated matches without exceeding text or match budgets."""
        if len(text) > self._max_text_chars:
            raise InputLimitExceededError(
                limit="max_text_chars",
                maximum=self._max_text_chars,
            )

        matches: list[_DetectedMatch] = []
        for rule in self._rule_set:
            remaining = self._max_matches - len(matches)
            try:
                raw = (
                    rule.find_limited(text, remaining)
                    if isinstance(rule, RedactionRule)
                    else rule.find(text)
                )
            except InputLimitExceededError as exc:
                if exc.limit != "max_matches":
                    raise
                raise InputLimitExceededError(
                    limit="max_matches",
                    maximum=self._max_matches,
                ) from exc
            if len(raw) > remaining:
                raise InputLimitExceededError(
                    limit="max_matches",
                    maximum=self._max_matches,
                )
            for match in raw:
                _validate_match(match, text, rule.name)
            matches.extend(raw)
        return tuple(matches)


# ---------------------------------------------------------------------------
# FindingResolver
# ---------------------------------------------------------------------------


class FindingResolver:
    """Resolve overlapping matches to a non-overlapping, deterministic set.

    When two matches start at the same position, the longer one wins (greedy).
    When a match is completely contained within another, the outer one wins.
    Partial overlaps keep the earlier-starting match.

    All conflict resolution is concentrated here so it can be tested in
    isolation without running the full pipeline.
    """

    def resolve(self, matches: tuple[_DetectedMatch, ...]) -> tuple[_DetectedMatch, ...]:
        """Return a non-overlapping subset of matches in document order."""
        selected: list[_DetectedMatch] = []
        last_end = -1

        for match in sorted(matches, key=lambda m: (m.start, -m.length)):
            if match.start < last_end:
                continue
            selected.append(match)
            last_end = match.end

        return tuple(selected)


# ---------------------------------------------------------------------------
# TextRedactor
# ---------------------------------------------------------------------------


class TextRedactor:
    """Apply pre-resolved matches to text, producing cleaned text and public Findings.

    Output is assembled in one forward pass from the original offsets.
    The rule used for replacement is always the rule that produced the match —
    looked up directly from the RuleSet by name, with no ambiguity.
    """

    __slots__ = ("_rule_set", "_masking")

    def __init__(self, rule_set: RuleSet, masking: MaskingStrategy) -> None:
        self._rule_set = rule_set
        self._masking = masking

    def redact(
        self,
        text: str,
        resolved_matches: tuple[_DetectedMatch, ...],
        *,
        retain_sensitive_matches: bool = False,
    ) -> tuple[str, tuple[Finding, ...]]:
        """Apply matches to text and return (cleaned_text, public_findings).

        The original matched value is never stored in the public Finding unless
        ``retain_sensitive_matches=True``.  That flag should only be used in
        trusted tooling that is never written to logs or telemetry.
        """
        if not resolved_matches:
            return text, ()

        findings: list[Finding] = []
        parts: list[str] = []
        cursor = 0

        for match in resolved_matches:
            rule = self._rule_set[match.rule_name]
            replacement = rule.replacement_for(match, self._masking)
            parts.extend((text[cursor : match.start], replacement))
            cursor = match.end
            finding = Finding(
                rule_name=match.rule_name,
                category=match.category,
                start=match.start,
                end=match.end,
                replacement=replacement,
                reason=match.reason,
                metadata={key: value for key, value in match.metadata.items() if key != "value"},
                _matched=match.matched if retain_sensitive_matches else "",
            )
            findings.append(finding)

        parts.append(text[cursor:])
        return "".join(parts), tuple(findings)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def _validate_match(match: _DetectedMatch, text: str, expected_rule_name: str) -> None:
    """Raise RuleValidationError for any structurally invalid match.

    This check runs after each rule produces its matches, before conflict
    resolution, so invalid findings never reach the slicing stage.
    """
    if not isinstance(match.start, int) or isinstance(match.start, bool):
        raise RuleValidationError(
            f"Rule {expected_rule_name!r} produced a match with non-integer start offset"
        )
    if not isinstance(match.end, int) or isinstance(match.end, bool):
        raise RuleValidationError(
            f"Rule {expected_rule_name!r} produced a match with non-integer end offset"
        )
    if match.start < 0:
        raise RuleValidationError(
            f"Rule {expected_rule_name!r} produced a match with negative start ({match.start})"
        )
    if match.end <= match.start:
        raise RuleValidationError(
            f"Rule {expected_rule_name!r} produced a match where end ({match.end}) "
            f"<= start ({match.start})"
        )
    if match.end > len(text):
        raise RuleValidationError(
            f"Rule {expected_rule_name!r} produced a match with end ({match.end}) "
            f"beyond text length ({len(text)})"
        )
    if match.rule_name != expected_rule_name:
        raise RuleValidationError(
            f"Rule {expected_rule_name!r} produced a match claiming rule_name {match.rule_name!r}"
        )
