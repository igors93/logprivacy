from __future__ import annotations

import logging

import pytest

from logprivacy.cleaner import Cleaner
from logprivacy.exceptions import InputLimitExceededError, RuleValidationError
from logprivacy.integrations.logging_filter import LogPrivacyFilter
from logprivacy.internal.matches import _DetectedMatch
from logprivacy.internal.pipeline import TextScanner
from logprivacy.masking.strategy import MaskingStrategy
from logprivacy.policy import CleanerPolicy
from logprivacy.rules.base import RedactionRule
from logprivacy.rules.set import RuleSet


class _LegacyDuckRule:
    name = "legacy_duck"
    category = "test"

    def __init__(self) -> None:
        self.find_called = False

    def find(self, text: str) -> tuple[_DetectedMatch, ...]:
        self.find_called = True
        return ()

    def replacement_for(self, match: _DetectedMatch, masking: MaskingStrategy) -> str:
        return "[TEST]"


class _BoundedDuckRule(_LegacyDuckRule):
    def __init__(self) -> None:
        super().__init__()
        self.find_limited_called = False
        self.received_limit: int | None = None

    def find(self, text: str) -> tuple[_DetectedMatch, ...]:
        self.find_called = True
        raise AssertionError("unbounded find() must not be called")

    def find_limited(self, text: str, max_matches: int) -> tuple[_DetectedMatch, ...]:
        self.find_limited_called = True
        self.received_limit = max_matches
        return ()


class _InheritedUnboundedRule(RedactionRule):
    name = "inherited_unbounded"
    category = "test"

    def find(self, text: str) -> tuple[_DetectedMatch, ...]:
        return ()


class _MaliciousLimitRule(RedactionRule):
    name = "malicious_limit"
    category = "test"

    def find(self, text: str) -> tuple[_DetectedMatch, ...]:
        return ()

    def find_limited(self, text: str, max_matches: int) -> tuple[_DetectedMatch, ...]:
        raise InputLimitExceededError(
            limit="max_matches\nERROR forged-event",
            maximum=max_matches,
        )


def _record(message: str) -> logging.LogRecord:
    return logging.LogRecord(
        name="security.limit-marker",
        level=logging.WARNING,
        pathname=__file__,
        lineno=1,
        msg=message,
        args=(),
        exc_info=None,
    )


def test_rule_without_bounded_find_is_rejected_before_find_runs() -> None:
    rule = _LegacyDuckRule()

    with pytest.raises(RuleValidationError, match="find_limited"):
        RuleSet((rule,))

    assert rule.find_called is False


def test_redaction_rule_subclass_keeps_legacy_bounded_fallback() -> None:
    scanner = TextScanner(
        RuleSet((_InheritedUnboundedRule(),)),
        max_text_chars=100,
        max_matches=3,
    )

    assert scanner.scan("safe") == ()


def test_duck_typed_rule_with_find_limited_uses_the_bounded_contract() -> None:
    rule = _BoundedDuckRule()
    scanner = TextScanner(
        RuleSet((rule,)),
        max_text_chars=100,
        max_matches=3,
    )

    assert scanner.scan("safe") == ()
    assert rule.find_limited_called is True
    assert rule.received_limit == 3
    assert rule.find_called is False


class _NoReplacementRule:
    name = "no_replacement"
    category = "test"

    def find(self, text: str) -> tuple[_DetectedMatch, ...]:
        return ()


class _InvalidOffsetRule(RedactionRule):
    name = "invalid_offset"
    category = "test"

    def find(self, text: str) -> tuple[_DetectedMatch, ...]:
        return (
            _DetectedMatch(
                rule_name=self.name,
                category=self.category,
                start=-1,
                end=1,
                matched="x",
                reason="invalid offset regression",
            ),
        )


def test_missing_replacement_error_keeps_precedence() -> None:
    with pytest.raises(RuleValidationError, match="missing callable 'replacement_for'"):
        RuleSet((_NoReplacementRule(),))


def test_duplicate_name_is_checked_for_legacy_subclasses() -> None:
    class FirstRule(RedactionRule):
        name = "duplicate"
        category = "test"

        def find(self, text: str) -> tuple[_DetectedMatch, ...]:
            return ()

    class SecondRule(FirstRule):
        pass

    with pytest.raises(RuleValidationError, match="Duplicate rule name"):
        RuleSet((FirstRule(), SecondRule()))


def test_legacy_subclass_still_reaches_match_validation() -> None:
    scanner = TextScanner(
        RuleSet((_InvalidOffsetRule(),)),
        max_text_chars=100,
        max_matches=3,
    )

    with pytest.raises(RuleValidationError, match="negative start"):
        scanner.scan("safe")


def test_input_limit_marker_escapes_control_characters() -> None:
    policy = CleanerPolicy(rules=(_MaliciousLimitRule(),))
    record = _record("trigger")

    assert LogPrivacyFilter(cleaner=Cleaner(policy=policy)).filter(record) is True

    rendered = record.getMessage()
    assert rendered.splitlines() == [rendered]
    assert "\n" not in rendered
    assert r"\x0aERROR forged-event" in rendered
    assert "trigger" not in rendered
