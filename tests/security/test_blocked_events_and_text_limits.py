from __future__ import annotations

import logging

import pytest

from logprivacy.cleaner import Cleaner
from logprivacy.exceptions import LogBlockedError, LogPrivacyError
from logprivacy.integrations.logging_filter import LogPrivacyFilter
from logprivacy.internal.matches import _DetectedMatch
from logprivacy.policy import CleanerPolicy


class _NoOpRule:
    name = "noop"
    category = "test"

    def find(self, text: str) -> tuple[_DetectedMatch, ...]:
        return ()

    def replacement_for(self, match: _DetectedMatch, masking: object) -> str:
        return "[TEST]"


class _ExplodingRule(_NoOpRule):
    def __init__(self) -> None:
        self.called = False

    def find(self, text: str) -> tuple[_DetectedMatch, ...]:
        self.called = True
        raise AssertionError("rules must not run for oversized input")


class _CharacterRule:
    name = "character"
    category = "test"

    def find(self, text: str) -> tuple[_DetectedMatch, ...]:
        return tuple(
            _DetectedMatch(
                rule_name=self.name,
                category=self.category,
                start=index,
                end=index + 1,
                matched=value,
                reason="test character",
            )
            for index, value in enumerate(text)
        )

    def replacement_for(self, match: _DetectedMatch, masking: object) -> str:
        return "[X]"


def _record(message: str) -> logging.LogRecord:
    return logging.LogRecord(
        name="security.auth",
        level=logging.WARNING,
        pathname=__file__,
        lineno=1,
        msg=message,
        args=(),
        exc_info=None,
    )


def test_default_filter_preserves_blocked_event_without_secret() -> None:
    record = _record("Login failed: password=attacker-controlled-value")
    log_filter = LogPrivacyFilter(cleaner=Cleaner(policy=CleanerPolicy.production()))

    assert log_filter.filter(record) is True

    rendered = record.getMessage()
    assert "attacker-controlled-value" not in rendered
    assert rendered == "[LOGPRIVACY BLOCKED categories=credential]"
    assert record.args == ()
    assert record.exc_info is None
    assert record.stack_info is None


def test_explicit_drop_blocked_true_keeps_legacy_drop_behavior() -> None:
    record = _record("password=attacker-controlled-value")
    log_filter = LogPrivacyFilter(
        cleaner=Cleaner(policy=CleanerPolicy.production()),
        drop_blocked=True,
    )

    assert log_filter.filter(record) is False


def test_explicit_drop_blocked_false_still_raises() -> None:
    record = _record("password=attacker-controlled-value")
    log_filter = LogPrivacyFilter(
        cleaner=Cleaner(policy=CleanerPolicy.production()),
        drop_blocked=False,
    )

    with pytest.raises(LogBlockedError):
        log_filter.filter(record)


def test_oversized_text_is_rejected_before_rules_run() -> None:
    rule = _ExplodingRule()
    cleaner = Cleaner(policy=CleanerPolicy(rules=(rule,)))

    with pytest.raises(LogPrivacyError):
        cleaner.clean_text("a" * 1_000_001)

    assert rule.called is False


def test_text_at_size_limit_is_processed() -> None:
    cleaner = Cleaner(policy=CleanerPolicy(rules=(_NoOpRule(),)))
    text = "a" * 1_000_000

    assert cleaner.clean_text(text) == text


def test_cleaning_rejects_more_matches_than_policy_budget() -> None:
    cleaner = Cleaner(
        policy=CleanerPolicy(
            rules=(_CharacterRule(),),
            max_findings=3,
        )
    )

    with pytest.raises(LogPrivacyError):
        cleaner.clean_text("abcd")


def test_cleaning_accepts_matches_at_policy_budget() -> None:
    cleaner = Cleaner(
        policy=CleanerPolicy(
            rules=(_CharacterRule(),),
            max_findings=3,
        )
    )

    assert cleaner.clean_text("abc") == "[X][X][X]"


def test_logging_replaces_oversized_message_with_safe_marker() -> None:
    record = _record("a" * 1_000_001)

    assert LogPrivacyFilter().filter(record) is True
    assert record.getMessage() == "[LOGPRIVACY INPUT LIMIT EXCEEDED limit=max_text_chars]"


def test_many_allowed_matches_keep_order_and_content() -> None:
    cleaner = Cleaner(
        policy=CleanerPolicy(
            rules=(_CharacterRule(),),
            max_findings=1_000,
        )
    )

    assert cleaner.clean_text("a" * 1_000) == "[X]" * 1_000


def test_blocked_placeholder_removes_sensitive_extra_values() -> None:
    record = _record("password=attacker-controlled-value")
    record.api_key = "extra-secret-value"

    assert (
        LogPrivacyFilter(cleaner=Cleaner(policy=CleanerPolicy.production())).filter(record) is True
    )

    assert record.api_key == "[REDACTED]"
    assert "extra-secret-value" not in repr(record.__dict__)


def test_audit_marks_oversized_text_incomplete_without_running_rules() -> None:
    rule = _ExplodingRule()
    cleaner = Cleaner(policy=CleanerPolicy(rules=(rule,)))

    report = cleaner.audit("a" * 1_000_001)

    assert report.complete is False
    assert report.limitations == ("max_text_chars",)
    assert rule.called is False


def test_audit_marks_match_budget_exhaustion_incomplete() -> None:
    cleaner = Cleaner(
        policy=CleanerPolicy(
            rules=(_CharacterRule(),),
            max_findings=3,
        )
    )

    report = cleaner.audit("abcd")

    assert report.complete is False
    assert report.limitations == ("max_findings",)
    assert len(report.findings) == 3


def test_regex_rules_stop_at_raw_match_budget() -> None:
    from logprivacy.internal.pipeline import TextScanner
    from logprivacy.rules.base import RegexRedactionRule
    from logprivacy.rules.set import RuleSet

    rule = RegexRedactionRule.from_pattern(
        name="letter",
        category="test",
        pattern="a",
    )
    scanner = TextScanner(RuleSet((rule,)), max_text_chars=100, max_matches=3)

    with pytest.raises(LogPrivacyError):
        scanner.scan("aaaa")


def test_credential_rule_stops_at_raw_match_budget() -> None:
    from logprivacy.internal.pipeline import TextScanner
    from logprivacy.rules.credential import CredentialRule
    from logprivacy.rules.set import RuleSet

    scanner = TextScanner(
        RuleSet((CredentialRule(),)),
        max_text_chars=1_000,
        max_matches=2,
    )

    with pytest.raises(LogPrivacyError):
        scanner.scan("password=one password=two password=three")


def test_token_rule_stops_at_raw_match_budget() -> None:
    from logprivacy.internal.pipeline import TextScanner
    from logprivacy.rules.set import RuleSet
    from logprivacy.rules.token import TokenRule

    scanner = TextScanner(
        RuleSet((TokenRule(),)),
        max_text_chars=1_000,
        max_matches=2,
    )

    with pytest.raises(LogPrivacyError):
        scanner.scan("Bearer abcdefgh Bearer ijklmnop Bearer qrstuvwx")


def test_credit_card_rule_stops_at_raw_match_budget() -> None:
    from logprivacy.internal.pipeline import TextScanner
    from logprivacy.rules.credit_card import CreditCardRule
    from logprivacy.rules.set import RuleSet

    scanner = TextScanner(
        RuleSet((CreditCardRule(),)),
        max_text_chars=1_000,
        max_matches=2,
    )

    with pytest.raises(LogPrivacyError):
        scanner.scan("4111111111111111 4111111111111111 4111111111111111")
