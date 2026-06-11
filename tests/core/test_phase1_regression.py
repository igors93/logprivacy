"""Phase 1 regression and invariant tests.

Covers:
- RuleSet validation (duplicates, empty names, bad contracts)
- Default vs explicit empty rule set semantics
- DetectedMatch / Finding separation (no sensitive value in public objects)
- TextScanner / FindingResolver / TextRedactor separation
- Overlap resolution determinism
- Invalid finding handling
- Public API backward compatibility
- Idempotence invariant: clean(clean(x)) == clean(x)
- Safety invariant: sensitive value never appears in public output
"""

from __future__ import annotations

import pytest

from logprivacy import (
    Cleaner,
    CleanerPolicy,
    CustomRegexRule,
    EmailRule,
    Finding,
    LogBlockedError,
    PlaceholderMaskingStrategy,
    RuleValidationError,
    SecretRule,
    TokenRule,
    UrlRule,
    assert_clean,
    audit,
    clean,
    clean_text,
    clean_url,
    clean_with_result,
    explain,
    get_safe_logger,
    safe_print,
)
from logprivacy.internal.matches import _DetectedMatch
from logprivacy.internal.pipeline import FindingResolver, TextRedactor, TextScanner
from logprivacy.rules.base import RedactionRule
from logprivacy.rules.set import RuleSet

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _NakedRule:
    """Object that looks like a rule but is missing required attributes."""


class _NoFind:
    """Has name and category but no find()."""

    name = "nofind"
    category = "test"


class _NoReplacement:
    """Has name, category, find() but no replacement_for()."""

    name = "noreplace"
    category = "test"

    def find(self, text: str) -> tuple[_DetectedMatch, ...]:  # type: ignore[return]
        return ()


class _AlwaysEmail(RedactionRule):
    """Minimal rule that always returns one match at position 0-5."""

    name = "always_email"
    category = "email"

    def find(self, text: str) -> tuple[_DetectedMatch, ...]:
        if len(text) < 5:
            return ()
        return (
            _DetectedMatch(
                rule_name=self.name,
                category=self.category,
                start=0,
                end=5,
                matched=text[:5],
                reason="test",
            ),
        )


class _NegativeOffset(RedactionRule):
    """Malformed rule: returns negative start."""

    name = "bad_negative"
    category = "test"

    def find(self, text: str) -> tuple[_DetectedMatch, ...]:
        return (
            _DetectedMatch(
                rule_name=self.name,
                category=self.category,
                start=-1,
                end=3,
                matched="abc",
                reason="test",
            ),
        )


class _EndLessThanStart(RedactionRule):
    """Malformed rule: end <= start."""

    name = "bad_end"
    category = "test"

    def find(self, text: str) -> tuple[_DetectedMatch, ...]:
        return (
            _DetectedMatch(
                rule_name=self.name,
                category=self.category,
                start=5,
                end=3,
                matched="ab",
                reason="test",
            ),
        )


class _EndBeyondText(RedactionRule):
    """Malformed rule: end > len(text)."""

    name = "bad_beyond"
    category = "test"

    def find(self, text: str) -> tuple[_DetectedMatch, ...]:
        return (
            _DetectedMatch(
                rule_name=self.name,
                category=self.category,
                start=0,
                end=len(text) + 1,
                matched=text or "x",
                reason="test",
            ),
        )


class _EmptyRange(RedactionRule):
    """Malformed rule: empty interval (end == start)."""

    name = "bad_empty"
    category = "test"

    def find(self, text: str) -> tuple[_DetectedMatch, ...]:
        return (
            _DetectedMatch(
                rule_name=self.name,
                category=self.category,
                start=2,
                end=2,
                matched="",
                reason="test",
            ),
        )


class _WrongRuleName(RedactionRule):
    """Malformed rule: match claims a different rule_name."""

    name = "real_name"
    category = "test"

    def find(self, text: str) -> tuple[_DetectedMatch, ...]:
        if not text:
            return ()
        return (
            _DetectedMatch(
                rule_name="impostor_name",
                category=self.category,
                start=0,
                end=1,
                matched=text[0],
                reason="test",
            ),
        )


# ---------------------------------------------------------------------------
# Task 1: RuleSet validation
# ---------------------------------------------------------------------------


class TestRuleSetValidation:
    def test_accepts_valid_rules(self) -> None:
        rs = RuleSet((EmailRule(), SecretRule()))
        assert len(rs) == 2

    def test_rejects_duplicate_names(self) -> None:
        r1 = EmailRule()
        r2 = EmailRule()
        with pytest.raises(RuleValidationError, match="Duplicate rule name"):
            RuleSet((r1, r2))

    def test_duplicate_name_error_does_not_expose_content(self) -> None:
        r1 = EmailRule()
        r2 = EmailRule()
        try:
            RuleSet((r1, r2))
        except RuleValidationError as exc:
            message = str(exc)
            assert "email" in message  # rule name is OK to include
            assert "@" not in message  # no email addresses in error

    def test_rejects_different_classes_with_same_name(self) -> None:
        class AnotherEmail(RedactionRule):
            name = "email"
            category = "email"

            def find(self, text: str) -> tuple[_DetectedMatch, ...]:
                return ()

        with pytest.raises(RuleValidationError, match="Duplicate rule name"):
            RuleSet((EmailRule(), AnotherEmail()))

    def test_rejects_empty_rule_name(self) -> None:
        rule = CustomRegexRule(name="", category="test", pattern=r"\d+")
        with pytest.raises(RuleValidationError):
            RuleSet((rule,))

    def test_rejects_empty_category(self) -> None:
        rule = CustomRegexRule(name="mytest", category="", pattern=r"\d+")
        with pytest.raises(RuleValidationError):
            RuleSet((rule,))

    def test_rejects_object_missing_name(self) -> None:
        with pytest.raises(RuleValidationError, match="missing 'name'"):
            RuleSet((_NakedRule(),))  # type: ignore[arg-type]

    def test_rejects_object_missing_find(self) -> None:
        with pytest.raises(RuleValidationError, match="missing callable 'find'"):
            RuleSet((_NoFind(),))  # type: ignore[arg-type]

    def test_rejects_object_missing_replacement_for(self) -> None:
        with pytest.raises(RuleValidationError, match="missing callable 'replacement_for'"):
            RuleSet((_NoReplacement(),))  # type: ignore[arg-type]

    def test_preserves_rule_order(self) -> None:
        rules = (UrlRule(), EmailRule(), SecretRule(), TokenRule())
        rs = RuleSet(rules)
        assert tuple(rs) == rules

    def test_lookup_by_name(self) -> None:
        rs = RuleSet((EmailRule(), SecretRule()))
        found = rs.get("email")
        assert found is not None
        assert found.name == "email"

    def test_lookup_missing_name_returns_none(self) -> None:
        rs = RuleSet((EmailRule(),))
        assert rs.get("nothere") is None

    def test_getitem_missing_raises_keyerror(self) -> None:
        rs = RuleSet((EmailRule(),))
        with pytest.raises(KeyError):
            _ = rs["nothere"]

    def test_empty_ruleset_is_valid(self) -> None:
        rs = RuleSet(())
        assert len(rs) == 0
        assert list(rs) == []

    def test_ruleset_is_not_mutable(self) -> None:
        rs = RuleSet((EmailRule(),))
        with pytest.raises(AttributeError):
            rs._rules = ()  # type: ignore[misc]

    def test_append_returns_new_ruleset(self) -> None:
        rs1 = RuleSet((EmailRule(),))
        rs2 = rs1.append(SecretRule())
        assert len(rs1) == 1
        assert len(rs2) == 2

    def test_append_rejects_duplicate(self) -> None:
        rs = RuleSet((EmailRule(),))
        with pytest.raises(RuleValidationError, match="Duplicate"):
            rs.append(EmailRule())


# ---------------------------------------------------------------------------
# Task 2: Default vs explicit empty rule set
# ---------------------------------------------------------------------------


class TestDefaultVsEmptyRuleSet:
    def test_default_construction_loads_rules(self) -> None:
        policy = CleanerPolicy()
        assert len(policy.rules) > 0

    def test_explicit_empty_rules_stays_empty(self) -> None:
        policy = CleanerPolicy(rules=())
        assert policy.rules == ()

    def test_default_and_explicit_empty_are_different(self) -> None:
        default = CleanerPolicy()
        empty = CleanerPolicy(rules=())
        assert default.rules != empty.rules
        assert len(empty.rules) == 0

    def test_with_rules_no_args_produces_empty(self) -> None:
        policy = CleanerPolicy.default().with_rules()
        assert policy.rules == ()

    def test_with_rules_no_args_is_different_from_default(self) -> None:
        default = CleanerPolicy.default()
        empty = default.with_rules()
        assert len(empty.rules) == 0
        assert len(default.rules) > 0

    def test_add_rules_onto_empty_works(self) -> None:
        policy = CleanerPolicy.default().with_rules().add_rules(EmailRule())
        assert len(policy.rules) == 1
        assert policy.rules[0].name == "email"

    def test_clean_text_with_no_rules_returns_original(self) -> None:
        cleaner = Cleaner(policy=CleanerPolicy(rules=()))
        text = "john@example.com password=secret123"
        assert cleaner.clean_text(text) == text

    def test_sensitive_key_protection_works_with_empty_rules(self) -> None:
        policy = CleanerPolicy(rules=())
        assert policy.is_sensitive_key("password") is True

    def test_clean_mapping_with_no_rules_still_redacts_sensitive_keys(self) -> None:
        policy = CleanerPolicy(rules=())
        cleaner = Cleaner(policy=policy)
        result = cleaner.clean({"password": "secret123", "user": "alice"})
        assert result["password"] != "secret123"
        assert result["user"] == "alice"

    def test_default_factory_policy_is_identical_to_classmethod(self) -> None:
        a = CleanerPolicy()
        b = CleanerPolicy.default()
        assert {r.name for r in a.rules} == {r.name for r in b.rules}

    def test_policy_repr_does_not_expose_sentinel_class(self) -> None:
        policy = CleanerPolicy()
        text = repr(policy)
        assert "_RulesNotProvided" not in text


# ---------------------------------------------------------------------------
# Task 3: DetectedMatch vs public Finding safety
# ---------------------------------------------------------------------------


class TestFindingSafety:
    def _run(self, text: str) -> tuple[str, tuple[Finding, ...]]:
        result = clean_with_result(text)
        return result.cleaned, result.findings

    def test_finding_repr_does_not_contain_matched_value(self) -> None:
        _, findings = self._run("john@example.com")
        assert findings
        for finding in findings:
            assert "john" not in repr(finding)
            assert "example.com" not in repr(finding)

    def test_finding_to_dict_excludes_matched_by_default(self) -> None:
        _, findings = self._run("john@example.com")
        assert findings
        d = findings[0].to_dict()
        assert "matched" not in d

    def test_finding_matched_property_is_empty_by_default(self) -> None:
        _, findings = self._run("john@example.com")
        assert findings
        assert findings[0].matched == ""

    def test_redaction_result_repr_does_not_contain_original(self) -> None:
        secret = "sk-abcdefghijklmnopqrst"
        result = clean_with_result(secret)
        assert secret not in repr(result)

    def test_audit_report_repr_is_safe(self) -> None:
        secret = "sk-abcdefghijklmnopqrst"
        report = audit(secret)
        assert secret not in repr(report)

    def test_audit_report_summary_is_safe(self) -> None:
        secret = "sk-abcdefghijklmnopqrst"
        report = audit(secret)
        assert secret not in str(report.summary())

    def test_audit_report_describe_is_safe(self) -> None:
        secret = "sk-abcdefghijklmnopqrst"
        report = audit(secret)
        assert secret not in report.describe()

    def test_audit_report_details_is_safe(self) -> None:
        secret = "sk-abcdefghijklmnopqrst"
        report = audit(secret)
        for detail in report.details():
            assert secret not in str(detail)

    def test_redaction_result_explain_is_safe(self) -> None:
        secret = "sk-abcdefghijklmnopqrst"
        result = clean_with_result(secret)
        assert secret not in result.explain()

    def test_exception_does_not_contain_sensitive_value(self) -> None:
        policy = CleanerPolicy.default().block("credential")
        cleaner = Cleaner(policy=policy)
        try:
            cleaner.clean_text("password=super-secret-value")
        except LogBlockedError as exc:
            assert "super-secret-value" not in str(exc)

    def test_partial_masking_still_works(self) -> None:
        cleaner = Cleaner(policy=CleanerPolicy.default(masking="partial"))
        result = cleaner.clean_text("john@example.com")
        assert result == "j***@example.com"

    def test_hash_masking_still_works(self) -> None:
        cleaner = Cleaner(policy=CleanerPolicy.default(masking="hash"))
        result = cleaner.clean_text("john@example.com")
        assert result.startswith("[EMAIL:")

    def test_credential_rule_still_keeps_key_context(self) -> None:
        result = clean_text("password=supersecret")
        assert "password=" in result
        assert "supersecret" not in result

    def test_token_bearer_rule_still_keeps_prefix(self) -> None:
        result = clean_text("Authorization: Bearer abc.def.ghi.jkl12345")
        assert "Bearer" in result
        assert "abc.def.ghi.jkl12345" not in result


# ---------------------------------------------------------------------------
# Task 4: Scanner / Resolver / Redactor separation
# ---------------------------------------------------------------------------


class TestPipelineSeparation:
    def _rule_set(self) -> RuleSet:
        return RuleSet(CleanerPolicy.default().rules)

    def test_scanner_returns_detected_matches(self) -> None:
        scanner = TextScanner(self._rule_set())
        matches = scanner.scan("john@example.com")
        assert matches
        assert all(isinstance(m, _DetectedMatch) for m in matches)

    def test_scanner_returns_empty_for_clean_text(self) -> None:
        scanner = TextScanner(self._rule_set())
        assert scanner.scan("hello world") == ()

    def test_resolver_returns_non_overlapping(self) -> None:
        resolver = FindingResolver()
        m1 = _DetectedMatch(
            rule_name="email", category="email", start=0, end=20, matched="x" * 20, reason=""
        )
        m2 = _DetectedMatch(
            rule_name="url", category="url", start=5, end=30, matched="x" * 25, reason=""
        )
        result = resolver.resolve((m1, m2))
        assert len(result) == 1
        assert result[0] is m1  # longer match at same-ish position — m1 starts first

    def test_resolver_prefers_longer_match_at_same_start(self) -> None:
        resolver = FindingResolver()
        short = _DetectedMatch(
            rule_name="a", category="c", start=0, end=5, matched="hello", reason=""
        )
        long_ = _DetectedMatch(
            rule_name="b", category="c", start=0, end=10, matched="hello wor", reason=""
        )
        result = resolver.resolve((short, long_))
        assert len(result) == 1
        assert result[0] is long_

    def test_resolver_allows_adjacent_non_overlapping(self) -> None:
        resolver = FindingResolver()
        m1 = _DetectedMatch(rule_name="a", category="c", start=0, end=5, matched="hello", reason="")
        m2 = _DetectedMatch(
            rule_name="b", category="c", start=5, end=10, matched="world", reason=""
        )
        result = resolver.resolve((m1, m2))
        assert len(result) == 2

    def test_resolver_handles_contained_match(self) -> None:
        resolver = FindingResolver()
        outer = _DetectedMatch(
            rule_name="a", category="c", start=0, end=20, matched="x" * 20, reason=""
        )
        inner = _DetectedMatch(
            rule_name="b", category="c", start=5, end=10, matched="x" * 5, reason=""
        )
        result = resolver.resolve((outer, inner))
        assert len(result) == 1
        assert result[0] is outer

    def test_resolver_is_deterministic_regardless_of_input_order(self) -> None:
        resolver = FindingResolver()
        m1 = _DetectedMatch(rule_name="a", category="c", start=0, end=5, matched="hello", reason="")
        m2 = _DetectedMatch(rule_name="b", category="c", start=3, end=8, matched="lo wo", reason="")
        r1 = resolver.resolve((m1, m2))
        r2 = resolver.resolve((m2, m1))
        assert r1 == r2

    def test_redactor_produces_public_findings_without_matched(self) -> None:
        rs = self._rule_set()
        redactor = TextRedactor(rs, PlaceholderMaskingStrategy())
        match = _DetectedMatch(
            rule_name="email",
            category="email",
            start=0,
            end=16,
            matched="john@example.com",
            reason="test",
        )
        cleaned, findings = redactor.redact("john@example.com", (match,))
        assert cleaned == "[EMAIL]"
        assert findings[0].matched == ""

    def test_redactor_uses_correct_rule_for_replacement(self) -> None:
        rs = self._rule_set()
        redactor = TextRedactor(rs, PlaceholderMaskingStrategy())
        match = _DetectedMatch(
            rule_name="credential",
            category="credential",
            start=0,
            end=13,
            matched="password=abc",
            reason="test",
            metadata={"key": "password", "sep": "=", "quote": "", "value": "abc"},
        )
        cleaned, findings = redactor.redact("password=abc", (match,))
        assert "password=" in cleaned
        assert "abc" not in cleaned


# ---------------------------------------------------------------------------
# Task 5: Overlap regression
# ---------------------------------------------------------------------------


class TestOverlapResolution:
    def _resolve(self, *matches: _DetectedMatch) -> tuple[_DetectedMatch, ...]:
        return FindingResolver().resolve(matches)

    def test_same_start_different_lengths(self) -> None:
        short = _DetectedMatch(
            rule_name="a", category="c", start=0, end=5, matched="x" * 5, reason=""
        )
        long_ = _DetectedMatch(
            rule_name="b", category="c", start=0, end=15, matched="x" * 15, reason=""
        )
        result = self._resolve(short, long_)
        assert len(result) == 1
        assert result[0] is long_

    def test_partial_overlap(self) -> None:
        m1 = _DetectedMatch(
            rule_name="a", category="c", start=0, end=10, matched="x" * 10, reason=""
        )
        m2 = _DetectedMatch(
            rule_name="b", category="c", start=7, end=15, matched="x" * 8, reason=""
        )
        result = self._resolve(m1, m2)
        assert len(result) == 1
        assert result[0] is m1

    def test_three_chained(self) -> None:
        m1 = _DetectedMatch(rule_name="a", category="c", start=0, end=5, matched="x" * 5, reason="")
        m2 = _DetectedMatch(rule_name="b", category="c", start=3, end=8, matched="x" * 5, reason="")
        m3 = _DetectedMatch(
            rule_name="c", category="c", start=6, end=12, matched="x" * 6, reason=""
        )
        result = self._resolve(m1, m2, m3)
        # m1 wins over m2, then m3 starts at 6 which is > m1.end=5 so m3 is accepted
        assert len(result) == 2
        assert result[0] is m1
        assert result[1] is m3

    def test_adjacent_are_not_overlapping(self) -> None:
        m1 = _DetectedMatch(rule_name="a", category="c", start=0, end=5, matched="x" * 5, reason="")
        m2 = _DetectedMatch(
            rule_name="b", category="c", start=5, end=10, matched="x" * 5, reason=""
        )
        result = self._resolve(m1, m2)
        assert len(result) == 2

    def test_different_rule_order_same_result(self) -> None:
        email = _DetectedMatch(
            rule_name="email",
            category="email",
            start=0,
            end=16,
            matched="john@example.com",
            reason="",
        )
        url = _DetectedMatch(
            rule_name="url",
            category="url",
            start=0,
            end=40,
            matched="https://example.com/john@example.com",
            reason="",
        )
        r1 = self._resolve(email, url)
        r2 = self._resolve(url, email)
        assert r1 == r2


# ---------------------------------------------------------------------------
# Invalid match validation
# ---------------------------------------------------------------------------


class TestInvalidMatchValidation:
    def _cleaner(self, rule: RedactionRule) -> Cleaner:
        policy = CleanerPolicy.default().with_rules(rule)
        return Cleaner(policy=policy)

    def test_negative_offset_raises(self) -> None:
        cleaner = self._cleaner(_NegativeOffset())
        with pytest.raises(RuleValidationError, match="negative start"):
            cleaner.clean_text("abcdef")

    def test_end_less_than_start_raises(self) -> None:
        cleaner = self._cleaner(_EndLessThanStart())
        with pytest.raises(RuleValidationError, match="end.*<= start"):
            cleaner.clean_text("abcdefgh")

    def test_end_beyond_text_raises(self) -> None:
        cleaner = self._cleaner(_EndBeyondText())
        with pytest.raises(RuleValidationError, match="beyond text length"):
            cleaner.clean_text("abcdef")

    def test_empty_range_raises(self) -> None:
        cleaner = self._cleaner(_EmptyRange())
        with pytest.raises(RuleValidationError, match="end.*<= start"):
            cleaner.clean_text("abcdef")

    def test_wrong_rule_name_raises(self) -> None:
        cleaner = self._cleaner(_WrongRuleName())
        with pytest.raises(RuleValidationError, match="rule_name"):
            cleaner.clean_text("abcdef")

    def test_invalid_match_error_does_not_contain_text(self) -> None:
        cleaner = self._cleaner(_NegativeOffset())
        try:
            cleaner.clean_text("secret-sensitive-content")
        except RuleValidationError as exc:
            assert "secret-sensitive-content" not in str(exc)


# ---------------------------------------------------------------------------
# Idempotence invariant
# ---------------------------------------------------------------------------


IDEMPOTENCE_CASES = [
    "hello world",
    "john@example.com",
    "password=secret123",
    "Bearer eyJabc.def.ghi",
    "sk-abcdefghijklmnopqrst",
    "4532015112830366",
    "https://user:pass@example.com/path?token=abc",
    "[EMAIL]",
    "[SECRET]",
    "[REDACTED]",
    "no sensitive data here",
    "nested token=abc123456789 and email=john@example.com",
]


@pytest.mark.parametrize("value", IDEMPOTENCE_CASES)
def test_clean_is_idempotent(value: str) -> None:
    """clean(clean(x)) == clean(x) for placeholder masking."""
    once = clean_text(value)
    twice = clean_text(once)
    assert once == twice, f"Not idempotent: {value!r} -> {once!r} -> {twice!r}"


# ---------------------------------------------------------------------------
# Safety invariant: sensitive value never in public output
# ---------------------------------------------------------------------------


SENSITIVE_CASES = [
    ("john@example.com", "john"),
    ("password=mysecret123", "mysecret123"),
    ("Bearer abc.def.ghi.jklmno12345", "abc.def.ghi.jklmno12345"),
    ("sk-abcdefghijklmnopqrst", "sk-abcde"),
    ("4532015112830366", "4532015112830366"),
]


@pytest.mark.parametrize("text,fragment", SENSITIVE_CASES)
def test_sensitive_value_not_in_finding_repr(text: str, fragment: str) -> None:
    result = clean_with_result(text)
    for finding in result.findings:
        assert fragment not in repr(finding)


@pytest.mark.parametrize("text,fragment", SENSITIVE_CASES)
def test_sensitive_value_not_in_finding_to_dict(text: str, fragment: str) -> None:
    result = clean_with_result(text)
    for finding in result.findings:
        assert fragment not in str(finding.to_dict())


@pytest.mark.parametrize("text,fragment", SENSITIVE_CASES)
def test_sensitive_value_not_in_result_repr(text: str, fragment: str) -> None:
    result = clean_with_result(text)
    assert fragment not in repr(result)


@pytest.mark.parametrize("text,fragment", SENSITIVE_CASES)
def test_sensitive_value_not_in_audit_repr(text: str, fragment: str) -> None:
    report = audit(text)
    assert fragment not in repr(report)
    assert fragment not in report.describe()
    assert fragment not in str(report.summary())


# ---------------------------------------------------------------------------
# Backward compatibility: all public APIs still work
# ---------------------------------------------------------------------------


class TestPublicAPICompatibility:
    def test_clean(self) -> None:
        assert clean("john@example.com") == "[EMAIL]"

    def test_clean_text(self) -> None:
        assert clean_text("john@example.com") == "[EMAIL]"

    def test_clean_with_result(self) -> None:
        r = clean_with_result("john@example.com")
        assert r.cleaned == "[EMAIL]"
        assert r.finding_count == 1

    def test_audit(self) -> None:
        report = audit({"password": "123"})
        assert not report.safe
        assert report.risk_level == "high"

    def test_assert_clean_passes(self) -> None:
        assert_clean("hello world")

    def test_assert_clean_fails(self) -> None:
        from logprivacy import LogPrivacyAssertionError

        with pytest.raises(LogPrivacyAssertionError):
            assert_clean("john@example.com")

    def test_explain(self) -> None:
        text = explain("password=123")
        assert "credential" in text

    def test_safe_print(self, capsys: pytest.CaptureFixture[str]) -> None:
        safe_print("john@example.com")
        captured = capsys.readouterr()
        assert "[EMAIL]" in captured.out
        assert "john" not in captured.out

    def test_get_safe_logger(self) -> None:
        logger = get_safe_logger("test_compat")
        assert logger is not None

    def test_clean_url(self) -> None:
        result = clean_url("https://api.example.com/path?token=abc123")
        assert "abc123" not in result

    def test_placeholder_strategy(self) -> None:
        cleaner = Cleaner(policy=CleanerPolicy.default())
        assert cleaner.clean_text("john@example.com") == "[EMAIL]"

    def test_partial_strategy(self) -> None:
        cleaner = Cleaner(policy=CleanerPolicy.default(masking="partial"))
        assert cleaner.clean_text("john@example.com") == "j***@example.com"

    def test_hash_strategy(self) -> None:
        cleaner = Cleaner(policy=CleanerPolicy.default(masking="hash"))
        assert cleaner.clean_text("john@example.com").startswith("[EMAIL:")

    def test_default_policy(self) -> None:
        policy = CleanerPolicy.default()
        assert policy.rules

    def test_strict_policy(self) -> None:
        policy = CleanerPolicy.strict()
        assert any(r.category == "ip_address" for r in policy.rules)

    def test_web_policy(self) -> None:
        policy = CleanerPolicy.web()
        assert any(r.category == "url" for r in policy.rules)

    def test_production_policy_blocks(self) -> None:
        policy = CleanerPolicy.production()
        cleaner = Cleaner(policy=policy)
        with pytest.raises(LogBlockedError):
            cleaner.clean_text("password=mysecret")

    def test_block_mode(self) -> None:
        cleaner = Cleaner(policy=CleanerPolicy.default().block("credential"))
        with pytest.raises(LogBlockedError):
            cleaner.clean_text("password=mysecret")

    def test_custom_regex_rule(self) -> None:
        rule = CustomRegexRule(name="test_ssn", category="pii", pattern=r"\d{3}-\d{2}-\d{4}")
        cleaner = Cleaner(policy=CleanerPolicy.default().add_rules(rule))
        assert "123-45-6789" not in cleaner.clean_text("SSN: 123-45-6789")

    def test_logprivacy_filter_import(self) -> None:
        from logprivacy import LogPrivacyFilter

        assert LogPrivacyFilter is not None

    def test_logprivacy_formatter_import(self) -> None:
        from logprivacy import LogPrivacyFormatter

        assert LogPrivacyFormatter is not None


# ---------------------------------------------------------------------------
# Duplicate-rule-name detection at policy build time
# ---------------------------------------------------------------------------


class TestDuplicateRuleAtPolicyLevel:
    def test_cleaner_rejects_duplicate_rule_names(self) -> None:
        policy = CleanerPolicy.default().with_rules(EmailRule(), EmailRule())
        with pytest.raises(RuleValidationError, match="Duplicate rule name"):
            Cleaner(policy=policy)

    def test_error_message_is_safe_for_duplicate(self) -> None:
        policy = CleanerPolicy.default().with_rules(EmailRule(), EmailRule())
        try:
            Cleaner(policy=policy)
        except RuleValidationError as exc:
            assert "john" not in str(exc)
            assert "@" not in str(exc)
