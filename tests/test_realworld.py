"""Real-world usage scenarios that validate end-to-end behaviour."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from logprivacy import (
    Cleaner,
    CleanerPolicy,
    LogBlockedError,
    LogPrivacyAssertionError,
    LogPrivacyFilter,
    assert_clean,
    audit,
    clean_url,
    clean_with_result,
)

# ---------------------------------------------------------------------------
# Logger with %-style format arguments
# ---------------------------------------------------------------------------


def test_logger_cleans_percent_format_args() -> None:
    """logger.info('user=%s password=%s', email, password) must clean both args."""
    record = logging.LogRecord(
        name="rw-test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="user=%s password=%s",
        args=("john@example.com", "s3cr3t"),
        exc_info=None,
    )
    LogPrivacyFilter().filter(record)
    assert record.getMessage() == "user=[EMAIL] password=[SECRET]"
    assert record.args == ()


# ---------------------------------------------------------------------------
# URL with mixed safe and unsafe query parameters
# ---------------------------------------------------------------------------


def test_clean_url_mixed_params() -> None:
    url = "https://api.example.com/v1/search?q=python&page=1&api_key=abc123&lang=en"
    result = clean_url(url)
    assert "q=python" in result
    assert "page=1" in result
    assert "lang=en" in result
    assert "abc123" not in result
    assert "[SECRET]" in result


def test_clean_url_placeholders_are_readable() -> None:
    url = "https://example.com/?token=t123&email=a@b.com"
    result = clean_url(url)
    assert "[SECRET]" in result
    assert "[EMAIL]" in result
    # Brackets must not be percent-encoded in the output
    assert "%5B" not in result
    assert "%5D" not in result


# ---------------------------------------------------------------------------
# File cleaning with multiple lines
# ---------------------------------------------------------------------------


def test_clean_file_multiple_lines(tmp_path: Path) -> None:
    log_file = tmp_path / "app.log"
    log_file.write_text(
        "INFO login john@example.com\nDEBUG password=abc123\nINFO status ok\n",
        encoding="utf-8",
    )
    output_file = tmp_path / "app.clean.log"

    from logprivacy import clean_file

    clean_file(str(log_file), output=str(output_file))

    cleaned = output_file.read_text(encoding="utf-8")
    assert "john@example.com" not in cleaned
    assert "abc123" not in cleaned
    assert "status ok" in cleaned


# ---------------------------------------------------------------------------
# CleanerPolicy.production() blocks credentials
# ---------------------------------------------------------------------------


def test_production_policy_blocks_credentials() -> None:
    cleaner = Cleaner(policy=CleanerPolicy.production())
    with pytest.raises(LogBlockedError):
        cleaner.clean("password=hunter2")


def test_production_policy_blocks_tokens() -> None:
    cleaner = Cleaner(policy=CleanerPolicy.production())
    with pytest.raises(LogBlockedError):
        cleaner.clean("Authorization: Bearer secret-token-12345")


# ---------------------------------------------------------------------------
# assert_clean() fails on structured data with sensitive values
# ---------------------------------------------------------------------------


def test_assert_clean_fails_for_sensitive_dict() -> None:
    with pytest.raises(LogPrivacyAssertionError):
        assert_clean({"password": "hunter2"})


def test_assert_clean_fails_for_list_with_email() -> None:
    with pytest.raises(LogPrivacyAssertionError):
        assert_clean(["john@example.com"])


def test_assert_clean_passes_for_safe_dict() -> None:
    assert_clean({"username": "john", "status": "active"})


# ---------------------------------------------------------------------------
# Partial masking preserves shape without exposing the full secret
# ---------------------------------------------------------------------------


def test_partial_masking_does_not_expose_full_secret() -> None:
    cleaner = Cleaner(policy=CleanerPolicy.default(masking="partial"))
    result = cleaner.clean_text("sk_live_abcdef1234567890")
    # Middle characters are replaced with * — the secret body must not appear
    assert "abcdef1234567890" not in result
    assert "*" in result


def test_partial_masking_email_hides_local_part() -> None:
    cleaner = Cleaner(policy=CleanerPolicy.default(masking="partial"))
    result = cleaner.clean_text("john@example.com")
    assert "john" not in result
    assert "example.com" in result


# ---------------------------------------------------------------------------
# Hash masking is stable across calls
# ---------------------------------------------------------------------------


def test_hash_masking_is_stable() -> None:
    cleaner = Cleaner(policy=CleanerPolicy.default(masking="hash"))
    first = cleaner.clean_text("sk_live_abcdef1234567890")
    second = cleaner.clean_text("sk_live_abcdef1234567890")
    assert first == second


def test_hash_masking_differs_for_different_secrets() -> None:
    cleaner = Cleaner(policy=CleanerPolicy.default(masking="hash"))
    a = cleaner.clean_text("sk_live_aaaa1111")
    b = cleaner.clean_text("sk_live_bbbb2222")
    assert a != b


# ---------------------------------------------------------------------------
# audit() with structured data
# ---------------------------------------------------------------------------


def test_audit_dict_with_sensitive_key() -> None:
    report = audit({"password": "hunter2"})
    assert report.safe is False
    assert report.risk_level == "high"


def test_audit_list_with_email() -> None:
    report = audit(["john@example.com", "nothing here"])
    assert report.safe is False
    assert "email" in report.categories


def test_audit_tuple_with_token_like_value() -> None:
    report = audit(("Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789",))
    assert report.safe is False


def test_audit_safe_dict_passes() -> None:
    report = audit({"username": "john", "status": "active", "count": 42})
    assert report.safe is True


# ---------------------------------------------------------------------------
# clean_with_result() returns finding metadata
# ---------------------------------------------------------------------------


def test_clean_with_result_finding_count() -> None:
    result = clean_with_result("john@example.com password=abc123")
    assert result.changed is True
    assert result.finding_count >= 2


def test_clean_with_result_categories_include_email() -> None:
    result = clean_with_result("user john@example.com")
    assert "email" in result.categories
