import pytest

from logcleaner import (
    LogCleanerAssertionError,
    assert_clean,
    audit,
    clean,
    clean_text,
    clean_url,
    clean_with_result,
)


def test_clean_text_redacts_email_and_password():
    assert clean_text("email=john@example.com password=123") == "email=[EMAIL] password=[SECRET]"


def test_clean_accepts_structured_data():
    data = {"email": "john@example.com", "password": "123", "safe": "ok"}
    assert clean(data) == {"email": "[EMAIL]", "password": "[SECRET]", "safe": "ok"}


def test_clean_with_result_returns_summary():
    result = clean_with_result("john@example.com")
    assert result.cleaned == "[EMAIL]"
    assert result.finding_count == 1
    assert result.categories == ("email",)


def test_audit_reports_risk():
    report = audit("email=john@example.com password=123")
    assert report.safe is False
    assert report.risk_level == "high"
    assert report.categories == ("email", "credential")


def test_assert_clean_passes_for_safe_text():
    assert_clean("operation completed successfully")


def test_assert_clean_fails_for_sensitive_text():
    with pytest.raises(LogCleanerAssertionError):
        assert_clean("password=123")


def test_clean_url_preserves_safe_query_params():
    url = "https://api.example.com/users?page=1&token=abc123&email=john@example.com"
    assert (
        clean_url(url)
        == "https://api.example.com/users?page=1&token=%5BSECRET%5D&email=%5BEMAIL%5D"
    )
