import pytest

from logprivacy import (
    LogPrivacyAssertionError,
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
    with pytest.raises(LogPrivacyAssertionError):
        assert_clean("password=123")


def test_clean_url_preserves_safe_query_params():
    url = "https://api.example.com/users?page=1&token=abc123&email=john@example.com"
    assert clean_url(url) == "https://api.example.com/users?page=1&token=[SECRET]&email=[EMAIL]"


def test_clean_url_with_no_query_params():
    url = "https://api.example.com/users"
    assert clean_url(url) == "https://api.example.com/users"


def test_clean_url_with_only_safe_params():
    url = "https://api.example.com/search?q=hello&page=2"
    assert clean_url(url) == "https://api.example.com/search?q=hello&page=2"


def test_clean_url_non_url_string_is_cleaned_as_text():
    assert clean_url("email=john@example.com") == "email=[EMAIL]"


def test_audit_structured_dict_with_sensitive_key():
    report = audit({"password": "123"})
    assert report.safe is False
    assert report.risk_level == "high"
    assert "credential" in report.categories


def test_audit_structured_dict_with_email_value():
    report = audit({"user": "john@example.com"})
    assert report.safe is False
    assert "email" in report.categories


def test_audit_list_containing_email():
    report = audit(["john@example.com", "safe string"])
    assert report.safe is False
    assert "email" in report.categories


def test_audit_tuple_containing_token_like_text():
    report = audit(("Authorization: Bearer supersecrettoken123456789",))
    assert report.safe is False


def test_audit_nested_dict_with_sensitive_value():
    report = audit({"user": {"password": "secret123"}})
    assert report.safe is False
    assert report.risk_level == "high"


def test_assert_clean_fails_with_sensitive_dict():
    from logprivacy import LogPrivacyAssertionError

    with pytest.raises(LogPrivacyAssertionError):
        assert_clean({"password": "123"})


# ---------------------------------------------------------------------------
# assert_clean message includes paths and findings (LP-REM-006)
# ---------------------------------------------------------------------------


def test_assert_clean_message_includes_finding_location() -> None:
    with pytest.raises(LogPrivacyAssertionError) as exc_info:
        assert_clean({"user": {"password": "secret123"}})

    msg = str(exc_info.value)
    assert "credential" in msg
    assert "$.user.password" in msg


def test_assert_clean_message_includes_multiple_categories() -> None:
    with pytest.raises(LogPrivacyAssertionError) as exc_info:
        assert_clean({"email": "user@example.com", "token": "sk_live_abc123def456"})

    msg = str(exc_info.value)
    assert exc_info.value.categories
    assert len(msg) > 40


def test_assert_clean_message_comes_from_report_describe() -> None:
    with pytest.raises(LogPrivacyAssertionError) as exc_info:
        assert_clean("password=abc123")

    msg = str(exc_info.value)
    assert "Findings" in msg
    assert "credential" in msg
