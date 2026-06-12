from logprivacy import audit, clean, clean_text


def test_json_password_with_spaces_is_redacted() -> None:
    source = '{"password": "correct horse battery staple"}'

    cleaned = clean_text(source)

    assert cleaned == '{"password": "[SECRET]"}'
    assert "correct horse battery staple" not in cleaned


def test_python_repr_password_with_spaces_is_redacted() -> None:
    source = "{'password': 'correct horse battery staple'}"

    cleaned = clean_text(source)

    assert cleaned == "{'password': '[SECRET]'}"
    assert "correct horse battery staple" not in cleaned


def test_quoted_password_with_an_escaped_quote_is_fully_redacted() -> None:
    source = '{"password": "correct \\"horse\\" battery staple"}'

    cleaned = clean_text(source)

    assert cleaned == '{"password": "[SECRET]"}'
    assert "battery staple" not in cleaned


def test_json_password_redaction_preserves_following_fields() -> None:
    source = '{"password": "correct horse battery staple", "status": "failed"}'

    cleaned = clean_text(source)

    assert cleaned == '{"password": "[SECRET]", "status": "failed"}'


def test_unquoted_json_password_value_preserves_closing_brace() -> None:
    source = '{"password": 123456}'

    cleaned = clean_text(source)

    assert cleaned == '{"password": [SECRET]}'


def test_clean_redacts_sensitive_mapping_keys_by_default() -> None:
    source = {"john@example.com": "active"}

    cleaned = clean(source)

    assert cleaned == {"[EMAIL]": "active"}
    assert "john@example.com" not in cleaned


def test_clean_preserves_non_sensitive_mapping_keys() -> None:
    source = {"status": "active", 42: "answer"}

    assert clean(source) == source


def test_clean_keeps_colliding_redacted_keys_without_data_loss() -> None:
    source = {"john@example.com": "first", "maria@example.com": "second"}

    cleaned = clean(source)

    assert cleaned == {"[EMAIL]": "first", "[EMAIL]#2": "second"}


def test_audit_reports_sensitive_mapping_keys_without_exposing_them() -> None:
    source = {"john@example.com": "active"}

    report = audit(source)

    assert report.safe is False
    assert report.categories == ("email",)
    assert report.locations == ('$["[EMAIL]"]',)
    assert "john@example.com" not in repr(report.findings)
    assert all("john@example.com" not in finding.location for finding in report.findings)


def test_placeholder_masking_is_idempotent_for_credentials() -> None:
    values = (
        "password=secret123",
        "nested token=abc123456789 and email=john@example.com",
        "Stack trace: user=john@example.com password=secret123",
    )

    for value in values:
        once = clean_text(value)
        assert clean_text(once) == once


def test_bracketed_placeholder_does_not_duplicate_closing_bracket() -> None:
    assert clean_text("password=[SECRET]") == "password=[SECRET]"
