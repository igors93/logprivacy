from logcleaner import clean, clean_text, clean_with_result


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
