from logprivacy import clean


def test_mapping_redacts_sensitive_key_value():
    assert clean({"password": "abc"}) == {"password": "[SECRET]"}


def test_mapping_recurses_nested_values():
    assert clean({"user": {"email": "john@example.com"}}) == {"user": {"email": "[EMAIL]"}}
