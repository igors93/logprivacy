from logprivacy import CleanerPolicy, clean_url


def test_clean_url_preserves_existing_public_behavior() -> None:
    url = "https://api.example.com/users?page=1&token=abc123&email=john@example.com"

    assert clean_url(url) == ("https://api.example.com/users?page=1&token=[SECRET]&email=[EMAIL]")


def test_clean_url_redacts_complete_userinfo() -> None:
    url = "https://alice:super-secret@example.com/private"

    cleaned = clean_url(url)

    assert cleaned == "https://[SECRET]@example.com/private"
    assert "alice" not in cleaned
    assert "super-secret" not in cleaned


def test_clean_url_redacts_oauth_fragment_parameters() -> None:
    url = "https://app.example/callback#access_token=abc123&id_token=jwt-value&state=ok"

    cleaned = clean_url(url)

    assert cleaned == (
        "https://app.example/callback#access_token=[SECRET]&id_token=[SECRET]&state=ok"
    )
    assert "abc123" not in cleaned
    assert "jwt-value" not in cleaned


def test_clean_url_uses_policy_sensitive_keys_for_query_parameters() -> None:
    url = "https://api.example/resource?client_secret=plain-value&private_key=key-data"

    cleaned = clean_url(url)

    assert cleaned == ("https://api.example/resource?client_secret=[SECRET]&private_key=[SECRET]")
    assert "plain-value" not in cleaned
    assert "key-data" not in cleaned


def test_clean_url_redacts_url_specific_authorization_values() -> None:
    url = "https://app.example/callback?code=oauth-code&signature=signed-value&session_id=s1"

    cleaned = clean_url(url)

    assert cleaned == (
        "https://app.example/callback?code=[SECRET]&signature=[SECRET]&session_id=[SECRET]"
    )
    assert "oauth-code" not in cleaned
    assert "signed-value" not in cleaned


def test_clean_url_reencodes_decoded_query_separators() -> None:
    url = "https://example.com/search?q=hello%26admin%3Dtrue"

    assert clean_url(url) == "https://example.com/search?q=hello%26admin%3Dtrue"


def test_clean_url_reencodes_control_characters() -> None:
    url = "https://example.com/search?q=hello%0Awarning%0Dnext"

    cleaned = clean_url(url)

    assert "\n" not in cleaned
    assert "\r" not in cleaned
    assert cleaned == "https://example.com/search?q=hello%0Awarning%0Dnext"


def test_clean_url_cleans_sensitive_data_in_path_and_plain_fragment() -> None:
    url = "https://example.com/users/john@example.com#owner@example.com"

    assert clean_url(url) == "https://example.com/users/[EMAIL]#[EMAIL]"


def test_clean_url_supports_hash_masking_for_sensitive_components() -> None:
    policy = CleanerPolicy.default(masking="hash")
    url = "https://alice:password@example.com/?client_secret=plain-value"

    cleaned = clean_url(url, policy=policy)

    assert "alice:password" not in cleaned
    assert "plain-value" not in cleaned
    assert cleaned.startswith("https://[SECRET:")
    assert "client_secret=[SECRET:" in cleaned


def test_clean_url_can_redact_the_entire_url() -> None:
    assert clean_url("https://example.com/path?token=abc", redact_full=True) == "[URL]"
