from logprivacy import Cleaner, CleanerPolicy, clean_text
from logprivacy.rules import CredentialRule


def test_credential_rule_finds_password_assignment():
    findings = CredentialRule().find("password=123")
    assert len(findings) == 1
    assert findings[0].category == "credential"


def test_credential_rule_keeps_key_visible():
    assert clean_text("password=123") == "password=[SECRET]"


def test_authorization_bearer_redacts_the_complete_token():
    token = "secret-token-12345"

    cleaned = clean_text(f"Authorization: Bearer {token}")

    assert cleaned == "Authorization: Bearer [TOKEN]"
    assert token not in cleaned


def test_authorization_basic_redacts_the_complete_credential():
    credential = "dXNlcjpwYXNz"

    cleaned = clean_text(f"Authorization: Basic {credential}")

    assert cleaned == "Authorization: Basic [SECRET]"
    assert credential not in cleaned


def test_authorization_bearer_preserves_following_log_fields():
    token = "abcdefgh12345678"

    cleaned = clean_text(f"Authorization: Bearer {token} status=401")

    assert cleaned == "Authorization: Bearer [TOKEN] status=401"


def test_authorization_bearer_is_one_complete_credential_finding():
    value = "Authorization: Bearer abcdefgh12345678"

    findings = CredentialRule().find(value)

    assert len(findings) == 1
    assert findings[0].matched == value
    assert findings[0].category == "token"


def test_authorization_bearer_supports_quoted_assignments():
    token = "abcdefgh12345678"

    cleaned = clean_text(f'authorization="Bearer {token}"')

    assert cleaned == 'authorization="Bearer [TOKEN]"'
    assert token not in cleaned


def test_authorization_bearer_uses_hash_masking_without_exposing_the_token():
    token = "abcdefgh12345678"
    cleaner = Cleaner(policy=CleanerPolicy.default(masking="hash"))

    cleaned = cleaner.clean_text(f"Authorization: Bearer {token}")

    assert cleaned.startswith("Authorization: Bearer [TOKEN:")
    assert cleaned.endswith("]")
    assert token not in cleaned
