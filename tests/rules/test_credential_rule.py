from logcleaner import clean_text
from logcleaner.rules import CredentialRule

def test_credential_rule_finds_password_assignment():
    findings = CredentialRule().find("password=123")
    assert len(findings) == 1
    assert findings[0].category == "credential"

def test_credential_rule_keeps_key_visible():
    assert clean_text("password=123") == "password=[SECRET]"
