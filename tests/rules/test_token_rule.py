from logcleaner import clean_text
from logcleaner.rules import TokenRule


def test_token_rule_finds_bearer_token():
    findings = TokenRule().find("Authorization: Bearer abcdefgh12345678")
    assert len(findings) == 1
    assert findings[0].category == "token"


def test_token_rule_keeps_bearer_prefix():
    assert clean_text("Bearer abcdefgh12345678") == "Bearer [TOKEN]"
