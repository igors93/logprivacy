from logcleaner.rules import SecretRule


def test_secret_rule_finds_stripe_key():
    findings = SecretRule().find("key=sk_live_abcdefghijklmnop")
    assert len(findings) == 1
    assert findings[0].category == "secret"
