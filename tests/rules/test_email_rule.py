from logcleaner.rules import EmailRule


def test_email_rule_finds_email():
    findings = EmailRule().find("user john@example.com logged in")
    assert len(findings) == 1
    assert findings[0].category == "email"
