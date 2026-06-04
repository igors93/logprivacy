from logcleaner import clean_text
from logcleaner.rules import CreditCardRule


def test_credit_card_rule_finds_luhn_valid_value():
    findings = CreditCardRule().find("card=4111 1111 1111 1111")
    assert len(findings) == 1
    assert findings[0].category == "credit_card"


def test_credit_card_rule_ignores_invalid_value():
    assert CreditCardRule().find("card=4111 1111 1111 1112") == ()


def test_credit_card_is_cleaned():
    assert clean_text("card=4111 1111 1111 1111") == "card=[CREDIT_CARD]"
