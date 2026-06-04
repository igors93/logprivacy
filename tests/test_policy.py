from logcleaner import CleanerPolicy
from logcleaner.rules import EmailRule


def test_default_policy_has_rules():
    assert CleanerPolicy.default().rules


def test_strict_policy_contains_ip_rule():
    assert "ip_address" in {rule.category for rule in CleanerPolicy.strict().rules}


def test_policy_can_disable_category():
    policy = CleanerPolicy.default().without_categories("email")
    assert "email" not in {rule.category for rule in policy.rules}


def test_policy_can_add_rule():
    policy = CleanerPolicy.default().add_rules(EmailRule())
    assert policy.rules[-1].category == "email"


def test_sensitive_key_detection_is_case_insensitive():
    assert CleanerPolicy.default().is_sensitive_key("API-Key")
