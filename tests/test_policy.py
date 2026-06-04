from logcleaner import Cleaner, CleanerPolicy
from logcleaner.rules import EmailRule


def test_default_policy_has_rules():
    policy = CleanerPolicy.default()
    assert policy.rules


def test_strict_policy_contains_ip_rule():
    policy = CleanerPolicy.strict()
    assert "ip_address" in {rule.category for rule in policy.rules}


def test_policy_can_disable_category():
    policy = CleanerPolicy.default().without_categories("email")
    assert "email" not in {rule.category for rule in policy.rules}


def test_policy_can_add_rule():
    policy = CleanerPolicy.default().add_rules(EmailRule())
    assert policy.rules[-1].category == "email"


def test_sensitive_key_detection_is_case_insensitive():
    policy = CleanerPolicy.default()
    assert policy.is_sensitive_key("API-Key")


def test_partial_masking_policy():
    cleaner = Cleaner(policy=CleanerPolicy.default(masking="partial"))
    assert cleaner.clean_text("john@example.com") == "j***@example.com"


def test_hash_masking_policy():
    cleaner = Cleaner(policy=CleanerPolicy.default(masking="hash"))
    assert cleaner.clean_text("john@example.com").startswith("[EMAIL:")
