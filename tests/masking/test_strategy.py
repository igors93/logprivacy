from logcleaner.masking import HashMaskingStrategy, PlaceholderMaskingStrategy
from logcleaner.result import Finding


def test_placeholder_strategy_masks_by_category():
    strategy = PlaceholderMaskingStrategy()
    finding = Finding("email", "email", 0, 3, "x@y.com")
    assert strategy.mask(finding) == "[EMAIL]"


def test_placeholder_strategy_uses_fallback():
    strategy = PlaceholderMaskingStrategy()
    assert strategy.mask_category("unknown") == "[REDACTED]"


def test_hash_strategy_is_stable():
    strategy = HashMaskingStrategy()
    finding = Finding("email", "email", 0, 3, "x@y.com")
    assert strategy.mask(finding) == strategy.mask(finding)
