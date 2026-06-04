from logcleaner.masking import PlaceholderMaskingStrategy
from logcleaner.result import Finding


def test_placeholder_strategy_masks_by_category():
    strategy = PlaceholderMaskingStrategy()
    finding = Finding("email", "email", 0, 3, "x@y.com")
    assert strategy.mask(finding) == "[EMAIL]"


def test_placeholder_strategy_uses_fallback():
    assert PlaceholderMaskingStrategy().mask_category("unknown") == "[REDACTED]"
