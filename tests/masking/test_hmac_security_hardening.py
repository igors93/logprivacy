"""Security regression tests for HMACMaskingStrategy."""

from __future__ import annotations

import pytest

from logprivacy.masking.strategy import HMACMaskingStrategy

_KEY = b"0123456789abcdef0123456789abcdef"


def _digest(token: str) -> str:
    return token.rsplit(":", maxsplit=1)[1][:-1]


def test_hmac_rejects_key_shorter_than_sixteen_bytes() -> None:
    short_key = b"123456789012345"
    assert len(short_key) == 15

    with pytest.raises(ValueError, match="at least 16 bytes"):
        HMACMaskingStrategy(key=short_key)


def test_hmac_accepts_exactly_sixteen_bytes() -> None:
    minimum_key = b"0123456789abcdef"
    assert len(minimum_key) == 16

    strategy = HMACMaskingStrategy(key=minimum_key)

    assert strategy.mask_value("value", "identifier").startswith("[IDENTIFIER:hmac:")


def test_hmac_framing_separates_category_from_value() -> None:
    strategy = HMACMaskingStrategy(key=_KEY, digest_size=64)

    first = strategy.mask_value("123", "account id")
    second = strategy.mask_value("id 123", "account")

    # The previous ``category + b" " + value`` construction produced the
    # same HMAC message for these two distinct inputs.
    assert _digest(first) != _digest(second)


def test_hmac_remains_deterministic_after_framing() -> None:
    strategy = HMACMaskingStrategy(key=_KEY)

    assert strategy.mask_value("user-123", "user_id") == strategy.mask_value(
        "user-123",
        "user_id",
    )


def test_hmac_domain_differs_from_legacy_unframed_message() -> None:
    strategy = HMACMaskingStrategy(key=_KEY, digest_size=64)

    current = _digest(strategy.mask_value("value", "category"))

    import hmac
    from hashlib import sha256

    legacy = hmac.new(_KEY, b"category value", sha256).hexdigest()

    assert current != legacy
