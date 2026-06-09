from __future__ import annotations

import re

import pytest

from logprivacy import Cleaner, CleanerPolicy, HashMaskingStrategy
from logprivacy.result import Finding


def _finding(value: str = "secret-value", category: str = "secret") -> Finding:
    return Finding(
        rule_name="test",
        category=category,
        start=0,
        end=len(value),
        matched=value,
        reason="test value",
    )


def test_hash_default_uses_sixteen_hexadecimal_characters() -> None:
    masked = HashMaskingStrategy().mask(_finding())

    assert re.fullmatch(r"\[SECRET:[0-9a-f]{16}\]", masked)


def test_hash_is_stable_for_the_same_input() -> None:
    strategy = HashMaskingStrategy()

    assert strategy.mask(_finding()) == strategy.mask(_finding())


def test_hash_uses_framed_category_domain_separation() -> None:
    strategy = HashMaskingStrategy()

    secret = strategy.mask(_finding(category="secret"))
    token = strategy.mask(_finding(category="token"))

    assert secret.split(":", 1)[1] != token.split(":", 1)[1]


def test_keyed_hash_is_stable_and_does_not_expose_the_key_or_value() -> None:
    key = b"0123456789abcdef0123456789abcdef"
    strategy = HashMaskingStrategy(key=key)

    first = strategy.mask(_finding())
    second = strategy.mask(_finding())

    assert first == second
    assert "secret-value" not in first
    assert key.decode() not in repr(strategy)


def test_different_keys_create_different_tokens() -> None:
    first = HashMaskingStrategy(key=b"aaaaaaaaaaaaaaaa").mask(_finding())
    second = HashMaskingStrategy(key=b"bbbbbbbbbbbbbbbb").mask(_finding())

    assert first != second


def test_string_keys_are_encoded_as_utf8() -> None:
    strategy = HashMaskingStrategy(key="production-key-123")

    assert strategy.mask(_finding()) == strategy.mask(_finding())


def test_keyed_hash_integrates_with_cleaner_across_inputs() -> None:
    strategy = HashMaskingStrategy(key=b"0123456789abcdef")
    policy = CleanerPolicy.default(masking=strategy)
    cleaner = Cleaner(policy=policy)

    text = cleaner.clean_text("password=secret-value")
    structured = cleaner.clean({"password": "secret-value"})

    assert re.fullmatch(r"password=\[SECRET:[0-9a-f]{16}\]", text)
    assert structured == {"password": text.split("=", 1)[1]}
    assert "secret-value" not in text


@pytest.mark.parametrize("length", [0, 1, 8, 11, 65, 100])
def test_hash_rejects_unsafe_digest_lengths(length: int) -> None:
    with pytest.raises(ValueError, match="length must be between"):
        HashMaskingStrategy(length=length)


def test_hash_rejects_boolean_length() -> None:
    with pytest.raises(TypeError, match="length must be an integer"):
        HashMaskingStrategy(length=True)  # type: ignore[arg-type]


@pytest.mark.parametrize("key", [b"", b"short", "too-short"])
def test_hash_rejects_short_keys(key: str | bytes) -> None:
    with pytest.raises(ValueError, match="at least 16 bytes"):
        HashMaskingStrategy(key=key)


def test_hash_rejects_mutable_key_types() -> None:
    with pytest.raises(TypeError, match="key must be"):
        HashMaskingStrategy(key=bytearray(b"0123456789abcdef"))  # type: ignore[arg-type]


def test_hash_rejects_key_and_legacy_salt_together() -> None:
    with pytest.raises(ValueError, match="cannot be configured together"):
        HashMaskingStrategy(key=b"0123456789abcdef", salt="legacy")


def test_legacy_salt_remains_deterministic_but_is_hidden_from_repr() -> None:
    strategy = HashMaskingStrategy(salt="legacy-correlation-salt")

    assert strategy.mask(_finding()) == strategy.mask(_finding())
    assert "legacy-correlation-salt" not in repr(strategy)
