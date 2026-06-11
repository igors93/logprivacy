"""Tests for HMACMaskingStrategy."""

from __future__ import annotations

import pytest

from logprivacy.exceptions import PseudonymizationConfigurationError
from logprivacy.field_rules import FieldRule
from logprivacy.masking.strategy import HMACMaskingStrategy
from logprivacy.path_rules.rules import PathRule
from logprivacy.policy import CleanerPolicy
from logprivacy.safe_data import to_safe_data, to_safe_data_with_result

_KEY = b"test-key-exactly-32-bytes-padded!"


def make_strategy(**kwargs: object) -> HMACMaskingStrategy:
    return HMACMaskingStrategy(key=_KEY, **kwargs)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


def test_basic_construction():
    s = HMACMaskingStrategy(key=_KEY)
    assert s.digest_size == 12


def test_empty_key_rejected():
    with pytest.raises(ValueError, match="must not be empty"):
        HMACMaskingStrategy(key=b"")


def test_non_bytes_key_rejected():
    with pytest.raises(TypeError, match="must be bytes"):
        HMACMaskingStrategy(key="string-key")  # type: ignore[arg-type]


def test_bool_key_rejected():
    with pytest.raises(TypeError, match="must be bytes"):
        HMACMaskingStrategy(key=True)  # type: ignore[arg-type]


def test_digest_size_too_small():
    with pytest.raises(ValueError, match="digest_size must be between"):
        HMACMaskingStrategy(key=_KEY, digest_size=7)


def test_digest_size_too_large():
    with pytest.raises(ValueError, match="digest_size must be between"):
        HMACMaskingStrategy(key=_KEY, digest_size=65)


def test_digest_size_bool_rejected():
    with pytest.raises(TypeError, match="must be an integer"):
        HMACMaskingStrategy(key=_KEY, digest_size=True)  # type: ignore[arg-type]


def test_digest_size_boundary_min():
    s = HMACMaskingStrategy(key=_KEY, digest_size=8)
    assert s.digest_size == 8


def test_digest_size_boundary_max():
    s = HMACMaskingStrategy(key=_KEY, digest_size=64)
    assert s.digest_size == 64


# ---------------------------------------------------------------------------
# repr / str do not leak key
# ---------------------------------------------------------------------------


def test_repr_does_not_contain_key():
    s = HMACMaskingStrategy(key=_KEY)
    r = repr(s)
    assert _KEY.decode() not in r
    assert "key" not in r.lower() or "key=..." not in r  # repr hides key


def test_str_does_not_contain_key():
    s = HMACMaskingStrategy(key=_KEY)
    assert _KEY.decode() not in str(s)


# ---------------------------------------------------------------------------
# Determinism and uniqueness
# ---------------------------------------------------------------------------


def test_same_value_same_key_same_category_deterministic():
    s = HMACMaskingStrategy(key=_KEY)
    t1 = s.mask_value("alice@example.com", "email")
    t2 = s.mask_value("alice@example.com", "email")
    assert t1 == t2


def test_different_values_different_tokens():
    s = HMACMaskingStrategy(key=_KEY)
    t1 = s.mask_value("alice@example.com", "email")
    t2 = s.mask_value("bob@example.com", "email")
    assert t1 != t2


def test_different_categories_different_tokens():
    s = HMACMaskingStrategy(key=_KEY)
    t1 = s.mask_value("value", "email")
    t2 = s.mask_value("value", "token")
    assert t1 != t2


def test_different_keys_different_tokens():
    s1 = HMACMaskingStrategy(key=b"key-one-32-bytes-padded-exactly!")
    s2 = HMACMaskingStrategy(key=b"key-two-32-bytes-padded-exactly!")
    t1 = s1.mask_value("alice", "user")
    t2 = s2.mask_value("alice", "user")
    assert t1 != t2


def test_key_rotation_invalidates_tokens():
    old_key = b"old-key-32-bytes-padded-exactly!"
    new_key = b"new-key-32-bytes-padded-exactly!"
    s_old = HMACMaskingStrategy(key=old_key)
    s_new = HMACMaskingStrategy(key=new_key)
    assert s_old.mask_value("user123", "user_id") != s_new.mask_value("user123", "user_id")


# ---------------------------------------------------------------------------
# Token format
# ---------------------------------------------------------------------------


def test_token_format():
    s = HMACMaskingStrategy(key=_KEY, digest_size=12)
    token = s.mask_value("hello", "email")
    assert token.startswith("[EMAIL:hmac:")
    assert token.endswith("]")
    # inner part should be 12 hex chars
    inner = token[len("[EMAIL:hmac:") : -1]
    assert len(inner) == 12
    assert all(c in "0123456789abcdef" for c in inner)


def test_digest_size_respected():
    s = HMACMaskingStrategy(key=_KEY, digest_size=20)
    token = s.mask_value("hello", "email")
    inner = token[len("[EMAIL:hmac:") : -1]
    assert len(inner) == 20


def test_unicode_input():
    s = HMACMaskingStrategy(key=_KEY)
    token = s.mask_value("用户@例子.中国", "email")
    assert "[EMAIL:hmac:" in token


def test_mask_category_no_value():
    s = HMACMaskingStrategy(key=_KEY)
    placeholder = s.mask_category("email")
    assert placeholder == "[EMAIL:hmac:?]"


def test_category_special_chars_sanitized():
    s = HMACMaskingStrategy(key=_KEY)
    token = s.mask_value("val", "some-category")
    assert "[SOME_CATEGORY:hmac:" in token


def test_empty_category_fallback():
    s = HMACMaskingStrategy(key=_KEY)
    token = s.mask_value("val", "")
    assert "[REDACTED:hmac:" in token


# ---------------------------------------------------------------------------
# FieldRule pseudonymize action
# ---------------------------------------------------------------------------


def test_fieldrule_pseudonymize():
    s = HMACMaskingStrategy(key=_KEY)
    policy = (
        CleanerPolicy.default()
        .with_rules()
        .with_pseudonymizer(s)
        .add_field_rules(FieldRule.exact("user_id", action="pseudonymize", category="user_id"))
    )
    data = {"user_id": "U123"}
    result = to_safe_data(data, policy=policy)
    assert result["user_id"].startswith("[USER_ID:hmac:")  # type: ignore[union-attr]


def test_fieldrule_pseudonymize_no_strategy_raises():
    policy = (
        CleanerPolicy.default()
        .with_rules()
        .add_field_rules(FieldRule.exact("user_id", action="pseudonymize"))
    )
    with pytest.raises(PseudonymizationConfigurationError):
        to_safe_data({"user_id": "U123"}, policy=policy)


# ---------------------------------------------------------------------------
# PathRule pseudonymize action
# ---------------------------------------------------------------------------


def test_pathrule_pseudonymize():
    s = HMACMaskingStrategy(key=_KEY)
    policy = (
        CleanerPolicy.default()
        .with_rules()
        .with_pseudonymizer(s)
        .add_path_rules(PathRule.exact("user.id", action="pseudonymize", category="user_id"))
    )
    data = {"user": {"id": "U999"}}
    result = to_safe_data(data, policy=policy)
    assert result["user"]["id"].startswith("[USER_ID:hmac:")  # type: ignore[index]


# ---------------------------------------------------------------------------
# Counters
# ---------------------------------------------------------------------------


def test_pseudonymized_counter():
    s = HMACMaskingStrategy(key=_KEY)
    policy = (
        CleanerPolicy.default()
        .with_rules()
        .with_pseudonymizer(s)
        .add_field_rules(
            FieldRule.exact("a", action="pseudonymize"),
            FieldRule.exact("b", action="pseudonymize"),
        )
    )
    result_obj = to_safe_data_with_result({"a": "x", "b": "y", "c": "z"}, policy=policy)
    assert result_obj.stats.pseudonymized == 2
