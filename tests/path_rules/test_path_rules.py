"""Tests for PathRule and path-based field redaction."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from logprivacy.exceptions import LogBlockedError, PseudonymizationConfigurationError
from logprivacy.masking.strategy import HMACMaskingStrategy
from logprivacy.path_rules.rules import PathRule
from logprivacy.policy import CleanerPolicy
from logprivacy.safe_data import to_safe_data, to_safe_data_with_result

# ---------------------------------------------------------------------------
# PathRule construction
# ---------------------------------------------------------------------------


def test_exact_simple():
    rule = PathRule.exact("account.balance")
    assert rule.path == "account.balance"
    assert rule.action == "mask"
    assert rule.mode == "exact"


def test_exact_nested():
    rule = PathRule.exact("user.profile.email", action="remove")
    assert rule.action == "remove"
    assert rule.mode == "exact"


def test_glob_with_wildcard():
    rule = PathRule.glob("orders.*.order_id", action="mask")
    assert rule.mode == "glob"
    assert rule._segments == ("orders", "*", "order_id")


def test_glob_category():
    rule = PathRule.glob("payments.*.card_number", action="pseudonymize", category="cc")
    assert rule.category == "cc"


def test_exact_truncate():
    rule = PathRule.exact("user.notes", action="truncate", max_chars=50)
    assert rule.max_chars == 50


def test_wildcard_in_exact_rejected():
    with pytest.raises(ValueError, match="wildcard"):
        PathRule.exact("orders.*.id")


def test_double_star_rejected():
    with pytest.raises(ValueError, match=r"\*\*"):
        PathRule.glob("orders.**.id")


def test_partial_wildcard_rejected():
    with pytest.raises(ValueError, match="partial wildcard"):
        PathRule.glob("orders.foo*.id")


def test_empty_path_rejected():
    with pytest.raises(ValueError, match="must not be empty"):
        PathRule.exact("")


def test_dot_start_rejected():
    with pytest.raises(ValueError, match="must not start"):
        PathRule.exact(".account.balance")


def test_dot_end_rejected():
    with pytest.raises(ValueError, match="must not end"):
        PathRule.exact("account.balance.")


def test_double_dot_rejected():
    with pytest.raises(ValueError, match="must not contain"):
        PathRule.exact("account..balance")


def test_max_chars_non_truncate_rejected():
    with pytest.raises(ValueError, match="only supported for truncate"):
        PathRule.exact("user.name", action="mask", max_chars=10)


def test_truncate_without_max_chars_rejected():
    with pytest.raises(ValueError, match="require max_chars"):
        PathRule.exact("user.name", action="truncate")


def test_invalid_action_rejected():
    with pytest.raises(ValueError, match="action must be one of"):
        PathRule(path="user.name", action="explode")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# matches_traversal_path
# ---------------------------------------------------------------------------


def test_exact_match_two_segment():
    rule = PathRule.exact("account.balance")
    assert rule.matches_traversal_path(("account", "balance"))


def test_exact_match_camelcase_key():
    rule = PathRule.exact("account.balance")
    # "Balance" normalizes to "balance" which matches — normalization is case-insensitive
    assert rule.matches_traversal_path(("account", "Balance"))
    # But "amount" does not match "balance"
    assert not rule.matches_traversal_path(("account", "amount"))


def test_exact_match_normalized():
    rule = PathRule.exact("accountBalance")
    # normalize_field_name("accountBalance") = "account_balance"
    # traversal path raw key "accountBalance" -> normalize -> "account_balance"
    assert rule.matches_traversal_path(("accountBalance",))


def test_exact_no_match_different_depth():
    rule = PathRule.exact("account.balance")
    assert not rule.matches_traversal_path(("account",))
    assert not rule.matches_traversal_path(("account", "balance", "extra"))


def test_glob_wildcard_matches_any():
    rule = PathRule.glob("orders.*.order_id")
    assert rule.matches_traversal_path(("orders", "0", "order_id"))
    assert rule.matches_traversal_path(("orders", "abc", "order_id"))


def test_glob_wildcard_matches_int_index():
    rule = PathRule.glob("items.*.price")
    # int index 2 -> str "2" -> matches *
    assert rule.matches_traversal_path(("items", 2, "price"))


def test_glob_no_match_wrong_prefix():
    rule = PathRule.glob("orders.*.order_id")
    assert not rule.matches_traversal_path(("payments", "0", "order_id"))


# ---------------------------------------------------------------------------
# to_safe_data with PathRule — mask
# ---------------------------------------------------------------------------


def test_pathrule_masks_exact_field():
    policy = (
        CleanerPolicy.default()
        .with_rules()
        .add_path_rules(PathRule.exact("account.balance", action="mask"))
    )
    data = {"account": {"balance": "12345.00", "name": "Alice"}}
    result = to_safe_data(data, policy=policy)
    assert result["account"]["balance"] != "12345.00"  # type: ignore[index]
    assert result["account"]["name"] == "Alice"  # type: ignore[index]


def test_pathrule_remove_action():
    policy = (
        CleanerPolicy.default()
        .with_rules()
        .add_path_rules(PathRule.exact("user.ssn", action="remove"))
    )
    data = {"user": {"ssn": "123-45-6789", "name": "Bob"}}
    result = to_safe_data(data, policy=policy)
    assert result["user"]["ssn"] == "[REMOVED]"  # type: ignore[index]
    assert result["user"]["name"] == "Bob"  # type: ignore[index]


def test_pathrule_truncate_action():
    policy = (
        CleanerPolicy.default()
        .with_rules()
        .add_path_rules(PathRule.exact("log.message", action="truncate", max_chars=10))
    )
    data = {"log": {"message": "a" * 20}}
    result = to_safe_data(data, policy=policy)
    msg = result["log"]["message"]  # type: ignore[index]
    assert msg == "aaaaaaaaaa[TRUNCATED]"


def test_pathrule_block_raises():
    # Use "config.key" — "config" is not a sensitive key so we reach the nested field
    policy = (
        CleanerPolicy.default()
        .with_rules()
        .add_path_rules(PathRule.exact("config.key", action="block"))
    )
    with pytest.raises(LogBlockedError):
        to_safe_data({"config": {"key": "value"}}, policy=policy)


def test_pathrule_glob_mask_list_items():
    policy = (
        CleanerPolicy.default()
        .with_rules()
        .add_path_rules(PathRule.glob("payments.*.card", action="remove"))
    )
    data = {"payments": [{"card": "4111111111111111", "amount": 100}]}
    result = to_safe_data(data, policy=policy)
    assert result["payments"][0]["card"] == "[REMOVED]"  # type: ignore[index]
    assert result["payments"][0]["amount"] == 100  # type: ignore[index]


def test_pathrule_same_field_different_paths():
    """PathRule distinguishes "user.amount" vs "config.amount"."""
    policy = (
        CleanerPolicy.default()
        .with_rules()
        .add_path_rules(PathRule.exact("user.amount", action="remove"))
    )
    # Use non-sensitive-key field names to avoid sensitive_key masking
    data = {"user": {"amount": "100"}, "config": {"amount": "200"}}
    result = to_safe_data(data, policy=policy)
    assert result["user"]["amount"] == "[REMOVED]"  # type: ignore[index]
    # config.amount is not matched by the rule — normalized normally
    assert result["config"]["amount"] == "200"  # type: ignore[index]


def test_pathrule_wins_over_field_rule():
    """PathRule takes priority over FieldRule for the same field name."""
    policy = (
        CleanerPolicy.default()
        .with_rules()
        .add_field_rules(
            __import__("logprivacy.field_rules", fromlist=["FieldRule"]).FieldRule.exact(
                "balance", action="mask"
            )
        )
        .add_path_rules(PathRule.exact("account.balance", action="remove"))
    )
    data = {"account": {"balance": "999"}}
    result = to_safe_data(data, policy=policy)
    assert result["account"]["balance"] == "[REMOVED]"  # type: ignore[index]


def test_pathrule_wins_over_sensitive_keys():
    """PathRule takes priority over sensitive_keys masking."""
    policy = (
        CleanerPolicy.default()
        .with_rules()
        .add_path_rules(PathRule.exact("config.password", action="remove"))
    )
    data = {"config": {"password": "supersecret"}}
    result = to_safe_data(data, policy=policy)
    assert result["config"]["password"] == "[REMOVED]"  # type: ignore[index]


# ---------------------------------------------------------------------------
# Dataclass normalization
# ---------------------------------------------------------------------------


def test_pathrule_with_dataclass():
    @dataclass
    class Order:
        order_id: str
        amount: float

    policy = (
        CleanerPolicy.default()
        .with_rules()
        .add_path_rules(PathRule.exact("order_id", action="remove"))
    )
    result = to_safe_data(Order(order_id="ORD-123", amount=9.99), policy=policy)
    assert result["order_id"] == "[REMOVED]"  # type: ignore[index]
    assert result["amount"] == 9.99  # type: ignore[index]


# ---------------------------------------------------------------------------
# Exception normalization
# ---------------------------------------------------------------------------


def test_pathrule_with_exception():
    policy = (
        CleanerPolicy.default()
        .with_rules()
        .add_path_rules(PathRule.exact("message", action="remove"))
    )
    exc = ValueError("sensitive message here")
    result = to_safe_data(exc, policy=policy)
    assert result["message"] == "[REMOVED]"  # type: ignore[index]


# ---------------------------------------------------------------------------
# Counters
# ---------------------------------------------------------------------------


def test_path_rule_matches_counter():
    policy = (
        CleanerPolicy.default()
        .with_rules()
        .add_path_rules(
            PathRule.exact("a.b", action="remove"),
            PathRule.exact("a.c", action="remove"),
        )
    )
    result_obj = to_safe_data_with_result({"a": {"b": "x", "c": "y", "d": "z"}}, policy=policy)
    assert result_obj.stats.path_rule_matches == 2
    assert result_obj.stats.removed == 2


# ---------------------------------------------------------------------------
# Pseudonymize action
# ---------------------------------------------------------------------------


def test_pathrule_pseudonymize_with_strategy():
    key = b"test-key-for-pseudonymize-32bytes!"
    hmac_strat = HMACMaskingStrategy(key=key)
    policy = (
        CleanerPolicy.default()
        .with_rules()
        .with_pseudonymizer(hmac_strat)
        .add_path_rules(PathRule.exact("user.id", action="pseudonymize", category="user_id"))
    )
    data = {"user": {"id": "U12345"}}
    result = to_safe_data(data, policy=policy)
    token = result["user"]["id"]  # type: ignore[index]
    assert token.startswith("[USER_ID:hmac:")
    # same input -> same token
    result2 = to_safe_data(data, policy=policy)
    assert result2["user"]["id"] == token  # type: ignore[index]


def test_pathrule_pseudonymize_no_strategy_raises():
    policy = (
        CleanerPolicy.default()
        .with_rules()
        .add_path_rules(PathRule.exact("user.id", action="pseudonymize"))
    )
    with pytest.raises(PseudonymizationConfigurationError):
        to_safe_data({"user": {"id": "U12345"}}, policy=policy)
