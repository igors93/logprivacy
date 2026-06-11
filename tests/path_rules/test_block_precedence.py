"""Regression tests for security-first block rule precedence."""

from __future__ import annotations

import pytest

from logprivacy.exceptions import LogBlockedError
from logprivacy.field_rules import FieldRule
from logprivacy.path_rules import PathRule
from logprivacy.policy import CleanerPolicy
from logprivacy.safe_data import to_safe_data


def _base_policy() -> CleanerPolicy:
    return CleanerPolicy.default().with_rules()


def test_later_path_block_overrides_earlier_path_mask() -> None:
    policy = _base_policy().add_path_rules(
        PathRule.exact("account.token", action="mask"),
        PathRule.exact("account.token", action="block"),
    )

    with pytest.raises(LogBlockedError):
        to_safe_data({"account": {"token": "secret-token"}}, policy=policy)


def test_later_field_block_overrides_earlier_field_mask() -> None:
    policy = _base_policy().add_field_rules(
        FieldRule.exact("token", action="mask"),
        FieldRule.exact("token", action="block"),
    )

    with pytest.raises(LogBlockedError):
        to_safe_data({"token": "secret-token"}, policy=policy)


def test_field_block_overrides_matching_path_mask() -> None:
    policy = (
        _base_policy()
        .add_path_rules(PathRule.exact("account.token", action="mask"))
        .add_field_rules(FieldRule.exact("token", action="block"))
    )

    with pytest.raises(LogBlockedError):
        to_safe_data({"account": {"token": "secret-token"}}, policy=policy)


def test_path_block_overrides_matching_field_mask() -> None:
    policy = (
        _base_policy()
        .add_path_rules(PathRule.exact("account.token", action="block"))
        .add_field_rules(FieldRule.exact("token", action="mask"))
    )

    with pytest.raises(LogBlockedError):
        to_safe_data({"account": {"token": "secret-token"}}, policy=policy)


def test_field_block_is_checked_before_allowlist_omission() -> None:
    policy = (
        _base_policy()
        .add_field_rules(FieldRule.exact("token", action="block"))
        .allow_paths("status")
    )

    with pytest.raises(LogBlockedError):
        to_safe_data({"status": "ok", "token": "secret-token"}, policy=policy)


def test_later_sequence_path_block_overrides_earlier_mask() -> None:
    policy = _base_policy().add_path_rules(
        PathRule.glob("items.*", action="mask"),
        PathRule.glob("items.*", action="block"),
    )

    with pytest.raises(LogBlockedError):
        to_safe_data({"items": ["secret-token"]}, policy=policy)


def test_first_non_block_path_rule_still_wins() -> None:
    policy = _base_policy().add_path_rules(
        PathRule.exact("account.value", action="remove"),
        PathRule.exact("account.value", action="mask"),
    )

    assert to_safe_data({"account": {"value": "visible"}}, policy=policy) == {
        "account": {"value": "[REMOVED]"}
    }


def test_first_non_block_field_rule_still_wins() -> None:
    policy = _base_policy().add_field_rules(
        FieldRule.exact("value", action="remove"),
        FieldRule.exact("value", action="mask"),
    )

    assert to_safe_data({"value": "visible"}, policy=policy) == {"value": "[REMOVED]"}
