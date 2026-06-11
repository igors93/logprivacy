"""Regression tests for allowlist precedence as an output boundary."""

from __future__ import annotations

import pytest

from logprivacy import (
    CleanerPolicy,
    FieldRule,
    LogBlockedError,
    PathRule,
    to_safe_data,
    to_safe_data_with_result,
)


def test_allowlist_omits_path_even_when_path_rule_would_mask() -> None:
    policy = (
        CleanerPolicy.default()
        .allow_paths("status")
        .add_path_rules(PathRule.exact("account.balance", action="mask"))
    )

    result = to_safe_data_with_result(
        {
            "status": "ok",
            "account": {"balance": "10000"},
        },
        policy=policy,
    )

    assert result.cleaned == {"status": "ok"}
    assert result.stats.not_allowed == 1
    assert result.stats.path_rule_matches == 0


def test_allowlist_omits_path_even_when_path_rule_would_remove() -> None:
    policy = (
        CleanerPolicy.default()
        .allow_paths("status")
        .add_path_rules(PathRule.exact("debug", action="remove"))
    )

    safe = to_safe_data(
        {
            "status": "ok",
            "debug": "internal details",
        },
        policy=policy,
    )

    assert safe == {"status": "ok"}
    assert "debug" not in safe


def test_allowlisted_path_still_uses_path_rule() -> None:
    policy = (
        CleanerPolicy.default()
        .allow_paths("account.balance")
        .add_path_rules(PathRule.exact("account.balance", action="mask"))
    )

    result = to_safe_data_with_result(
        {
            "account": {
                "balance": "10000",
                "currency": "USD",
            }
        },
        policy=policy,
    )

    assert result.cleaned == {"account": {"balance": "[SECRET]"}}
    assert result.stats.path_rule_matches == 1
    assert result.stats.not_allowed == 1


def test_parent_prefix_cannot_be_reintroduced_as_masked_scalar() -> None:
    policy = (
        CleanerPolicy.default()
        .allow_paths("account.balance")
        .add_path_rules(PathRule.exact("account", action="mask"))
    )

    result = to_safe_data_with_result(
        {"account": {"balance": "10000"}},
        policy=policy,
    )

    assert result.cleaned == {}
    assert result.stats.not_allowed == 1


def test_allowlist_runs_before_non_blocking_field_rule() -> None:
    policy = (
        CleanerPolicy.default()
        .allow_paths("status")
        .add_field_rules(FieldRule.exact("debug", action="mask"))
    )

    result = to_safe_data_with_result(
        {
            "status": "ok",
            "debug": "internal details",
        },
        policy=policy,
    )

    assert result.cleaned == {"status": "ok"}
    assert result.stats.field_rule_matches == 0
    assert result.stats.not_allowed == 1


def test_block_still_precedes_allowlist() -> None:
    policy = (
        CleanerPolicy.default()
        .allow_paths("status")
        .add_path_rules(PathRule.exact("debug", action="block"))
    )

    with pytest.raises(LogBlockedError):
        to_safe_data(
            {
                "status": "ok",
                "debug": "internal details",
            },
            policy=policy,
        )
