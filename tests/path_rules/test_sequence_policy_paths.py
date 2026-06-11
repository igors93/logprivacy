"""Regression tests for policies applied directly to sequence elements."""

from __future__ import annotations

from logprivacy import AdapterRegistry, CleanerPolicy, PathRule
from logprivacy.safe_data import to_safe_data, to_safe_data_with_result


def test_allowlist_keeps_only_selected_root_sequence_index() -> None:
    policy = CleanerPolicy.default().with_rules().allow_paths("1")

    result = to_safe_data(["first", "second", "third"], policy=policy)

    assert result == ["second"]


def test_allowlist_uses_source_indices_after_an_earlier_item_is_omitted() -> None:
    policy = CleanerPolicy.default().with_rules().allow_paths("items.1")

    result = to_safe_data(
        {"items": ["first", "second", "third"]},
        policy=policy,
    )

    assert result == {"items": ["second"]}


def test_allowlist_wildcard_keeps_direct_scalar_sequence_elements() -> None:
    policy = CleanerPolicy.default().with_rules().allow_paths("items.*")

    result = to_safe_data(
        {"items": ["first", "second"]},
        policy=policy,
    )

    assert result == {"items": ["first", "second"]}


def test_allowlist_filters_fields_inside_each_sequence_mapping() -> None:
    policy = CleanerPolicy.default().with_rules().allow_paths("orders.*.status")

    result = to_safe_data(
        {
            "orders": [
                {"status": "filled", "amount": 10},
                {"status": "cancelled", "amount": 20},
            ]
        },
        policy=policy,
    )

    assert result == {
        "orders": [
            {"status": "filled"},
            {"status": "cancelled"},
        ]
    }


def test_allowlist_drops_scalar_that_only_matches_parent_prefix() -> None:
    policy = CleanerPolicy.default().with_rules().allow_paths("orders.*.status")

    result = to_safe_data(
        {
            "orders": [
                {"status": "filled", "amount": 10},
                "unexpected sensitive scalar",
            ]
        },
        policy=policy,
    )

    assert result == {"orders": [{"status": "filled"}]}


def test_allowlist_drops_named_scalar_that_only_matches_parent_prefix() -> None:
    policy = CleanerPolicy.default().with_rules().allow_paths("error.type")

    result = to_safe_data({"error": "unexpected scalar"}, policy=policy)

    assert result == {}


def test_path_rule_applies_to_exact_root_sequence_index() -> None:
    policy = (
        CleanerPolicy.default().with_rules().add_path_rules(PathRule.exact("1", action="remove"))
    )

    result = to_safe_data(["first", "second", "third"], policy=policy)

    assert result == ["first", "[REMOVED]", "third"]


def test_path_rule_glob_applies_directly_to_nested_sequence_elements() -> None:
    policy = (
        CleanerPolicy.default()
        .with_rules()
        .add_path_rules(PathRule.glob("items.*", action="remove"))
    )

    result = to_safe_data({"items": ["first", "second"]}, policy=policy)

    assert result == {"items": ["[REMOVED]", "[REMOVED]"]}


def test_path_rule_applies_to_tuple_elements() -> None:
    policy = (
        CleanerPolicy.default()
        .with_rules()
        .add_path_rules(PathRule.glob("items.*", action="remove"))
    )

    result = to_safe_data({"items": ("first", "second")}, policy=policy)

    assert result == {"items": ["[REMOVED]", "[REMOVED]"]}


def test_path_rule_wildcard_applies_to_set_elements() -> None:
    policy = (
        CleanerPolicy.default()
        .with_rules()
        .add_path_rules(PathRule.glob("items.*", action="remove"))
    )

    result = to_safe_data({"items": {"first", "second"}}, policy=policy)

    assert result == {"items": ["[REMOVED]", "[REMOVED]"]}


def test_allowlist_applies_inside_sequence_returned_by_adapter() -> None:
    class ExternalOrders:
        pass

    adapters = AdapterRegistry.default()
    adapters.register(
        ExternalOrders,
        lambda value: [
            {"status": "filled", "amount": 10},
            {"status": "cancelled", "amount": 20},
        ],
    )
    policy = CleanerPolicy.default().with_rules().allow_paths("payload.*.status")

    result = to_safe_data(
        {"payload": ExternalOrders()},
        policy=policy,
        adapters=adapters,
    )

    assert result == {
        "payload": [
            {"status": "filled"},
            {"status": "cancelled"},
        ]
    }


def test_sequence_allowlist_updates_not_allowed_counter_without_marking_incomplete() -> None:
    policy = CleanerPolicy.default().with_rules().allow_paths("items.1")

    result = to_safe_data_with_result(
        {"items": ["first", "second", "third"]},
        policy=policy,
    )

    assert result.cleaned == {"items": ["second"]}
    assert result.stats.not_allowed == 2
    assert result.complete is True
    assert result.limitations == ()


def test_path_rule_counter_includes_direct_sequence_elements() -> None:
    policy = (
        CleanerPolicy.default()
        .with_rules()
        .add_path_rules(PathRule.glob("items.*", action="remove"))
    )

    result = to_safe_data_with_result(
        {"items": ["first", "second"]},
        policy=policy,
    )

    assert result.stats.path_rule_matches == 2
    assert result.stats.removed == 2
