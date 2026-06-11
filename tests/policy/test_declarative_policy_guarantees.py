"""Regression tests for complete and fail-closed declarative policy handling."""

from __future__ import annotations

from dataclasses import replace

import pytest

from logprivacy.exceptions import PolicyConfigurationError
from logprivacy.field_rules import FieldRule
from logprivacy.masking.strategy import HMACMaskingStrategy, PartialMaskingStrategy
from logprivacy.path_rules import PathRule
from logprivacy.policy import CleanerPolicy


def _rule_signature(policy: CleanerPolicy) -> tuple[tuple[object, ...], ...]:
    return tuple(
        (
            type(rule).__module__,
            type(rule).__qualname__,
            getattr(rule, "name", None),
            getattr(rule, "category", None),
            getattr(getattr(rule, "pattern", None), "pattern", None),
        )
        for rule in policy.rules
    )


def test_from_dict_applies_every_accepted_policy_control() -> None:
    policy = CleanerPolicy.from_dict(
        {
            "schema_version": 1,
            "base": "web",
            "masking": "partial",
            "sensitive_keys": ["pin", "private_value"],
            "block_categories": ["token", "secret", "token"],
            "max_depth": 4,
            "max_items": 250,
            "max_findings": 25,
            "clean_mapping_keys": True,
            "clean_unknown_objects": True,
            "field_rules": [{"match": "pin", "action": "remove"}],
            "path_rules": [{"path": "account.balance", "action": "mask"}],
            "allowlist": {"paths": ["account.balance"]},
        }
    )

    assert isinstance(policy.masking, PartialMaskingStrategy)
    assert policy.sensitive_keys == ("pin", "private_value")
    assert policy.block_categories == ("token", "secret")
    assert policy.max_depth == 4
    assert policy.max_items == 250
    assert policy.max_findings == 25
    assert policy.clean_mapping_keys is True
    assert policy.clean_unknown_objects is True
    assert policy.field_rules == (FieldRule.exact("pin", action="remove"),)
    assert policy.path_rules == (PathRule.exact("account.balance", action="mask"),)
    assert policy.allowlist == ("account.balance",)


def test_declarative_round_trip_preserves_supported_policy_controls() -> None:
    original = (
        CleanerPolicy.strict(masking="partial")
        .add_field_rules(FieldRule.exact("pin", action="remove"))
        .add_path_rules(PathRule.glob("orders.*.id", action="mask"))
        .allow_paths("orders.*.id")
    )
    original = replace(
        original,
        sensitive_keys=("pin", "credential"),
        block_categories=("token", "secret"),
        clean_mapping_keys=True,
        clean_unknown_objects=True,
        max_depth=7,
        max_items=321,
        max_findings=45,
    )

    serialized = original.to_dict()
    restored = CleanerPolicy.from_dict(serialized)

    assert _rule_signature(restored) == _rule_signature(original)
    assert type(restored.masking) is type(original.masking)
    assert restored.sensitive_keys == original.sensitive_keys
    assert restored.block_categories == original.block_categories
    assert restored.clean_mapping_keys == original.clean_mapping_keys
    assert restored.clean_unknown_objects == original.clean_unknown_objects
    assert restored.max_depth == original.max_depth
    assert restored.max_items == original.max_items
    assert restored.max_findings == original.max_findings
    assert restored.field_rules == original.field_rules
    assert restored.path_rules == original.path_rules
    assert restored.allowlist == original.allowlist


def test_rule_free_policy_round_trips_with_none_base() -> None:
    original = (
        CleanerPolicy.default()
        .with_rules()
        .add_field_rules(FieldRule.exact("pin", action="remove"))
    )

    serialized = original.to_dict()
    restored = CleanerPolicy.from_dict(serialized)

    assert serialized["base"] == "none"
    assert restored.rules == ()
    assert restored.field_rules == original.field_rules


def test_production_policy_round_trip_preserves_blocking_behavior() -> None:
    original = CleanerPolicy.production()

    serialized = original.to_dict()
    restored = CleanerPolicy.from_dict(serialized)

    assert _rule_signature(restored) == _rule_signature(original)
    assert restored.block_categories == original.block_categories


def test_custom_text_rule_set_is_rejected_instead_of_silently_lost() -> None:
    from logprivacy.rules.base import RedactionRule

    class ApplicationRule(RedactionRule):
        name = "application_rule"
        category = "application_secret"

        def find(self, text: str) -> tuple[object, ...]:
            return ()

    custom = CleanerPolicy.default().add_rules(ApplicationRule())

    with pytest.raises(PolicyConfigurationError, match="text rules cannot be represented"):
        custom.to_dict()


def test_custom_masking_configuration_is_rejected_instead_of_silently_lost() -> None:
    from logprivacy.masking.strategy import PlaceholderMaskingStrategy

    policy = CleanerPolicy.default().with_masking(PlaceholderMaskingStrategy(fallback="[CUSTOM]"))

    with pytest.raises(PolicyConfigurationError, match="masking strategy cannot be represented"):
        policy.to_dict()


def test_pseudonymizer_key_is_never_exported() -> None:
    key = b"test-key-32-bytes-long-and-safe!"
    policy = CleanerPolicy.default().with_pseudonymizer(HMACMaskingStrategy(key=key))

    serialized = policy.to_json()

    assert "pseudonymizer" not in serialized
    assert key.decode() not in serialized


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("masking", "unknown"),
        ("sensitive_keys", "not-a-list"),
        ("block_categories", ["ok", 3]),
        ("max_depth", -1),
        ("max_items", 0),
        ("max_findings", True),
        ("clean_mapping_keys", 1),
        ("clean_unknown_objects", "yes"),
    ],
)
def test_invalid_declarative_controls_are_rejected(field: str, value: object) -> None:
    with pytest.raises(PolicyConfigurationError):
        CleanerPolicy.from_dict({"schema_version": 1, field: value})


def test_unknown_base_error_does_not_reflect_attacker_controlled_value() -> None:
    secret_value = "private-secret-base-name"

    with pytest.raises(PolicyConfigurationError) as exc_info:
        CleanerPolicy.from_dict({"schema_version": 1, "base": secret_value})

    assert secret_value not in str(exc_info.value)


def test_invalid_json_error_does_not_reflect_source_content() -> None:
    sensitive_source = '{"password":"secret",'

    with pytest.raises(PolicyConfigurationError) as exc_info:
        CleanerPolicy.from_json(sensitive_source)

    assert sensitive_source not in str(exc_info.value)
