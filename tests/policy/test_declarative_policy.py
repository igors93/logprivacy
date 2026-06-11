"""Tests for CleanerPolicy.from_dict / to_dict / from_json / to_json."""

from __future__ import annotations

import json

import pytest

from logprivacy.exceptions import PolicyConfigurationError
from logprivacy.field_rules import FieldRule
from logprivacy.masking.strategy import HMACMaskingStrategy
from logprivacy.path_rules.rules import PathRule
from logprivacy.policy import CleanerPolicy

# ---------------------------------------------------------------------------
# from_dict basics
# ---------------------------------------------------------------------------


def test_from_dict_basic():
    data = {"schema_version": 1}
    policy = CleanerPolicy.from_dict(data)
    assert isinstance(policy, CleanerPolicy)


def test_from_dict_with_base_strict():
    data = {"schema_version": 1, "base": "strict"}
    policy = CleanerPolicy.from_dict(data)
    # strict has more rules than default
    assert len(policy.rules) > 0


def test_from_dict_unknown_base_rejected():
    with pytest.raises(PolicyConfigurationError, match="unknown base policy"):
        CleanerPolicy.from_dict({"schema_version": 1, "base": "nonexistent"})


def test_from_dict_unknown_field_rejected():
    with pytest.raises(PolicyConfigurationError, match="unknown policy configuration fields"):
        CleanerPolicy.from_dict({"schema_version": 1, "unknown_key": True})


def test_from_dict_wrong_schema_version():
    with pytest.raises(PolicyConfigurationError, match="unsupported schema_version"):
        CleanerPolicy.from_dict({"schema_version": 2})


def test_from_dict_missing_schema_version():
    with pytest.raises(PolicyConfigurationError, match="unsupported schema_version"):
        CleanerPolicy.from_dict({})


def test_from_dict_not_dict():
    with pytest.raises(PolicyConfigurationError, match="must be a mapping"):
        CleanerPolicy.from_dict([1, 2, 3])


# ---------------------------------------------------------------------------
# field_rules parsing
# ---------------------------------------------------------------------------


def test_from_dict_with_field_rules():
    data = {
        "schema_version": 1,
        "field_rules": [{"match": "ssn", "action": "remove"}],
    }
    policy = CleanerPolicy.from_dict(data)
    # default rules + 1 extra
    assert any(fr.match == "ssn" for fr in policy.field_rules)


def test_from_dict_field_rule_invalid_action():
    data = {
        "schema_version": 1,
        "field_rules": [{"match": "ssn", "action": "explode"}],
    }
    with pytest.raises(PolicyConfigurationError, match="field_rules"):
        CleanerPolicy.from_dict(data)


def test_from_dict_field_rule_missing_match():
    with pytest.raises(PolicyConfigurationError, match="field_rules\\[0\\].match"):
        CleanerPolicy.from_dict({"schema_version": 1, "field_rules": [{"action": "mask"}]})


def test_from_dict_field_rule_not_mapping():
    with pytest.raises(PolicyConfigurationError, match="field_rules\\[0\\]"):
        CleanerPolicy.from_dict({"schema_version": 1, "field_rules": ["string"]})


def test_from_dict_field_rule_unknown_field():
    with pytest.raises(PolicyConfigurationError, match="unknown fields"):
        CleanerPolicy.from_dict(
            {
                "schema_version": 1,
                "field_rules": [{"match": "x", "oops": True}],
            }
        )


# ---------------------------------------------------------------------------
# path_rules parsing
# ---------------------------------------------------------------------------


def test_from_dict_with_path_rules():
    data = {
        "schema_version": 1,
        "path_rules": [{"path": "user.id", "action": "remove"}],
    }
    policy = CleanerPolicy.from_dict(data)
    assert len(policy.path_rules) == 1
    assert isinstance(policy.path_rules[0], PathRule)


def test_from_dict_path_rule_glob():
    data = {
        "schema_version": 1,
        "path_rules": [{"path": "items.*.price", "mode": "glob", "action": "mask"}],
    }
    policy = CleanerPolicy.from_dict(data)
    pr = policy.path_rules[0]
    assert isinstance(pr, PathRule)
    assert pr.mode == "glob"


def test_from_dict_path_rule_invalid():
    with pytest.raises(PolicyConfigurationError, match="path_rules"):
        CleanerPolicy.from_dict(
            {
                "schema_version": 1,
                "path_rules": [{"path": "", "action": "mask"}],
            }
        )


# ---------------------------------------------------------------------------
# allowlist parsing
# ---------------------------------------------------------------------------


def test_from_dict_with_allowlist():
    data = {
        "schema_version": 1,
        "allowlist": {"paths": ["user.name", "status"]},
    }
    policy = CleanerPolicy.from_dict(data)
    assert policy.allowlist == ("user.name", "status")


def test_from_dict_allowlist_not_dict():
    with pytest.raises(PolicyConfigurationError, match="allowlist must be a mapping"):
        CleanerPolicy.from_dict({"schema_version": 1, "allowlist": ["user.name"]})


def test_from_dict_allowlist_unknown_field():
    with pytest.raises(PolicyConfigurationError, match="unknown allowlist fields"):
        CleanerPolicy.from_dict({"schema_version": 1, "allowlist": {"paths": [], "extra": True}})


def test_from_dict_allowlist_path_not_string():
    with pytest.raises(PolicyConfigurationError, match="must be a string"):
        CleanerPolicy.from_dict({"schema_version": 1, "allowlist": {"paths": [123]}})


# ---------------------------------------------------------------------------
# to_dict
# ---------------------------------------------------------------------------


def test_to_dict_schema_version():
    policy = CleanerPolicy.default()
    d = policy.to_dict()
    assert d["schema_version"] == 1


def test_to_dict_has_field_rules():
    policy = CleanerPolicy.default().add_field_rules(FieldRule.exact("ssn", action="remove"))
    d = policy.to_dict()
    assert any(fr["match"] == "ssn" for fr in d["field_rules"])  # type: ignore[index]


def test_to_dict_has_path_rules():
    policy = CleanerPolicy.default().add_path_rules(PathRule.exact("user.id", action="remove"))
    d = policy.to_dict()
    assert len(d["path_rules"]) == 1  # type: ignore[arg-type]
    assert d["path_rules"][0]["path"] == "user.id"  # type: ignore[index]


def test_to_dict_allowlist():
    policy = CleanerPolicy.default().allow_paths("user.name")
    d = policy.to_dict()
    assert d["allowlist"] == {"paths": ["user.name"]}  # type: ignore[comparison-overlap]


def test_to_dict_no_allowlist_key_when_none():
    policy = CleanerPolicy.default()
    d = policy.to_dict()
    assert "allowlist" not in d


def test_to_dict_does_not_export_pseudonymizer():
    key = b"test-key-32-bytes-long-and-safe!"
    s = HMACMaskingStrategy(key=key)
    policy = CleanerPolicy.default().with_pseudonymizer(s)
    d = policy.to_dict()
    assert "pseudonymizer" not in d
    serialized = json.dumps(d)
    assert key.decode() not in serialized


# ---------------------------------------------------------------------------
# to_json / from_json
# ---------------------------------------------------------------------------


def test_to_json_is_valid_json():
    policy = CleanerPolicy.default()
    s = policy.to_json()
    parsed = json.loads(s)
    assert parsed["schema_version"] == 1


def test_from_json_basic():
    j = '{"schema_version": 1}'
    policy = CleanerPolicy.from_json(j)
    assert isinstance(policy, CleanerPolicy)


def test_from_json_invalid_json():
    with pytest.raises(PolicyConfigurationError, match="invalid JSON"):
        CleanerPolicy.from_json("not-json")


# ---------------------------------------------------------------------------
# Round-trip
# ---------------------------------------------------------------------------


def test_round_trip_field_rules():
    policy = (
        CleanerPolicy.default()
        .with_rules()
        .add_field_rules(FieldRule.exact("ssn", action="remove"))
    )
    d = policy.to_dict()
    d["schema_version"] = 1
    policy2 = CleanerPolicy.from_dict(d)
    assert any(fr.match == "ssn" for fr in policy2.field_rules)


def test_round_trip_path_rules():
    policy = (
        CleanerPolicy.default()
        .with_rules()
        .add_path_rules(PathRule.exact("user.id", action="remove"))
    )
    d = policy.to_dict()
    d["schema_version"] = 1
    policy2 = CleanerPolicy.from_dict(d)
    assert len(policy2.path_rules) == 1
    pr = policy2.path_rules[0]
    assert isinstance(pr, PathRule)
    assert pr.path == "user.id"
    assert pr.action == "remove"


def test_round_trip_allowlist():
    policy = CleanerPolicy.default().with_rules().allow_paths("a.b", "c")
    d = policy.to_dict()
    d["schema_version"] = 1
    policy2 = CleanerPolicy.from_dict(d)
    assert policy2.allowlist == ("a.b", "c")


def test_from_dict_production_base():
    policy = CleanerPolicy.from_dict({"schema_version": 1, "base": "production"})
    assert "credential" in policy.block_categories


def test_from_dict_web_base():
    policy = CleanerPolicy.from_dict({"schema_version": 1, "base": "web"})
    assert isinstance(policy, CleanerPolicy)
