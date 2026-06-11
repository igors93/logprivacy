"""Tests for allowlist-based field filtering."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from logprivacy.path_rules.allowlist import _AllowlistMatcher, _parse_allowlist_path
from logprivacy.path_rules.rules import PathRule
from logprivacy.policy import CleanerPolicy
from logprivacy.safe_data import to_safe_data, to_safe_data_with_result

# ---------------------------------------------------------------------------
# _AllowlistMatcher unit tests
# ---------------------------------------------------------------------------


def test_empty_allowlist_rejects_everything():
    """_AllowlistMatcher with no patterns rejects all paths.

    The 'no active allowlist' case is signaled by _allowlist_active=False,
    not by an empty _AllowlistMatcher.
    """
    matcher = _AllowlistMatcher(())
    assert not matcher.is_path_allowed(("any", "path"))
    assert not matcher.is_path_allowed(("x",))


def test_exact_path_allowed():
    matcher = _AllowlistMatcher(("user.name",))
    assert matcher.is_path_allowed(("user", "name"))


def test_non_matching_path_rejected():
    matcher = _AllowlistMatcher(("user.name",))
    assert not matcher.is_path_allowed(("user", "email"))


def test_parent_prefix_allowed():
    """Parent path is preserved when a descendant is allowed."""
    matcher = _AllowlistMatcher(("error.type",))
    assert matcher.is_path_allowed(("error",))  # prefix of allowed path
    assert matcher.is_path_allowed(("error", "type"))


def test_deeper_than_allowed_not_prefix():
    """Path longer than all patterns is rejected."""
    matcher = _AllowlistMatcher(("user.name",))
    assert not matcher.is_path_allowed(("user", "name", "first"))


def test_wildcard_in_allowlist():
    matcher = _AllowlistMatcher(("orders.*.status",))
    assert matcher.is_path_allowed(("orders",))
    assert matcher.is_path_allowed(("orders", "0"))
    assert matcher.is_path_allowed(("orders", "0", "status"))
    assert not matcher.is_path_allowed(("orders", "0", "amount"))


def test_parse_allowlist_path_basic():
    assert _parse_allowlist_path("error.type") == ("error", "type")


def test_parse_allowlist_path_wildcard():
    assert _parse_allowlist_path("orders.*.id") == ("orders", "*", "id")


def test_parse_allowlist_path_empty_rejected():
    with pytest.raises(ValueError, match="must not be empty"):
        _parse_allowlist_path("")


def test_parse_allowlist_path_dot_start():
    with pytest.raises(ValueError, match="must not start or end"):
        _parse_allowlist_path(".foo")


def test_parse_allowlist_path_double_star():
    with pytest.raises(ValueError, match=r"\*\*"):
        _parse_allowlist_path("foo.**.bar")


# ---------------------------------------------------------------------------
# Integration: allow_paths on CleanerPolicy
# ---------------------------------------------------------------------------


def test_allowlist_retains_allowed_field():
    policy = CleanerPolicy.default().with_rules().allow_paths("user.name")
    data = {"user": {"name": "Alice", "email": "alice@example.com"}}
    result = to_safe_data(data, policy=policy)
    # user.name is allowed; user.email is not
    assert result["user"]["name"] == "Alice"  # type: ignore[index]
    assert "email" not in result["user"]  # type: ignore[index]


def test_allowlist_removes_non_allowed():
    policy = CleanerPolicy.default().with_rules().allow_paths("status")
    data = {"status": "ok", "secret": "hidden"}
    result = to_safe_data(data, policy=policy)
    assert result["status"] == "ok"  # type: ignore[index]
    assert "secret" not in result


def test_empty_allowlist_removes_all():
    policy = CleanerPolicy.default().with_rules().allow_paths()
    data = {"a": 1, "b": 2}
    result = to_safe_data(data, policy=policy)
    assert result == {}


def test_allowlist_still_sanitizes_email_in_allowed_field():
    policy = CleanerPolicy.default().allow_paths("user.email")
    data = {"user": {"email": "alice@example.com", "secret": "xyz"}}
    result = to_safe_data(data, policy=policy)
    # allowed field but contains PII — gets sanitized
    assert "alice@example.com" not in str(result["user"]["email"])  # type: ignore[index]
    assert "secret" not in result["user"]  # type: ignore[index]


def test_pathrule_block_wins_over_allowlist():
    """PathRule block takes priority; allowlist still checked afterward."""
    policy = (
        CleanerPolicy.default()
        .with_rules()
        .add_path_rules(PathRule.exact("user.secret", action="block"))
        .allow_paths("user.name", "user.secret")
    )
    from logprivacy.exceptions import LogBlockedError

    with pytest.raises(LogBlockedError):
        to_safe_data({"user": {"secret": "val", "name": "Alice"}}, policy=policy)


def test_allowlist_with_pathrule_remove():
    """PathRule remove fires before allowlist check."""
    policy = (
        CleanerPolicy.default()
        .with_rules()
        .add_path_rules(PathRule.exact("user.private", action="remove"))
        .allow_paths("user.name", "user.private")
    )
    data = {"user": {"name": "Bob", "private": "sensitive"}}
    result = to_safe_data(data, policy=policy)
    assert result["user"]["name"] == "Bob"  # type: ignore[index]
    assert result["user"]["private"] == "[REMOVED]"  # type: ignore[index]


def test_allowlist_with_field_rule():
    """FieldRule still fires after allowlist check (allowed but masked)."""
    from logprivacy.field_rules import FieldRule

    policy = (
        CleanerPolicy.default()
        .with_rules()
        .add_field_rules(FieldRule.exact("token", action="mask"))
        .allow_paths("token")
    )
    data = {"token": "abc123", "other": "hello"}
    result = to_safe_data(data, policy=policy)
    assert result["token"] != "abc123"  # masked
    assert "other" not in result


def test_allowlist_with_sensitive_keys():
    """sensitive_keys masking still fires on allowed fields."""
    policy = CleanerPolicy.default().with_rules().allow_paths("password", "username")
    data = {"password": "hunter2", "username": "alice", "extra": "x"}
    result = to_safe_data(data, policy=policy)
    # password is allowed but is a sensitive key -> masked
    assert result["password"] != "hunter2"  # type: ignore[index]
    assert result["username"] == "alice"  # type: ignore[index]
    assert "extra" not in result


def test_allowlist_with_dataclass():
    @dataclass
    class User:
        name: str
        email: str

    policy = CleanerPolicy.default().with_rules().allow_paths("name")
    result = to_safe_data(User(name="Alice", email="alice@example.com"), policy=policy)
    assert result["name"] == "Alice"  # type: ignore[index]
    assert "email" not in result


def test_allowlist_with_exception():
    policy = CleanerPolicy.default().with_rules().allow_paths("type")
    exc = ValueError("sensitive")
    result = to_safe_data(exc, policy=policy)
    assert "type" in result
    assert "message" not in result


def test_not_allowed_counter():
    policy = CleanerPolicy.default().with_rules().allow_paths("a")
    result_obj = to_safe_data_with_result({"a": 1, "b": 2, "c": 3}, policy=policy)
    assert result_obj.stats.not_allowed == 2


def test_no_allowlist_no_change():
    policy = CleanerPolicy.default().with_rules()
    data = {"a": 1, "b": "hello"}
    result = to_safe_data(data, policy=policy)
    assert result["a"] == 1  # type: ignore[index]
    assert result["b"] == "hello"  # type: ignore[index]


def test_allowlist_wildcard_in_list():
    policy = CleanerPolicy.default().with_rules().allow_paths("items.*.name")
    data = {"items": [{"name": "Widget", "cost": 5}, {"name": "Gadget", "cost": 10}]}
    result = to_safe_data(data, policy=policy)
    assert result["items"][0]["name"] == "Widget"  # type: ignore[index]
    assert "cost" not in result["items"][0]  # type: ignore[index]
    assert result["items"][1]["name"] == "Gadget"  # type: ignore[index]


def test_allowlist_recursion_safe():
    """Allowlist handles recursive structures gracefully."""
    policy = CleanerPolicy.default().with_rules().allow_paths("a")
    d: dict = {"a": 1}
    d["self"] = d
    result = to_safe_data(d, policy=policy)
    assert result["a"] == 1  # type: ignore[index]
    assert "self" not in result  # type: ignore[index]
