"""Regression tests for completeness with untrusted mapping keys."""

from __future__ import annotations

from typing import cast

from logprivacy import to_safe_data, to_safe_data_with_result
from logprivacy.typing import JSONValue


class HostileKey:
    """Hashable key whose string representations must never be invoked."""

    def __hash__(self) -> int:
        return id(self)

    def __str__(self) -> str:
        raise RuntimeError("secret-from-str")

    def __repr__(self) -> str:
        raise RuntimeError("secret-from-repr")


def _as_mapping(value: JSONValue) -> dict[str, JSONValue]:
    assert isinstance(value, dict)
    return cast(dict[str, JSONValue], value)


def test_untrusted_mapping_key_marks_result_incomplete() -> None:
    result = to_safe_data_with_result(
        {
            HostileKey(): {
                "token": "fake-secret-token-123456789",
            }
        }
    )

    assert result.complete is False
    assert result.limitations == ("untrusted_mapping_key",)
    assert result.stats.masked == 1

    cleaned = _as_mapping(result.cleaned)
    assert list(cleaned) == ["<HostileKey>"]
    assert list(cleaned.values()) == ["[SECRET]"]
    assert "fake-secret-token-123456789" not in repr(cleaned)
    assert "secret-from-str" not in repr(cleaned)
    assert "secret-from-repr" not in repr(cleaned)


def test_multiple_untrusted_keys_record_limitation_once() -> None:
    result = to_safe_data_with_result(
        {
            HostileKey(): "first-secret-value",
            HostileKey(): "second-secret-value",
        }
    )

    assert result.complete is False
    assert result.limitations == ("untrusted_mapping_key",)
    assert result.stats.masked == 2

    cleaned = _as_mapping(result.cleaned)
    assert set(cleaned.values()) == {"[SECRET]"}
    assert len(cleaned) == 2


def test_trusted_mapping_keys_remain_complete() -> None:
    result = to_safe_data_with_result(
        {
            "status": "ok",
            42: "safe",
            b"name": "value",
        }
    )

    assert result.complete is True
    assert "untrusted_mapping_key" not in result.limitations


def test_plain_to_safe_data_preserves_fail_closed_output() -> None:
    cleaned = to_safe_data(
        {
            HostileKey(): {
                "password": "fake-password-123456",
            }
        }
    )

    mapping = _as_mapping(cleaned)
    assert mapping == {"<HostileKey>": "[SECRET]"}
