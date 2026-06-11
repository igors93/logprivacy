from __future__ import annotations

import io
import json
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import date, datetime, time
from decimal import Decimal
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest

from logprivacy import (
    AdapterRegistry,
    CleanerPolicy,
    FieldRule,
    JSONScalar,
    JSONValue,
    LogBlockedError,
    safe_json_dump,
    safe_json_dumps,
    to_safe_data,
)


class Role(Enum):
    ADMIN = "admin"


@dataclass
class UserPayload:
    email: str
    password: str


class CustomPayload:
    def __init__(self, identifier: str, metadata: dict[str, object]) -> None:
        self.identifier = identifier
        self.metadata = metadata


def test_public_json_types_are_importable() -> None:
    scalar: JSONScalar = "ok"
    value: JSONValue = {"items": [scalar, None, 1, 1.5, True]}
    assert value["items"][0] == "ok"


def test_to_safe_data_cleans_basic_json_safe_structures() -> None:
    value = {
        "message": "hello",
        "email": "john@example.com",
        "password": "secret123",
        "items": ["token=abc123456789", ("safe",)],
    }

    assert to_safe_data(value) == {
        "message": "hello",
        "email": "[EMAIL]",
        "password": "[SECRET]",
        "items": ["token=[SECRET]", ["safe"]],
    }


def test_to_safe_data_supports_standard_library_types() -> None:
    value = {
        "dataclass": UserPayload("john@example.com", "secret123"),
        "enum": Role.ADMIN,
        "decimal": Decimal("10.50"),
        "datetime": datetime(2026, 1, 2, 3, 4, 5),
        "date": date(2026, 1, 2),
        "time": time(3, 4, 5),
        "uuid": UUID("12345678-1234-5678-1234-567812345678"),
        "path": Path("/tmp/password=secret123"),
        "bytes": b"email=john@example.com",
        "set": {"b", "a"},
    }

    safe = to_safe_data(value)

    assert safe["dataclass"] == {"email": "[EMAIL]", "password": "[SECRET]"}
    assert safe["enum"] == "admin"
    assert safe["decimal"] == "10.50"
    assert safe["datetime"] == "2026-01-02T03:04:05"
    assert safe["date"] == "2026-01-02"
    assert safe["time"] == "03:04:05"
    assert safe["uuid"] == "12345678-1234-5678-1234-567812345678"
    assert safe["path"] == "/tmp/password=[SECRET]"
    assert safe["bytes"] == "email=[EMAIL]"
    assert safe["set"] == ["a", "b"]


def test_to_safe_data_exception_output_is_small_and_sanitized() -> None:
    safe = to_safe_data(ValueError("password=secret123"))

    assert safe == {"type": "ValueError", "message": "password=[SECRET]"}


def test_recursive_mapping_and_sequence_fail_closed() -> None:
    mapping: dict[str, object] = {}
    mapping["self"] = mapping
    sequence: list[object] = []
    sequence.append(sequence)

    assert to_safe_data(mapping) == {"self": {"[LOGPRIVACY_ERROR]": "[RECURSIVE]"}}
    assert to_safe_data(sequence) == [["[RECURSIVE]"]]


def test_hostile_str_and_mapping_iteration_do_not_leak() -> None:
    class HostileStr:
        def __str__(self) -> str:
            raise RuntimeError("password=secret123")

    class BrokenMapping(Mapping[str, object]):
        def __getitem__(self, key: str) -> object:
            raise KeyError(key)

        def __iter__(self) -> Any:
            raise RuntimeError("password=secret123")

        def __len__(self) -> int:
            return 1

        def items(self) -> Any:
            raise RuntimeError("password=secret123")

    assert to_safe_data(HostileStr()) == "[UNSUPPORTED:HostileStr]"
    assert to_safe_data(BrokenMapping()) == {"[LOGPRIVACY_ERROR]": "[UNAVAILABLE]"}


def test_adapters_are_public_sanitized_and_not_global() -> None:
    registry = AdapterRegistry.default()
    registry.register(
        CustomPayload,
        lambda value: {
            "identifier": value.identifier,
            "metadata": value.metadata,
        },
    )
    payload = CustomPayload("user-1", {"password": "secret123", "note": "john@example.com"})

    assert to_safe_data(payload, adapters=registry) == {
        "identifier": "user-1",
        "metadata": {"password": "[SECRET]", "note": "[EMAIL]"},
    }
    assert to_safe_data(payload) == "[UNSUPPORTED:CustomPayload]"


def test_adapter_errors_fail_closed_without_payload() -> None:
    registry = AdapterRegistry.default()

    def broken(_: CustomPayload) -> object:
        raise RuntimeError("password=secret123")

    registry.register(CustomPayload, broken)

    assert to_safe_data(CustomPayload("secret", {}), adapters=registry) == (
        "[UNSUPPORTED:CustomPayload]"
    )


def test_non_string_keys_are_cleaned_and_collisions_are_deterministic() -> None:
    value = {1: "first", "1": "second", b"password": "secret123"}

    assert to_safe_data(value) == {
        "1": "first",
        "1#2": "second",
        "password": "[SECRET]",
    }


def test_limits_are_applied_to_safe_data() -> None:
    depth_policy = replace(CleanerPolicy.default(), max_depth=0)
    item_policy = replace(CleanerPolicy.default(), max_items=1)

    assert to_safe_data({"outer": {"password": "secret123"}}, policy=depth_policy) == {
        "outer": "[MAX_DEPTH]"
    }
    assert to_safe_data({"a": 1, "b": 2}, policy=item_policy) == {
        "a": 1,
        "[LOGPRIVACY_TRUNCATED]": "[TRUNCATED]",
    }


def test_field_rules_mask_remove_truncate_block_and_precedence() -> None:
    policy = CleanerPolicy.default().add_field_rules(
        FieldRule.exact("password", action="remove"),
        FieldRule.contains("api token", action="mask"),
        FieldRule.regex(r".*_raw$", action="truncate", max_chars=18),
    )

    assert to_safe_data(
        {
            "password": "secret123",
            "apiToken": "abc123456789",
            "requestRaw": "password=secret123 outside",
        },
        policy=policy,
    ) == {
        "password": "[REMOVED]",
        "apiToken": "[SECRET]",
        "requestRaw": "password=[SECRET]",
    }

    block_policy = CleanerPolicy.default().add_field_rules(FieldRule.exact("raw", action="block"))
    with pytest.raises(LogBlockedError) as exc_info:
        to_safe_data({"raw": "password=secret123"}, policy=block_policy)
    assert exc_info.value.categories == ("field",)


def test_invalid_field_regex_is_rejected_safely() -> None:
    with pytest.raises(ValueError, match="invalid field rule regex"):
        FieldRule.regex("[")


def test_safe_json_dumps_and_dump_sanitize_before_serialization() -> None:
    value = {
        "user": UserPayload("john@example.com", "secret123"),
        "nan": float("nan"),
        "inf": float("inf"),
        "decimal_nan": Decimal("NaN"),
    }

    dumped = safe_json_dumps(value, sort_keys=True)
    assert json.loads(dumped) == to_safe_data(value)
    assert "john@example.com" not in dumped
    assert "secret123" not in dumped
    assert "NaN" not in dumped
    assert "Infinity" not in dumped

    file = io.StringIO()
    safe_json_dump(value, file, sort_keys=True)
    assert json.loads(file.getvalue()) == to_safe_data(value)


def test_safe_json_dumps_rejects_default_option() -> None:
    with pytest.raises(TypeError, match="default="):
        safe_json_dumps({"password": "secret123"}, default=str)


def test_to_safe_data_is_idempotent_for_safe_output() -> None:
    value = {
        "email": "john@example.com",
        "payload": UserPayload("mary@example.com", "secret123"),
        "items": {"b", "a"},
    }
    safe = to_safe_data(value)

    assert to_safe_data(safe) == safe
