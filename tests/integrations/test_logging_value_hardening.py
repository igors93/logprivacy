from __future__ import annotations

import logging
import sys
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import replace
from typing import Any

from logprivacy import Cleaner, CleanerPolicy, LogPrivacyFilter
from logprivacy.internal.rendering import DEFAULT_MAX_RENDER_CHARS


def _record(
    message: object = "event",
    *,
    args: tuple[object, ...] | dict[str, object] = (),
    exc_info: tuple[type[BaseException], BaseException, object] | None = None,
) -> logging.LogRecord:
    return logging.LogRecord(
        name="logging-hardening",
        level=logging.ERROR,
        pathname=__file__,
        lineno=1,
        msg=message,
        args=args,
        exc_info=exc_info,  # type: ignore[arg-type]
    )


class HostileKey:
    def __init__(self, identifier: int) -> None:
        self.identifier = identifier
        self.represented = False

    def __hash__(self) -> int:
        return self.identifier

    def __str__(self) -> str:
        self.represented = True
        raise AssertionError("hostile key __str__ must not run")

    def __repr__(self) -> str:
        self.represented = True
        raise AssertionError("hostile key __repr__ must not run")


class BrokenMapping(Mapping[str, object]):
    def __getitem__(self, key: str) -> object:
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        raise RuntimeError("password=iteration-secret")

    def __len__(self) -> int:
        return 1

    def items(self) -> Any:
        raise RuntimeError("password=items-secret")


class BrokenSequence(Sequence[object]):
    def __getitem__(self, index: int) -> object:
        if index == 0:
            return "john@example.com"
        raise RuntimeError("password=iteration-secret")

    def __len__(self) -> int:
        return 2


class BrokenObject:
    def __str__(self) -> str:
        raise RuntimeError("password=object-secret")


class SecretInt(int):
    def __str__(self) -> str:
        return "owner=john@example.com password=numeric-secret"

    def __repr__(self) -> str:
        return "password=numeric-repr-secret"


def test_logging_keeps_range_compact_instead_of_expanding_it() -> None:
    record = _record()
    record.payload = range(1_000_000_000)

    assert LogPrivacyFilter().filter(record) is True

    assert record.payload == range(1_000_000_000)


def test_logging_marks_recursive_sequences_without_recursing_forever() -> None:
    payload: list[object] = []
    payload.append(payload)
    record = _record()
    record.payload = payload

    assert LogPrivacyFilter().filter(record) is True

    assert record.payload == [["[RECURSIVE]"]]


def test_logging_applies_global_item_budget_fail_closed() -> None:
    policy = replace(CleanerPolicy.default(), max_items=2)
    record = _record()
    record.payload = ["safe", "also-safe", "john@example.com"]

    assert LogPrivacyFilter(cleaner=Cleaner(policy=policy)).filter(record) is True

    assert record.payload == ["safe", "also-safe", "[TRUNCATED]"]
    assert "john@example.com" not in repr(record.payload)


def test_logging_applies_depth_limit_without_returning_original_branch() -> None:
    policy = replace(CleanerPolicy.default(), max_depth=0)
    record = _record()
    record.payload = {"nested": {"password": "deep-secret"}}

    assert LogPrivacyFilter(cleaner=Cleaner(policy=policy)).filter(record) is True

    assert record.payload == {"nested": "[MAX_DEPTH]"}
    assert "deep-secret" not in repr(record.payload)


def test_logging_replaces_hostile_mapping_keys_and_preserves_collisions() -> None:
    first = HostileKey(1)
    second = HostileKey(2)
    record = _record()
    record.payload = {
        "<HostileKey>": "safe",
        first: "first-secret",
        second: "second-secret",
    }

    assert LogPrivacyFilter().filter(record) is True

    assert record.payload == {
        "<HostileKey>": "safe",
        "<HostileKey>#2": "[SECRET]",
        "<HostileKey>#3": "[SECRET]",
    }
    assert first.represented is False
    assert second.represented is False


def test_logging_fails_closed_when_mapping_iteration_breaks() -> None:
    record = _record()
    record.payload = BrokenMapping()

    assert LogPrivacyFilter().filter(record) is True

    assert record.payload == {"[LOGPRIVACY_ERROR]": "[UNAVAILABLE]"}
    assert "items-secret" not in repr(record.payload)


def test_logging_fails_closed_when_sequence_iteration_breaks() -> None:
    record = _record()
    record.payload = BrokenSequence()

    assert LogPrivacyFilter().filter(record) is True

    assert record.payload == ["[EMAIL]", "[UNAVAILABLE]"]
    assert "iteration-secret" not in repr(record.payload)


def test_logging_handles_objects_whose_string_conversion_fails() -> None:
    record = _record("value=%s", args=(BrokenObject(),))

    assert LogPrivacyFilter().filter(record) is True

    assert "object-secret" not in record.getMessage()
    assert "<unprintable BrokenObject>" in record.getMessage()


def test_logging_does_not_trust_numeric_subclasses_as_primitives() -> None:
    record = _record()
    record.payload = SecretInt(7)

    assert LogPrivacyFilter().filter(record) is True

    assert type(record.payload) is str
    assert "john@example.com" not in record.payload
    assert "numeric-secret" not in record.payload
    assert record.payload == "owner=[EMAIL] password=[SECRET]"


def test_logging_bounds_large_extra_strings() -> None:
    record = _record()
    record.payload = "x" * (DEFAULT_MAX_RENDER_CHARS * 4)

    assert LogPrivacyFilter().filter(record) is True

    assert isinstance(record.payload, str)
    assert len(record.payload) <= DEFAULT_MAX_RENDER_CHARS
    assert record.payload.endswith("...")


def test_logging_escapes_controls_in_structured_values() -> None:
    record = _record()
    record.payload = "safe\npassword=secret-value\x1b[31m"

    assert LogPrivacyFilter().filter(record) is True

    assert "\n" not in record.payload
    assert "\x1b" not in record.payload
    assert "\\x0a" in record.payload
    assert "password=[SECRET]" in record.payload


def test_named_mapping_arguments_keep_interpolation_keys() -> None:
    record = _record(
        "user=%(user)s count=%(count)d",
        args={"user": "john@example.com", "count": 7},
    )

    assert LogPrivacyFilter().filter(record) is True

    assert record.getMessage() == "user=[EMAIL] count=7"
    assert record.args == ()


def test_truncated_format_arguments_fall_back_without_exposing_values() -> None:
    policy = replace(CleanerPolicy.default(), max_items=1)
    record = _record(
        "%s %s %s",
        args=("john@example.com", "password=second-secret", "third-secret"),
    )

    assert LogPrivacyFilter(cleaner=Cleaner(policy=policy)).filter(record) is True

    rendered = record.getMessage()
    assert "john@example.com" not in rendered
    assert "second-secret" not in rendered
    assert "third-secret" not in rendered
    assert record.args == ()


def test_exception_with_broken_string_conversion_cannot_break_filter() -> None:
    class BrokenException(RuntimeError):
        def __str__(self) -> str:
            raise RuntimeError("password=exception-secret")

    try:
        raise BrokenException()
    except BrokenException:
        record = _record("failed", exc_info=sys.exc_info())  # type: ignore[arg-type]

    assert LogPrivacyFilter().filter(record) is True

    assert record.exc_info is None
    assert record.exc_text is not None
    assert "exception-secret" not in record.exc_text


def test_sets_are_rendered_safely_and_bounded() -> None:
    record = _record()
    record.payload = {"john@example.com", "password=secret-value"}

    assert LogPrivacyFilter().filter(record) is True

    assert type(record.payload) is str
    assert "john@example.com" not in record.payload
    assert "secret-value" not in record.payload
    assert "[EMAIL]" in record.payload
    assert "password=[SECRET]" in record.payload


def test_non_string_message_preserves_format_placeholders_until_interpolation() -> None:
    class MessageTemplate:
        def __str__(self) -> str:
            return "email=%s password=%s"

    record = _record(
        MessageTemplate(),
        args=("john@example.com", "secret-value"),
    )

    assert LogPrivacyFilter().filter(record) is True

    assert record.getMessage() == "email=[EMAIL] password=[SECRET]"
