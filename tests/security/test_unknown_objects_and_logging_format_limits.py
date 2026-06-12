from __future__ import annotations

import logging

from logprivacy import Cleaner, CleanerPolicy, LogPrivacyFilter, clean


class LeakyObject:
    def __init__(self) -> None:
        self.string_calls = 0

    def __str__(self) -> str:
        self.string_calls += 1
        return "owner=john@example.com password=secret123"


def _record(message: str, args: tuple[object, ...] | dict[str, object]) -> logging.LogRecord:
    return logging.LogRecord(
        name="secure",
        level=logging.ERROR,
        pathname=__file__,
        lineno=1,
        msg=message,
        args=(args,) if isinstance(args, dict) else args,
        exc_info=None,
    )


def test_clean_fails_closed_for_unknown_objects_without_stringifying() -> None:
    value = LeakyObject()

    cleaned = clean(value)

    assert cleaned == "[UNSUPPORTED:LeakyObject]"
    assert cleaned is not value
    assert value.string_calls == 0


def test_clean_unknown_objects_opt_in_still_sanitizes_string_representation() -> None:
    value = LeakyObject()
    cleaner = Cleaner(policy=CleanerPolicy(clean_unknown_objects=True))

    cleaned = cleaner.clean(value)

    assert "john@example.com" not in cleaned
    assert "secret123" not in cleaned
    assert value.string_calls == 1


def test_clean_preserves_known_scalar_values() -> None:
    assert clean(None) is None
    assert clean(42) == 42
    assert clean(True) is True


def test_clean_unknown_objects_opt_in_preserves_existing_scalar_stringification() -> None:
    cleaner = Cleaner(policy=CleanerPolicy(clean_unknown_objects=True))

    assert cleaner.clean(42) == "42"


def test_filter_rejects_explicit_width_above_render_budget() -> None:
    record = _record("%1000000s", ("x",))

    assert LogPrivacyFilter().filter(record) is True

    assert record.getMessage() == ("[LOGPRIVACY INPUT LIMIT EXCEEDED limit=message_format_chars]")


def test_filter_rejects_explicit_precision_above_render_budget() -> None:
    record = _record("%.1000000s", ("x",))

    assert LogPrivacyFilter().filter(record) is True

    assert "limit=message_format_chars" in record.getMessage()


def test_filter_rejects_dynamic_width_above_render_budget() -> None:
    record = _record("%*s", (1_000_000, "x"))

    assert LogPrivacyFilter().filter(record) is True

    assert "limit=message_format_chars" in record.getMessage()


def test_filter_rejects_cumulative_width_above_render_budget() -> None:
    record = _record("%9000s%9000s", ("x", "y"))

    assert LogPrivacyFilter().filter(record) is True

    assert "limit=message_format_chars" in record.getMessage()


def test_filter_preserves_common_positional_and_mapping_formats() -> None:
    positional = _record("user=%s attempts=%d", ("john@example.com", 3))
    mapping = _record("user=%(user)s", {"user": "john@example.com"})

    assert LogPrivacyFilter().filter(positional) is True
    assert LogPrivacyFilter().filter(mapping) is True

    assert positional.getMessage() == "user=[EMAIL] attempts=3"
    assert mapping.getMessage() == "user=[EMAIL]"


def test_filter_preserves_safe_dynamic_width() -> None:
    record = _record("%*s", (5, "x"))

    assert LogPrivacyFilter().filter(record) is True

    assert record.getMessage() == "    x"
