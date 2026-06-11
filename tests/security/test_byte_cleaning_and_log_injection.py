from __future__ import annotations

import logging
import sys

import pytest

from logprivacy import CleanerPolicy, LogBlockedError, clean
from logprivacy.integrations.logging_filter import LogPrivacyFilter


@pytest.mark.parametrize("factory", [bytes, bytearray, memoryview])
def test_clean_redacts_byte_like_values_and_preserves_type(factory: type) -> None:
    source = factory(b"password=correct-horse-battery-staple")

    cleaned = clean(source)

    assert type(cleaned) is type(source)
    assert bytes(cleaned) == b"password=[SECRET]"


@pytest.mark.parametrize("factory", [bytes, bytearray, memoryview])
def test_clean_keeps_safe_byte_like_values_and_preserves_type(factory: type) -> None:
    source = factory(b"status=ok")

    cleaned = clean(source)

    assert type(cleaned) is type(source)
    assert bytes(cleaned) == b"status=ok"


def test_clean_byte_values_honor_production_blocking() -> None:
    with pytest.raises(LogBlockedError):
        clean(
            b"password=correct-horse-battery-staple",
            policy=CleanerPolicy.production(),
        )


def test_clean_redacts_byte_values_nested_in_mappings() -> None:
    cleaned = clean({"request_body": b"password=correct-horse-battery-staple"})

    assert cleaned["request_body"] == b"password=[SECRET]"


def test_logging_filter_escapes_newlines_in_message_template() -> None:
    record = logging.LogRecord(
        name="application.auth",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="Login failed for igor\nERROR forged admin login",
        args=(),
        exc_info=None,
    )

    assert LogPrivacyFilter().filter(record)
    rendered = logging.Formatter("%(levelname)s %(message)s").format(record)

    assert rendered == r"INFO Login failed for igor\x0aERROR forged admin login"
    assert rendered.splitlines() == [rendered]


def test_logging_filter_escapes_newlines_in_message_arguments() -> None:
    record = logging.LogRecord(
        name="application.auth",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="Login failed for %s",
        args=("igor\nERROR forged admin login",),
        exc_info=None,
    )

    assert LogPrivacyFilter().filter(record)
    rendered = logging.Formatter("%(levelname)s %(message)s").format(record)

    assert rendered == r"INFO Login failed for igor\x0aERROR forged admin login"
    assert rendered.splitlines() == [rendered]


def test_logging_filter_keeps_exception_tracebacks_multiline() -> None:
    try:
        raise ValueError("invalid password=correct-horse-battery-staple")
    except ValueError:
        exc_info = sys.exc_info()

    record = logging.LogRecord(
        name="application.auth",
        level=logging.ERROR,
        pathname=__file__,
        lineno=1,
        msg="Authentication failed",
        args=(),
        exc_info=exc_info,
    )

    assert LogPrivacyFilter().filter(record)

    assert record.exc_info is None
    assert record.exc_text is not None
    assert "\n" in record.exc_text
    assert "correct-horse-battery-staple" not in record.exc_text
    assert "[SECRET]" in record.exc_text
