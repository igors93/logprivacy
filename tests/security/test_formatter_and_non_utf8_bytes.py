from __future__ import annotations

import logging
import sys

import pytest

from logprivacy import clean
from logprivacy.integrations.logging_formatter import LogPrivacyFormatter


@pytest.mark.parametrize("factory", [bytes, bytearray, memoryview])
def test_clean_preserves_safe_non_utf8_bytes(factory: type) -> None:
    source = factory(b"\xff\xfestatus=ok\x80")

    cleaned = clean(source)

    assert type(cleaned) is type(source)
    assert bytes(cleaned) == b"\xff\xfestatus=ok\x80"


@pytest.mark.parametrize("factory", [bytes, bytearray, memoryview])
def test_clean_masks_secret_without_corrupting_non_utf8_bytes(factory: type) -> None:
    source = factory(b"\xffpassword=correct-horse-battery-staple\n\xfe")

    cleaned = clean(source)

    assert type(cleaned) is type(source)
    assert bytes(cleaned) == b"\xffpassword=[SECRET]\n\xfe"


def test_logging_formatter_escapes_newlines_in_message_arguments() -> None:
    formatter = LogPrivacyFormatter()
    record = logging.LogRecord(
        name="application.auth",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="Login failed for %s",
        args=("igor\nERROR forged admin login",),
        exc_info=None,
    )

    rendered = formatter.format(record)

    assert rendered == r"Login failed for igor\x0aERROR forged admin login"
    assert rendered.splitlines() == [rendered]


def test_logging_formatter_keeps_clean_tracebacks_multiline() -> None:
    formatter = LogPrivacyFormatter()
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

    rendered = formatter.format(record)

    assert rendered.startswith("Authentication failed\nTraceback")
    assert "correct-horse-battery-staple" not in rendered
    assert "password=[SECRET]" in rendered
