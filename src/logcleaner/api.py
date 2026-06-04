"""Small public functions for the most common LogCleaner use cases."""

from __future__ import annotations

import logging
from typing import Any

from logcleaner.audit import AuditReport
from logcleaner.cleaner import Cleaner
from logcleaner.exceptions import LogCleanerAssertionError
from logcleaner.integrations.logging_filter import LogCleanerFilter
from logcleaner.policy import CleanerPolicy
from logcleaner.result import RedactionResult

_DEFAULT_CLEANER = Cleaner()


def clean(value: Any, *, policy: CleanerPolicy | None = None) -> Any:
    """
    Return a cleaned copy of a string or structured value.

    Accepts strings, dicts, lists, and tuples. Nested structures are traversed
    recursively. This is the most common entry point.

    Example::

        clean("email=john@example.com password=123")
        # "email=[EMAIL] password=[SECRET]"

        clean({"password": "123", "status": "ok"})
        # {"password": "[SECRET]", "status": "ok"}
    """
    cleaner = _DEFAULT_CLEANER if policy is None else Cleaner(policy=policy)
    return cleaner.clean(value)


def clean_text(text: str, *, policy: CleanerPolicy | None = None) -> str:
    """
    Return a cleaned string.

    Like ``clean()`` but always returns a string. Use this when you know the
    input is a string and want a typed return value.
    """
    cleaner = _DEFAULT_CLEANER if policy is None else Cleaner(policy=policy)
    return cleaner.clean_text(text)


def clean_with_result(
    text: str,
    *,
    policy: CleanerPolicy | None = None,
) -> RedactionResult[str]:
    """
    Return a ``RedactionResult`` containing the cleaned text and detected findings.

    Use this when you need to know what was redacted, not just the cleaned output.

    Example::

        result = clean_with_result("john@example.com")
        result.cleaned        # "[EMAIL]"
        result.finding_count  # 1
        result.categories     # ("email",)
    """
    cleaner = _DEFAULT_CLEANER if policy is None else Cleaner(policy=policy)
    return cleaner.clean_with_result(text)


def audit(value: Any, *, policy: CleanerPolicy | None = None) -> AuditReport:
    """
    Return an ``AuditReport`` describing sensitive data found in a value.

    Does not modify the input. Works on strings, dicts, lists, and tuples.
    Use this to check whether a value is safe to log before actually logging it.

    Example::

        report = audit({"password": "123"})
        report.safe        # False
        report.risk_level  # "high"
        report.categories  # ("credential",)
    """
    cleaner = _DEFAULT_CLEANER if policy is None else Cleaner(policy=policy)
    return cleaner.audit(value)


def explain(text: str, *, policy: CleanerPolicy | None = None) -> str:
    """
    Return a human-readable explanation of what ``clean()`` would redact.

    Useful for debugging policies and understanding why something is redacted.
    """
    cleaner = _DEFAULT_CLEANER if policy is None else Cleaner(policy=policy)
    return cleaner.explain(text)


def assert_clean(value: Any, *, policy: CleanerPolicy | None = None) -> None:
    """
    Raise ``LogCleanerAssertionError`` if sensitive data is found in a value.

    Intended for tests and CI pipelines. Works on strings, dicts, lists, and
    tuples. Passes silently when the value is safe.

    Example::

        def test_response_payload_is_safe():
            assert_clean(response.json())
    """
    report = audit(value, policy=policy)
    if not report.safe:
        categories = ", ".join(report.categories)
        raise LogCleanerAssertionError(
            f"Sensitive data found: {categories}",
            categories=report.categories,
        )


def safe_print(
    *values: Any, sep: str = " ", end: str = "\n", policy: CleanerPolicy | None = None
) -> None:
    """
    Print values after cleaning them.

    Drop-in replacement for ``print()`` during debugging. Accepts the same
    ``sep`` and ``end`` keyword arguments.

    Example::

        safe_print("token=abc123456789", {"password": "123456"})
        # token=[SECRET] {'password': '[SECRET]'}
    """
    cleaner = _DEFAULT_CLEANER if policy is None else Cleaner(policy=policy)
    rendered = sep.join(str(cleaner.clean(value)) for value in values)
    print(rendered, end=end)


def get_safe_logger(
    name: str | None = None,
    *,
    policy: CleanerPolicy | None = None,
    level: int | None = None,
) -> logging.Logger:
    """
    Return a stdlib logger with a ``LogCleanerFilter`` attached.

    Calling this function multiple times with the same logger name is safe:
    a second call without an explicit ``policy`` reuses the existing filter.
    A second call with an explicit ``policy`` replaces the filter so the new
    policy takes effect immediately.

    Example::

        logger = get_safe_logger(__name__)
        logger.warning("User john@example.com used password=123456")
        # emits: User [EMAIL] used password=[SECRET]
    """
    logger = logging.getLogger(name)
    if level is not None:
        logger.setLevel(level)

    existing = next((f for f in logger.filters if isinstance(f, LogCleanerFilter)), None)

    if existing is None:
        cleaner = Cleaner(policy=policy or CleanerPolicy.default())
        logger.addFilter(LogCleanerFilter(cleaner=cleaner))
    elif policy is not None:
        # Replace the filter so the caller's explicit policy takes effect
        logger.removeFilter(existing)
        logger.addFilter(LogCleanerFilter(cleaner=Cleaner(policy=policy)))

    return logger


def clean_url(url: str, *, policy: CleanerPolicy | None = None, redact_full: bool = False) -> str:
    """Clean a URL while preserving safe context."""
    from logcleaner.url import clean_url as _clean_url

    return _clean_url(url, policy=policy, redact_full=redact_full)


def scan_file(
    path: str, *, policy: CleanerPolicy | None = None, encoding: str = "utf-8"
) -> AuditReport:
    """Scan a text file and return an audit report."""
    from logcleaner.files import scan_file as _scan_file

    return _scan_file(path, policy=policy, encoding=encoding)


def clean_file(
    path: str,
    *,
    output: str,
    policy: CleanerPolicy | None = None,
    encoding: str = "utf-8",
) -> object:
    """Clean a text file and write the cleaned output."""
    from logcleaner.files import clean_file as _clean_file

    return _clean_file(path, output=output, policy=policy, encoding=encoding)
