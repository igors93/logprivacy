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

    This is the easiest entry point:

        clean("email=john@example.com password=123")
    """
    cleaner = _DEFAULT_CLEANER if policy is None else Cleaner(policy=policy)
    return cleaner.clean(value)


def clean_text(text: str, *, policy: CleanerPolicy | None = None) -> str:
    """Return a cleaned string."""
    cleaner = _DEFAULT_CLEANER if policy is None else Cleaner(policy=policy)
    return cleaner.clean_text(text)


def clean_with_result(
    text: str,
    *,
    policy: CleanerPolicy | None = None,
) -> RedactionResult[str]:
    """Return a rich result containing the cleaned text and detected findings."""
    cleaner = _DEFAULT_CLEANER if policy is None else Cleaner(policy=policy)
    return cleaner.clean_with_result(text)


def audit(value: Any, *, policy: CleanerPolicy | None = None) -> AuditReport:
    """Return a safe report of sensitive values found in a value."""
    cleaner = _DEFAULT_CLEANER if policy is None else Cleaner(policy=policy)
    return cleaner.audit(value)


def explain(text: str, *, policy: CleanerPolicy | None = None) -> str:
    """Return a human-readable explanation of how text is cleaned."""
    cleaner = _DEFAULT_CLEANER if policy is None else Cleaner(policy=policy)
    return cleaner.explain(text)


def assert_clean(value: Any, *, policy: CleanerPolicy | None = None) -> None:
    """Raise LogCleanerAssertionError if sensitive data is found."""
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
    """Print values after cleaning them."""
    cleaner = _DEFAULT_CLEANER if policy is None else Cleaner(policy=policy)
    rendered = sep.join(str(cleaner.clean(value)) for value in values)
    print(rendered, end=end)


def get_safe_logger(
    name: str | None = None,
    *,
    policy: CleanerPolicy | None = None,
    level: int | None = None,
) -> logging.Logger:
    """Return a stdlib logger with a LogCleanerFilter attached."""
    logger = logging.getLogger(name)
    if level is not None:
        logger.setLevel(level)

    cleaner = Cleaner(policy=policy or CleanerPolicy.default())
    if not any(isinstance(item, LogCleanerFilter) for item in logger.filters):
        logger.addFilter(LogCleanerFilter(cleaner=cleaner))
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
