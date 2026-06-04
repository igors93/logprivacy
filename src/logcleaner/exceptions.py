"""Exceptions raised by LogCleaner."""

from __future__ import annotations


class LogCleanerError(Exception):
    """Base exception for LogCleaner errors."""


class RuleValidationError(LogCleanerError):
    """Raised when a redaction rule is invalid."""


class LogBlockedError(LogCleanerError):
    """Raised when block mode prevents a sensitive value from being logged."""

    def __init__(self, message: str, *, categories: tuple[str, ...]) -> None:
        super().__init__(message)
        self.categories = categories


class LogCleanerAssertionError(AssertionError):
    """Raised by assert_clean() when sensitive data is found."""

    def __init__(self, message: str, *, categories: tuple[str, ...]) -> None:
        super().__init__(message)
        self.categories = categories
