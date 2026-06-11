"""Exceptions raised by LogPrivacy."""

from __future__ import annotations


class LogPrivacyError(Exception):
    """Base exception for LogPrivacy errors."""


class RuleValidationError(LogPrivacyError):
    """Raised when a redaction rule is invalid."""


class LogBlockedError(LogPrivacyError):
    """Raised when block mode prevents a sensitive value from being logged."""

    def __init__(self, message: str, *, categories: tuple[str, ...]) -> None:
        super().__init__(message)
        self.categories = categories


class LogPrivacyAssertionError(AssertionError):
    """Raised by assert_clean() when sensitive data is found."""

    def __init__(self, message: str, *, categories: tuple[str, ...]) -> None:
        super().__init__(message)
        self.categories = categories
