"""Exceptions raised by LogCleaner."""


class LogCleanerError(Exception):
    """Base exception for LogCleaner errors."""


class RuleValidationError(LogCleanerError):
    """Raised when a redaction rule is invalid."""
