"""LogCleaner public API."""

from __future__ import annotations

from logcleaner.api import clean, clean_text, clean_with_result
from logcleaner.cleaner import Cleaner
from logcleaner.exceptions import LogCleanerError, RuleValidationError
from logcleaner.integrations.logging_filter import LogCleanerFilter
from logcleaner.integrations.logging_formatter import LogCleanerFormatter
from logcleaner.policy import CleanerPolicy
from logcleaner.result import Finding, RedactionResult
from logcleaner.rules.custom import CustomRegexRule
from logcleaner.rules.email import EmailRule
from logcleaner.rules.secret import SecretRule
from logcleaner.rules.token import TokenRule
from logcleaner.rules.url import UrlRule

__all__ = [
    "Cleaner",
    "CleanerPolicy",
    "CustomRegexRule",
    "EmailRule",
    "Finding",
    "LogCleanerError",
    "LogCleanerFilter",
    "LogCleanerFormatter",
    "RedactionResult",
    "RuleValidationError",
    "SecretRule",
    "TokenRule",
    "UrlRule",
    "clean",
    "clean_text",
    "clean_with_result",
]

__version__ = "0.1.0"
