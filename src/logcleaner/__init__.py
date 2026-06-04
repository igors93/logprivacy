"""
LogCleaner public API.

Simple by default, powerful by composition, safe by guidance.
"""

from __future__ import annotations

from logcleaner.api import (
    assert_clean,
    audit,
    clean,
    clean_file,
    clean_text,
    clean_url,
    clean_with_result,
    explain,
    get_safe_logger,
    safe_print,
    scan_file,
)
from logcleaner.audit import AuditReport
from logcleaner.cleaner import Cleaner
from logcleaner.exceptions import (
    LogBlockedError,
    LogCleanerAssertionError,
    LogCleanerError,
    RuleValidationError,
)
from logcleaner.integrations.logging_filter import LogCleanerFilter
from logcleaner.integrations.logging_formatter import LogCleanerFormatter
from logcleaner.masking.strategy import (
    HashMaskingStrategy,
    PartialMaskingStrategy,
    PlaceholderMaskingStrategy,
)
from logcleaner.policy import CleanerPolicy
from logcleaner.result import Finding, RedactionResult
from logcleaner.rules.custom import CustomRegexRule
from logcleaner.rules.email import EmailRule
from logcleaner.rules.secret import SecretRule
from logcleaner.rules.token import TokenRule
from logcleaner.rules.url import UrlRule

__all__ = [
    "AuditReport",
    "Cleaner",
    "CleanerPolicy",
    "CustomRegexRule",
    "EmailRule",
    "Finding",
    "HashMaskingStrategy",
    "LogBlockedError",
    "LogCleanerAssertionError",
    "LogCleanerError",
    "LogCleanerFilter",
    "LogCleanerFormatter",
    "PartialMaskingStrategy",
    "PlaceholderMaskingStrategy",
    "RedactionResult",
    "RuleValidationError",
    "SecretRule",
    "TokenRule",
    "UrlRule",
    "assert_clean",
    "audit",
    "clean",
    "clean_file",
    "clean_text",
    "clean_url",
    "clean_with_result",
    "explain",
    "get_safe_logger",
    "safe_print",
    "scan_file",
]

__version__ = "0.2.0"
