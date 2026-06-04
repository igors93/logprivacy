"""
LogPrivacy public API.

Simple by default, powerful by composition, safe by guidance.
"""

from __future__ import annotations

from logprivacy.api import (
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
from logprivacy.audit import AuditReport
from logprivacy.cleaner import Cleaner
from logprivacy.exceptions import (
    LogBlockedError,
    LogPrivacyAssertionError,
    LogPrivacyError,
    RuleValidationError,
)
from logprivacy.integrations.logging_filter import LogPrivacyFilter
from logprivacy.integrations.logging_formatter import LogPrivacyFormatter
from logprivacy.masking.strategy import (
    HashMaskingStrategy,
    PartialMaskingStrategy,
    PlaceholderMaskingStrategy,
)
from logprivacy.policy import CleanerPolicy
from logprivacy.result import Finding, RedactionResult
from logprivacy.rules.custom import CustomRegexRule
from logprivacy.rules.email import EmailRule
from logprivacy.rules.secret import SecretRule
from logprivacy.rules.token import TokenRule
from logprivacy.rules.url import UrlRule

__all__ = [
    "AuditReport",
    "Cleaner",
    "CleanerPolicy",
    "CustomRegexRule",
    "EmailRule",
    "Finding",
    "HashMaskingStrategy",
    "LogBlockedError",
    "LogPrivacyAssertionError",
    "LogPrivacyError",
    "LogPrivacyFilter",
    "LogPrivacyFormatter",
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

__version__ = "0.5.1"
