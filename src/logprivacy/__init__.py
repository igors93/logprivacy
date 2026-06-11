"""
LogPrivacy public API.

Simple by default, powerful by composition, safe by guidance.
"""

from __future__ import annotations

from logprivacy.adapters import AdapterRegistry
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
from logprivacy.field_rules import FieldAction, FieldRule
from logprivacy.integrations.logging_filter import LogPrivacyFilter
from logprivacy.integrations.logging_formatter import LogPrivacyFormatter
from logprivacy.json import safe_json_dump, safe_json_dumps
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
from logprivacy.safe_data import to_safe_data
from logprivacy.typing import JSONScalar, JSONValue

__all__ = [
    "AdapterRegistry",
    "AuditReport",
    "Cleaner",
    "CleanerPolicy",
    "CustomRegexRule",
    "EmailRule",
    "FieldAction",
    "FieldRule",
    "Finding",
    "HashMaskingStrategy",
    "JSONScalar",
    "JSONValue",
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
    "safe_json_dump",
    "safe_json_dumps",
    "scan_file",
    "to_safe_data",
]

__version__ = "0.5.1"
