"""LogPrivacy public exceptions."""

from __future__ import annotations

from logprivacy.exceptions.errors import (
    InputLimitExceededError,
    JSONLProcessingError,
    LogBlockedError,
    LogPrivacyAssertionError,
    LogPrivacyError,
    PolicyConfigurationError,
    PseudonymizationConfigurationError,
    RuleValidationError,
)

__all__ = [
    "InputLimitExceededError",
    "JSONLProcessingError",
    "LogBlockedError",
    "LogPrivacyAssertionError",
    "LogPrivacyError",
    "PolicyConfigurationError",
    "PseudonymizationConfigurationError",
    "RuleValidationError",
]
