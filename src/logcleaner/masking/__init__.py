"""Masking strategies and placeholder values."""

from logcleaner.masking.placeholders import (
    DEFAULT_PLACEHOLDERS,
    EMAIL_PLACEHOLDER,
    IP_ADDRESS_PLACEHOLDER,
    PHONE_PLACEHOLDER,
    SECRET_PLACEHOLDER,
    TOKEN_PLACEHOLDER,
    URL_PLACEHOLDER,
)
from logcleaner.masking.strategy import (
    HashMaskingStrategy,
    MaskingStrategy,
    PartialMaskingStrategy,
    PlaceholderMaskingStrategy,
)

__all__ = [
    "DEFAULT_PLACEHOLDERS",
    "EMAIL_PLACEHOLDER",
    "HashMaskingStrategy",
    "IP_ADDRESS_PLACEHOLDER",
    "MaskingStrategy",
    "PHONE_PLACEHOLDER",
    "PartialMaskingStrategy",
    "PlaceholderMaskingStrategy",
    "SECRET_PLACEHOLDER",
    "TOKEN_PLACEHOLDER",
    "URL_PLACEHOLDER",
]
