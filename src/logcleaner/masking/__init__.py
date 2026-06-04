"""Masking strategies and placeholder values."""
from logcleaner.masking.placeholders import DEFAULT_PLACEHOLDERS, EMAIL_PLACEHOLDER, IP_ADDRESS_PLACEHOLDER, SECRET_PLACEHOLDER, TOKEN_PLACEHOLDER, URL_PLACEHOLDER
from logcleaner.masking.strategy import MaskingStrategy, PlaceholderMaskingStrategy
__all__ = ["DEFAULT_PLACEHOLDERS", "EMAIL_PLACEHOLDER", "IP_ADDRESS_PLACEHOLDER", "MaskingStrategy", "PlaceholderMaskingStrategy", "SECRET_PLACEHOLDER", "TOKEN_PLACEHOLDER", "URL_PLACEHOLDER"]
