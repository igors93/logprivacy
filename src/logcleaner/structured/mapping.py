"""Mapping cleaning support."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def clean_mapping(mapping: Mapping[Any, Any], cleaner: Any, depth: int) -> dict[Any, Any]:
    """Return a cleaned dictionary copy."""
    cleaned: dict[Any, Any] = {}
    for key, value in mapping.items():
        output_key = cleaner.clean_text(str(key)) if cleaner.policy.clean_mapping_keys else key
        if cleaner.policy.is_sensitive_key(key):
            cleaned[output_key] = cleaner.policy.masking.mask_category("secret")
        else:
            cleaned[output_key] = cleaner._clean_value(value, depth=depth + 1)
    return cleaned
