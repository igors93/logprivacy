"""Mapping cleaning support."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from logprivacy.masking.value import mask_sensitive_value

if TYPE_CHECKING:
    from logprivacy.cleaner import Cleaner


def clean_mapping(mapping: Mapping[Any, Any], cleaner: Cleaner, depth: int) -> dict[Any, Any]:
    """Return a cleaned dictionary copy."""
    cleaned: dict[Any, Any] = {}
    for key, value in mapping.items():
        output_key = cleaner.clean_text(str(key)) if cleaner.policy.clean_mapping_keys else key
        if cleaner.policy.is_sensitive_key(key):
            cleaned[output_key] = mask_sensitive_value(
                value,
                category="credential",
                rule_name="sensitive_key",
                reason="value belongs to a sensitive mapping key",
                policy=cleaner.policy,
            )
        else:
            cleaned[output_key] = cleaner._clean_value(value, depth=depth + 1)
    return cleaned
