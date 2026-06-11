"""JSON-safe structured sanitization."""

from __future__ import annotations

import json as _json
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import date as Date
from datetime import datetime as DateTime
from datetime import time as Time
from decimal import Decimal
from enum import Enum
from pathlib import Path
from typing import Any, cast
from uuid import UUID

from logprivacy.adapters import AdapterConverter, AdapterRegistry
from logprivacy.cleaner import Cleaner
from logprivacy.exceptions import LogBlockedError
from logprivacy.field_rules import FieldRule
from logprivacy.internal.traversal import (
    ERROR_MAPPING_KEY,
    LIMIT_ITERATION_ERROR,
    LIMIT_MAX_DEPTH,
    LIMIT_MAX_ITEMS,
    LIMIT_REPRESENTATION_ERROR,
    MAX_DEPTH_PLACEHOLDER,
    RECURSIVE_PLACEHOLDER,
    TRUNCATED_MAPPING_KEY,
    TRUNCATED_PLACEHOLDER,
    UNAVAILABLE_PLACEHOLDER,
    TraversalState,
    safe_mapping_key_text,
)
from logprivacy.masking.value import mask_sensitive_value
from logprivacy.policy import CleanerPolicy
from logprivacy.typing import JSONValue

NON_FINITE_NUMBER_PLACEHOLDER = "[NON_FINITE_NUMBER]"
REMOVED_PLACEHOLDER = "[REMOVED]"

_EXACT_BYTE_TYPES = frozenset({bytes, bytearray, memoryview})
_SAFE_TYPE_NAME_PATTERN = re.compile(r"[^A-Za-z0-9_.-]+")


def to_safe_data(
    value: object,
    *,
    policy: CleanerPolicy | None = None,
    adapters: AdapterRegistry | None = None,
) -> JSONValue:
    """Return a sanitized value made only of JSON-compatible Python types.

    Unknown objects fail closed as ``"[UNSUPPORTED:TypeName]"``. Converter
    results from ``adapters`` are processed again by the same sanitization
    pipeline and are never trusted as already safe.
    """
    effective_policy = CleanerPolicy.default() if policy is None else policy
    effective_adapters = AdapterRegistry.default() if adapters is None else adapters.copy()
    normalizer = _SafeDataNormalizer(effective_policy, effective_adapters)
    return normalizer.normalize(value)


@dataclass(slots=True)
class _SafeDataNormalizer:
    policy: CleanerPolicy
    adapters: AdapterRegistry
    _cleaner: Cleaner = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._cleaner = Cleaner(policy=self.policy)

    def normalize(self, value: object) -> JSONValue:
        state = TraversalState(remaining_items=self.policy.max_items)
        return self._normalize(value, depth=0, state=state)

    def _normalize(self, value: object, *, depth: int, state: TraversalState) -> JSONValue:
        if depth > self.policy.max_depth:
            state.mark_limit(LIMIT_MAX_DEPTH)
            return MAX_DEPTH_PLACEHOLDER

        value_type = type(value)

        if value is None or value_type is bool:
            return cast(JSONValue, value)
        if value_type is int:
            return cast(JSONValue, value)
        if value_type is float:
            float_value = cast(float, value)
            return float_value if math.isfinite(float_value) else NON_FINITE_NUMBER_PLACEHOLDER
        if isinstance(value, str):
            return self._clean_text(value)
        if value_type in _EXACT_BYTE_TYPES:
            return self._clean_text(bytes(cast(Any, value)).decode("utf-8", errors="replace"))

        if isinstance(value, Mapping):
            return self._normalize_mapping(value, depth=depth, state=state)
        if isinstance(value, (list, tuple)):
            return self._normalize_sequence(value, depth=depth, state=state)
        if isinstance(value, (set, frozenset)):
            return self._normalize_set(value, depth=depth, state=state)

        converter = self.adapters.resolve(value)
        if converter is not None:
            return self._normalize_with_adapter(value, converter, depth=depth, state=state)

        if is_dataclass(value) and not isinstance(value, type):
            return self._normalize_dataclass(value, depth=depth, state=state)
        if isinstance(value, Enum):
            return self._normalize(value.value, depth=depth + 1, state=state)
        if isinstance(value, Decimal):
            return (
                self._clean_text(str(value)) if value.is_finite() else NON_FINITE_NUMBER_PLACEHOLDER
            )
        if isinstance(value, DateTime):
            return self._clean_text(value.isoformat())
        if isinstance(value, Date):
            return self._clean_text(value.isoformat())
        if isinstance(value, Time):
            return self._clean_text(value.isoformat())
        if isinstance(value, UUID):
            return self._clean_text(str(value))
        if isinstance(value, Path):
            return self._clean_text(str(value))
        if isinstance(value, BaseException):
            return self._normalize_exception(value, depth=depth, state=state)

        return f"[UNSUPPORTED:{_safe_type_name(value)}]"

    def _normalize_with_adapter(
        self,
        value: object,
        converter: AdapterConverter,
        *,
        depth: int,
        state: TraversalState,
    ) -> JSONValue:
        value_id = id(value)
        if value_id in state.active:
            return RECURSIVE_PLACEHOLDER

        state.active.add(value_id)
        try:
            try:
                converted_value = converter(value)
            except Exception:
                state.mark_limit(LIMIT_REPRESENTATION_ERROR)
                return f"[UNSUPPORTED:{_safe_type_name(value)}]"
            return self._normalize(converted_value, depth=depth + 1, state=state)
        finally:
            state.active.discard(value_id)

    def _normalize_mapping(
        self,
        mapping: Mapping[Any, Any],
        *,
        depth: int,
        state: TraversalState,
    ) -> dict[str, JSONValue]:
        mapping_id = id(mapping)
        if mapping_id in state.active:
            return {ERROR_MAPPING_KEY: RECURSIVE_PLACEHOLDER}

        state.active.add(mapping_id)
        cleaned: dict[str, JSONValue] = {}
        try:
            try:
                iterator = iter(mapping.items())
            except Exception:
                state.mark_limit(LIMIT_ITERATION_ERROR)
                return {ERROR_MAPPING_KEY: UNAVAILABLE_PLACEHOLDER}

            while True:
                try:
                    key, item = next(iterator)
                except StopIteration:
                    break
                except Exception:
                    state.mark_limit(LIMIT_ITERATION_ERROR)
                    cleaned[ERROR_MAPPING_KEY] = UNAVAILABLE_PLACEHOLDER
                    break

                if not state.consume_item():
                    cleaned[TRUNCATED_MAPPING_KEY] = TRUNCATED_PLACEHOLDER
                    break

                key_text, trusted_key = safe_mapping_key_text(key)
                output_key = _unique_json_key(self._clean_text(key_text), cleaned)

                if not trusted_key:
                    cleaned[output_key] = self._mask_field_value(item)
                    continue

                field_rule = self._matching_field_rule(key_text)
                if field_rule is not None:
                    cleaned[output_key] = self._apply_field_rule(
                        field_rule,
                        item,
                        depth=depth + 1,
                        state=state,
                    )
                elif self.policy.is_sensitive_key(key):
                    cleaned[output_key] = self._mask_field_value(item)
                else:
                    cleaned[output_key] = self._normalize(item, depth=depth + 1, state=state)
            return cleaned
        finally:
            state.active.discard(mapping_id)

    def _normalize_dataclass(
        self,
        value: object,
        *,
        depth: int,
        state: TraversalState,
    ) -> dict[str, JSONValue]:
        value_id = id(value)
        if value_id in state.active:
            return {ERROR_MAPPING_KEY: RECURSIVE_PLACEHOLDER}

        state.active.add(value_id)
        cleaned: dict[str, JSONValue] = {}
        try:
            for field_info in fields(cast(Any, value)):
                if not state.consume_item():
                    cleaned[TRUNCATED_MAPPING_KEY] = TRUNCATED_PLACEHOLDER
                    break

                key_text = field_info.name
                output_key = _unique_json_key(self._clean_text(key_text), cleaned)
                try:
                    field_value = getattr(value, key_text)
                except Exception:
                    cleaned[output_key] = UNAVAILABLE_PLACEHOLDER
                    continue

                field_rule = self._matching_field_rule(key_text)
                if field_rule is not None:
                    cleaned[output_key] = self._apply_field_rule(
                        field_rule,
                        field_value,
                        depth=depth + 1,
                        state=state,
                    )
                elif self.policy.is_sensitive_key(key_text):
                    cleaned[output_key] = self._mask_field_value(field_value)
                else:
                    cleaned[output_key] = self._normalize(
                        field_value,
                        depth=depth + 1,
                        state=state,
                    )
            return cleaned
        finally:
            state.active.discard(value_id)

    def _normalize_sequence(
        self,
        sequence: Sequence[Any],
        *,
        depth: int,
        state: TraversalState,
    ) -> list[JSONValue]:
        sequence_id = id(sequence)
        if sequence_id in state.active:
            return [RECURSIVE_PLACEHOLDER]

        state.active.add(sequence_id)
        cleaned: list[JSONValue] = []
        try:
            try:
                iterator = iter(sequence)
            except Exception:
                state.mark_limit(LIMIT_ITERATION_ERROR)
                return [UNAVAILABLE_PLACEHOLDER]

            while True:
                try:
                    item = next(iterator)
                except StopIteration:
                    break
                except Exception:
                    state.mark_limit(LIMIT_ITERATION_ERROR)
                    cleaned.append(UNAVAILABLE_PLACEHOLDER)
                    break

                if not state.consume_item():
                    cleaned.append(TRUNCATED_PLACEHOLDER)
                    break
                cleaned.append(self._normalize(item, depth=depth + 1, state=state))
            return cleaned
        finally:
            state.active.discard(sequence_id)

    def _normalize_set(
        self,
        values: set[Any] | frozenset[Any],
        *,
        depth: int,
        state: TraversalState,
    ) -> list[JSONValue]:
        value_id = id(values)
        if value_id in state.active:
            return [RECURSIVE_PLACEHOLDER]

        state.active.add(value_id)
        cleaned: list[JSONValue] = []
        try:
            try:
                iterator = iter(values)
            except Exception:
                state.mark_limit(LIMIT_ITERATION_ERROR)
                return [UNAVAILABLE_PLACEHOLDER]

            while True:
                try:
                    item = next(iterator)
                except StopIteration:
                    break
                except Exception:
                    state.mark_limit(LIMIT_ITERATION_ERROR)
                    cleaned.append(UNAVAILABLE_PLACEHOLDER)
                    break

                if not state.consume_item():
                    state.mark_limit(LIMIT_MAX_ITEMS)
                    cleaned.append(TRUNCATED_PLACEHOLDER)
                    break
                cleaned.append(self._normalize(item, depth=depth + 1, state=state))
            return sorted(cleaned, key=_json_sort_key)
        finally:
            state.active.discard(value_id)

    def _normalize_exception(
        self,
        value: BaseException,
        *,
        depth: int,
        state: TraversalState,
    ) -> dict[str, JSONValue]:
        value_id = id(value)
        if value_id in state.active:
            return {"type": _safe_type_name(value), "message": RECURSIVE_PLACEHOLDER}

        state.active.add(value_id)
        try:
            try:
                message = str(value)
            except Exception:
                state.mark_limit(LIMIT_REPRESENTATION_ERROR)
                message = UNAVAILABLE_PLACEHOLDER
            return {
                "type": _safe_type_name(value),
                "message": self._normalize(message, depth=depth + 1, state=state),
            }
        finally:
            state.active.discard(value_id)

    def _matching_field_rule(self, field_name: str) -> FieldRule | None:
        for rule in self.policy.field_rules:
            if rule.matches(field_name):
                return rule
        return None

    def _apply_field_rule(
        self,
        rule: FieldRule,
        value: object,
        *,
        depth: int,
        state: TraversalState,
    ) -> JSONValue:
        if rule.action == "mask":
            return self._mask_field_value(value)
        if rule.action == "remove":
            return REMOVED_PLACEHOLDER
        if rule.action == "truncate":
            text = _truncatable_text(value)
            if text is None:
                return TRUNCATED_PLACEHOLDER
            max_chars = rule.max_chars
            if max_chars is None:
                return TRUNCATED_PLACEHOLDER
            return self._normalize(text[:max_chars], depth=depth, state=state)
        if rule.action == "block":
            raise LogBlockedError(
                "LogPrivacy blocked a structured field by policy",
                categories=("field",),
            )
        return self._mask_field_value(value)

    def _mask_field_value(self, value: object) -> str:
        return mask_sensitive_value(
            value,
            category="credential",
            rule_name="field_rule",
            reason="value belongs to a sensitive structured field",
            policy=self.policy,
        )

    def _clean_text(self, value: str) -> str:
        return self._cleaner.clean_text(value)


def _truncatable_text(value: object) -> str | None:
    value_type = type(value)
    if value_type is str:
        return cast(str, value)
    if value_type in _EXACT_BYTE_TYPES:
        return bytes(cast(Any, value)).decode("utf-8", errors="replace")
    return None


def _unique_json_key(candidate: str, existing: dict[str, JSONValue]) -> str:
    if candidate not in existing:
        return candidate

    suffix = 2
    while True:
        unique = f"{candidate}#{suffix}"
        if unique not in existing:
            return unique
        suffix += 1


def _json_sort_key(value: JSONValue) -> str:
    return _json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
    )


def _safe_type_name(value: object) -> str:
    name = type(value).__name__ or "object"
    safe = _SAFE_TYPE_NAME_PATTERN.sub("_", name)[:80]
    return safe or "object"
